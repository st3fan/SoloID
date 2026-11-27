package soloid

import (
	"encoding/json"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

type authorizationRequest struct {
	ClientID    string  `json:"client_id"`
	RedirectURI string  `json:"redirect_uri"`
	Scope       string  `json:"scope"`
	Challenge   string  `json:"code_challenge"`
	State       *string `json:"state,omitempty"`
	Nonce       *string `json:"nonce,omitempty"`
}
type authorizationCode struct {
	authorizationRequest
	Sub      string
	AuthTime int64
	CV       string
	Expires  time.Time
}

var challengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var verifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
var maxAgePattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})$`)

func optional(p url.Values, key string) *string {
	if !p.Has(key) {
		return nil
	}
	v := p.Get(key)
	return &v
}
func uniqueParams(p url.Values) bool {
	for _, values := range p {
		if len(values) != 1 {
			return false
		}
	}
	return true
}
func authorization(r *Runtime, p url.Values) (*authorizationRequest, string, string) {
	c := r.clients[p.Get("client_id")]
	redirect := p.Get("redirect_uri")
	if !uniqueParams(p) || c == nil || !slices.Contains(c.RedirectURIs, redirect) {
		return nil, "invalid_request", ""
	}
	fail := func(e string) (*authorizationRequest, string, string) { return nil, e, redirect }
	if p.Get("response_type") != "code" {
		return fail("unsupported_response_type")
	}
	for _, k := range []string{"request", "request_uri", "registration"} {
		if p.Has(k) {
			return fail(k + "_not_supported")
		}
	}
	if p.Has("claims") || p.Has("id_token_hint") || (p.Has("response_mode") && p.Get("response_mode") != "query") {
		return fail("invalid_request")
	}
	scopes := []string{}
	for _, s := range strings.Split(p.Get("scope"), " ") {
		if s == "" {
			continue
		}
		if !slices.Contains([]string{"openid", "email", "profile", "offline_access"}, s) {
			return fail("invalid_scope")
		}
		if s != "offline_access" && !slices.Contains(scopes, s) {
			scopes = append(scopes, s)
		}
	}
	if !slices.Contains(scopes, "openid") {
		return fail("invalid_scope")
	}
	if p.Get("code_challenge_method") != "S256" || !challengePattern.MatchString(p.Get("code_challenge")) {
		return fail("invalid_request")
	}
	prompts := strings.Fields(p.Get("prompt"))
	for _, s := range prompts {
		if !slices.Contains([]string{"none", "login", "select_account", "consent"}, s) {
			return fail("invalid_request")
		}
	}
	if slices.Contains(prompts, "none") && len(prompts) != 1 {
		return fail("invalid_request")
	}
	if slices.Contains(prompts, "consent") {
		return fail("consent_required")
	}
	if p.Has("max_age") && !maxAgePattern.MatchString(p.Get("max_age")) {
		return fail("invalid_request")
	}
	for _, k := range []string{"state", "nonce", "login_hint"} {
		if len(p.Get(k)) > 256 {
			return fail("invalid_request")
		}
	}
	request := &authorizationRequest{ClientID: c.ID, RedirectURI: redirect, Scope: strings.Join(scopes, " "), Challenge: p.Get("code_challenge"), State: optional(p, "state"), Nonce: optional(p, "nonce")}
	encoded, _ := json.Marshal(request)
	if len(encoded) > 2400 {
		return fail("invalid_request")
	}
	return request, "", redirect
}
func callback(r *Runtime, redirect, key, value string, state *string) string {
	u, _ := url.Parse(redirect)
	q := u.Query()
	q.Set(key, value)
	q.Set("iss", r.Config.Issuer)
	if state != nil {
		q.Set("state", *state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
func (p *Provider) issueCode(r *Runtime, a authorizationRequest, u *User, authTime int64) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.runtime != r {
		return "", ErrBusy
	}
	now := p.now()
	for k, c := range p.codes {
		if !now.Before(c.Expires) {
			delete(p.codes, k)
		}
	}
	if len(p.codes) >= 10000 {
		return "", ErrBusy
	}
	value := randomToken()
	p.codes[challenge(value)] = authorizationCode{a, u.ID, authTime, credentialVersion(r, u), now.Add(time.Minute)}
	return value, nil
}
func (p *Provider) takeCode(r *Runtime, value string) (authorizationCode, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.runtime != r {
		return authorizationCode{}, false
	}
	k := challenge(value)
	code, ok := p.codes[k]
	delete(p.codes, k)
	return code, ok && p.now().Before(code.Expires)
}
