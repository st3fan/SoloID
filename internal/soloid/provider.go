package soloid

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
)

type Provider struct {
	mu      sync.RWMutex
	runtime *Runtime
	codes   map[string]authorizationCode
	limiter loginLimiter
	now     func() time.Time
	log     func(map[string]any)
}

func NewProvider(r *Runtime, log func(map[string]any)) *Provider {
	if log == nil {
		log = func(map[string]any) {}
	}
	return &Provider{runtime: r, codes: map[string]authorizationCode{}, limiter: loginLimiter{entries: map[string]*loginEntry{}}, now: time.Now, log: log}
}
func (p *Provider) Reload(r *Runtime) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.runtime = r
	clear(p.codes)
}

type response struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func (b *response) Header() http.Header { return b.header }
func (b *response) WriteHeader(code int) {
	if b.status == 0 {
		b.status = code
	}
}
func (b *response) Write(data []byte) (int, error) {
	if b.status == 0 {
		b.status = 200
	}
	return b.body.Write(data)
}
func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func protocolError(w http.ResponseWriter, status int, code string) {
	jsonResponse(w, status, map[string]string{"error": code})
}
func failure(w http.ResponseWriter, status int) error {
	return render(w, status, page{Kind: "message", Title: "Unable to continue", Message: "Return to your app and start signing in again."})
}
func form(req *http.Request) (url.Values, error) {
	typ, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || typ != "application/x-www-form-urlencoded" {
		return nil, errors.New("invalid form content type")
	}
	data, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	p, err := url.ParseQuery(string(data))
	if err != nil || !uniqueParams(p) {
		return nil, errors.New("invalid form")
	}
	return p, nil
}

func (p *Provider) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'")
	if len(req.URL.String()) > 8192 {
		_ = failure(w, 400)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, req.Body, 16384))
	if err != nil {
		protocolError(w, 413, "invalid_request")
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(data))
	p.mu.RLock()
	r := p.runtime
	p.mu.RUnlock()
	if slices.Contains([]string{"/token", "/userinfo", "/jwks.json", "/.well-known/openid-configuration"}, req.URL.Path) {
		w.Header().Add("Vary", "Origin")
		origin := req.Header.Get("Origin")
		for _, client := range r.Config.Clients {
			for _, uri := range client.RedirectURIs {
				u, _ := url.Parse(uri)
				if origin == urlOrigin(u) {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				}
			}
		}
		if req.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.WriteHeader(204)
			return
		}
	}
	b := &response{header: make(http.Header)}
	err = p.route(b, req, r)
	// Buffer cookies/tokens/redirects until the config snapshot is rechecked.
	// Reload and response publication share this lock: no stale grants can escape.
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.runtime != r {
		err = ErrBusy
	}
	if err != nil {
		kind := "internal"
		status := 500
		code := "server_error"
		if errors.Is(err, ErrBusy) {
			kind = "busy"
			status = 503
			code = "temporarily_unavailable"
			w.Header().Set("Retry-After", "5")
		}
		p.log(map[string]any{"event": "request_error", "kind": kind})
		protocolError(w, status, code)
		return
	}
	for k, values := range b.header {
		w.Header()[k] = values
	}
	if b.status == 0 {
		b.status = 200
	}
	w.WriteHeader(b.status)
	_, _ = w.Write(b.body.Bytes())
}

func (p *Provider) route(w http.ResponseWriter, req *http.Request, r *Runtime) error {
	switch req.Method + " " + req.URL.Path {
	case "GET /":
		return render(w, 200, page{Kind: "message", Title: "SoloID", Message: "Open an app to sign in, or visit /logout to end your SoloID session."})
	case "GET /healthz":
		jsonResponse(w, 200, map[string]string{"status": "ok"})
	case "GET /app.css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = w.Write(stylesheet)
	case "GET /.well-known/openid-configuration":
		jsonResponse(w, 200, discovery(r.Config.Issuer))
	case "GET /jwks.json":
		jsonResponse(w, 200, r.JWKS)
	case "GET /authorize":
		return p.authorize(w, req, r)
	case "GET /login", "POST /login":
		return p.login(w, req, r)
	case "POST /token":
		return p.token(w, req, r)
	case "GET /userinfo", "POST /userinfo":
		return p.userinfo(w, req, r)
	case "GET /logout", "POST /logout":
		return p.logout(w, req, r)
	default:
		return render(w, 404, page{Kind: "message", Title: "Page not found", Message: "Open your app to start signing in."})
	}
	return nil
}
func discovery(issuer string) map[string]any {
	return map[string]any{
		"issuer":                                         issuer,
		"authorization_endpoint":                         issuer + "/authorize",
		"token_endpoint":                                 issuer + "/token",
		"userinfo_endpoint":                              issuer + "/userinfo",
		"jwks_uri":                                       issuer + "/jwks.json",
		"end_session_endpoint":                           issuer + "/logout",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code"},
		"subject_types_supported":                        []string{"public"},
		"id_token_signing_alg_values_supported":          []string{"RS256"},
		"scopes_supported":                               []string{"openid", "email", "profile"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic", "client_secret_post", "none"},
		"claims_supported":                               []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "email", "email_verified", "name"},
		"claims_parameter_supported":                     false,
		"request_parameter_supported":                    false,
		"request_uri_parameter_supported":                false,
		"authorization_response_iss_parameter_supported": true,
	}
}

func (p *Provider) authorize(w http.ResponseWriter, req *http.Request, r *Runtime) error {
	params, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return failure(w, 400)
	}
	a, code, redirect := authorization(r, params)
	if a == nil {
		if redirect == "" {
			return failure(w, 400)
		}
		http.Redirect(w, req, callback(r, redirect, "error", code, optional(params, "state")), 302)
		return nil
	}
	u, authTime := session(req, r, p.now())
	prompts := strings.Fields(params.Get("prompt"))
	maxAge := int64(1 << 62)
	if params.Has("max_age") {
		maxAge, _ = strconv.ParseInt(params.Get("max_age"), 10, 64)
	}
	force := slices.Contains(prompts, "login") || slices.Contains(prompts, "select_account") || maxAge == 0
	if u != nil && !force && p.now().Unix()-authTime <= maxAge {
		if !allowed(r.clients[a.ClientID], u) {
			http.Redirect(w, req, callback(r, redirect, "error", "access_denied", a.State), 302)
			return nil
		}
		code, err := p.issueCode(r, *a, u, authTime)
		if err != nil {
			return err
		}
		http.Redirect(w, req, callback(r, redirect, "code", code, a.State), 302)
		return nil
	}
	if slices.Contains(prompts, "none") {
		http.Redirect(w, req, callback(r, redirect, "error", "login_required", a.State), 302)
		return nil
	}
	if err := writeCookie(w, r, "pending", cookieClaims{Request: a, CSRF: randomToken()}, 10*time.Minute, p.now()); err != nil {
		return err
	}
	http.Redirect(w, req, "/login", 302)
	return nil
}

func (p *Provider) login(w http.ResponseWriter, req *http.Request, r *Runtime) error {
	pending := readCookie(req, r, "pending", p.now())
	var client *Client
	if pending != nil && pending.Request != nil && pending.CSRF != "" {
		client = r.clients[pending.Request.ClientID]
		if client != nil && !slices.Contains(client.RedirectURIs, pending.Request.RedirectURI) {
			client = nil
		}
	}
	if req.Method == "GET" {
		if client == nil {
			return failure(w, 400)
		}
		return render(w, 200, loginPage(client, pending.CSRF, "", ""))
	}
	body, err := form(req)
	if req.Header.Get("Origin") != r.Config.Issuer || client == nil || err != nil || !equal(body.Get("csrf"), pending.CSRF) {
		return failure(w, 403)
	}
	email, password := body.Get("email"), body.Get("password")
	if len(email) > 254 || len(password) > 1024 {
		return render(w, 401, loginPage(client, pending.CSRF, "", "Login Failed"))
	}
	result, err := p.limiter.attempt(req.Context(), r, client.ID, email, password, p.now)
	if err != nil {
		return err
	}
	p.log(map[string]any{"event": "login", "email": NormalizeEmail(email), "outcome": result.outcome})
	if result.user == nil {
		status := 401
		message := "Login Failed"
		if result.outcome == "rate_limited" {
			status = 429
			message = "Login Failed (Rate Limited)"
			w.Header().Set("Retry-After", strconv.Itoa(result.retryAfter))
		}
		return render(w, status, loginPage(client, pending.CSRF, email, message))
	}
	authTime := p.now().Unix()
	code, err := p.issueCode(r, *pending.Request, result.user, authTime)
	if err != nil {
		return err
	}
	err = writeCookie(w, r, "session", cookieClaims{Claims: jwt.Claims{Subject: result.user.ID}, AuthTime: authTime, CV: credentialVersion(r, result.user)}, r.sessionTTL, p.now())
	if err != nil {
		return err
	}
	clearCookie(w, r, "pending")
	http.Redirect(w, req, callback(r, pending.Request.RedirectURI, "code", code, pending.Request.State), 303)
	return nil
}

func (p *Provider) token(w http.ResponseWriter, req *http.Request, r *Runtime) error {
	body, err := form(req)
	if err != nil {
		protocolError(w, 400, "invalid_request")
		return nil
	}
	if body.Get("grant_type") != "authorization_code" {
		protocolError(w, 400, "unsupported_grant_type")
		return nil
	}
	id, secret := body.Get("client_id"), body.Get("client_secret")
	auth := req.Header.Get("Authorization")
	if auth != "" {
		encodedID, encodedSecret, ok := req.BasicAuth()
		decodedID, e1 := url.QueryUnescape(encodedID)
		decodedSecret, e2 := url.QueryUnescape(encodedSecret)
		if !ok || body.Has("client_secret") || e1 != nil || e2 != nil || (body.Has("client_id") && id != decodedID) {
			protocolError(w, 400, "invalid_request")
			return nil
		}
		id, secret = decodedID, decodedSecret
	}
	client := r.clients[id]
	authenticated := false
	if client != nil && client.Public {
		authenticated = auth == "" && !body.Has("client_secret")
	} else if len(secret) <= 1024 {
		hash := r.dummyHash
		if client != nil {
			hash = client.SecretHash
		}
		correct, err := verifyPassword(hash, secret)
		if err != nil {
			return err
		}
		authenticated = client != nil && correct
	}
	if !authenticated {
		status := 400
		if auth != "" {
			status = 401
			w.Header().Set("WWW-Authenticate", `Basic realm="SoloID"`)
		}
		protocolError(w, status, "invalid_client")
		return nil
	}
	code, ok := p.takeCode(r, body.Get("code"))
	u := r.users[code.Sub]
	verifier := body.Get("code_verifier")
	if !ok || u == nil || code.ClientID != client.ID || code.RedirectURI != body.Get("redirect_uri") || !slices.Contains(client.RedirectURIs, code.RedirectURI) || !allowed(client, u) || !equal(code.CV, credentialVersion(r, u)) || !verifierPattern.MatchString(verifier) || !equal(code.Challenge, challenge(verifier)) {
		protocolError(w, 400, "invalid_grant")
		return nil
	}
	tokens, err := issueTokens(r, code, u, p.now())
	if err != nil {
		return err
	}
	jsonResponse(w, 200, tokens)
	return nil
}
func (p *Provider) userinfo(w http.ResponseWriter, req *http.Request, r *Runtime) error {
	auth := strings.Fields(req.Header.Get("Authorization"))
	token := ""
	if len(auth) == 2 && strings.EqualFold(auth[0], "Bearer") {
		token = auth[1]
	}
	if req.Method == "POST" {
		body, err := form(req)
		if err != nil {
			protocolError(w, 400, "invalid_request")
			return nil
		}
		if body.Has("access_token") {
			if req.Header.Get("Authorization") != "" {
				protocolError(w, 400, "invalid_request")
				return nil
			}
			token = body.Get("access_token")
		}
	}
	c, err := verifyAccess(r, token, p.now())
	if err == nil {
		u, client := r.users[c.Subject], r.clients[c.ClientID]
		if u != nil && client != nil && allowed(client, u) && equal(c.CV, credentialVersion(r, u)) {
			jsonResponse(w, 200, userClaims(u, c.Scope))
			return nil
		}
	}
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	protocolError(w, 401, "invalid_token")
	return nil
}
func (p *Provider) logout(w http.ResponseWriter, req *http.Request, r *Runtime) error {
	if req.Method == "GET" {
		params, err := url.ParseQuery(req.URL.RawQuery)
		if err != nil || !uniqueParams(params) || len(params.Get("state")) > 256 {
			return failure(w, 400)
		}
		id := params.Get("client_id")
		if params.Has("id_token_hint") {
			hint := logoutClient(r, params.Get("id_token_hint"))
			if hint == "" || (id != "" && id != hint) {
				return failure(w, 400)
			}
			id = hint
		}
		redirect := optional(params, "post_logout_redirect_uri")
		if redirect != nil && (r.clients[id] == nil || !slices.Contains(r.clients[id].LogoutURIs, *redirect)) {
			return failure(w, 400)
		}
		csrf := randomToken()
		if err := writeCookie(w, r, "logout", cookieClaims{CSRF: csrf, ClientID: id, Redirect: redirect, State: optional(params, "state")}, 10*time.Minute, p.now()); err != nil {
			return err
		}
		return render(w, 200, page{Kind: "logout", Title: "Sign out", CSRF: csrf})
	}
	c := readCookie(req, r, "logout", p.now())
	body, err := form(req)
	if req.Header.Get("Origin") != r.Config.Issuer || c == nil || c.CSRF == "" || err != nil || !equal(c.CSRF, body.Get("csrf")) {
		return failure(w, 403)
	}
	if c.Redirect != nil && (r.clients[c.ClientID] == nil || !slices.Contains(r.clients[c.ClientID].LogoutURIs, *c.Redirect)) {
		return failure(w, 400)
	}
	for _, kind := range []string{"session", "pending", "logout"} {
		clearCookie(w, r, kind)
	}
	if c.Redirect != nil {
		u, _ := url.Parse(*c.Redirect)
		q := u.Query()
		if c.State != nil {
			q.Set("state", *c.State)
		}
		u.RawQuery = q.Encode()
		http.Redirect(w, req, u.String(), 303)
		return nil
	}
	return render(w, 200, page{Kind: "message", Title: "You're signed out", Message: "You can close this window. Open an app when you're ready to sign in again."})
}
