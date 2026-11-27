package soloid

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const password = "correct horse battery staple"
const clientSecret = "test client secret +:/?!"
const verifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"

var fixtureOnce sync.Once
var fixtureRuntime *Runtime

func fixture(t *testing.T) *Runtime {
	t.Helper()
	fixtureOnce.Do(func() {
		c, err := NewSkeleton()
		if err != nil {
			t.Fatal(err)
		}
		c.Issuer = "http://localhost:3000"
		c.Users = []User{{ID: "user-one", Email: "one@example.com", Name: "One User", PasswordHash: HashPassword(password)}, {ID: "user-two", Email: "two@example.com", Name: "Two User", PasswordHash: HashPassword("another strong password")}}
		c.Clients = []Client{
			{ID: "web", Name: "Demo app", SecretHash: HashPassword(clientSecret), RedirectURIs: []string{"https://app.example.com/callback?existing=1"}, LogoutURIs: []string{"https://app.example.com/signed-out"}},
			{ID: "public", Public: true, RedirectURIs: []string{"https://spa.example.com/callback"}},
			{ID: "restricted", Public: true, RedirectURIs: []string{"https://restricted.example.com/callback"}, AllowedUsers: []string{"user-two"}},
		}
		fixtureRuntime, err = PrepareConfig(c)
		if err != nil {
			t.Fatal(err)
		}
	})
	return fixtureRuntime
}
func configCopy(t *testing.T, r *Runtime) Config {
	t.Helper()
	data, err := json.Marshal(r.Config)
	if err != nil {
		t.Fatal(err)
	}
	var c Config
	if err = json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	return c
}
func prepared(t *testing.T, c Config) *Runtime {
	t.Helper()
	r, err := PrepareConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func authParams(client string) url.Values {
	redirect := "https://spa.example.com/callback"
	if client == "web" {
		redirect = "https://app.example.com/callback?existing=1"
	}
	if client == "restricted" {
		redirect = "https://restricted.example.com/callback"
	}
	return url.Values{"client_id": {client}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid email profile"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}, "state": {"state-value"}, "nonce": {"nonce-value"}}
}

type browser struct {
	p       *Provider
	issuer  string
	cookies map[string]*http.Cookie
	csrf    string
	t       *testing.T
}

func newBrowser(t *testing.T, p *Provider) *browser {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return &browser{p: p, issuer: p.runtime.Config.Issuer, cookies: map[string]*http.Cookie{}, t: t}
}
func (b *browser) request(method, path string, form url.Values, headers ...string) *httptest.ResponseRecorder {
	b.t.Helper()
	body := ""
	if form != nil {
		body = form.Encode()
	}
	req := httptest.NewRequest(method, b.issuer+path, strings.NewReader(body))
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	b.p.ServeHTTP(w, req)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return w
}

var csrfPattern = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (b *browser) start(params url.Values) *httptest.ResponseRecorder {
	b.t.Helper()
	w := b.request("GET", "/authorize?"+params.Encode(), nil)
	if w.Header().Get("Location") == "/login" {
		page := b.request("GET", "/login", nil)
		matches := csrfPattern.FindStringSubmatch(page.Body.String())
		if len(matches) != 2 {
			b.t.Fatalf("missing form: %s", page.Body)
		}
		b.csrf = matches[1]
	}
	return w
}
func (b *browser) login(email, pass string) *httptest.ResponseRecorder {
	return b.request("POST", "/login", url.Values{"csrf": {b.csrf}, "email": {email}, "password": {pass}}, "Origin", b.issuer)
}
func status(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status %d, want %d: %s", w.Code, want, w.Body)
	}
}
func location(t *testing.T, w *httptest.ResponseRecorder) url.Values {
	t.Helper()
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}
func jsonBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func (b *browser) code(client string, params url.Values) string {
	b.t.Helper()
	if params == nil {
		params = authParams(client)
	}
	params.Set("prompt", "login")
	b.start(params)
	w := b.login("one@example.com", password)
	status(b.t, w, 303)
	return location(b.t, w).Get("code")
}
func tokenForm(code, client string) url.Values {
	p := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {client}, "redirect_uri": {authParams(client).Get("redirect_uri")}, "code_verifier": {verifier}}
	if client == "web" {
		p.Set("client_secret", clientSecret)
	}
	return p
}
func (b *browser) tokens(client string, params url.Values) map[string]any {
	b.t.Helper()
	code := b.code(client, params)
	w := b.request("POST", "/token", tokenForm(code, client))
	status(b.t, w, 200)
	return jsonBody(b.t, w)
}

func TestOIDCFlowAndClaims(t *testing.T) {
	r := fixture(t)
	b := newBrowser(t, NewProvider(r, nil))
	d := jsonBody(t, b.request("GET", "/.well-known/openid-configuration", nil))
	if d["issuer"] != r.Config.Issuer || fmt.Sprint(d["grant_types_supported"]) != "[authorization_code]" || fmt.Sprint(d["code_challenge_methods_supported"]) != "[S256]" {
		t.Fatal(d)
	}
	w := b.request("GET", "/jwks.json", nil)
	var keys jose.JSONWebKeySet
	if json.Unmarshal(w.Body.Bytes(), &keys) != nil || len(keys.Keys) != 1 || !keys.Keys[0].IsPublic() {
		t.Fatal("unsafe JWKS")
	}
	b.start(authParams("web"))
	login := b.login("one@example.com", password)
	status(t, login, 303)
	cb := location(t, login)
	if cb.Get("state") != "state-value" || cb.Get("existing") != "1" || cb.Get("iss") != r.Config.Issuer {
		t.Fatal(cb)
	}
	w = b.request("POST", "/token", tokenForm(cb.Get("code"), "web"))
	status(t, w, 200)
	tokens := jsonBody(t, w)
	if tokens["refresh_token"] != nil || tokens["expires_in"] != float64(900) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("token contract")
	}
	token, err := jwt.ParseSigned(tokens["id_token"].(string), []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	var claims jwt.Claims
	var custom map[string]any
	if err = token.Claims(keys.Keys[0].Key, &claims, &custom); err != nil {
		t.Fatal(err)
	}
	if err = claims.Validate(jwt.Expected{Issuer: r.Config.Issuer, AnyAudience: jwt.Audience{"web"}}); err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "user-one" || claims.Expiry.Time().Sub(claims.IssuedAt.Time()) != 5*time.Minute || custom["nonce"] != "nonce-value" || custom["email_verified"] != false {
		t.Fatal(custom)
	}
	info := b.request("GET", "/userinfo", nil, "Authorization", "Bearer "+tokens["access_token"].(string))
	status(t, info, 200)
	if got := jsonBody(t, info); got["email"] != "one@example.com" || got["name"] != "One User" || got["sub"] != "user-one" {
		t.Fatal(got)
	}
	status(t, b.request("GET", "/userinfo", nil, "Authorization", "Bearer "+tokens["id_token"].(string)), 401)
	a := authParams("public")
	a.Set("scope", "openid offline_access")
	minimal := b.tokens("public", a)
	if minimal["scope"] != "openid" {
		t.Fatal(minimal)
	}
	info = b.request("POST", "/userinfo", url.Values{"access_token": {minimal["access_token"].(string)}})
	status(t, info, 200)
	if got := jsonBody(t, info); len(got) != 1 || got["sub"] != "user-one" {
		t.Fatal(got)
	}
	status(t, b.request("POST", "/userinfo", url.Values{"access_token": {minimal["access_token"].(string)}}, "Authorization", "Bearer "+minimal["access_token"].(string)), 400)
}
func TestClientAuthenticationAndCodeBindings(t *testing.T) {
	b := newBrowser(t, NewProvider(fixture(t), nil))
	for _, method := range []string{"basic", "post"} {
		t.Run(method, func(t *testing.T) {
			code := b.code("web", nil)
			body := tokenForm(code, "web")
			headers := []string{}
			if method == "basic" {
				body.Del("client_secret")
				headers = []string{"Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte("web:"+url.QueryEscape(clientSecret)))}
			}
			status(t, b.request("POST", "/token", body, headers...), 200)
		})
	}
	code := b.code("web", nil)
	body := tokenForm(code, "web")
	body.Set("client_secret", "wrong")
	status(t, b.request("POST", "/token", body), 400)
	status(t, b.request("POST", "/token", tokenForm(code, "web")), 200)
	for _, change := range []struct{ key, value string }{{"code_verifier", strings.Repeat("z", 43)}, {"code_verifier", ""}, {"redirect_uri", "https://spa.example.com/callback?altered=1"}, {"client_id", "restricted"}, {"client_secret", "unexpected"}} {
		t.Run(change.key+change.value, func(t *testing.T) {
			code := b.code("public", nil)
			body := tokenForm(code, "public")
			body.Set(change.key, change.value)
			status(t, b.request("POST", "/token", body), 400)
		})
	}
	code = b.code("public", nil)
	responses := make(chan int, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			other := newBrowser(t, b.p)
			responses <- other.request("POST", "/token", tokenForm(code, "public")).Code
		})
	}
	wg.Wait()
	close(responses)
	got := []int{}
	for c := range responses {
		got = append(got, c)
	}
	slices.Sort(got)
	if !slices.Equal(got, []int{200, 400}) {
		t.Fatal(got)
	}
}
func TestAuthorizationValidation(t *testing.T) {
	b := newBrowser(t, NewProvider(fixture(t), nil))
	for _, change := range []struct{ key, value, want string }{{"redirect_uri", "https://evil.example/cb", ""}, {"client_id", "missing", ""}, {"response_type", "token", "unsupported_response_type"}, {"scope", "email", "invalid_scope"}, {"code_challenge_method", "plain", "invalid_request"}, {"code_challenge", "", "invalid_request"}, {"prompt", "none login", "invalid_request"}, {"prompt", "consent", "consent_required"}, {"max_age", "-1", "invalid_request"}, {"request_uri", "https://evil.example", "request_uri_not_supported"}, {"claims", "{}", "invalid_request"}} {
		t.Run(change.key+change.value, func(t *testing.T) {
			a := authParams("web")
			a.Set(change.key, change.value)
			w := b.start(a)
			if change.want == "" {
				status(t, w, 400)
				if w.Header().Get("Location") != "" {
					t.Fatal("untrusted redirect")
				}
			} else if location(t, w).Get("error") != change.want {
				t.Fatal(w.Header())
			}
		})
	}
	status(t, b.request("GET", "/authorize?"+authParams("web").Encode()+"&client_id=web", nil), 400)
	status(t, b.request("GET", "/authorize?"+authParams("web").Encode()+"&bad=%zz", nil), 400)
}
func TestSessionExpiryAndCodeExpiry(t *testing.T) {
	p := NewProvider(fixture(t), nil)
	now := time.Now().Truncate(time.Second)
	p.now = func() time.Time { return now }
	b := newBrowser(t, p)
	a := authParams("public")
	a.Set("prompt", "none")
	if location(t, b.start(a)).Get("error") != "login_required" {
		t.Fatal("silent login without session")
	}
	code := b.code("public", nil)
	tokens := b.tokens("public", nil)
	if location(t, b.start(a)).Get("code") == "" {
		t.Fatal("SSO failed")
	}
	for _, extra := range []struct{ k, v string }{{"prompt", "login"}, {"prompt", "select_account"}, {"max_age", "0"}} {
		a := authParams("public")
		a.Set(extra.k, extra.v)
		if b.start(a).Header().Get("Location") != "/login" {
			t.Fatal("did not force login")
		}
	}
	now = now.Add(time.Minute)
	status(t, b.request("POST", "/token", tokenForm(code, "public")), 400)
	now = now.Add(14*time.Minute - time.Second)
	status(t, b.request("GET", "/userinfo", nil, "Authorization", "Bearer "+tokens["access_token"].(string)), 200)
	now = now.Add(time.Second)
	status(t, b.request("GET", "/userinfo", nil, "Authorization", "Bearer "+tokens["access_token"].(string)), 401)
	now = now.Add(12 * time.Hour)
	if location(t, b.start(a)).Get("error") != "login_required" {
		t.Fatal("session did not expire")
	}
}
func TestFailuresAndCSRF(t *testing.T) {
	b := newBrowser(t, NewProvider(fixture(t), nil))
	b.start(authParams("web"))
	known := b.login("one@example.com", "<script>secret</script>")
	unknown := b.login("absent@example.com", "<script>secret</script>")
	status(t, known, 401)
	status(t, unknown, 401)
	if strings.ReplaceAll(known.Body.String(), "one@example.com", "EMAIL") != strings.ReplaceAll(unknown.Body.String(), "absent@example.com", "EMAIL") {
		t.Fatal("account enumeration through failure page")
	}
	if strings.Contains(known.Body.String(), "secret") || strings.Contains(known.Body.String(), "<script") {
		t.Fatal("reflected password")
	}
	bad := b.login(`"><script>x</script>`, "wrong")
	if strings.Contains(bad.Body.String(), "<script>") {
		t.Fatal("unescaped email")
	}
	if known.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("browser Origin suppressed")
	}
	form := url.Values{"email": {"one@example.com"}, "password": {password}, "csrf": {b.csrf}}
	status(t, b.request("POST", "/login", form, "Origin", "https://evil.example"), 403)
	form.Add("email", "two@example.com")
	status(t, b.request("POST", "/login", form, "Origin", b.issuer), 403)
	b.csrf = "bad"
	status(t, b.login("one@example.com", password), 403)
	b.cookies["soloid-pending"] = &http.Cookie{Name: "soloid-pending", Value: "forged"}
	status(t, b.login("one@example.com", password), 403)
	status(t, b.request("POST", "/token", url.Values{"large": {strings.Repeat("x", 17000)}}), 413)
	status(t, b.request("GET", "/authorize?large="+strings.Repeat("x", 8200), nil), 400)
}
func TestFailureLimiter(t *testing.T) {
	for _, email := range []string{"one@example.com", "absent@example.com"} {
		t.Run(email, func(t *testing.T) {
			p := NewProvider(fixture(t), nil)
			now := time.Now().Truncate(time.Second)
			p.now = func() time.Time { return now }
			b := newBrowser(t, p)
			b.start(authParams("web"))
			for i := 0; i < 5; i++ {
				form := url.Values{"email": {strings.ToUpper(email)}, "password": {"wrong"}, "csrf": {b.csrf}}
				status(t, b.request("POST", "/login", form, "Origin", b.issuer, "X-Forwarded-For", fmt.Sprintf("192.0.2.%d", i)), 401)
			}
			w := b.login(email, password)
			status(t, w, 429)
			if !strings.Contains(w.Body.String(), "Login Failed (Rate Limited)") || w.Header().Get("Retry-After") != "900" {
				t.Fatal("lockout contract")
			}
			status(t, b.login("two@example.com", "wrong"), 401)
			p.Reload(prepared(t, configCopy(t, p.runtime)))
			status(t, b.login(email, password), 429)
			now = now.Add(899 * time.Second)
			b.start(authParams("web"))
			w = b.login(email, password)
			status(t, w, 429)
			if w.Header().Get("Retry-After") != "1" {
				t.Fatal("retries extended lock")
			}
			now = now.Add(time.Second)
			status(t, b.login(email, "wrong"), 401)
		})
	}
	t.Run("concurrency and reset", func(t *testing.T) {
		p := NewProvider(fixture(t), nil)
		b := newBrowser(t, p)
		b.start(authParams("web"))
		responses := make(chan int, 6)
		var wg sync.WaitGroup
		for range 6 {
			other := newBrowser(t, p)
			other.csrf = b.csrf
			for k, c := range b.cookies {
				other.cookies[k] = c
			}
			wg.Go(func() { responses <- other.login("one@example.com", "wrong").Code })
		}
		wg.Wait()
		close(responses)
		got := []int{}
		for c := range responses {
			got = append(got, c)
		}
		slices.Sort(got)
		if !slices.Equal(got, []int{401, 401, 401, 401, 401, 429}) {
			t.Fatal(got)
		}
		for range 4 {
			status(t, b.login("two@example.com", "wrong"), 401)
		}
		status(t, b.login("two@example.com", "another strong password"), 303)
		a := authParams("web")
		a.Set("prompt", "login")
		b.start(a)
		for range 5 {
			status(t, b.login("two@example.com", "wrong"), 401)
		}
	})
	t.Run("one hour window", func(t *testing.T) {
		p := NewProvider(fixture(t), nil)
		now := time.Now()
		p.now = func() time.Time { return now }
		b := newBrowser(t, p)
		b.start(authParams("public"))
		for range 4 {
			status(t, b.login("one@example.com", "wrong"), 401)
		}
		now = now.Add(time.Hour)
		b.start(authParams("public"))
		for range 5 {
			status(t, b.login("one@example.com", "wrong"), 401)
		}
	})
}
func TestConfigurationChangesAndRestrictions(t *testing.T) {
	r := fixture(t)
	p := NewProvider(r, nil)
	b := newBrowser(t, p)
	b.start(authParams("restricted"))
	for range 6 {
		status(t, b.login("one@example.com", password), 401)
	}
	tokens := b.tokens("web", nil)
	if location(t, b.start(authParams("restricted"))).Get("error") != "access_denied" {
		t.Fatal("SSO bypassed restriction")
	}
	code := b.code("public", nil)
	c := configCopy(t, r)
	c.Users[0].Email = "renamed@example.com"
	p.Reload(prepared(t, c))
	status(t, b.request("POST", "/token", tokenForm(code, "public")), 400)
	w := b.start(authParams("public"))
	if location(t, w).Get("code") == "" {
		t.Fatal("rename revoked session")
	}
	c.Clients[0].AllowedUsers = []string{}
	p.Reload(prepared(t, c))
	status(t, b.request("GET", "/userinfo", nil, "Authorization", "Bearer "+tokens["access_token"].(string)), 401)
	c.Users[0].PasswordHash = HashPassword("a different long password")
	p.Reload(prepared(t, c))
	if b.start(authParams("public")).Header().Get("Location") != "/login" {
		t.Fatal("password did not revoke session")
	}
	status(t, b.request("GET", "/userinfo", nil, "Authorization", "Bearer "+tokens["access_token"].(string)), 401)
}
func TestHTTPSCookiesRestartAndLogout(t *testing.T) {
	c := configCopy(t, fixture(t))
	c.Issuer = "https://id.example.com"
	r := prepared(t, c)
	b := newBrowser(t, NewProvider(r, nil))
	w := b.start(authParams("public"))
	cookie := w.Result().Cookies()[0]
	if cookie.Name != "__Host-soloid-pending" || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("unsafe cookie")
	}
	b.code("public", nil)
	b.p = NewProvider(r, nil)
	a := authParams("public")
	a.Set("prompt", "none")
	if location(t, b.start(a)).Get("code") == "" {
		t.Fatal("restart revoked unchanged session")
	}
	status(t, b.request("GET", "/logout?client_id=web&post_logout_redirect_uri=https://evil.example", nil), 400)
	w = b.request("GET", "/logout?client_id=web&post_logout_redirect_uri=https://app.example.com/signed-out&state=bye", nil)
	status(t, w, 200)
	csrf := csrfPattern.FindStringSubmatch(w.Body.String())[1]
	status(t, b.request("POST", "/logout", url.Values{"csrf": {csrf}}, "Origin", "https://evil.example"), 403)
	w = b.request("POST", "/logout", url.Values{"csrf": {csrf}}, "Origin", c.Issuer)
	status(t, w, 303)
	if w.Header().Get("Location") != "https://app.example.com/signed-out?state=bye" {
		t.Fatal(w.Header())
	}
	if location(t, b.start(a)).Get("error") != "login_required" {
		t.Fatal("logout did not clear session")
	}
}
func TestRotationAndExpiredLogoutHints(t *testing.T) {
	r := fixture(t)
	p := NewProvider(r, nil)
	now := time.Now()
	p.now = func() time.Time { return now }
	b := newBrowser(t, p)
	tokens := b.tokens("web", nil)
	c := configCopy(t, r)
	fresh, err := NewSkeleton()
	if err != nil {
		t.Fatal(err)
	}
	c.SigningKey = fresh.SigningKey
	pub, _ := json.Marshal(r.JWKS.Keys[0])
	c.PreviousKeys = []json.RawMessage{pub}
	p.Reload(prepared(t, c))
	status(t, b.request("GET", "/userinfo", nil, "Authorization", "Bearer "+tokens["access_token"].(string)), 200)
	now = now.Add(6 * time.Minute)
	q := url.Values{"client_id": {"web"}, "post_logout_redirect_uri": {"https://app.example.com/signed-out"}, "id_token_hint": {tokens["id_token"].(string)}}
	status(t, b.request("GET", "/logout?"+q.Encode(), nil), 200)
	c.PreviousKeys = nil
	p.Reload(prepared(t, c))
	status(t, b.request("GET", "/userinfo", nil, "Authorization", "Bearer "+tokens["access_token"].(string)), 401)
	status(t, b.request("GET", "/logout?"+q.Encode(), nil), 400)
	q.Del("id_token_hint")
	status(t, b.request("GET", "/logout?"+q.Encode(), nil), 200)
}

// Pause real RSA signing to deterministically exercise a config reload race.
type pausedSigner struct {
	key              jose.JSONWebKey
	started, release chan struct{}
	once             sync.Once
}

func (s *pausedSigner) Public() *jose.JSONWebKey        { k := s.key.Public(); return &k }
func (s *pausedSigner) Algs() []jose.SignatureAlgorithm { return []jose.SignatureAlgorithm{jose.RS256} }
func (s *pausedSigner) SignPayload(payload []byte, _ jose.SignatureAlgorithm) ([]byte, error) {
	s.once.Do(func() { close(s.started); <-s.release })
	sum := sha256.Sum256(payload)
	return rsa.SignPKCS1v15(rand.Reader, s.key.Key.(*rsa.PrivateKey), crypto.SHA256, sum[:])
}
func TestReloadDuringSigning(t *testing.T) {
	r := prepared(t, configCopy(t, fixture(t)))
	signer := &pausedSigner{key: r.key, started: make(chan struct{}), release: make(chan struct{})}
	r.key.Key = signer
	p := NewProvider(r, nil)
	b := newBrowser(t, p)
	code := b.code("public", nil)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- b.request("POST", "/token", tokenForm(code, "public")) }()
	select {
	case <-signer.started:
	case <-time.After(5 * time.Second):
		t.Fatal("signing not reached")
	}
	p.Reload(fixture(t))
	close(signer.release)
	w := <-done
	status(t, w, 503)
	if jsonBody(t, w)["error"] != "temporarily_unavailable" || len(w.Result().Cookies()) != 0 {
		t.Fatal("stale response escaped")
	}
	b.tokens("public", nil)
}
func TestCORSAndResourceLimits(t *testing.T) {
	p := NewProvider(fixture(t), nil)
	b := newBrowser(t, p)
	for _, origin := range []string{"https://spa.example.com", "https://evil.example"} {
		w := b.request("OPTIONS", "/token", nil, "Origin", origin)
		if (w.Header().Get("Access-Control-Allow-Origin") != "") != (origin == "https://spa.example.com") {
			t.Fatal(w.Header())
		}
	}
	b.start(authParams("public"))
	passwordSlots <- struct{}{}
	passwordSlots <- struct{}{}
	w := b.login("one@example.com", password)
	<-passwordSlots
	<-passwordSlots
	status(t, w, 503)
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("missing overload retry")
	}
	for i := range 10000 {
		p.limiter.entries[fmt.Sprint(i)] = &loginEntry{expires: time.Now().Add(time.Hour), failures: 1}
	}
	status(t, b.login("another@example.com", "wrong"), 503)
	clear(p.limiter.entries)
	p.limiter.queued = 32
	status(t, b.login("one@example.com", password), 503)
	p.limiter.queued = 0
	for i := range 10000 {
		p.codes[fmt.Sprint(i)] = authorizationCode{Expires: time.Now().Add(time.Minute)}
	}
	status(t, b.login("one@example.com", password), 503)
}
func TestHashCompatibility(t *testing.T) {
	// Produced independently by the previous @node-rs/argon2 implementation.
	const encoded = "$argon2id$v=19$m=65536,t=3,p=4$BwcHBwcHBwcHBwcHBwcHBw$PuPCRNNjHmNdNNI7G8xwshS44z9xhv0+wpdVNmc99yw"
	for _, pass := range []string{"cross-language test password", "wrong"} {
		ok, err := verifyPassword(encoded, pass)
		if err != nil || ok != (pass == "cross-language test password") {
			t.Fatal("incompatible PHC verification", err)
		}
	}
}
func TestTimingDiagnostic(t *testing.T) {
	if os.Getenv("SOLOID_TIMING") != "1" {
		t.Skip("opt-in timing diagnostic")
	}
	r := fixture(t)
	samples := map[string][]time.Duration{"known": {}, "unknown": {}}
	for i := range 110 {
		order := []string{"known", "unknown"}
		if i%2 != 0 {
			slices.Reverse(order)
		}
		for _, kind := range order {
			b := newBrowser(t, NewProvider(r, nil))
			b.start(authParams("public"))
			email := "one@example.com"
			if kind == "unknown" {
				email = "absent@example.com"
			}
			start := time.Now()
			status(t, b.login(email, "same invalid password"), 401)
			if i >= 10 {
				samples[kind] = append(samples[kind], time.Since(start))
			}
		}
	}
	for kind, times := range samples {
		slices.Sort(times)
		t.Logf("%s: n=%d median=%s p95=%s", kind, len(times), times[50], times[95])
	}
	t.Log("Diagnostic only; equivalent Argon2 work does not guarantee identical timing.")
}

func TestConcurrentReloadAndRequests(t *testing.T) {
	p := NewProvider(fixture(t), nil)
	a, b := fixture(t), prepared(t, configCopy(t, fixture(t)))
	var count atomic.Int64
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 30 {
				browser := newBrowser(t, p)
				w := browser.request("GET", "/.well-known/openid-configuration", nil)
				if w.Code == 200 {
					count.Add(1)
				} else if w.Code != 503 {
					t.Errorf("unexpected status %d", w.Code)
				}
			}
		})
	}
	wg.Go(func() {
		for range 50 {
			p.Reload(a)
			p.Reload(b)
		}
	})
	wg.Wait()
	if count.Load() == 0 {
		t.Fatal("no requests completed")
	}
}
