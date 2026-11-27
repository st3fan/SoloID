package soloid

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func challenge(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func credentialVersion(r *Runtime, u *User) string {
	h := hmac.New(sha256.New, r.cookieKey)
	h.Write([]byte(u.PasswordHash))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func sign(key any, alg jose.SignatureAlgorithm, kind string, payload any) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, (&jose.SignerOptions{}).WithType(jose.ContentType(kind)))
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(payload).Serialize()
}

type cookieClaims struct {
	jwt.Claims
	AuthTime int64                 `json:"auth_time,omitempty"`
	CV       string                `json:"cv,omitempty"`
	CSRF     string                `json:"csrf,omitempty"`
	Request  *authorizationRequest `json:"request,omitempty"`
	ClientID string                `json:"clientID,omitempty"`
	Redirect *string               `json:"redirect,omitempty"`
	State    *string               `json:"state,omitempty"`
}

func cookieName(r *Runtime, kind string) string {
	prefix := ""
	if strings.HasPrefix(r.Config.Issuer, "https:") {
		prefix = "__Host-"
	}
	return prefix + "soloid-" + kind
}
func writeCookie(w http.ResponseWriter, r *Runtime, kind string, c cookieClaims, ttl time.Duration, now time.Time) error {
	c.Claims = jwt.Claims{Issuer: r.Config.Issuer, Subject: c.Subject, Audience: jwt.Audience{"soloid:" + kind}, IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(ttl))}
	token, err := sign(r.cookieKey, jose.HS256, "soloid-"+kind, c)
	if err != nil {
		return err
	}
	if len(token) > 3800 {
		return errors.New("cookie payload too large")
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName(r, kind), Value: token, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(r.Config.Issuer, "https:"), SameSite: http.SameSiteLaxMode, MaxAge: int(ttl.Seconds())})
	return nil
}
func readCookie(req *http.Request, r *Runtime, kind string, now time.Time) *cookieClaims {
	cookie, err := req.Cookie(cookieName(r, kind))
	if err != nil || len(cookie.Value) > 3800 {
		return nil
	}
	token, err := jwt.ParseSigned(cookie.Value, []jose.SignatureAlgorithm{jose.HS256})
	if err != nil || len(token.Headers) != 1 || token.Headers[0].ExtraHeaders[jose.HeaderType] != "soloid-"+kind {
		return nil
	}
	var c cookieClaims
	if token.Claims(r.cookieKey, &c) != nil || c.Expiry == nil || c.IssuedAt == nil || !now.Before(c.Expiry.Time()) || c.ValidateWithLeeway(jwt.Expected{Issuer: r.Config.Issuer, AnyAudience: jwt.Audience{"soloid:" + kind}, Time: now}, 0) != nil {
		return nil
	}
	return &c
}
func clearCookie(w http.ResponseWriter, r *Runtime, kind string) {
	http.SetCookie(w, &http.Cookie{Name: cookieName(r, kind), Path: "/", MaxAge: -1, HttpOnly: true, Secure: strings.HasPrefix(r.Config.Issuer, "https:"), SameSite: http.SameSiteLaxMode})
}
func session(req *http.Request, r *Runtime, now time.Time) (*User, int64) {
	c := readCookie(req, r, "session", now)
	if c == nil {
		return nil, 0
	}
	u := r.users[c.Subject]
	if u == nil || !equal(c.CV, credentialVersion(r, u)) || c.AuthTime <= 0 {
		return nil, 0
	}
	return u, c.AuthTime
}

func userClaims(u *User, scope string) map[string]any {
	claims := map[string]any{"sub": u.ID}
	scopes := strings.Fields(scope)
	if slices.Contains(scopes, "email") {
		claims["email"] = u.Email
		claims["email_verified"] = u.EmailVerified
	}
	if slices.Contains(scopes, "profile") && u.Name != "" {
		claims["name"] = u.Name
	}
	return claims
}
func issueTokens(r *Runtime, code authorizationCode, u *User, now time.Time) (map[string]any, error) {
	id := userClaims(u, code.Scope)
	id["auth_time"] = code.AuthTime
	if code.Nonce != nil {
		id["nonce"] = *code.Nonce
	}
	id["iss"] = r.Config.Issuer
	id["aud"] = code.ClientID
	id["iat"] = now.Unix()
	id["exp"] = now.Add(5 * time.Minute).Unix()
	idToken, err := sign(r.key, jose.RS256, "JWT", id)
	if err != nil {
		return nil, err
	}
	accessToken, err := sign(r.key, jose.RS256, "at+jwt", map[string]any{"iss": r.Config.Issuer, "aud": r.Config.Issuer + "/userinfo", "sub": u.ID, "iat": now.Unix(), "exp": now.Add(15 * time.Minute).Unix(), "scope": code.Scope, "client_id": code.ClientID, "cv": code.CV})
	if err != nil {
		return nil, err
	}
	return map[string]any{"id_token": idToken, "access_token": accessToken, "token_type": "Bearer", "expires_in": 900, "scope": code.Scope}, nil
}

type accessClaims struct {
	jwt.Claims
	Scope    string `json:"scope"`
	ClientID string `json:"client_id"`
	CV       string `json:"cv"`
}

func verifyRSA(r *Runtime, value, kind string, out any) error {
	if len(value) > 8192 {
		return errors.New("token too large")
	}
	token, err := jwt.ParseSigned(value, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return err
	}
	if len(token.Headers) != 1 || token.Headers[0].ExtraHeaders[jose.HeaderType] != kind {
		return errors.New("wrong token type")
	}
	keys := r.JWKS.Key(token.Headers[0].KeyID)
	if len(keys) != 1 {
		return errors.New("unknown signing key")
	}
	return token.Claims(keys[0].Key, out)
}
func verifyAccess(r *Runtime, value string, now time.Time) (*accessClaims, error) {
	var c accessClaims
	if err := verifyRSA(r, value, "at+jwt", &c); err != nil {
		return nil, err
	}
	if c.Subject == "" || c.Expiry == nil || c.IssuedAt == nil || !now.Before(c.Expiry.Time()) || c.Scope == "" || c.ClientID == "" || c.CV == "" {
		return nil, errors.New("missing claims or expired token")
	}
	return &c, c.ValidateWithLeeway(jwt.Expected{Issuer: r.Config.Issuer, AnyAudience: jwt.Audience{r.Config.Issuer + "/userinfo"}, Time: now}, 0)
}
func logoutClient(r *Runtime, value string) string {
	var c jwt.Claims
	// Expired ID tokens are hints, not authentication. Confirmation is still required.
	if verifyRSA(r, value, "JWT", &c) != nil || c.Issuer != r.Config.Issuer || c.Subject == "" || len(c.Audience) != 1 || r.clients[c.Audience[0]] == nil {
		return ""
	}
	return c.Audience[0]
}
