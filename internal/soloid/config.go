package soloid

import (
	"bytes"
	"crypto"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

type User struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	Name          string `json:"name,omitempty"`
	EmailVerified bool   `json:"email_verified"`
	PasswordHash  string `json:"password_hash"`
}

type Client struct {
	ID           string   `json:"client_id"`
	Name         string   `json:"name,omitempty"`
	Public       bool     `json:"public,omitempty"`
	SecretHash   string   `json:"client_secret_hash,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	LogoutURIs   []string `json:"post_logout_redirect_uris,omitempty"`
	AllowedUsers []string `json:"allowed_users"`
}

type Config struct {
	Issuer       string            `json:"issuer"`
	Secret       string            `json:"secret"`
	SigningKey   json.RawMessage   `json:"signing_key"`
	PreviousKeys []json.RawMessage `json:"previous_public_keys"`
	SessionTTL   string            `json:"session_ttl"`
	Users        []User            `json:"users"`
	Clients      []Client          `json:"clients"`
}

// Runtime is immutable once installed in a Provider.
type Runtime struct {
	Config     Config
	users      map[string]*User
	emails     map[string]*User
	clients    map[string]*Client
	sessionTTL time.Duration
	cookieKey  []byte
	key        jose.JSONWebKey
	JWKS       jose.JSONWebKeySet
	dummyHash  string
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var ttlPattern = regexp.MustCompile(`^([1-9][0-9]*)(m|h|d)$`)

func NormalizeEmail(value string) string { return strings.ToLower(strings.TrimSpace(value)) }
func allowed(client *Client, user *User) bool {
	return client.AllowedUsers == nil || slices.Contains(client.AllowedUsers, user.ID)
}

func validURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && len(value) <= 2048 && u.Hostname() != "" && u.User == nil &&
		!strings.ContainsAny(value, "#*\\\r\n\t ") &&
		(u.Scheme == "https" || (u.Scheme == "http" && u.Hostname() == "localhost"))
}

func urlOrigin(u *url.URL) string {
	host := strings.ToLower(u.Host)
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		host = strings.TrimSuffix(host, ":"+u.Port())
	}
	return u.Scheme + "://" + strings.TrimSuffix(host, ":")
}

func LoadConfig(path string) (*Runtime, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read configuration")
	}
	return ParseConfig(data)
}

func ParseConfig(data []byte) (*Runtime, error) {
	var c Config
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return nil, errors.New("invalid configuration JSON or unknown field")
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("unexpected data after configuration")
	}
	return PrepareConfig(c)
}

func PrepareConfig(c Config) (*Runtime, error) {
	// Own every slice and pointer: callers cannot mutate a live runtime during reload.
	data, err := json.Marshal(c)
	if err != nil {
		return nil, errors.New("invalid configuration")
	}
	if err = json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	u, err := url.Parse(c.Issuer)
	if err != nil || !validURL(c.Issuer) || c.Issuer != urlOrigin(u) || u.RawQuery != "" || u.ForceQuery {
		return nil, errors.New("issuer must be an HTTPS origin without a path, query, or trailing slash (HTTP localhost is allowed)")
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(c.Secret)
	if err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != c.Secret {
		return nil, errors.New("secret must encode 32 random bytes as canonical base64url")
	}
	if c.SessionTTL == "" {
		c.SessionTTL = "12h"
	}
	parts := ttlPattern.FindStringSubmatch(c.SessionTTL)
	if parts == nil {
		return nil, errors.New("invalid session_ttl")
	}
	n, err := strconv.ParseInt(parts[1], 10, 64)
	multiplier := map[string]int64{"m": 60, "h": 3600, "d": 86400}[parts[2]]
	if err != nil || n > 30*86400/multiplier {
		return nil, errors.New("session_ttl must be at most 30 days")
	}
	r := &Runtime{Config: c, users: map[string]*User{}, emails: map[string]*User{}, clients: map[string]*Client{}, sessionTTL: time.Duration(n*multiplier) * time.Second}
	if len(c.Users) < 1 || len(c.Users) > 1000 || len(c.Clients) < 1 || len(c.Clients) > 100 {
		return nil, errors.New("configure 1–1000 users and 1–100 clients")
	}
	for i := range r.Config.Users {
		user := &r.Config.Users[i]
		user.Email = NormalizeEmail(user.Email)
		address, err := mail.ParseAddress(user.Email)
		if !identifier.MatchString(user.ID) || r.users[user.ID] != nil || err != nil || address.Address != user.Email || len(user.Email) > 254 || r.emails[user.Email] != nil || len(user.Name) > 200 {
			return nil, errors.New("invalid or duplicate user ID/email/name")
		}
		if _, _, err := parseHash(user.PasswordHash); err != nil {
			return nil, fmt.Errorf("user password_hash: %w", err)
		}
		r.users[user.ID] = user
		r.emails[user.Email] = user
	}
	for i := range r.Config.Clients {
		client := &r.Config.Clients[i]
		if !identifier.MatchString(client.ID) || r.clients[client.ID] != nil || len(client.Name) > 100 || len(client.RedirectURIs) < 1 || len(client.RedirectURIs) > 20 || len(client.LogoutURIs) > 20 {
			return nil, errors.New("invalid or duplicate client")
		}
		if client.Public {
			if client.SecretHash != "" {
				return nil, errors.New("public clients must omit their secret")
			}
		} else if _, _, err := parseHash(client.SecretHash); err != nil {
			return nil, fmt.Errorf("client_secret_hash: %w", err)
		}
		for _, uri := range append(slices.Clone(client.RedirectURIs), client.LogoutURIs...) {
			if !validURL(uri) {
				return nil, errors.New("invalid redirect URL: require exact HTTPS (or HTTP localhost), without fragments, credentials or wildcards")
			}
		}
		for _, id := range client.AllowedUsers {
			if r.users[id] == nil {
				return nil, errors.New("allowed_users must reference configured user IDs")
			}
		}
		r.clients[client.ID] = client
	}
	if len(c.PreviousKeys) > 5 {
		return nil, errors.New("at most five previous public keys")
	}
	key, err := parseKey(c.SigningKey, true)
	if err != nil {
		return nil, err
	}
	r.key = key
	r.JWKS.Keys = append(r.JWKS.Keys, key.Public())
	for _, raw := range c.PreviousKeys {
		key, err := parseKey(raw, false)
		if err != nil {
			return nil, err
		}
		for _, existing := range r.JWKS.Keys {
			if key.KeyID == existing.KeyID {
				return nil, errors.New("duplicate signing key")
			}
		}
		r.JWKS.Keys = append(r.JWKS.Keys, key)
	}
	r.cookieKey, err = hkdf.Key(sha256.New, secret, nil, "soloid:cookie:v1", 32)
	if err != nil {
		return nil, err
	}
	r.dummyHash = HashPassword(randomToken())
	return r, nil
}

func parseKey(raw json.RawMessage, private bool) (jose.JSONWebKey, error) {
	var key jose.JSONWebKey
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || json.Unmarshal(raw, &key) != nil {
		return key, errors.New("invalid RSA JWK")
	}
	if !private {
		for _, field := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
			if _, ok := fields[field]; ok {
				return key, errors.New("previous keys must be public RSA JWKs")
			}
		}
	}
	var pub *rsa.PublicKey
	if private {
		k, ok := key.Key.(*rsa.PrivateKey)
		if !ok {
			return key, errors.New("signing_key must be a complete RSA private JWK")
		}
		for _, field := range []string{"d", "p", "q", "dp", "dq", "qi"} {
			if len(fields[field]) == 0 {
				return key, errors.New("signing_key must be complete")
			}
		}
		if k.Validate() != nil {
			return key, errors.New("invalid RSA private key")
		}
		pub = &k.PublicKey
	} else {
		var ok bool
		pub, ok = key.Key.(*rsa.PublicKey)
		if !ok {
			return key, errors.New("expected public RSA key")
		}
	}
	if pub.N.BitLen() < 2048 {
		return key, errors.New("RSA key must be at least 2048 bits")
	}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return key, err
	}
	key.KeyID = base64.RawURLEncoding.EncodeToString(thumbprint)
	key.Algorithm = "RS256"
	key.Use = "sig"
	return key, nil
}

func NewSkeleton() (Config, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return Config{}, err
	}
	raw, err := json.Marshal(jose.JSONWebKey{Key: key})
	if err != nil {
		return Config{}, err
	}
	return Config{Issuer: "https://id.example.com", Secret: randomToken(), SigningKey: raw, PreviousKeys: []json.RawMessage{}, SessionTTL: "12h",
		Users:   []User{{ID: randomToken(), Email: "you@example.com", Name: "Your name", PasswordHash: "REPLACE_WITH_HASH"}},
		Clients: []Client{{ID: "grafana", Name: "Grafana", SecretHash: "REPLACE_WITH_HASH_FROM_GEN_SECRET", RedirectURIs: []string{"https://grafana.example.com/login/generic_oauth"}}}}, nil
}
