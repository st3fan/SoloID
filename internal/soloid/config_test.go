package soloid

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestConfigRejectsUnsafeInput(t *testing.T) {
	r := fixture(t)
	cases := map[string]func(*Config){
		"duplicate email":      func(c *Config) { c.Users[1].Email = " ONE@EXAMPLE.COM " },
		"duplicate id":         func(c *Config) { c.Users[1].ID = c.Users[0].ID },
		"duplicate client":     func(c *Config) { c.Clients[1].ID = c.Clients[0].ID },
		"hash cost":            func(c *Config) { c.Users[0].PasswordHash = strings.Replace(c.Users[0].PasswordHash, "t=3", "t=1", 1) },
		"hash encoding":        func(c *Config) { s := c.Users[0].PasswordHash; c.Users[0].PasswordHash = s[:len(s)-1] + "B" },
		"hash newline":         func(c *Config) { c.Users[0].PasswordHash += "\n" },
		"wildcard":             func(c *Config) { c.Clients[0].RedirectURIs = []string{"https://app.example.com/*"} },
		"fragment":             func(c *Config) { c.Clients[0].RedirectURIs = []string{"https://app.example.com/callback#fragment"} },
		"empty fragment":       func(c *Config) { c.Clients[0].RedirectURIs = []string{"https://app.example.com/callback#"} },
		"logout fragment":      func(c *Config) { c.Clients[0].LogoutURIs = []string{"https://app.example.com/signed-out#"} },
		"URL credentials":      func(c *Config) { c.Clients[0].RedirectURIs = []string{"https://user:pass@app.example.com/callback"} },
		"missing secret":       func(c *Config) { c.Clients[0].SecretHash = "" },
		"public secret":        func(c *Config) { c.Clients[1].SecretHash = c.Clients[0].SecretHash },
		"unknown allowed user": func(c *Config) { c.Clients[0].AllowedUsers = []string{"missing"} },
		"unsafe issuer":        func(c *Config) { c.Issuer = "http://unsafe.example" },
		"issuer path":          func(c *Config) { c.Issuer = "https://id.example.com/" },
		"issuer empty query":   func(c *Config) { c.Issuer = "https://id.example.com?" },
		"issuer default port":  func(c *Config) { c.Issuer = "https://id.example.com:443" },
		"issuer host case":     func(c *Config) { c.Issuer = "https://ID.example.com" },
		"secret":               func(c *Config) { c.Secret = "short" },
		"secret newline":       func(c *Config) { c.Secret += "\n" },
		"private old key":      func(c *Config) { c.PreviousKeys = []json.RawMessage{c.SigningKey} },
		"public signing key":   func(c *Config) { c.SigningKey, _ = json.Marshal(r.JWKS.Keys[0]) },
		"ttl overflow":         func(c *Config) { c.SessionTTL = "999999999999999999999d" },
		"ttl too long":         func(c *Config) { c.SessionTTL = "31d" },
		"no users":             func(c *Config) { c.Users = nil },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c := configCopy(t, r)
			change(&c)
			raw, _ := json.Marshal(c)
			if _, err := ParseConfig(raw); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
	raw, _ := json.Marshal(r.Config)
	for name, raw := range map[string][]byte{"unknown field": append([]byte(`{"surprise":true,`), raw[1:]...), "trailing JSON": append(raw, []byte(` {}`)...)} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig(raw); err == nil {
				t.Fatal("accepted invalid JSON")
			}
		})
	}
}
func TestEmptyAllowedUsersDeniesEveryone(t *testing.T) {
	c := configCopy(t, fixture(t))
	c.Clients[0].AllowedUsers = []string{}
	r := prepared(t, c)
	b := newBrowser(t, NewProvider(r, nil))
	b.start(authParams("web"))
	status(t, b.login("one@example.com", password), 401)
	c.Clients[0].AllowedUsers = nil
	b = newBrowser(t, NewProvider(prepared(t, c), nil))
	b.start(authParams("web"))
	status(t, b.login("one@example.com", password), 303)
}
