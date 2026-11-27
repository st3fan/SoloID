package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/st3fan/soloid/internal/soloid"
	"golang.org/x/oauth2"
)

func TestBinaryIntegration(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "soloid")
	build := exec.Command("go", "run", "./scripts/build", "-o", binary)
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	invoke := func(input string, args ...string) ([]byte, error) {
		cmd := exec.Command(binary, args...)
		cmd.Stdin = strings.NewReader(input)
		return cmd.CombinedOutput()
	}
	initial, err := invoke("", "init")
	if err != nil {
		t.Fatal(err)
	}
	var config soloid.Config
	if err = json.Unmarshal(initial, &config); err != nil {
		t.Fatal(err)
	}
	const password = "integration test password"
	hash, err := invoke(password+"\n", "hash", "--stdin")
	if err != nil {
		t.Fatal(err)
	}
	config.Users[0].PasswordHash = strings.TrimSpace(string(hash))
	config.Users[0].Email = "one@example.com"
	config.Users[0].ID = "test-user"
	secretJSON, err := invoke("", "gen-secret")
	if err != nil {
		t.Fatal(err)
	}
	var secrets map[string]string
	if err = json.Unmarshal(secretJSON, &secrets); err != nil {
		t.Fatal(err)
	}
	config.Clients[0].ID = "web"
	config.Clients[0].SecretHash = secrets["client_secret_hash"]
	config.Clients[0].RedirectURIs = []string{"https://app.example.com/callback"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	issuer := fmt.Sprintf("http://localhost:%d", port)
	config.Issuer = issuer
	path := filepath.Join(dir, "config.json")
	writeConfig := func() {
		data, _ := json.Marshal(config)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig()
	if output, err := invoke("", "check", "--config", path); err != nil || !bytes.Contains(output, []byte("Configuration valid")) {
		t.Fatalf("check: %v %s", err, output)
	}
	logs, err := os.Create(filepath.Join(dir, "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logs.Close()
	server := exec.Command(binary)
	server.Env = append(os.Environ(), "SOLOID_CONFIG="+path, fmt.Sprintf("PORT=%d", port), "SOLOID_VERSION=v99.0.0", "SOLOID_COMMIT="+strings.Repeat("0", 40))
	server.Stdout = logs
	server.Stderr = logs
	if err = server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = server.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- server.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("shutdown: %v", err)
			}
		case <-time.After(12 * time.Second):
			_ = server.Process.Kill()
			<-done
			t.Error("shutdown timed out")
		}
	})
	client := &http.Client{Timeout: 5 * time.Second}
	waitFor := func(check func() bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if check() {
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("server did not reach expected state")
	}
	waitFor(func() bool {
		resp, err := client.Get(issuer + "/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		t.Fatal(err)
	}
	oauth := oauth2.Config{ClientID: "web", ClientSecret: secrets["client_secret"], Endpoint: provider.Endpoint(), RedirectURL: config.Clients[0].RedirectURIs[0], Scopes: []string{"openid", "email", "profile"}}
	oauth.Endpoint.AuthStyle = oauth2.AuthStyleInHeader
	verifier := oauth2.GenerateVerifier()
	nonce := "integration-nonce"
	state := "integration-state"
	authURL := oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce))
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Timeout: 5 * time.Second, Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := browser.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/login" {
		t.Fatal("authorization failed")
	}
	resp, err = browser.Get(issuer + "/login")
	if err != nil {
		t.Fatal(err)
	}
	html, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(html)
	if len(csrf) != 2 {
		t.Fatal("no login form")
	}
	for _, slogan := range []string{"One account. Your apps.", "Your identity. Your server.", "Your account is managed", "Simple, private sign-in", "<script"} {
		if bytes.Contains(html, []byte(slogan)) {
			t.Fatalf("unexpected page content %q", slogan)
		}
	}
	identityJSON, err := invoke("", "version")
	if err != nil {
		t.Fatal(err)
	}
	var identity map[string]string
	_ = json.Unmarshal(identityJSON, &identity)
	if !bytes.Contains(html, []byte("/commit/"+identity["commit"])) {
		t.Fatal("footer did not use embedded commit")
	}
	if identity["version"] == "" {
		if bytes.Contains(html, []byte("/releases/tag/")) {
			t.Fatal("dev footer showed release")
		}
	} else if !bytes.Contains(html, []byte("/releases/tag/"+identity["version"])) {
		t.Fatal("release link missing")
	}
	form := url.Values{"email": {"one@example.com"}, "password": {password}, "csrf": {string(csrf[1])}}
	req, _ := http.NewRequest("POST", issuer+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", issuer)
	resp, err = browser.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 303 {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	callback, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if callback.Query().Get("state") != state || callback.Query().Get("iss") != issuer {
		t.Fatal("callback binding")
	}
	tokens, err := oauth.Exchange(ctx, callback.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatal(err)
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: "web"}).Verify(ctx, tokens.Extra("id_token").(string))
	if err != nil {
		t.Fatal(err)
	}
	if idToken.Subject != "test-user" || idToken.Nonce != nonce {
		t.Fatal("wrong ID token claims")
	}
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(tokens))
	if err != nil || info.Subject != "test-user" || info.Email != "one@example.com" {
		t.Fatalf("userinfo: %v", err)
	}
	resp, err = client.Get(issuer + "/app.css")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "text/css") {
		t.Fatal("embedded styles unavailable")
	}
	// Invalid reload keeps the last complete configuration; valid reload swaps it.
	if err = os.WriteFile(path, []byte("{ broken JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = server.Process.Signal(syscall.SIGHUP)
	waitFor(func() bool {
		data, _ := os.ReadFile(logs.Name())
		return bytes.Contains(data, []byte("config_reload_failed"))
	})
	if _, err = provider.UserInfo(ctx, oauth2.StaticTokenSource(tokens)); err != nil {
		t.Fatal("invalid reload replaced good config", err)
	}
	config.Users[0].Name = "Reloaded User"
	writeConfig()
	_ = server.Process.Signal(syscall.SIGHUP)
	waitFor(func() bool {
		info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(tokens))
		if err != nil {
			return false
		}
		var claims map[string]any
		_ = info.Claims(&claims)
		return claims["name"] == "Reloaded User"
	})
	data, _ := os.ReadFile(logs.Name())
	for _, secret := range []string{password, tokens.AccessToken, secrets["client_secret"]} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatal("secret in logs")
		}
	}
	for _, tc := range []struct {
		count int
		valid bool
	}{{6, false}, {11, false}, {12, true}, {256, true}, {257, false}} {
		t.Run(fmt.Sprintf("unicode-%d", tc.count), func(t *testing.T) {
			_, err := invoke(strings.Repeat("😀", tc.count), "hash", "--stdin")
			if (err == nil) != tc.valid {
				t.Fatal("wrong Unicode password boundary")
			}
		})
	}
	if _, err := invoke("", "hash", "do-not-accept-password-arguments"); err == nil {
		t.Fatal("CLI accepted plaintext argument")
	}
	t.Log("Real binary: CLI, discovery, PKCE, signed ID token/JWKS, userinfo, embedded UI, SIGHUP, Unicode boundaries passed")
}
