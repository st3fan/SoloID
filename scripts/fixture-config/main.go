// Disposable test credentials only. Never use this configuration in production.
package main

import (
	"encoding/json"
	"os"

	"github.com/st3fan/soloid/internal/soloid"
)

func main() {
	c, err := soloid.NewSkeleton()
	if err != nil {
		panic(err)
	}
	c.Issuer = os.Getenv("TEST_ISSUER")
	if c.Issuer == "" {
		c.Issuer = "http://localhost:3000"
	}
	c.Users = []soloid.User{
		{ID: "user-one", Email: "one@example.com", Name: "One User", PasswordHash: soloid.HashPassword("correct horse battery staple")},
		{ID: "user-two", Email: "two@example.com", Name: "Two User", PasswordHash: soloid.HashPassword("another strong password")},
	}
	c.Clients = []soloid.Client{
		{ID: "web", Name: "Demo app", SecretHash: soloid.HashPassword("test client secret +:/?!"), RedirectURIs: []string{"https://app.example.com/callback"}, LogoutURIs: []string{"https://app.example.com/signed-out"}},
		{ID: "public", Name: "Demo app", Public: true, RedirectURIs: []string{"https://spa.example.com/callback"}},
	}
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	if err := e.Encode(c); err != nil {
		panic(err)
	}
}
