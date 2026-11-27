package soloid

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/st3fan/soloid/internal/buildinfo"
)

//go:embed web/page.html
var pageHTML string

//go:embed web/app.css
var stylesheet []byte
var pages = template.Must(template.New("page").Parse(pageHTML))

type page struct{ Kind, Title, Message, App, CSRF, Email, Error, Version, ReleaseURL, Commit, CommitURL string }

func loginPage(c *Client, csrf, email, message string) page {
	name := c.Name
	if name == "" {
		name = c.ID
	}
	return page{Kind: "login", Title: "Sign in", App: name, CSRF: csrf, Email: email, Error: message}
}
func render(w http.ResponseWriter, status int, p page) error {
	const github = "https://github.com/st3fan/SoloID"
	if buildinfo.Version != "" {
		p.Version = "v" + strings.TrimPrefix(buildinfo.Version, "v")
		p.ReleaseURL = github + "/releases/tag/" + url.PathEscape(buildinfo.Version)
	}
	commit := buildinfo.Revision()
	p.Commit = commit
	if commit != "unknown" {
		p.Commit = commit[:7]
		p.CommitURL = github + "/commit/" + commit
	}
	var b bytes.Buffer
	if err := pages.Execute(&b, p); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, err := w.Write(b.Bytes())
	return err
}
