package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/st3fan/soloid/internal/buildinfo"
	"github.com/st3fan/soloid/internal/soloid"
	"golang.org/x/term"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string, in *os.File, out, stderr io.Writer) error {
	command := "serve"
	if len(args) > 0 {
		command = args[0]
		args = args[1:]
	}
	if command == "--help" || command == "help" {
		fmt.Fprintln(out, "SoloID\n\n  serve                 Start the provider (default)\n  init                  Print a fresh config skeleton\n  hash [--stdin]        Hash a password (otherwise prompts without echo)\n  gen-secret            Print a client secret and its hash\n  check --config PATH   Validate configuration\n  healthcheck           Check the local HTTP listener\n  version               Print embedded build identity")
		return nil
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var path string
	var stdin bool
	if command == "serve" || command == "check" {
		flags.StringVar(&path, "config", os.Getenv("SOLOID_CONFIG"), "JSON configuration path")
	}
	if command == "hash" {
		flags.BoolVar(&stdin, "stdin", false, "read password from standard input")
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected argument; never pass passwords as command arguments")
	}
	encode := func(v any) error { e := json.NewEncoder(out); e.SetIndent("", "  "); return e.Encode(v) }
	switch command {
	case "serve":
		return serve(path, out)
	case "init":
		c, err := soloid.NewSkeleton()
		if err != nil {
			return err
		}
		return encode(c)
	case "hash":
		var password string
		if stdin {
			data, err := io.ReadAll(io.LimitReader(in, 1027))
			if err != nil {
				return err
			}
			password = string(data)
			if strings.HasSuffix(password, "\n") {
				password = strings.TrimSuffix(strings.TrimSuffix(password, "\n"), "\r")
			}
		} else {
			read := func(label string) (string, error) {
				if !term.IsTerminal(int(in.Fd())) {
					return "", errors.New("use an interactive terminal or hash --stdin")
				}
				fmt.Fprint(stderr, label)
				value, err := term.ReadPassword(int(in.Fd()))
				fmt.Fprintln(stderr)
				return string(value), err
			}
			var err error
			password, err = read("Password: ")
			if err != nil {
				return err
			}
			confirm, err := read("Confirm password: ")
			if err != nil {
				return err
			}
			if password != confirm {
				return errors.New("passwords do not match")
			}
		}
		if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 12 || len(password) > 1024 {
			return errors.New("use at least 12 Unicode code points and at most 1024 UTF-8 bytes")
		}
		fmt.Fprintln(out, soloid.HashPassword(password))
		return nil
	case "gen-secret":
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		secret := base64.RawURLEncoding.EncodeToString(b)
		return encode(map[string]string{"client_secret": secret, "client_secret_hash": soloid.HashPassword(secret)})
	case "check":
		if path == "" {
			return errors.New("pass --config PATH or set SOLOID_CONFIG")
		}
		if _, err := soloid.LoadConfig(path); err != nil {
			return err
		}
		fmt.Fprintln(out, "Configuration valid")
		return nil
	case "healthcheck":
		port, err := listenPort()
		if err != nil {
			return err
		}
		client := http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
		if err != nil {
			return errors.New("health check failed")
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return errors.New("health check failed")
		}
		return nil
	case "version":
		return encode(map[string]string{"version": buildinfo.Version, "commit": buildinfo.Revision()})
	default:
		return errors.New("unknown command; run soloid --help")
	}
}
func listenPort() (string, error) {
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("invalid PORT")
	}
	return strconv.Itoa(n), nil
}
func serve(path string, out io.Writer) error {
	if path == "" {
		return errors.New("SOLOID_CONFIG is required")
	}
	if err := buildinfo.Validate(buildinfo.Version, buildinfo.Revision()); err != nil {
		return err
	}
	r, err := soloid.LoadConfig(path)
	if err != nil {
		return err
	}
	port, err := listenPort()
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(out, nil))
	provider := soloid.NewProvider(r, func(event map[string]any) {
		attrs := make([]any, 0, len(event)*2)
		for k, v := range event {
			attrs = append(attrs, k, v)
		}
		logger.Info("provider", attrs...)
	})
	server := &http.Server{Addr: "0.0.0.0:" + port, Handler: provider, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32768}
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	exited := make(chan error, 1)
	go func() { exited <- server.ListenAndServe() }()
	logger.Info("listening", "port", port)
	for {
		select {
		case err := <-exited:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case sig := <-signals:
			if sig == syscall.SIGHUP {
				next, err := soloid.LoadConfig(path)
				if err != nil {
					logger.Error("config_reload_failed", "message", "Keeping previous configuration. Run soloid check for details.")
				} else {
					provider.Reload(next)
					logger.Info("config_reloaded")
				}
			} else {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				return server.Shutdown(ctx)
			}
		}
	}
}
