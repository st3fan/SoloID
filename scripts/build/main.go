// Build the one static binary with validated release identity. Run from the repo root.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/st3fan/soloid/internal/buildinfo"
)

func main() {
	output := flag.String("o", "bin/soloid", "output binary")
	flag.Parse()
	version, commit := os.Getenv("SOLOID_VERSION"), os.Getenv("SOLOID_COMMIT")
	if commit == "" {
		data, err := exec.Command("git", "rev-parse", "HEAD").Output()
		if err == nil {
			commit = strings.TrimSpace(string(data))
		} else {
			commit = "unknown"
		}
	}
	if err := buildinfo.Validate(version, commit); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	const pkg = "github.com/st3fan/soloid/internal/buildinfo"
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w -X "+pkg+".Version="+version+" -X "+pkg+".Commit="+commit, "-o", *output, "./cmd/soloid")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}
}
