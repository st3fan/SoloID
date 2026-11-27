// Package buildinfo holds identity embedded at build time, never runtime env.
package buildinfo

import (
	"errors"
	"regexp"
	"runtime/debug"
	"strings"
)

var Version string
var Commit string
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var versionPattern = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+\.)*[0-9A-Za-z-]+)?(\+([0-9A-Za-z-]+\.)*[0-9A-Za-z-]+)?$`)

func Validate(version, commit string) error {
	if commit != "" && commit != "unknown" && !commitPattern.MatchString(commit) {
		return errors.New("SOLOID_COMMIT must be a full Git commit SHA")
	}
	if version == "" {
		return nil
	}
	if !versionPattern.MatchString(version) || !commitPattern.MatchString(commit) {
		return errors.New("release builds require a semantic SOLOID_VERSION and full SOLOID_COMMIT")
	}
	base := strings.SplitN(version, "+", 2)[0]
	if _, pre, ok := strings.Cut(base, "-"); ok {
		for _, part := range strings.Split(pre, ".") {
			numeric := strings.Trim(part, "0123456789") == ""
			if numeric && len(part) > 1 && part[0] == '0' {
				return errors.New("numeric prerelease identifiers cannot have leading zeros")
			}
		}
	}
	return nil
}
func Revision() string {
	if commitPattern.MatchString(Commit) {
		return Commit
	}
	if Commit == "unknown" {
		return Commit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" && commitPattern.MatchString(setting.Value) {
				return setting.Value
			}
		}
	}
	return "unknown"
}
