package buildinfo

import (
	"strings"
	"testing"
)

func TestReleaseIdentityValidation(t *testing.T) {
	sha := strings.Repeat("a", 40)
	for _, tc := range []struct {
		version, commit string
		valid           bool
	}{
		{"", "unknown", true}, {"", sha, true}, {"v0.1.0", sha, true}, {"1.2.3-rc.1+build.4", sha, true},
		{"v0.1", sha, false}, {"v01.2.3", sha, false}, {"1.2.3-01", sha, false}, {"1.2.3", "unknown", false}, {"v1.2.3", "abc1234", false}, {"", "bad", false}, {"1.2.3;evil", sha, false},
	} {
		t.Run(tc.version+"/"+tc.commit, func(t *testing.T) {
			if (Validate(tc.version, tc.commit) == nil) != tc.valid {
				t.Fatal("wrong build metadata validation")
			}
		})
	}
}
