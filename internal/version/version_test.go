package version

import (
	"regexp"
	"strings"
	"testing"
)

// Version must never be empty — would render as "unisupply v" in CLI output.
func TestVersionNotEmpty(t *testing.T) {
	if Version == "" {
		t.Fatal("Version must not be empty")
	}
}

// Version must look like semver MAJOR.MINOR.PATCH with an optional
// pre-release suffix. The leading "v" is intentionally rejected — it is
// added at print sites, not stored in the constant.
func TestVersionIsSemver(t *testing.T) {
	re := regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)
	if !re.MatchString(Version) {
		t.Fatalf("Version %q must match MAJOR.MINOR.PATCH[-pre] (no leading v)", Version)
	}
	if strings.HasPrefix(Version, "v") {
		t.Fatalf("Version %q must not include leading 'v' — added at print sites only", Version)
	}
}

// Pre-release suffixes we explicitly support. Any future suffix should be
// added here so the policy stays centralized.
func TestPreReleaseSuffixIsRecognized(t *testing.T) {
	if !strings.Contains(Version, "-") {
		return // stable release, nothing to check
	}
	suffix := Version[strings.Index(Version, "-")+1:]
	allowed := []string{"dev", "alpha", "beta", "rc"}
	base := suffix
	if dot := strings.Index(suffix, "."); dot >= 0 {
		base = suffix[:dot]
	}
	for _, ok := range allowed {
		if base == ok {
			return
		}
	}
	t.Fatalf("pre-release suffix %q starts with %q; allowed: %v", suffix, base, allowed)
}

// IsPreRelease must agree with the literal Version string.
func TestIsPreReleaseMatchesVersion(t *testing.T) {
	want := strings.Contains(Version, "-")
	if got := IsPreRelease(); got != want {
		t.Fatalf("IsPreRelease() = %v, want %v for Version %q", got, want, Version)
	}
}

// String() must include Version, and must include Commit/BuildDate iff they
// are set. This locks the print contract used by the CLI banner.
func TestStringContainsVersion(t *testing.T) {
	if !strings.Contains(String(), Version) {
		t.Fatalf("String() = %q must contain Version %q", String(), Version)
	}
}

func TestStringWithBuildMetadata(t *testing.T) {
	origCommit, origDate := Commit, BuildDate
	t.Cleanup(func() { Commit, BuildDate = origCommit, origDate })

	Commit, BuildDate = "abc1234", "2026-05-07T10:00:00Z"
	s := String()
	for _, want := range []string{Version, "abc1234", "2026-05-07T10:00:00Z"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q missing %q", s, want)
		}
	}
}

func TestStringWithoutBuildMetadata(t *testing.T) {
	origCommit, origDate := Commit, BuildDate
	t.Cleanup(func() { Commit, BuildDate = origCommit, origDate })

	Commit, BuildDate = "unknown", "unknown"
	if got := String(); got != Version {
		t.Fatalf("String() = %q, want bare Version %q when metadata unset", got, Version)
	}
}
