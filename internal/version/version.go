// Package version is the single source of truth for the unisupply
// binary version and build metadata.
//
// Versioning policy (semver 2.0.0):
//
//	X.Y.Z-dev       — untagged working-tree build, never redistribute
//	X.Y.Z-alpha.N   — internal tester build (tag: vX.Y.Z-alpha.N)
//	X.Y.Z-beta.N    — early-adopter build  (tag: vX.Y.Z-beta.N)
//	X.Y.Z-rc.N      — release candidate    (tag: vX.Y.Z-rc.N)
//	X.Y.Z           — stable release       (tag: vX.Y.Z)
//
// Suffixes are OPTIONAL — pick the lightest one that fits the release:
//
//	patch (X.Y.Z+1):       -dev → stable      (skip alpha/beta/rc)
//	minor, low risk:       -dev → stable      (or one -rc if integrators want it)
//	minor, behavior shift: -dev → -beta → -rc → stable
//	major (X+1.0.0):       -dev → -alpha → -beta → -rc → stable
//
// The only non-optional suffix is -dev: every untagged commit between two
// releases must carry it. After cutting vX.Y.Z, bump Version to
// X.(Y+1).0-dev (or X.Y.(Z+1)-dev for a planned patch) on the next
// development commit.
//
// The leading "v" is added at print sites only — it is NOT part of
// the constant. Keep this package free of other internal imports so
// any package can depend on it without import-cycle risk.
package version

import (
	"runtime"
	"strings"
)

// Version is the semver string for the unisupply binary.
// Bump this on every release; append -dev between releases.
const Version = "0.4.0"

// Commit and BuildDate are populated at link time via:
//
//	go build -ldflags "\
//	  -X github.com/unidoc/unisupply/internal/version.Commit=$(git rev-parse --short HEAD) \
//	  -X github.com/unidoc/unisupply/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
//
// They default to "unknown" for plain `go build` / `go install`.
var (
	Commit    = "unknown"
	BuildDate = "unknown"
)

// IsPreRelease reports whether Version carries a SemVer pre-release
// suffix (anything after a "-"). Useful for telemetry and gating
// "do not redistribute" warnings.
func IsPreRelease() bool {
	return strings.Contains(Version, "-")
}

// String returns a human-readable version line suitable for the
// CLI banner and report headers, e.g.:
//
//	"0.4.0-dev (commit abc1234, built 2026-05-07T10:00:00Z, go1.25.3)"
//	"0.4.0"
//
// When Commit/BuildDate are unset (plain `go build`), the metadata
// suffix is omitted to keep output clean.
func String() string {
	if Commit == "unknown" && BuildDate == "unknown" {
		return Version
	}
	return Version + " (commit " + Commit + ", built " + BuildDate + ", " + runtime.Version() + ")"
}
