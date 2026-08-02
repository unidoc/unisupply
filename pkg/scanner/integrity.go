package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/unidoc/unisupply/pkg/netlog"
	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/resolver"
)

// IntegrityRiskLevel categorizes go.mod directive risk.
type IntegrityRiskLevel string

// Integrity risk level bands. LOW/MEDIUM/HIGH mirror scorer.RiskLevel for
// consistency in reports; INFO is used for directives that carry no risk on
// their own (e.g. exclude) but are still worth surfacing for transparency.
const (
	IntegrityInfo     IntegrityRiskLevel = "INFO"
	IntegrityLow      IntegrityRiskLevel = "LOW"
	IntegrityMedium   IntegrityRiskLevel = "MEDIUM"
	IntegrityHigh     IntegrityRiskLevel = "HIGH"
	IntegrityCritical IntegrityRiskLevel = "CRITICAL"
)

// GoSumVerified states for IntegrityReport.GoSumVerified. String-valued (not
// bool) so the report can distinguish honest-UNKNOWN outcomes ("offline",
// "skipped") from a verified pass/fail.
const (
	GoSumVerifiedTrue    = "true"    // `go mod verify` exited 0
	GoSumVerifiedFalse   = "false"   // `go mod verify` reported a mismatch
	GoSumVerifiedOffline = "offline" // offline mode — verification not attempted
	GoSumVerifiedSkipped = "skipped" // go.sum absent, cancelled, or verify could not complete for a non-integrity reason
)

// Integrity finding categories. Exported so consumers (e.g. the policy
// engine) can match findings by kind instead of by severity.
const (
	IntegrityCategoryReplaceVersionPin   = "replace_version_pin"
	IntegrityCategoryReplaceLocalPath    = "replace_local_path"
	IntegrityCategoryReplaceMajorVersion = "replace_major_version"
	IntegrityCategoryReplaceRedirect     = "replace_redirect"
	IntegrityCategoryExclude             = "exclude"
)

// IntegrityFinding represents a single go.mod directive finding.
type IntegrityFinding struct {
	Category    string             `json:"category"`
	Severity    IntegrityRiskLevel `json:"severity"`
	Module      string             `json:"module"`
	Detail      string             `json:"detail"`
	Remediation string             `json:"remediation"`
}

// IntegrityReport holds the project-level go.mod directive audit.
//
// This is shared scaffolding for the integrity trio (plan 46 Phase A):
// replace/exclude directives are audited here now; go.sum checks and
// pseudo-version findings are added by later plans (77, 79) as additional
// fields/categories on this same report.
type IntegrityReport struct {
	Findings      []IntegrityFinding `json:"findings,omitempty"`
	ReplaceCount  int                `json:"replace_count"`
	ExcludeCount  int                `json:"exclude_count"`
	RedirectCount int                `json:"redirect_count"` // HIGH-severity replaces (redirect to a different module)

	// GoSumVerified records the outcome of `go mod verify` — one of the
	// GoSumVerified* constants ("true"/"false"/"offline"/"skipped"), or empty
	// when verification was never attempted.
	GoSumVerified string `json:"gosum_verified,omitempty"`
}

// IntegrityScanner audits go.mod replace/exclude directives and go.sum
// integrity for supply chain risk.
type IntegrityScanner struct {
	// Offline skips go.sum verification (`go mod verify`) entirely, reporting
	// GoSumVerifiedOffline. Placeholder for the --offline CLI flag (plan 81).
	Offline bool
}

// NewIntegrityScanner creates a new integrity scanner.
func NewIntegrityScanner() *IntegrityScanner {
	return &IntegrityScanner{}
}

// ScanDirectives classifies every replace directive in gm and records every
// exclude directive as an INFO finding. It returns the project-level report
// alongside a per-module map of replace severity (keyed by the original
// module path), which the scorer uses to apply per-dependency risk factors.
func (is *IntegrityScanner) ScanDirectives(gm *parser.GoMod) (report *IntegrityReport, classes map[string]IntegrityRiskLevel) {
	report = &IntegrityReport{}
	classes = make(map[string]IntegrityRiskLevel, len(gm.Replaces))

	// Sort by original path for deterministic finding order.
	origPaths := make([]string, 0, len(gm.Replaces))
	for origPath := range gm.Replaces {
		origPaths = append(origPaths, origPath)
	}
	sort.Strings(origPaths)

	for _, origPath := range origPaths {
		rep := gm.Replaces[origPath]
		finding := classifyReplace(origPath, rep.New)
		if rep.OldVersion != "" {
			finding.Detail += fmt.Sprintf(" (applies only when version %s is selected)", rep.OldVersion)
		}
		classes[origPath] = finding.Severity
		report.Findings = append(report.Findings, finding)
		report.ReplaceCount++
		if finding.Severity == IntegrityHigh {
			report.RedirectCount++
		}
	}

	for _, ex := range gm.Excludes {
		report.Findings = append(report.Findings, IntegrityFinding{
			Category:    IntegrityCategoryExclude,
			Severity:    IntegrityInfo,
			Module:      ex.Path,
			Detail:      fmt.Sprintf("version %s is excluded from selection", ex.Version),
			Remediation: "Confirm the excluded version and the reason for exclusion are documented (e.g. a known-bad release).",
		})
		report.ExcludeCount++
	}

	return report, classes
}

// classifyReplace determines the severity of a single replace directive by
// comparing the original module path against the replacement:
//
//	replacement path == original path                          → version-pin override (LOW)
//	replacement path is a local filesystem path                  → local-path override (MEDIUM)
//	replacement path is a /vN major-version path of the same module → major-version redirect (MEDIUM)
//	otherwise                                                    → redirect to a different module (HIGH)
func classifyReplace(origPath string, replacement parser.Module) IntegrityFinding {
	switch {
	case replacement.Path == origPath:
		return IntegrityFinding{
			Category:    IntegrityCategoryReplaceVersionPin,
			Severity:    IntegrityLow,
			Module:      origPath,
			Detail:      fmt.Sprintf("%s is version-pinned to %s", origPath, replacement.Version),
			Remediation: "Version-pin replaces are expected; confirm the pinned version is intentional and current.",
		}
	case isLocalPath(replacement.Path):
		return IntegrityFinding{
			Category:    IntegrityCategoryReplaceLocalPath,
			Severity:    IntegrityMedium,
			Module:      origPath,
			Detail:      fmt.Sprintf("%s is replaced with local path %s", origPath, replacement.Path),
			Remediation: "Local-path replaces are expected in development; ensure this is removed before release.",
		}
	case isMajorVersionRedirect(origPath, replacement.Path):
		return IntegrityFinding{
			Category:    IntegrityCategoryReplaceMajorVersion,
			Severity:    IntegrityMedium,
			Module:      origPath,
			Detail:      fmt.Sprintf("%s is redirected to a major-version path of the same module: %s", origPath, replacement.Path),
			Remediation: "Major-version redirect within the same module; confirm intentional.",
		}
	default:
		return IntegrityFinding{
			Category:    IntegrityCategoryReplaceRedirect,
			Severity:    IntegrityHigh,
			Module:      origPath,
			Detail:      fmt.Sprintf("%s is redirected to a different module: %s", origPath, replacement.Path),
			Remediation: "Verify the redirect target is trusted — a replace to an unexpected module path can indicate a fork hijack or private-mirror compromise.",
		}
	}
}

// isLocalPath reports whether path is a filesystem-directory replacement
// target. It mirrors golang.org/x/mod/modfile.IsDirectoryPath: because go.mod
// files can move from one system to another, both Unix and Windows path
// syntaxes (relative, absolute, UNC, drive-letter) are recognized regardless
// of the host OS the scan runs on.
func isLocalPath(path string) bool {
	return path == "." || strings.HasPrefix(path, "./") || strings.HasPrefix(path, "/") ||
		path == ".." || strings.HasPrefix(path, "../") ||
		strings.HasPrefix(path, `.\`) || strings.HasPrefix(path, `\`) ||
		strings.HasPrefix(path, `..\`) ||
		(len(path) >= 2 && ('A' <= path[0] && path[0] <= 'Z' || 'a' <= path[0] && path[0] <= 'z') && path[1] == ':')
}

// majorVersionSuffixRe matches a trailing Go major-version path element
// (e.g. "/v2", "/v10"). Semantic import versioning only appends this suffix
// starting at v2 — v0/v1 modules never carry one.
var majorVersionSuffixRe = regexp.MustCompile(`^(.+)/v(\d+)$`)

// splitMajorVersionSuffix splits path into its base module path and major
// version number if path ends in a "/vN" (N >= 2) suffix. ok is false when
// path carries no such suffix.
func splitMajorVersionSuffix(path string) (base string, version int, ok bool) {
	m := majorVersionSuffixRe.FindStringSubmatch(path)
	if m == nil {
		return "", 0, false
	}
	v, err := strconv.Atoi(m[2])
	if err != nil || v < 2 {
		return "", 0, false
	}
	return m[1], v, true
}

// isMajorVersionRedirect reports whether replPath is a major-version sibling
// of origPath within the same module — either origPath gaining a "/vN" suffix
// (N >= 2) it did not previously have, or an existing "/vN" suffix on origPath
// being swapped for a different "/vM". Both cases share the same underlying
// module identity (the part before the version suffix) and are lower risk
// than a redirect to an unrelated module path.
func isMajorVersionRedirect(origPath, replPath string) bool {
	replBase, _, replOK := splitMajorVersionSuffix(replPath)
	if !replOK {
		return false
	}

	origBase, _, origOK := splitMajorVersionSuffix(origPath)
	if !origOK {
		origBase = origPath
	}

	return replBase == origBase
}

// gosumIncompleteListCap bounds how many missing modules are named in the
// gosum_incomplete finding detail before eliding the rest.
const gosumIncompleteListCap = 10

// ScanGoSum performs the offline go.sum presence and completeness checks and
// appends findings to report:
//
//   - go.mod has requirements but go.sum is missing → HIGH gosum_missing.
//   - go.sum is present but a direct (non-replaced) module@version has no
//     entry → MEDIUM gosum_incomplete naming the missing modules.
//
// The completeness check deliberately covers direct dependencies only. Under
// Go 1.17+ module graph pruning, transitive modules listed by `go mod graph`
// can legitimately have no go.sum entry (their go.mod is never loaded), so a
// full-graph join over-reports. A direct requirement is always an MVS root
// whose go.mod hash must be recorded — its absence is a real gap. Transitive
// integrity is covered by `go mod verify` and the toolchain's own load-time
// checks (see VerifyGoSum).
//
// Replaced modules are skipped — local-path and redirect replaces legitimately
// have no go.sum entry for the original module. When a vendor/modules.txt is
// present the completeness check is skipped entirely: builds with -mod=vendor
// (the default when vendor/ exists) do not consult go.sum.
func (is *IntegrityScanner) ScanGoSum(gomodPath string, gomod *parser.GoMod, graph *resolver.Graph, report *IntegrityReport) {
	dir := filepath.Dir(gomodPath)
	gosumPath := filepath.Join(dir, "go.sum")

	if _, err := os.Stat(gosumPath); err != nil {
		if len(gomod.Requirements) == 0 {
			return // no requirements — go.sum is legitimately absent
		}
		report.Findings = append(report.Findings, IntegrityFinding{
			Category:    "gosum_missing",
			Severity:    IntegrityHigh,
			Module:      gomod.ModulePath,
			Detail:      "go.mod declares requirements but no go.sum is present — dependency checksums are not pinned",
			Remediation: "Run `go mod tidy` and commit go.sum so every dependency download is verified against a pinned checksum.",
		})
		return
	}

	// vendor/modules.txt next to go.mod → -mod=vendor semantics; go.sum is
	// not consulted at build time, so completeness findings would be noise.
	if _, err := os.Stat(filepath.Join(dir, "vendor", "modules.txt")); err == nil {
		return
	}

	entries, err := parser.ParseGoSum(gosumPath)
	if err != nil {
		return
	}
	have := make(map[string]bool, len(entries))
	for _, e := range entries {
		have[e.Path+"@"+e.Version] = true
	}

	var missing []string
	for path, dep := range graph.Dependencies {
		if !dep.Direct || dep.Replaced {
			continue
		}
		if !have[path+"@"+dep.Module.Version] {
			missing = append(missing, path+"@"+dep.Module.Version)
		}
	}
	if len(missing) == 0 {
		return
	}
	sort.Strings(missing)

	listed := missing
	elided := ""
	if len(listed) > gosumIncompleteListCap {
		elided = fmt.Sprintf(" (and %d more)", len(listed)-gosumIncompleteListCap)
		listed = listed[:gosumIncompleteListCap]
	}
	report.Findings = append(report.Findings, IntegrityFinding{
		Category:    "gosum_incomplete",
		Severity:    IntegrityMedium,
		Module:      gomod.ModulePath,
		Detail:      fmt.Sprintf("%d direct dependency module(s) have no go.sum entry: %s%s", len(missing), strings.Join(listed, ", "), elided),
		Remediation: "Run `go mod tidy` to record checksums for every module in the build graph, then commit the updated go.sum.",
	})
}

// gosumDetailCap bounds how much of `go mod verify` output is embedded in the
// gosum_mismatch finding detail.
const gosumDetailCap = 500

// gosumMismatchMarkers are the `go mod verify` output fragments that identify
// a genuine integrity failure. "has been modified" is verify's own report of
// cache tampering; "checksum mismatch" / "SECURITY ERROR" are printed by the
// toolchain when a hash disagrees with go.sum. Any other non-zero exit (cold
// module cache with no network, proxy errors, …) is an environment problem,
// not an integrity signal.
var gosumMismatchMarkers = []string{"has been modified", "checksum mismatch", "SECURITY ERROR"}

// VerifyGoSum shells out to `go mod verify` in gomodPath's directory and
// records the outcome in report.GoSumVerified:
//
//   - exit 0 → "true"
//   - non-zero exit whose output carries a mismatch marker → "false" +
//     CRITICAL gosum_mismatch finding with the command output as detail
//   - Offline mode, go.sum absent, context cancellation, the toolchain
//     failing to run, or any other non-mismatch failure (e.g. a cold module
//     cache with no network) → honest-UNKNOWN "offline"/"skipped", never a
//     failure
//
// `go mod verify` checks the local module cache against go.sum and honors
// GOPRIVATE/GONOSUMDB itself, so the environment is inherited untouched.
func (is *IntegrityScanner) VerifyGoSum(ctx context.Context, gomodPath string, report *IntegrityReport) {
	if is.Offline {
		report.GoSumVerified = GoSumVerifiedOffline
		return
	}

	dir := filepath.Dir(gomodPath)
	if _, err := os.Stat(filepath.Join(dir, "go.sum")); err != nil {
		// Nothing to verify — gosum_missing (from ScanGoSum) already covers
		// the risk; running verify anyway would only duplicate it as a
		// misleading mismatch.
		report.GoSumVerified = GoSumVerifiedSkipped
		return
	}

	netlog.Subprocess("go mod verify", "verifies the local module cache; a cold cache may fetch via GOPROXY and sum.golang.org")

	cmd := exec.CommandContext(ctx, "go", "mod", "verify")
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err == nil {
		report.GoSumVerified = GoSumVerifiedTrue
		return
	}

	if ctx.Err() != nil {
		// The scan deadline expired or was cancelled — the process was killed
		// mid-run, so the non-zero exit says nothing about integrity.
		report.GoSumVerified = GoSumVerifiedSkipped
		return
	}

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		// The go binary is missing or could not be started — an environment
		// problem, not an integrity signal.
		report.GoSumVerified = GoSumVerifiedSkipped
		return
	}

	detail := strings.TrimSpace(string(output))
	mismatch := false
	for _, marker := range gosumMismatchMarkers {
		if strings.Contains(detail, marker) {
			mismatch = true
			break
		}
	}
	if !mismatch {
		// Non-zero exit without a mismatch marker: verify could not complete
		// (e.g. it had to fetch a module missing from the cache and the
		// network/proxy was unavailable). Not evidence of tampering.
		report.GoSumVerified = GoSumVerifiedSkipped
		return
	}

	if len(detail) > gosumDetailCap {
		detail = detail[:gosumDetailCap] + "…"
	}

	report.GoSumVerified = GoSumVerifiedFalse
	report.Findings = append(report.Findings, IntegrityFinding{
		Category:    "gosum_mismatch",
		Severity:    IntegrityCritical,
		Module:      "go.sum",
		Detail:      "go mod verify failed: " + detail,
		Remediation: "A module in the local cache does not match its go.sum checksum — possible tampering. Clear the module cache (`go clean -modcache`), re-download, and investigate how the mismatch was introduced before trusting this build.",
	})
}
