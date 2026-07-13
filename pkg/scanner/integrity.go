package scanner

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/unidoc/unisupply/pkg/parser"
)

// IntegrityRiskLevel categorizes go.mod directive risk.
type IntegrityRiskLevel string

// Integrity risk level bands. LOW/MEDIUM/HIGH mirror scorer.RiskLevel for
// consistency in reports; INFO is used for directives that carry no risk on
// their own (e.g. exclude) but are still worth surfacing for transparency.
const (
	IntegrityInfo   IntegrityRiskLevel = "INFO"
	IntegrityLow    IntegrityRiskLevel = "LOW"
	IntegrityMedium IntegrityRiskLevel = "MEDIUM"
	IntegrityHigh   IntegrityRiskLevel = "HIGH"
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
// replace/exclude directives are audited here now; go.sum/sumdb checks and
// pseudo-version findings are added by later plans (77, 79) as additional
// fields/categories on this same report.
type IntegrityReport struct {
	Findings      []IntegrityFinding `json:"findings,omitempty"`
	ReplaceCount  int                `json:"replace_count"`
	ExcludeCount  int                `json:"exclude_count"`
	RedirectCount int                `json:"redirect_count"` // HIGH-severity replaces (redirect to a different module)
}

// IntegrityScanner audits go.mod replace/exclude directives for supply chain risk.
type IntegrityScanner struct{}

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
