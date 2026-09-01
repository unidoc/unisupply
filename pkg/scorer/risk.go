// Package scorer implements the risk scoring algorithm.
package scorer

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/unidoc/unisupply/pkg/offline"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// Weights for risk scoring factors.
const (
	WeightVulnerabilities = 0.40
	WeightMaintenance     = 0.25
	WeightDepthRisk       = 0.15
	WeightMaintainerRisk  = 0.10
	WeightMaturity        = 0.10
)

// RiskLevel categorizes the risk score.
type RiskLevel string

// Risk level bands. Boundaries are documented in CLAUDE.md.
const (
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"

	// RiskUnknown is the project-level headline band when the scan could not
	// measure enough to earn a verdict. It is NOT a band on the 0-100 scale and
	// levelFromScore never returns it — only ScoreAll assigns it, and only to
	// ProjectScore.OverallLevel. Per-dependency risk_level always carries a
	// real band.
	RiskUnknown RiskLevel = "UNKNOWN"
)

// HeadlineCandidate records one axis that competes to become the headline score.
// The five candidates are: severity_adjusted, p95_dep_risk, archived_floor,
// cve_floor, integrity_floor.
type HeadlineCandidate struct {
	Name       string  `json:"name"`        // "severity_adjusted" | "p95_dep_risk" | "archived_floor" | "cve_floor" | "integrity_floor"
	Score      float64 `json:"score"`       // raw candidate value (0–100)
	DrivingDep string  `json:"driving_dep"` // module path of the dep that set the score, e.g. "github.com/gorilla/i18n"
	Reason     string  `json:"reason"`      // human-readable explanation, e.g. "archived 129 months"
}

// DependencyScore holds the risk assessment for a single dependency.
type DependencyScore struct {
	Module         string                   `json:"module"`
	Version        string                   `json:"version"`
	Direct         bool                     `json:"direct"`
	RiskScore      int                      `json:"risk_score"`
	RiskLevel      RiskLevel                `json:"risk_level"`
	DependencyPath []string                 `json:"dependency_path"`
	Vulns          []scanner.Vulnerability  `json:"vulnerabilities,omitempty"`
	Maintenance    *scanner.MaintenanceInfo `json:"maintenance,omitempty"`
	MaintainerInfo *scanner.MaintainerInfo  `json:"maintainer_info,omitempty"`
	Typosquat      *scanner.TyposquatResult `json:"typosquat,omitempty"`
	Resilience     *scanner.ResilienceInfo  `json:"resilience,omitempty"`
	AIGenRisk      *scanner.AIGenRisk       `json:"ai_gen_risk,omitempty"`
	TrustIndex     *scanner.TrustIndexEntry `json:"trust_index,omitempty"`
	RiskFactors    []string                 `json:"risk_factors,omitempty"`

	// ReplaceClass is the severity of this dependency's go.mod replace
	// directive ("LOW" version-pin, "MEDIUM" local-path or same-module
	// major-version redirect, "HIGH" redirect to a different module), or
	// empty when the dependency is not replaced. See
	// scanner.IntegrityScanner.ScanDirectives.
	ReplaceClass scanner.IntegrityRiskLevel `json:"replace_class,omitempty"`

	// PseudoVersion is true when this dependency's pinned go.mod version is a
	// pseudo-version (see scanner.IntegrityScanner.ScanPseudoVersions). Set
	// regardless of test-only status — IsTestOnly is the honest signal for
	// whether it carried score/policy impact, this field is purely descriptive.
	PseudoVersion bool `json:"pseudo_version,omitempty"`

	// IsTestOnly carries the three-state test-only classification from the
	// resolver. See resolver.Dependency.IsTestOnly for the full semantics.
	// Task 10's discount logic MUST only apply the discount when this is &true
	// (confirmed test-only). A nil value (unknown) must not trigger any discount.
	IsTestOnly *bool `json:"is_test_only,omitempty"`

	// Component scores (for verbose output).
	VulnScore        float64 `json:"-"`
	MaintenanceScore float64 `json:"-"`
	DepthScore       float64 `json:"-"`
	MaintainerScore  float64 `json:"-"`
	MaturityScore    float64 `json:"-"`

	// Additive bonus terms applied after the weighted base (for verbose output).
	ResilienceBonus    float64 `json:"-"`
	AIGenBonus         float64 `json:"-"`
	TyposquatBonus     float64 `json:"-"`
	IntegrityBonus     float64 `json:"-"`
	PseudoVersionBonus float64 `json:"-"`
	// FlooredTo is non-zero when severityFloor overrode the weighted total.
	// The gap is NOT additive — rendered as "floored→N".
	FlooredTo int `json:"-"`
	// MaintainerWeightExcluded is true when maintainer data was unavailable so
	// the 0.10 maintainer weight was dropped and the remaining four weights were
	// renormalized to sum to 1.0. The displayed component scores no longer equal
	// their nominal ×weight contributions.
	MaintainerWeightExcluded bool `json:"-"`

	// VulnWeightExcluded is true when the vulnerability scan did not run, so the
	// 0.40 weight was dropped rather than scored as zero. See
	// ScoreInput.VulnScanUnavailable — an unrun scan is not a clean result.
	VulnWeightExcluded bool `json:"-"`

	// MaintenanceWeightExcluded is true when this module's maintenance lookup
	// failed, so the 0.25 weight was dropped rather than scored with the
	// hard-coded unknown constant.
	MaintenanceWeightExcluded bool `json:"-"`

	// MeasuredWeight is the denominator the weighted base was divided by: the
	// sum of the weights actually available for this dependency. 1.0 means every
	// axis was measured. Below that, the score describes only the measured axes
	// and is not comparable to a fully-measured one.
	MeasuredWeight float64 `json:"-"`
}

// ProjectScore holds the overall project risk assessment.
//
// The headline score is the maximum of five candidates:
//
//	OverallScore = max(severity_adjusted, p95_dep_risk, archived_floor, cve_floor, integrity_floor)
//
// MeanDepRiskScore is retained as a non-normative portfolio-wide signal.
// HeadlineDriver records which of the five candidates won.
type ProjectScore struct {
	OverallScore int       `json:"overall_risk_score"`
	OverallLevel RiskLevel `json:"overall_risk_level"`

	// HeadlineUnscoredReason is non-empty when OverallLevel is RiskUnknown: it
	// names what the scan could not measure and why that disqualifies a verdict.
	// OverallScore still carries the computed number so dashboards and policy
	// gates keep working, but it must not be presented as a verdict — consumers
	// that render a band MUST check this field.
	HeadlineUnscoredReason string `json:"headline_unscored_reason,omitempty"`

	Dependencies      []*DependencyScore `json:"dependencies"`
	CriticalRiskCount int                `json:"critical_risk_count"`
	HighRiskCount     int                `json:"high_risk_count"`
	MediumRiskCount   int                `json:"medium_risk_count"`
	LowRiskCount      int                `json:"low_risk_count"`
	TotalVulns        int                `json:"total_vulnerabilities"`
	Unmaintained2yr   int                `json:"unmaintained_2yr"`
	Unmaintained1yr   int                `json:"unmaintained_1yr"`

	// MeanDepRiskScore is non-normative: retained for dashboards/trend lines; not used in headline.
	// Equal to the pre-Task-10 OverallScore. Use this when you want a portfolio-wide signal
	// that is not dominated by a single dep.
	MeanDepRiskScore int `json:"mean_dep_risk_score"`

	// SeverityAdjustedVulnScore is the CVE-driven step-function axis. Derived
	// from the enriched CVE list with a test-only downgrade-then-step applied
	// before counting. See severityAdjustedVulnScore in risk.go.
	SeverityAdjustedVulnScore int `json:"severity_adjusted_vuln_score"`

	// HeadlineDriver is one of "severity_adjusted", "p95_dep_risk", "archived_floor",
	// "cve_floor", "integrity_floor" — which of the five candidates produced
	// OverallScore. Empty when there are no dependencies.
	HeadlineDriver string `json:"headline_driver,omitempty"`

	// HeadlineCandidate records the winning candidate's full detail (score, driving dep, reason).
	// Nil when there are no dependencies (same condition that clears HeadlineDriver).
	HeadlineCandidate *HeadlineCandidate `json:"headline_candidate,omitempty"`

	// WorstCVEID is the ID of the most-severe enriched CVE on a production-path
	// dep (after test-only downgrade). Surfaces the load-bearing finding at a
	// glance. Empty when no CVEs are present.
	WorstCVEID string `json:"worst_cve_id,omitempty"`

	// WorstCVESeverity is the severity tier (post-downgrade) of WorstCVEID.
	WorstCVESeverity string `json:"worst_cve_severity,omitempty"`

	// WorstCVESourceSeverity is the raw severity string reported by the
	// advisory source for WorstCVEID (e.g. "UNKNOWN" when enrichment failed).
	// May differ from WorstCVESeverity when the scorer promotes UNKNOWN.
	WorstCVESourceSeverity string `json:"worst_cve_source_severity,omitempty"`

	// Diagnostics carries tail aggregates that the headline intentionally drops
	// (they over-promote healthy projects with long stale-but-inert tails).
	// NON-NORMATIVE: downstream consumers must not build policy gates on these
	// fields. Retained for debugging only.
	Diagnostics *Diagnostics `json:"diagnostics,omitempty"`

	// DebugScoring is populated only when --debug-scoring is set. Contains the
	// full per-dep + step-function inputs that produced the headline so a
	// customer report can be reproduced offline.
	//
	// NON-NORMATIVE: downstream consumers must not build policy gates on these
	// fields. The schema is internal to unisupply and may change between
	// releases.
	DebugScoring *DebugScoring `json:"debug_scoring,omitempty"`

	// Warnings surfaces data-quality issues to consumers. Entries explain
	// which signals were unavailable during the scan (e.g. missing GitHub
	// token) so downstream tooling can decide how to act on the scores.
	// This field lives on the top-level ProjectScore only — NOT per-dep.
	Warnings []string `json:"warnings,omitempty"`
}

// Diagnostics carries tail aggregates retained for debugging.
//
// NON-NORMATIVE: do not build policy gates on these fields. The headline
// dropped them because empirically they over-promoted healthy projects with
// long stale-but-inert tails. They remain useful for spot-checking outliers.
type Diagnostics struct {
	// MaxDepRiskScore is the maximum per-dep RiskScore across all dependencies.
	MaxDepRiskScore int `json:"max_dep_risk_score"`
	// P95DepRiskScore is the 95th-percentile per-dep RiskScore.
	P95DepRiskScore int `json:"p95_dep_risk_score"`
}

// DebugScoring is the diagnostic block emitted under --debug-scoring.
//
// NON-NORMATIVE: schema may change between releases. Use for offline
// reproduction of a headline only.
type DebugScoring struct {
	// MeanDepRiskScore and SeverityAdjustedVulnScore mirror the top-level
	// fields for convenience.
	MeanDepRiskScore          int    `json:"mean_dep_risk_score"`
	SeverityAdjustedVulnScore int    `json:"severity_adjusted_vuln_score"`
	HeadlineDriver            string `json:"headline_driver"`

	// StepFunctionInputs holds the post-downgrade severity counts that fed the
	// step function.
	StepFunctionInputs StepFunctionInputs `json:"step_function_inputs"`

	// EnrichedCVEs is the full list of CVEs considered by the step function,
	// each annotated with the test-only flag and the post-downgrade tier.
	EnrichedCVEs []DebugCVE `json:"enriched_cves"`

	// PerDepInputs lists per-dep VulnScore inputs (worst-CVE severity, HIGH+
	// count, floor applied, fix-age amplifier triggered). One entry per dep
	// with at least one CVE.
	PerDepInputs []DebugPerDepInput `json:"per_dep_inputs"`
}

// StepFunctionInputs records the post-downgrade severity counts.
type StepFunctionInputs struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// DebugCVE annotates a single CVE with the inputs that determined its
// contribution to the step function.
type DebugCVE struct {
	ID             string `json:"id"`
	Module         string `json:"module"`
	OriginalTier   string `json:"original_severity"`
	DowngradedTier string `json:"downgraded_severity,omitempty"`
	TestOnly       *bool  `json:"test_only,omitempty"`
	// EnrichmentFailed mirrors scanner.Vulnerability.EnrichmentFailed so the
	// reader can tell why an UNKNOWN was treated as MEDIUM in the step function.
	EnrichmentFailed bool `json:"enrichment_failed,omitempty"`
	// Reachability is the govulncheck reachability tier: "called", "imported",
	// "required", or "" (non-govulncheck source; see isConfirmedReachable).
	Reachability string `json:"reachability,omitempty"`
	// ReachabilityDowngrade describes the tier shift applied due to reachability
	// (e.g. "CRITICAL→HIGH (imported)"). Empty when no downgrade was applied.
	ReachabilityDowngrade string `json:"reachability_downgrade,omitempty"`
	// EPSSScore mirrors scanner.Vulnerability.EPSSScore — the input to the
	// EPSS amplifier (promotes one tier at >= 0.5). Nil when unavailable.
	EPSSScore *float64 `json:"epss_score,omitempty"`
	// InKEV mirrors scanner.Vulnerability.InKEV — the input to the KEV
	// override (forces CRITICAL on any non-dropped tier).
	InKEV bool `json:"in_kev,omitempty"`
}

// DebugPerDepInput records the inputs to vulnScore for one dependency.
type DebugPerDepInput struct {
	Module           string `json:"module"`
	WorstSeverity    string `json:"worst_severity"`
	HighOrAboveCount int    `json:"high_or_above_count"`
	FloorApplied     int    `json:"floor_applied"`
	FixAgeAmplifier  bool   `json:"fix_age_amplifier_triggered"`
	FinalVulnScore   int    `json:"final_vuln_score"`
	FinalRiskScore   int    `json:"final_risk_score"`
	FinalRiskLevel   string `json:"final_risk_level"`
}

// ScoreInput bundles all scan results for scoring.
type ScoreInput struct {
	Graph       *resolver.Graph
	Vulns       map[string][]scanner.Vulnerability
	Maintenance map[string]*scanner.MaintenanceInfo
	Maintainers map[string]*scanner.MaintainerInfo
	Typosquats  map[string]*scanner.TyposquatResult
	Resilience  map[string]*scanner.ResilienceInfo
	AIGenRisks  map[string]*scanner.AIGenRisk
	TrustIndex  map[string]*scanner.TrustIndexEntry

	// Integrity maps a module path to its go.mod replace directive severity
	// (see scanner.IntegrityScanner.ScanDirectives). A missing entry means the
	// dependency is not replaced.
	Integrity map[string]scanner.IntegrityRiskLevel

	// PseudoVersion maps a module path to its pseudo-version pin severity
	// (see scanner.IntegrityScanner.ScanPseudoVersions). A missing entry means
	// the dependency is not pinned to a pseudo-version.
	PseudoVersion map[string]scanner.IntegrityRiskLevel

	// VulnScanUnavailable is true when the vulnerability scan did not run at all
	// — offline mode skips govulncheck, and an online run can fail outright. It
	// is project-scoped because govulncheck is all-or-nothing: it either
	// analyzed the module graph or it did not.
	//
	// This cannot be inferred from an empty Vulns map, which legitimately means
	// "scanned, nothing found". Without the distinction a skipped scan scores
	// identically to a verified-clean project, which is the one wrong answer.
	VulnScanUnavailable bool

	// GoSumMismatch is true when `go mod verify` reported a checksum mismatch
	// (scanner.IntegrityReport.GoSumVerified == "false"). It floors the
	// headline into the CRITICAL band via the integrity_floor candidate.
	// Honest-UNKNOWN verification states ("offline"/"skipped") must map to
	// false — only a confirmed mismatch drives the headline.
	GoSumMismatch bool

	// DebugMode populates ps.DebugScoring with diagnostic data when true.
	// Wired to the --debug-scoring CLI flag.
	DebugMode bool

	// Now is the scan-start clock reference used by the fix-age amplifier in
	// lowFixAgeFloor. It MUST match the quantized scan-start time the scanners
	// receive (cmd/unisupply/main.go sets all five from a single value), so
	// that two scans on the same UTC day produce identical floor decisions at
	// the 30/180/365-day boundaries. A zero value falls back to time.Now() —
	// use only in tests where deterministic day-boundary behavior is not
	// being asserted.
	Now time.Time
}

// ScoreAll computes risk scores for all dependencies and the overall project.
func ScoreAll(input ScoreInput) *ProjectScore {
	ps := &ProjectScore{}

	// Resolve the clock reference once. A zero input.Now falls back to
	// time.Now() so direct test callers that don't care about day-boundary
	// determinism keep working without modification.
	now := input.Now
	if now.IsZero() {
		now = time.Now()
	}

	// Count modules whose data was unavailable per axis. Used to build
	// top-level warnings so consumers understand the scoring gap. A degraded
	// scan that reports no gap is indistinguishable from a complete one.
	maintainerUnavailable := 0
	maintenanceUnavailable := 0
	resilienceUnavailable := 0

	// Sort dependency keys so that ScoreAll produces a deterministic
	// ps.Dependencies slice regardless of Go's map iteration order. This is
	// load-bearing: severityAdjustedVulnScore iterates the resulting slice and
	// uses a first-wins tie-breaker, so stable key order is required for
	// reproducible WorstCVEID values.
	depKeys := make([]string, 0, len(input.Graph.Dependencies))
	for k := range input.Graph.Dependencies {
		depKeys = append(depKeys, k)
	}
	sort.Strings(depKeys)

	for _, k := range depKeys {
		dep := input.Graph.Dependencies[k]
		ds := scoreDependency(
			dep,
			input.Vulns[dep.Module.Path],
			input.Maintenance[dep.Module.Path],
			input.Maintainers[dep.Module.Path],
			input.Typosquats[dep.Module.Path],
			input.Resilience[dep.Module.Path],
			input.AIGenRisks[dep.Module.Path],
			input.TrustIndex[dep.Module.Path],
			input.Integrity[dep.Module.Path],
			input.PseudoVersion[dep.Module.Path],
			input.VulnScanUnavailable,
			now,
		)
		ps.Dependencies = append(ps.Dependencies, ds)

		// Count vulns.
		ps.TotalVulns += len(ds.Vulns)

		// Count by risk level.
		switch {
		case ds.RiskScore >= 76:
			ps.CriticalRiskCount++
		case ds.RiskScore >= 51:
			ps.HighRiskCount++
		case ds.RiskScore >= 26:
			ps.MediumRiskCount++
		default:
			ps.LowRiskCount++
		}

		// Count unmaintained.
		if ds.Maintenance != nil {
			if ds.Maintenance.MonthsSinceRelease >= 24 {
				ps.Unmaintained2yr++
			} else if ds.Maintenance.MonthsSinceRelease >= 12 {
				ps.Unmaintained1yr++
			}
		}

		// Track missing maintainer signal. A nil entry means the scanner was
		// not run (non-GitHub module); DataAvailable == false means it was
		// attempted but failed (rate-limited, unauthenticated, network error).
		if m := input.Maintainers[dep.Module.Path]; m != nil && !m.DataAvailable {
			maintainerUnavailable++
		}

		// A missing maintenance entry means the lookup failed — the scanner
		// inserts only on success (see MaintenanceScanner.ScanAll).
		if ds.MaintenanceWeightExcluded {
			maintenanceUnavailable++
		}

		// Resilience carries no scoring weight of its own (it feeds a bonus,
		// already gated on DataAvailable), so there is no weight to exclude.
		// It still needs saying: an unavailable resilience axis silently
		// disables both the low-resilience bonus and the AI-gen detector, which
		// depends on ResilienceInfo.FirstReleaseDate.
		if r := input.Resilience[dep.Module.Path]; r != nil && !r.DataAvailable {
			resilienceUnavailable++
		}
	}

	// Name the actual cause. Offline is not a rate-limit problem, and telling an
	// air-gapped user their token is missing sends them after a fix that cannot
	// work.
	cause := "GitHub API unauthenticated"
	// prefix applies to the proxy-sourced axes below. Only the maintainer axis
	// reads the GitHub API, so `cause` must not be reused for the others —
	// naming the wrong service sends the user after a fix that cannot work, the
	// same reason offline is distinguished from a rate limit here at all.
	prefix := ""
	if offline.Enabled() {
		cause = "offline"
		prefix = "offline — "
	}

	if maintainerUnavailable > 0 {
		ps.Warnings = append(ps.Warnings,
			fmt.Sprintf("%s — maintainer data unavailable for %d module(s); maintainer weight excluded from those scores", cause, maintainerUnavailable),
		)
	}

	if maintenanceUnavailable > 0 {
		// The maintenance scanner reads the module proxy, so the maintainer cause
		// above would be wrong. Any non-offline cause is left to the
		// scanner-sourced warning, which has the underlying error.
		ps.Warnings = append(ps.Warnings,
			fmt.Sprintf("%smaintenance data unavailable for %d module(s); maintenance weight excluded from those scores rather than scored as unknown", prefix, maintenanceUnavailable),
		)
	}

	if resilienceUnavailable > 0 {
		// Not `cause`: ResilienceInfo.DataAvailable is gated on the module-proxy
		// version-list fetch, so "GitHub API unauthenticated" would name the wrong
		// service. Offline is the only cause this layer can state accurately.
		//
		// The AI-gen consequence is deliberately not mentioned here — the AI-gen
		// scanner emits its own warning naming the same modules, and stating it in
		// both put two lines about one gap in the SCAN LIMITATIONS block.
		ps.Warnings = append(ps.Warnings,
			fmt.Sprintf("%sresilience data unavailable for %d module(s); release-cadence and governance signals not measured", prefix, resilienceUnavailable),
		)
	}

	if input.VulnScanUnavailable {
		ps.Warnings = append(ps.Warnings,
			"vulnerability scan did not run; the 40% vulnerability weight is excluded from every dependency score — these scores describe only the axes that were measured and are NOT comparable to a scan that checked for CVEs",
		)
	}

	// Five-candidate headline: max(severity_adjusted, p95_dep_risk, archived_floor, cve_floor, integrity_floor).
	//
	// MeanDepRiskScore is non-normative — retained for dashboards/trend lines.
	// OverallScore = max(severity_adjusted, p95_dep_risk, archived_floor, cve_floor, integrity_floor).
	ps.MeanDepRiskScore = computeOverallScore(ps.Dependencies)

	sevResult := severityAdjustedVulnScore(now, ps.Dependencies)
	ps.Warnings = append(ps.Warnings, sevResult.warnings...)
	ps.SeverityAdjustedVulnScore = sevResult.score
	ps.WorstCVEID = sevResult.worstID
	ps.WorstCVESeverity = sevResult.worstSeverity
	ps.WorstCVESourceSeverity = sevResult.worstSourceSeverity

	// Build the severity_adjusted candidate. severity_adjusted is a portfolio
	// step-function over all CVE counts — there is no single driving dep.
	// DrivingDep is intentionally left empty; Reason summarises the aggregate.
	sevCandidate := HeadlineCandidate{Name: "severity_adjusted", Score: float64(sevResult.score)}
	{
		si := sevResult.stepInputs
		total := si.Critical + si.High + si.Medium + si.Low
		sevCandidate.Reason = fmt.Sprintf(
			"%d high-severity CVE across %d total (%d critical) → score %d",
			si.High, total, si.Critical, sevResult.score,
		)
	}

	candidates := []HeadlineCandidate{
		sevCandidate,
		p95DepRiskCandidate(ps.Dependencies),
		archivedFloor(ps.Dependencies),
		cveFloor(ps.Dependencies),
		integrityFloor(ps.Dependencies, input.GoSumMismatch),
	}
	winner := selectHeadline(candidates)
	ps.HeadlineCandidate = &winner
	ps.OverallScore = int(math.Round(winner.Score))
	ps.HeadlineDriver = winner.Name

	// HeadlineDriver is meaningless when there are no dependencies (all candidates
	// score 0). Clear it so the json:omitempty tag produces a clean empty-graph report.
	if len(ps.Dependencies) == 0 {
		ps.HeadlineDriver = ""
		ps.HeadlineCandidate = nil
	}
	ps.OverallLevel = levelFromScore(ps.OverallScore)

	// A headline band requires a scan that could actually earn one.
	//
	// Three of the five candidates are CVE-derived (severity_adjusted, cve_floor,
	// and the fix-age amplifier inside it). With no vulnerability data all three
	// are structurally zero, so the headline collapses onto p95_dep_risk — a
	// candidate designed to be one voice among five, not the sole decider. What
	// it then measures is whatever axes survived, which offline means depth and
	// maturity: graph position and a version string.
	//
	// Measured on UniDoc's own libraries, that promoted UniOffice from LOW to
	// MEDIUM offline on four untagged pseudo-version transitives, with no CVE
	// check performed. A band nobody can defend is worse than no band, so report
	// UNKNOWN and say what is missing. OverallScore keeps the computed number for
	// dashboards and policy gates.
	if input.VulnScanUnavailable && len(ps.Dependencies) > 0 {
		ps.OverallLevel = RiskUnknown
		ps.HeadlineUnscoredReason = "vulnerability scan did not run — 3 of the 5 headline candidates are CVE-derived and scored 0, leaving the headline decided by dependency-graph position and version scheme alone; the numeric score is indicative only"
	}

	// Diagnostics retained for debugging only — NON-NORMATIVE. Suppressed when
	// there are no deps (max/p95 over an empty set carries no information).
	if len(ps.Dependencies) > 0 {
		ps.Diagnostics = computeDiagnostics(ps.Dependencies)
	}

	// DebugScoring is populated only when the caller opts in via --debug-scoring.
	if input.DebugMode {
		ps.DebugScoring = buildDebugScoring(ps, &sevResult)
	}

	return ps
}

// scoreDependency computes the per-dep RiskScore and RiskLevel. The `now`
// argument is the clock reference for the LOW-CVE fix-age amplifier in
// lowFixAgeFloor; it should be the same quantized scan-start the scanners
// received (see ScoreInput.Now). A zero `now` falls back to time.Now() at
// the leaf (lowFixAgeFloor), preserving the pre-clock-injection test
// signatures.
func scoreDependency(
	dep *resolver.Dependency,
	vulns []scanner.Vulnerability,
	maint *scanner.MaintenanceInfo,
	maintainerInfo *scanner.MaintainerInfo,
	typosquat *scanner.TyposquatResult,
	resilience *scanner.ResilienceInfo,
	aiGenRisk *scanner.AIGenRisk,
	trustIndex *scanner.TrustIndexEntry,
	integrityClass scanner.IntegrityRiskLevel,
	pseudoVersionClass scanner.IntegrityRiskLevel,
	vulnScanUnavailable bool,
	now time.Time,
) *DependencyScore {
	// Backfill Maintenance.Archived from the maintainer scanner before building
	// DependencyScore so ds.Maintenance always holds the updated pointer.
	// The maintenance scanner uses the module proxy, which does not expose the
	// archived flag. MaintainerInfo.IsArchived is populated from the GitHub API
	// repo.Archived field and is the authoritative source.
	if maintainerInfo != nil && maintainerInfo.IsArchived {
		if maint == nil {
			maint = &scanner.MaintenanceInfo{Archived: true}
		} else if !maint.Archived {
			maint.Archived = true
		}
	}

	ds := &DependencyScore{
		Module:         dep.Module.Path,
		Version:        dep.Module.Version,
		Direct:         dep.Direct,
		IsTestOnly:     dep.IsTestOnly,
		DependencyPath: dep.UsedBy,
		Vulns:          vulns,
		Maintenance:    maint,
		MaintainerInfo: maintainerInfo,
		Typosquat:      typosquat,
		Resilience:     resilience,
		AIGenRisk:      aiGenRisk,
		TrustIndex:     trustIndex,
	}

	// A version-scoped replace whose old-version does not match the selected
	// version is inert: dep.Replaced (via parser.GoMod.ReplacementFor) is false
	// and the directive has no effect on the build. Only record the class when
	// the replace actually applies, so integrityFloor and the JSON
	// replace_class field stay consistent with dep.Replaced.
	if dep.Replaced {
		ds.ReplaceClass = integrityClass
	}

	// 1. Vulnerability score (0-100).
	ds.VulnScore = vulnScore(vulns)
	if ds.VulnScore > 0 {
		ds.RiskFactors = append(ds.RiskFactors, "known_vulnerabilities")
	}

	// 2. Maintenance score (0-100).
	ds.MaintenanceScore = maintenanceScore(maint)
	if maint != nil {
		if maint.Archived {
			ds.RiskFactors = append(ds.RiskFactors, "archived")
		}
		if maint.Deprecated {
			ds.RiskFactors = append(ds.RiskFactors, "deprecated")
		}
		if maint.MonthsSinceRelease >= 24 {
			ds.RiskFactors = append(ds.RiskFactors, "unmaintained")
		}
	}

	// 3. Depth score (0-100).
	ds.DepthScore = depthScore(dep.Depth)

	// 4. Maintainer risk score (0-100).
	// When DataAvailable is false the API call failed; treat the score as 0
	// so missing data does not inflate risk. The weight is also excluded from
	// the denominator below (re-normalization).
	ds.MaintainerScore = maintainerRiskScore(maintainerInfo, dep.Module.Path)
	if maintainerInfo != nil && maintainerInfo.DataAvailable {
		if maintainerInfo.BusFactor <= 1 && maintainerInfo.ContributorCount > 0 {
			ds.RiskFactors = append(ds.RiskFactors, "single_maintainer")
		}
		if maintainerInfo.ActivityPattern == "inactive" {
			ds.RiskFactors = append(ds.RiskFactors, "maintainer_inactive")
		}
		if maintainerInfo.TakeoverCandidate {
			ds.RiskFactors = append(ds.RiskFactors, "takeover_candidate")
		}
	}

	// 5. Module maturity score (0-100).
	ds.MaturityScore = maturityScore(dep.Module.Version, dep.Module.Path)

	// Bonus: typosquatting adds to the score as an additional risk factor.
	typosquatBonus := 0.0
	if typosquat != nil {
		typosquatBonus = typosquat.Confidence * 20
		ds.RiskFactors = append(ds.RiskFactors, "typosquatting_risk")
	}

	// AI-generated code risk adds to score.
	// The score-accumulation bonus fires on any non-zero AIGenRisk score so that
	// partial signals still influence the weighted total. However, promotion to
	// risk_factors (the human-visible flag) requires the stricter AND-gate
	// (age_months < 12 AND release_count <= 2 AND generic_name) indicated by
	// MeetsPromotionGate, preventing single-indicator false positives.
	aiGenBonus := 0.0
	if aiGenRisk != nil && aiGenRisk.Score > 0 {
		aiGenBonus = float64(aiGenRisk.Score) * 0.15 // up to 15 extra points
		if aiGenRisk.MeetsPromotionGate {
			ds.RiskFactors = append(ds.RiskFactors, "ai_gen_risk:"+aiGenRisk.RiskLevel)
		}
	}

	// Low resilience adds to score.
	//
	// DataAvailable gates this: when the proxy could not be reached the whole
	// struct is zero-valued, so Score is 0 and an ungated check would flag
	// every module as low-resilience on the strength of data it never had.
	// ResilienceInfo.DataAvailable documents exactly this ("all numeric fields
	// are zero-valued and MUST NOT be interpreted as real measurements").
	resilienceBonus := 0.0
	if resilience != nil && resilience.DataAvailable && resilience.Score < 30 {
		resilienceBonus = float64(30-resilience.Score) * 0.2 // up to 6 extra points for very low resilience
		ds.RiskFactors = append(ds.RiskFactors, "low_resilience")
	}

	// Replace directive: any replace (version-pin, local-path, or redirect)
	// surfaces as a risk factor for transparency. Only the MEDIUM (local-path
	// or same-module major-version redirect) and HIGH (redirect to a different
	// module) classes add to the score — a version-pin replace is expected and
	// carries no bonus.
	integrityBonus := 0.0
	if dep.Replaced {
		ds.RiskFactors = append(ds.RiskFactors, "replaced")
		switch integrityClass {
		case scanner.IntegrityHigh:
			integrityBonus = 20
		case scanner.IntegrityMedium:
			integrityBonus = 8
		}
	}

	// Pseudo-version pin: a distinct signal from aigen's pseudo_version_only
	// indicator (fires on zero-tagged-releases-ever, a historical property;
	// see the (*scanner.IntegrityScanner).ScanPseudoVersions doc comment for
	// the full distinction). INFO (test-only) carries no score impact by
	// design — only MEDIUM (direct) and LOW (transitive) add a bonus. Kept
	// intentionally small: a dep can trigger both this bonus (max 4) and the
	// pseudo_version_only indicator's share of the aigen bonus (that indicator
	// contributes 10 to the aigen score, i.e. 10*0.15 = 1.5 points here — the
	// aigen bonus as a whole can be larger) simultaneously, capping the
	// combined pseudo-version contribution at 5.5 — well below any
	// single-factor promotion threshold.
	pseudoVersionBonus := 0.0
	if pseudoVersionClass != "" {
		ds.PseudoVersion = true
		ds.RiskFactors = append(ds.RiskFactors, "pseudo_version_pin")
		switch pseudoVersionClass {
		case scanner.IntegrityMedium:
			pseudoVersionBonus = 4
		case scanner.IntegrityLow:
			pseudoVersionBonus = 2
		}
	}

	// Weighted total.
	//
	// Normal case: the five weights sum to 1.0 (0.40 + 0.25 + 0.15 + 0.10 + 0.10).
	//
	// Re-normalization: an axis whose data could not be collected is dropped
	// from BOTH the numerator and the denominator, so the surviving weights
	// rescale to 1.0. The alternative — scoring an unmeasured axis as zero, or
	// as a hard-coded "unknown" constant — reports a fabricated measurement as
	// a finding, which is the failure mode this whole block exists to prevent.
	//
	// Depth and maturity are never excluded: both derive from the resolved
	// graph and the version string, so they are available even offline. That
	// guarantees the denominator never reaches zero (floor 0.25).
	//
	// NOTE: after re-normalization the declared weights no longer sum to the
	// denominator — intentional; the denominator variable carries the corrected
	// total, and ds.MeasuredWeight records it for the report.
	weightedBase := ds.DepthScore*WeightDepthRisk + ds.MaturityScore*WeightMaturity
	denominator := WeightDepthRisk + WeightMaturity

	// Vulnerabilities. An empty vuln list means "clean" only when the scan
	// actually ran; vulnScanUnavailable distinguishes the two.
	if vulnScanUnavailable {
		ds.VulnWeightExcluded = true
	} else {
		weightedBase += ds.VulnScore * WeightVulnerabilities
		denominator += WeightVulnerabilities
	}

	// Maintenance. MaintenanceScanner.ScanAll inserts into its result map only
	// on a successful lookup, so a nil entry here means that module's lookup
	// failed — not that it has an unknown-but-measured status.
	if maint == nil {
		ds.MaintenanceWeightExcluded = true
	} else {
		weightedBase += ds.MaintenanceScore * WeightMaintenance
		denominator += WeightMaintenance
	}

	// Maintainer. A nil entry means the scanner never ran for this module (not
	// GitHub-hosted), which is not a collection failure — the axis scores 0 and
	// keeps its weight. DataAvailable == false means it ran and failed.
	if maintainerInfo != nil && !maintainerInfo.DataAvailable {
		ds.MaintainerWeightExcluded = true
	} else {
		weightedBase += ds.MaintainerScore * WeightMaintainerRisk
		denominator += WeightMaintainerRisk
	}

	ds.MeasuredWeight = denominator

	ds.TyposquatBonus = typosquatBonus
	ds.AIGenBonus = aiGenBonus
	ds.ResilienceBonus = resilienceBonus
	ds.IntegrityBonus = integrityBonus
	ds.PseudoVersionBonus = pseudoVersionBonus

	weighted := weightedBase/denominator +
		typosquatBonus +
		aiGenBonus +
		resilienceBonus +
		integrityBonus +
		pseudoVersionBonus

	ds.RiskScore = int(math.Round(weighted))

	// Severity-derived floor: replaces the old blanket >= 51 floor.
	// The floor and risk_level are determined by the worst CVE severity on this dep.
	// UNKNOWN severity uses a conservative MEDIUM floor when enrichment failed
	// (i.e. we could not determine severity — assume it could be HIGH).
	//
	// These tables answer different questions:
	//   per-dep (here)    = "how risky is this module?"
	//   project-level     = "worst-case CVE-driven floor for the whole project?" (Task 10)
	// Never call one from the other.
	if len(vulns) > 0 {
		floor, promotedLevel := severityFloor(now, vulns)
		if ds.RiskScore < floor {
			ds.FlooredTo = floor
			ds.RiskScore = floor
		}

		// Per-dep risk_level promotion: CRITICAL/HIGH CVEs promote the band
		// regardless of numeric score. This ensures a dep with CRITICAL CVE
		// always surfaces as CRITICAL in per-dep risk_level even when other
		// factors pull the numeric score below 76.
		if ds.RiskScore > 100 {
			ds.RiskScore = 100
		}
		numeric := levelFromScore(ds.RiskScore)
		if riskLevelOrder(promotedLevel) > riskLevelOrder(numeric) {
			ds.RiskLevel = promotedLevel
		} else {
			ds.RiskLevel = numeric
		}
		return ds
	}

	if ds.RiskScore > 100 {
		ds.RiskScore = 100
	}
	ds.RiskLevel = levelFromScore(ds.RiskScore)

	return ds
}

// severityWeight maps a normalized severity string to its per-dep weight.
//
// These weights answer: "how risky is this module?"
// They differ intentionally from the project-level severity_adjusted_vuln_score
// table in Task 10, which answers: "worst-case CVE-driven floor for the whole
// project?" Never unify or call one from the other.
func severityWeight(severity string) float64 {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 100
	case "HIGH":
		return 80
	case "MEDIUM":
		return 50
	case "LOW":
		return 25
	default:
		// UNKNOWN: more conservative than the old 50; reflects the uncertainty
		// cost of not knowing how bad the CVE is.
		return 40
	}
}

// vulnScore computes a per-dep vulnerability score using a max-plus-accumulator.
//
// Formula:
//
//	base = max(severityWeight) over all CVEs on this dep
//	bonus = 5 × (count_of_HIGH_or_above − 1), capped such that total ≤ 100
//
// Rationale: a single CRITICAL must dominate many LOWs, but multiple CRITICALs
// are materially worse than one CRITICAL. The bonus accounts for pile-up without
// letting LOW-severity noise inflate the score past the base severity.
//
// These weights answer: "how risky is this module?" (per-dep axis).
// See the project-level severity_adjusted_vuln_score table in Task 10 for the
// complementary axis. Never call one from the other.

// highOrAboveWeightFloor is the reachability-adjusted weight at or above which
// a CVE counts toward the pile-up bonus in vulnScore. Derived from the source
// tables (an imported HIGH: 80 × 0.7 = 56) rather than hardcoded, so it tracks
// any future change to severityWeight or reachabilityFactor automatically.
var highOrAboveWeightFloor = severityWeight("HIGH") * reachabilityFactor("imported")

func vulnScore(vulns []scanner.Vulnerability) float64 {
	if len(vulns) == 0 {
		return 0
	}

	maxWeight := 0.0
	highOrAboveCount := 0
	maxEPSS := 0.0

	for i := range vulns {
		v := &vulns[i]
		// Apply the reachability factor before comparing and accumulating.
		// "called"/""→×1.0, "imported"→×0.7, "required"→×0.3.
		w := severityWeight(v.Severity) * reachabilityFactor(v.Reachability)
		if w > maxWeight {
			maxWeight = w
		}
		// Count HIGH-or-above using the reachability-adjusted weight so that a
		// required CRITICAL (30 pts) is not treated equivalently to a called
		// CRITICAL (100 pts) in the pile-up bonus.
		if w >= highOrAboveWeightFloor {
			highOrAboveCount++
		}
		if v.EPSSScore != nil && *v.EPSSScore > maxEPSS {
			maxEPSS = *v.EPSSScore
		}
	}

	// Accumulator: base is the worst CVE; each additional HIGH-or-above adds 5.
	bonus := 0.0
	if highOrAboveCount > 1 {
		bonus = float64(highOrAboveCount-1) * 5
	}

	// EPSS additive bonus: the dep's worst exploitation probability adds up to
	// 15 points (e.g. one EPSS-0.8 CVE adds +12), capped at the 100 ceiling.
	total := maxWeight + bonus + maxEPSS*epssVulnScoreWeight
	if total > 100 {
		total = 100
	}
	return total
}

// severityFloor derives the minimum RiskScore floor and the promoted RiskLevel
// for a dep that has at least one vulnerability. The floor is based on the worst
// CVE severity present. The second return value is the minimum RiskLevel that
// must be applied regardless of the numeric score (per-dep risk_level promotion).
//
// Floor table:
//
//	any KEV-listed CVE (any reachability)  → 76 (CRITICAL band)
//	CRITICAL or HIGH                       → 51 (HIGH band)
//	MEDIUM                                 → 26 (MEDIUM band)
//	LOW                                    → 0  (no floor; amplifier below may still raise it)
//	UNKNOWN + enrichment failure + called  → 51 (pessimistic HIGH: confirmed reachable, severity unknown)
//	UNKNOWN + enrichment failure           → 26 (conservative MEDIUM)
//
// The `now` argument is forwarded to lowFixAgeFloor in the LOW-only branch.
// Pass the scan-start clock reference (see ScoreInput.Now) for day-quantized
// determinism; a zero value falls back to time.Now() at the leaf.
func severityFloor(now time.Time, vulns []scanner.Vulnerability) (floor int, promoted RiskLevel) {
	// Track the worst severity seen to determine the floor.
	// Only "called", "imported", and "" CVEs contribute to the floor.
	// "required" CVEs are excluded: their code never links into the build, so
	// they must not promote the per-dep risk level. They still contribute to
	// vulnScore via reachabilityFactor (×0.3) but do not set a severity floor.
	hasCritical := false
	hasHigh := false
	hasMedium := false
	hasUnknownCalledFailed := false // UNKNOWN + enrichment failure + confirmed called
	hasUnknownFailed := false       // UNKNOWN + enrichment failure, reachability unconfirmed
	hasKEV := false

	for i := range vulns {
		v := &vulns[i]
		// KEV check runs before the "required" skip: a CVE that CISA has
		// confirmed exploited in the wild floors the dep at CRITICAL (76)
		// regardless of severity or reachability — the per-dep axis answers
		// "how risky is this module?", and a module shipping a weaponized CVE
		// is critically risky whether or not this project links it.
		if v.InKEV {
			hasKEV = true
		}
		// Skip required-only CVEs — they do not contribute to the floor.
		if v.Reachability == "required" {
			continue
		}
		switch strings.ToUpper(v.Severity) {
		case "CRITICAL":
			hasCritical = true
		case "HIGH":
			hasHigh = true
		case "MEDIUM":
			hasMedium = true
		case "LOW":
			// LOW: no floor from severity alone; handled by fix-age amplifier below.
		default:
			// UNKNOWN: escalate to HIGH only when reachability is confirmed called;
			// empty reachability stays MEDIUM (absence of confirmation ≠ reachable).
			if v.EnrichmentFailed {
				if isConfirmedReachable(v) {
					hasUnknownCalledFailed = true
				} else {
					hasUnknownFailed = true
				}
			}
		}
	}

	switch {
	case hasKEV:
		// Confirmed exploited in the wild: CRITICAL floor (76) regardless of
		// severity — presence on KEV essentially mandates patching.
		return 76, RiskCritical
	case hasCritical:
		return 51, RiskCritical
	case hasHigh:
		return 51, RiskHigh
	case hasMedium:
		return 26, RiskMedium
	case hasUnknownCalledFailed:
		// Confirmed-reachable CVE with unknown severity: pessimistic HIGH floor.
		return 51, RiskHigh
	case hasUnknownFailed:
		// Enrichment failed but reachability unconfirmed: conservative MEDIUM.
		return 26, RiskMedium
	default:
		// Only LOW CVEs present (or only required CVEs, which are excluded above);
		// apply fix-age amplifier.
		floor = lowFixAgeFloor(now, vulns)
		return floor, RiskLow
	}
}

// lowFixAgeFloor returns a floor score for deps whose worst CVE is LOW severity.
// A LOW CVE that has had a fix available for a long time signals that the
// upstream is not actively patching — a maintenance risk disguised as a low CVE.
//
// Amplifier table (applied to the worst LOW CVE's age signals):
//
//	fix_available && days_since_fix_published >= 365 → 26 (MEDIUM)
//	fix_available && days_since_fix_published >= 180 → 20 (high LOW)
//	fix_available && days_since_fix_published >= 30  → no floor
//	!fix_available && days_since_disclosure >= 365   → 20
//	otherwise                                        → no floor
//
// The `now` argument is the scan-start clock reference (see ScoreInput.Now).
// Pass a quantized scan-start so two scans on the same UTC day produce
// identical 30/180/365-day boundary decisions for the same CVE. A zero
// `now` falls back to time.Now() — used only by legacy test callers that
// do not exercise day-boundary behavior.
func lowFixAgeFloor(now time.Time, vulns []scanner.Vulnerability) int {
	if now.IsZero() {
		now = time.Now()
	}
	floor := 0

	for i := range vulns {
		v := &vulns[i]
		// Only apply amplifier to LOW-severity CVEs.
		if !strings.EqualFold(v.Severity, "LOW") {
			continue
		}

		if v.FixPublishedAt != nil {
			// Fix is available: measure how long the user has had the option to patch.
			daysSinceFix := int(now.Sub(*v.FixPublishedAt).Hours() / 24)
			switch {
			case daysSinceFix >= 365:
				if 26 > floor {
					floor = 26
				}
			case daysSinceFix >= 180:
				if 20 > floor {
					floor = 20
				}
				// 30 <= daysSinceFix < 180: no floor contribution.
			}
		} else if v.PublishedAt != nil {
			// No fix available: measure time since disclosure.
			daysSinceDisclosure := int(now.Sub(*v.PublishedAt).Hours() / 24)
			if daysSinceDisclosure >= 365 {
				if 20 > floor {
					floor = 20
				}
			}
		}
		// DaysUnpatched is precomputed by Task 07; it equals days since FixPublishedAt
		// when a fix exists. It is used here indirectly via FixPublishedAt/PublishedAt.
	}

	return floor
}

func maintenanceScore(maint *scanner.MaintenanceInfo) float64 {
	if maint == nil {
		return 30 // Unknown maintenance status.
	}

	if maint.Archived {
		return 100
	}

	months := maint.MonthsSinceRelease
	switch {
	case months < 6:
		return 0
	case months < 12:
		return 25
	case months < 24:
		return 60
	default:
		return 90
	}
}

func depthScore(depth int) float64 {
	switch {
	case depth <= 0:
		return 0
	case depth == 1:
		return 20
	default:
		return 40
	}
}

func maintainerRiskScore(info *scanner.MaintainerInfo, modPath string) float64 {
	// Trusted namespaces maintained by well-known teams.
	if isTrustedNamespace(modPath) {
		return 0
	}

	if info == nil {
		return 30 // Unknown: scanner not run for this module.
	}

	// GitHub API call failed (rate-limit, 403, network error). Return 0 so
	// the absence of data does not inflate the score. The caller excludes
	// this component from the denominator via re-normalization.
	if !info.DataAvailable {
		return 0
	}

	if info.BusFactor == 0 {
		return 30 // Could not determine.
	}

	if info.BusFactor == 1 {
		// UniTrust-verified identity halves the single-maintainer risk: the bus
		// factor is unchanged, but a curated, confirmed identity is lower-risk
		// than an anonymous solo maintainer.
		if info.OwnerVerified {
			return 25
		}
		return 50 // Single maintainer, unverified.
	}

	return 0 // Multiple maintainers.
}

func maturityScore(version, modPath string) float64 {
	// Trusted namespaces use v0.x by design (e.g. golang.org/x/*).
	if isTrustedNamespace(modPath) {
		return 0
	}

	if version == "" {
		return 50 // No tags.
	}

	if strings.HasPrefix(version, "v0.") {
		return 30
	}

	return 0
}

// trustedNamespaces are module path prefixes maintained by well-known,
// trusted organizations. These get reduced maintainer and maturity risk
// because their v0.x and "unknown maintainer" status is by design, not neglect.
var trustedNamespaces = []string{
	"golang.org/x/",
	"google.golang.org/",
	"cloud.google.com/go",
	"k8s.io/",
	"sigs.k8s.io/",
	"go.opencensus.io",
	"go.opentelemetry.io/",
	"go.uber.org/",
	"github.com/golang/",
	"github.com/google/",
	"github.com/googleapis/",
	"github.com/grpc/",
}

func isTrustedNamespace(modPath string) bool {
	for _, ns := range trustedNamespaces {
		if strings.HasPrefix(modPath, ns) {
			return true
		}
	}
	return false
}

func computeOverallScore(deps []*DependencyScore) int {
	if len(deps) == 0 {
		return 0
	}

	totalWeight := 0.0
	weightedSum := 0.0
	hasVulns := false
	maxVulnScore := 0

	for _, ds := range deps {
		weight := 1.0 + float64(ds.RiskScore)/100.0
		totalWeight += weight
		weightedSum += float64(ds.RiskScore) * weight

		if len(ds.Vulns) > 0 {
			if ds.RiskScore > maxVulnScore {
				maxVulnScore = ds.RiskScore
			}
			// Mirror severityFloor's logic: "required" CVEs are excluded because
			// their code never links into the build. Only "called", "imported", or
			// unset (backward-compat alias for "called") trigger the floor.
			for i := range ds.Vulns {
				if ds.Vulns[i].Reachability != "required" {
					hasVulns = true
					break
				}
			}
		}
	}

	if totalWeight == 0 {
		return 0
	}

	score := int(math.Round(weightedSum / totalWeight))

	// Floor: if any dependency has a known vulnerability, the overall
	// project score should never be below MEDIUM (26). A project with
	// an actionable CVE should not appear as "LOW RISK".
	if hasVulns && score < 26 {
		score = 26
	}

	if score > 100 {
		score = 100
	}
	return score
}

func levelFromScore(score int) RiskLevel {
	switch {
	case score >= 76:
		return RiskCritical
	case score >= 51:
		return RiskHigh
	case score >= 26:
		return RiskMedium
	default:
		return RiskLow
	}
}

// riskLevelOrder returns a numeric ordinal for a RiskLevel, used for comparisons.
// Higher ordinal = higher risk.
func riskLevelOrder(l RiskLevel) int {
	switch l {
	case RiskCritical:
		return 3
	case RiskHigh:
		return 2
	case RiskMedium:
		return 1
	default:
		return 0
	}
}

// severityAdjustedResult is the bundled output of severityAdjustedVulnScore.
type severityAdjustedResult struct {
	score               int
	worstID             string
	worstSeverity       string
	worstSourceSeverity string // raw v.Severity before scoring (may be "UNKNOWN")
	stepInputs          StepFunctionInputs
	enrichedCVEs        []DebugCVE
	perDepInputs        []DebugPerDepInput
	// warnings holds hidden-risk notices (KEV or very-high EPSS on a CVE the
	// downgrades suppressed); the caller appends them to ps.Warnings.
	warnings []string
}

// severityAdjustedVulnScore computes the CVE-driven step-function axis.
//
// Algorithm (Task 10):
//
//  1. For every CVE on every dep, determine its effective tier:
//     - Severity is normalised to one of CRITICAL/HIGH/MEDIUM/LOW.
//     - UNKNOWN severity (either enrichment failed or never attempted) is
//     treated as MEDIUM. The user-facing renderer still shows "UNKNOWN" so
//     data uncertainty stays visible; the step function treats it as MEDIUM
//     because that is the conservative assumption.
//  2. Apply the test-only discount: when the dep's IsTestOnly is &true,
//     downgrade the tier by one notch (CRITICAL→HIGH, HIGH→MEDIUM,
//     MEDIUM→LOW, LOW→dropped). IsTestOnly == nil means classification was
//     unavailable — the discount MUST NOT apply (better to under-discount than
//     to silently absolve a real risk).
//  3. Count post-downgrade tiers across the whole graph.
//  4. Run the step function:
//     - any CRITICAL          → 95
//     - 3+ HIGH               → 85
//     - 1–2 HIGH              → 70
//     - any MEDIUM (no HIGH+) → 40
//     - LOW only              → 10
//     - none                  → 0
//
// The most-severe post-downgrade CVE is returned as worst{ID,Severity}; ties
// resolve in iteration order (deps first, then their vulns).
//
// These weights answer a different question than the per-dep severityWeight
// table — never unify the two.
//
// The `now` argument is forwarded to severityFloor and lowFixAgeFloor when
// building the per-dep debug payload. See ScoreInput.Now.
func severityAdjustedVulnScore(now time.Time, deps []*DependencyScore) severityAdjustedResult {
	res := severityAdjustedResult{}

	// Track the most-severe post-downgrade CVE so far.
	worstRank := -1

	for _, ds := range deps {
		if len(ds.Vulns) == 0 {
			continue
		}

		isTestOnlyConfirmed := ds.IsTestOnly != nil && *ds.IsTestOnly
		// perDepWorstRaw and perDepHighOrAbove feed the debug payload.
		perDepWorstRaw := ""
		perDepHighOrAbove := 0

		for i := range ds.Vulns {
			v := &ds.Vulns[i]
			rawTier := effectiveTier(v)
			if rawTier == "" {
				continue
			}

			// UNKNOWN + confirmed called → treat as HIGH for the step function.
			// Empty reachability stays MEDIUM (unconfirmed ≠ reachable).
			// Mirrors the severityFloor policy for the per-dep axis.
			if strings.EqualFold(v.Severity, "UNKNOWN") && isConfirmedReachable(v) {
				rawTier = "HIGH"
			}

			// Step 1: apply reachability downgrade (rawTier → reachabilityTier).
			// Empty Reachability is treated as "called" (backward compat).
			reachabilityTier, reachDesc := reachabilityDowngrade(rawTier, v.Reachability)

			// Step 2: apply test-only downgrade on top of the reachability tier.
			finalTier := reachabilityTier
			if isTestOnlyConfirmed && finalTier != "" {
				finalTier = downgradeTier(reachabilityTier)
			}

			// Step 3: apply threat-intel adjustment (EPSS amplifier, then KEV
			// override) on top of the downgrades. A downgrade-dropped CVE is
			// NOT resurrected — see adjustTierForThreatIntel.
			finalTier = adjustTierForThreatIntel(finalTier, v)

			// Hidden-risk warnings: static analysis downgraded this CVE, but
			// threat intel says it is being exploited (KEV) or is very likely
			// to be (EPSS >= 0.9). The right answer is human review.
			if wasDowngraded := reachDesc != "" || isTestOnlyConfirmed; wasDowngraded {
				context := v.Reachability
				if isTestOnlyConfirmed {
					context = "test-only"
				}
				switch {
				case v.InKEV:
					res.warnings = append(res.warnings, fmt.Sprintf(
						"KEV CVE %s on dep %s (%s) — confirmed exploited in the wild; verify reachability manually",
						v.ID, ds.Module, context))
				case v.EPSSScore != nil && *v.EPSSScore >= epssManualReviewThreshold:
					res.warnings = append(res.warnings, fmt.Sprintf(
						"high-EPSS CVE %s (%.0f%% exploitation probability) on dep %s (%s) — verify reachability manually",
						v.ID, *v.EPSSScore*100, ds.Module, context))
				}
			}

			// Track raw worst severity on this dep (for debug only).
			if tierRank(rawTier) > tierRank(perDepWorstRaw) {
				perDepWorstRaw = rawTier
			}
			if rawTier == "CRITICAL" || rawTier == "HIGH" {
				perDepHighOrAbove++
			}

			if finalTier == "" {
				// Downgraded (by reachability or test-only) tier drops out of the
				// step function entirely.
				dc := DebugCVE{
					ID:                    v.ID,
					Module:                ds.Module,
					OriginalTier:          rawTier,
					DowngradedTier:        "dropped",
					TestOnly:              ds.IsTestOnly,
					EnrichmentFailed:      v.EnrichmentFailed,
					Reachability:          v.Reachability,
					ReachabilityDowngrade: reachDesc,
					EPSSScore:             v.EPSSScore,
					InKEV:                 v.InKEV,
				}
				res.enrichedCVEs = append(res.enrichedCVEs, dc)
				continue
			}

			switch finalTier {
			case "CRITICAL":
				res.stepInputs.Critical++
			case "HIGH":
				res.stepInputs.High++
			case "MEDIUM":
				res.stepInputs.Medium++
			case "LOW":
				res.stepInputs.Low++
			}

			// Track the worst CVE by post-downgrade tier. This is the
			// load-bearing finding surfaced in WorstCVEID. Tie-breaking
			// within a tier is deterministic: ScoreAll populates
			// ps.Dependencies in lexicographic module-path order, so among
			// same-tier CVEs the one from the alphabetically earliest module
			// (and earliest in that module's Vulns slice) is chosen.
			if rank := tierRank(finalTier); rank > worstRank {
				worstRank = rank
				res.worstID = v.ID
				res.worstSeverity = finalTier
				res.worstSourceSeverity = v.Severity
			}

			dc := DebugCVE{
				ID:                    v.ID,
				Module:                ds.Module,
				OriginalTier:          rawTier,
				TestOnly:              ds.IsTestOnly,
				EnrichmentFailed:      v.EnrichmentFailed,
				Reachability:          v.Reachability,
				ReachabilityDowngrade: reachDesc,
				EPSSScore:             v.EPSSScore,
				InKEV:                 v.InKEV,
			}
			// Populate DowngradedTier when any downgrade (reachability or test-only)
			// changed the effective tier from the raw tier.
			if finalTier != rawTier {
				dc.DowngradedTier = finalTier
			}
			res.enrichedCVEs = append(res.enrichedCVEs, dc)
		}

		if perDepWorstRaw != "" {
			floor, _ := severityFloor(now, ds.Vulns)
			res.perDepInputs = append(res.perDepInputs, DebugPerDepInput{
				Module:           ds.Module,
				WorstSeverity:    perDepWorstRaw,
				HighOrAboveCount: perDepHighOrAbove,
				FloorApplied:     floor,
				FixAgeAmplifier:  lowFixAgeFloor(now, ds.Vulns) > 0,
				FinalVulnScore:   int(math.Round(ds.VulnScore)),
				FinalRiskScore:   ds.RiskScore,
				FinalRiskLevel:   string(ds.RiskLevel),
			})
		}
	}

	res.score = stepFunction(res.stepInputs)
	return res
}

// stepFunction maps post-downgrade severity counts to the project-level score.
func stepFunction(c StepFunctionInputs) int {
	switch {
	case c.Critical > 0:
		return 95
	case c.High >= 3:
		return 85
	case c.High >= 1:
		return 70
	case c.Medium > 0:
		return 40
	case c.Low > 0:
		return 10
	default:
		return 0
	}
}

// effectiveTier normalises a CVE's severity for the step function.
//
// UNKNOWN is treated as MEDIUM as a default. The caller (severityAdjustedVulnScore)
// may further promote UNKNOWN to HIGH when reachability is confirmed "called" —
// see the inline override there. This function handles only the tier vocabulary
// normalisation; reachability-aware escalation is the caller's responsibility.
func effectiveTier(v *scanner.Vulnerability) string {
	switch strings.ToUpper(strings.TrimSpace(v.Severity)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	case "":
		return "MEDIUM"
	default:
		// UNKNOWN and anything not in the tier vocabulary.
		return "MEDIUM"
	}
}

// ScoredSeverity returns the severity tier the scorer assigns to v for display
// and policy purposes. It mirrors the logic in severityAdjustedVulnScore:
// UNKNOWN defaults to MEDIUM unless reachability is confirmed "called", in which
// case it is promoted to HIGH. Known tiers are returned as-is.
//
// Use this instead of v.Severity when rendering scored results — it keeps the
// display and scoring logic in sync without duplicating the policy in reporters.
func ScoredSeverity(v *scanner.Vulnerability) string {
	if strings.EqualFold(v.Severity, "UNKNOWN") || v.Severity == "" {
		if isConfirmedReachable(v) {
			return "HIGH"
		}
		return "MEDIUM"
	}
	return strings.ToUpper(v.Severity)
}

// epssPromoteThreshold is the EPSS score at or above which a CVE's tier is
// promoted one notch. 0.5 means FIRST.org estimates >50% probability of
// exploitation within 30 days — the threshold for "actively dangerous".
const epssPromoteThreshold = 0.5

// epssManualReviewThreshold is the EPSS score at or above which a downgraded
// CVE triggers a "verify reachability manually" warning: static analysis says
// the code path isn't reachable, but the exploitation probability is so high
// that human review is warranted.
const epssManualReviewThreshold = 0.9

// epssVulnScoreWeight scales the per-dep EPSS additive bonus in vulnScore:
// bonus = max_epss_on_dep × 15.
const epssVulnScoreWeight = 15

// promoteTier shifts a tier up by one notch. CRITICAL stays CRITICAL.
func promoteTier(t string) string {
	switch t {
	case "LOW":
		return "MEDIUM"
	case "MEDIUM":
		return "HIGH"
	case "HIGH", "CRITICAL":
		return "CRITICAL"
	default:
		return t
	}
}

// adjustTierForThreatIntel applies the post-downgrade threat-intel rules to a
// CVE's step-function tier:
//
//  1. EPSS amplifier — score >= 0.5 and tier below CRITICAL: promote one tier.
//  2. KEV override   — CVE is in CISA's KEV catalog: force CRITICAL.
//
// Both apply AFTER the reachability and test-only downgrades because those
// encode "this code path isn't reachable in this project" — wild-exploitation
// status doesn't make an unreachable path more vulnerable. For the same
// reason, a downgrade-dropped CVE (tier == "") is NOT resurrected: once the
// downgrades remove a CVE from the step function, EPSS and KEV do not bring
// it back. This is the most counter-intuitive composition case — the
// hidden-risk warnings in severityAdjustedVulnScore surface it for human
// review instead.
func adjustTierForThreatIntel(tier string, v *scanner.Vulnerability) string {
	if tier == "" {
		return ""
	}
	if v.EPSSScore != nil && *v.EPSSScore >= epssPromoteThreshold {
		tier = promoteTier(tier)
	}
	if v.InKEV {
		tier = "CRITICAL"
	}
	return tier
}

// downgradeTier shifts a tier down by one notch. Used for test-only deps.
// LOW returns "" — the CVE drops out of the step function entirely.
func downgradeTier(t string) string {
	switch t {
	case "CRITICAL":
		return "HIGH"
	case "HIGH":
		return "MEDIUM"
	case "MEDIUM":
		return "LOW"
	case "LOW":
		return ""
	default:
		return ""
	}
}

// isConfirmedReachable reports whether v's reachability is explicitly confirmed
// at the "called" level for the purposes of UNKNOWN-severity escalation.
//
// This is intentionally stricter than the weight axis (reachabilityFactor /
// reachabilityDowngrade), which defaults "" to the worst-case factor of 1.0.
// Here "" is treated as unconfirmed — absence of a govulncheck-derived label
// does not imply the function was actually called. The two axes diverge
// deliberately:
//
//   - Weight axis: "" → 1.0 (pessimistic; don't under-weight unknown sources).
//   - Confirmation axis: "" → false (conservative; don't over-escalate severity).
func isConfirmedReachable(v *scanner.Vulnerability) bool {
	return v.Reachability == "called"
}

// reachabilityDowngrade returns the post-downgrade tier for a CVE based on how
// deeply its vulnerable code is reachable in the build graph.
//
// Downgrade table:
//
//	"called" or "" (backward compat) — no change; return tier as-is.
//	"imported"                        — one-tier downgrade (CRITICAL→HIGH, HIGH→MEDIUM, MEDIUM→LOW, LOW→dropped).
//	"required"                        — two-tier downgrade (CRITICAL→MEDIUM, HIGH→LOW, MEDIUM→dropped, LOW→dropped).
//
// Returns "" when the CVE should be dropped from the step function entirely.
// The second return value is a human-readable description of the downgrade
// applied (e.g. "CRITICAL→HIGH (imported)"), or "" when no downgrade occurs.
// This description populates DebugCVE.ReachabilityDowngrade for task-07.
func reachabilityDowngrade(tier, reachability string) (downgradedTier, description string) {
	switch reachability {
	case "imported":
		d := downgradeTier(tier)
		if d != tier {
			if d == "" {
				return "", tier + "→dropped (imported)"
			}
			return d, tier + "→" + d + " (imported)"
		}
		return tier, ""
	case "required":
		// Two-tier downgrade: apply downgradeTier twice.
		d := downgradeTier(downgradeTier(tier))
		if d != tier {
			if d == "" {
				return "", tier + "→dropped (required)"
			}
			return d, tier + "→" + d + " (required)"
		}
		return tier, ""
	default:
		// "called" and "" are treated as called — no downgrade.
		return tier, ""
	}
}

// reachabilityFactor returns the per-CVE weight multiplier for the vulnScore
// function based on how deeply the vulnerable code is reachable in the build.
//
//	"called" or "" (backward compat) → 1.0
//	"imported"                        → 0.7
//	"required"                        → 0.3
//
// Rationale: govulncheck's "required" tier means no package from the module is
// linked into the build at all. Endor Labs research indicates <9.5 % of
// vulnerabilities are actually reachable; ×0.3 keeps the signal visible without
// inflating CI-gate noise.
func reachabilityFactor(reachability string) float64 {
	switch reachability {
	case "imported":
		return 0.7
	case "required":
		return 0.3
	default:
		// "called" and "" treated as called.
		return 1.0
	}
}

// tierRank assigns a numeric ordinal for tier comparisons. Higher = worse.
// Returns -1 for the empty string so "dropped" sorts below any real tier.
func tierRank(t string) int {
	switch t {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return -1
	}
}

// computeDiagnostics returns tail aggregates that the headline intentionally
// drops. NON-NORMATIVE — retained for debugging only.
func computeDiagnostics(deps []*DependencyScore) *Diagnostics {
	if len(deps) == 0 {
		return nil
	}

	maxScore := 0
	for _, ds := range deps {
		if ds.RiskScore > maxScore {
			maxScore = ds.RiskScore
		}
	}

	p95 := p95DepRiskCandidate(deps)

	return &Diagnostics{
		MaxDepRiskScore: maxScore,
		P95DepRiskScore: int(p95.Score),
	}
}

// p95DepRiskCandidate computes the nearest-rank 95th-percentile per-dep RiskScore
// and wraps it as a HeadlineCandidate. The sort operates on a copy of deps so
// the caller's slice order is preserved (order is load-bearing for
// severityAdjustedVulnScore's first-wins tie-break).
func p95DepRiskCandidate(deps []*DependencyScore) HeadlineCandidate {
	if len(deps) == 0 {
		return HeadlineCandidate{Name: "p95_dep_risk"}
	}

	sorted := make([]*DependencyScore, len(deps))
	copy(sorted, deps)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].RiskScore < sorted[j].RiskScore
	})

	// Nearest-rank formula: idx = ceil(0.95 * N) - 1, clamped to [0, N-1].
	idx := int(math.Ceil(0.95*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}

	d := sorted[idx]
	return HeadlineCandidate{
		Name:       "p95_dep_risk",
		Score:      float64(d.RiskScore),
		DrivingDep: d.Module,
		Reason:     "p95 of dep risk scores",
	}
}

// archivedFloor floors the headline to HIGH when any non-test-only dep in the
// graph is archived.
//
// archived → upstream will never patch a future CVE → unbounded latent risk →
// HIGH floor (51); direct dependency escalates to 60.
// "on the import path" approximated as non-test-only in-graph (true call-graph
// reachability is per-CVE only).
// HIGH band starts at 51 (levelFromScore), so all HIGH floors use 51, not 50.
func archivedFloor(deps []*DependencyScore) HeadlineCandidate {
	best := HeadlineCandidate{Name: "archived_floor"}
	var bestDs *DependencyScore

	for _, ds := range deps {
		if ds.IsTestOnly != nil && *ds.IsTestOnly {
			continue
		}
		if ds.Maintenance == nil || !ds.Maintenance.Archived {
			continue
		}

		// HIGH band starts at 51 (levelFromScore), so all HIGH floors use 51, not 50.
		var score float64
		if ds.Direct {
			score = 60
		} else {
			score = 51
		}

		// Primary: higher floor score wins (direct > indirect).
		// Tie-break: higher RiskScore, then longer MonthsSinceRelease.
		better := score > best.Score
		if !better && score == best.Score && bestDs != nil {
			better = ds.RiskScore > bestDs.RiskScore ||
				(ds.RiskScore == bestDs.RiskScore && ds.Maintenance.MonthsSinceRelease > bestDs.Maintenance.MonthsSinceRelease)
		}

		if better {
			reason := "archived"
			if ds.Maintenance.MonthsSinceRelease > 0 {
				reason = fmt.Sprintf("archived %d months", ds.Maintenance.MonthsSinceRelease)
			}
			best.Score = score
			best.DrivingDep = ds.Module
			best.Reason = reason
			bestDs = ds
		}
	}

	return best
}

// cveFloor computes a floor score based on the CVE's reachability tier.
//
// Scoring matrix (reachability × severity):
//
//	called or "" CRITICAL  → 60
//	called or "" HIGH      → 55
//	imported CRITICAL      → 40
//	imported HIGH          → 40
//	required CRITICAL      → 40
//	else                   → 0
//
// Empty reachability is treated as "called" for backward compatibility (mirrors
// reachabilityDowngrade convention).
//
// Design note: in the current scoring model, severityAdjustedVulnScore produces
// values that meet or exceed cveFloor for the same CVE (e.g. called CRITICAL →
// severity_adjusted=95 vs cveFloor=60; required CRITICAL → both give 40 but
// severity_adjusted is first in the candidate slice). cveFloor therefore acts as
// a documented semantic anchor — it makes the scoring contract explicit for each
// reachability tier — and will become load-bearing if severity_adjusted weights
// are adjusted or new reachability tiers are introduced.
func cveFloor(deps []*DependencyScore) HeadlineCandidate {
	// cve_floor scoring: called CRITICAL→60, called HIGH→55,
	// imported CRITICAL/HIGH→40, required CRITICAL→40.
	best := HeadlineCandidate{Name: "cve_floor"}

	for _, ds := range deps {
		if ds.IsTestOnly != nil && *ds.IsTestOnly {
			continue
		}
		for i := range ds.Vulns {
			v := &ds.Vulns[i]
			tier := effectiveTier(v)
			reach := strings.ToLower(strings.TrimSpace(v.Reachability))
			// Empty reachability = "called" (backward compat).
			if reach == "" {
				reach = "called"
			}

			var score float64
			switch {
			case (reach == "called") && tier == "CRITICAL":
				score = 60
			case (reach == "called") && tier == "HIGH":
				score = 55
			case reach == "imported" && tier == "CRITICAL":
				score = 40
			case reach == "imported" && tier == "HIGH":
				score = 40
			case reach == "required" && tier == "CRITICAL":
				score = 40
			default:
				score = 0
			}

			if score > best.Score {
				best.Score = score
				best.DrivingDep = ds.Module
				best.Reason = fmt.Sprintf("%s %s %s", reach, tier, v.ID)
			}
		}
	}

	return best
}

// integrityFloor floors the headline to HIGH when any non-test-only dep in the
// graph carries a HIGH-severity replace directive (a redirect to a different
// module path — see scanner.IntegrityScanner.ScanDirectives), and to CRITICAL
// when `go mod verify` reported a go.sum checksum mismatch (gosumMismatch).
//
// LOW (version-pin) and MEDIUM (local-path) replace classes must never drive
// the headline — only a redirect to a different module signals a possible
// fork hijack or private-mirror compromise. HIGH band starts at 51
// (levelFromScore), so all HIGH floors use 51, not 50; direct dependency
// escalates to 60, mirroring archivedFloor. CRITICAL band starts at 76, so
// the go.sum-mismatch floor is 76 — it always outranks the replace floors.
func integrityFloor(deps []*DependencyScore, gosumMismatch bool) HeadlineCandidate {
	if gosumMismatch {
		return HeadlineCandidate{
			Name:       "integrity_floor",
			Score:      76,
			DrivingDep: "go.sum",
			Reason:     "go mod verify failed — a module in the local cache does not match its go.sum checksum",
		}
	}

	best := HeadlineCandidate{Name: "integrity_floor"}

	for _, ds := range deps {
		if ds.IsTestOnly != nil && *ds.IsTestOnly {
			continue
		}
		if ds.ReplaceClass != scanner.IntegrityHigh {
			continue
		}

		var score float64
		if ds.Direct {
			score = 60
		} else {
			score = 51
		}

		if score > best.Score {
			best.Score = score
			best.DrivingDep = ds.Module
			best.Reason = "replace directive redirects to a different module path"
		}
	}

	return best
}

// selectHeadline returns the HeadlineCandidate with the highest Score.
// Ties resolve in slice order (first wins). Returns zero-value when candidates
// is empty.
func selectHeadline(candidates []HeadlineCandidate) HeadlineCandidate {
	if len(candidates) == 0 {
		return HeadlineCandidate{}
	}
	winner := candidates[0]
	for _, c := range candidates[1:] {
		if c.Score > winner.Score {
			winner = c
		}
	}
	return winner
}

// buildDebugScoring assembles the --debug-scoring payload.
func buildDebugScoring(ps *ProjectScore, sev *severityAdjustedResult) *DebugScoring {
	return &DebugScoring{
		MeanDepRiskScore:          ps.MeanDepRiskScore,
		SeverityAdjustedVulnScore: ps.SeverityAdjustedVulnScore,
		HeadlineDriver:            ps.HeadlineDriver,
		StepFunctionInputs:        sev.stepInputs,
		EnrichedCVEs:              sev.enrichedCVEs,
		PerDepInputs:              sev.perDepInputs,
	}
}
