// Package scorer implements the risk scoring algorithm.
package scorer

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

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
)

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
}

// ProjectScore holds the overall project risk assessment.
//
// Task 10 introduces a two-axis headline:
//
//	OverallScore = max(MeanDepRiskScore, SeverityAdjustedVulnScore)
//
// MeanDepRiskScore is the legacy weighted-mean answer to "how risky is this
// portfolio on average?" SeverityAdjustedVulnScore is a CVE-driven step
// function that answers "how bad is the worst-case CVE pile-up?" The headline
// takes the max so a single CRITICAL CVE cannot be diluted by hundreds of
// clean transitives. HeadlineDriver records which axis won.
type ProjectScore struct {
	OverallScore      int                `json:"overall_risk_score"`
	OverallLevel      RiskLevel          `json:"overall_risk_level"`
	Dependencies      []*DependencyScore `json:"dependencies"`
	CriticalRiskCount int                `json:"critical_risk_count"`
	HighRiskCount     int                `json:"high_risk_count"`
	MediumRiskCount   int                `json:"medium_risk_count"`
	LowRiskCount      int                `json:"low_risk_count"`
	TotalVulns        int                `json:"total_vulnerabilities"`
	Unmaintained2yr   int                `json:"unmaintained_2yr"`
	Unmaintained1yr   int                `json:"unmaintained_1yr"`

	// MeanDepRiskScore is the weighted-mean axis (legacy formula). Equal to the
	// pre-Task-10 OverallScore. Use this when you want a portfolio-wide signal
	// that is not dominated by a single dep.
	MeanDepRiskScore int `json:"mean_dep_risk_score"`

	// SeverityAdjustedVulnScore is the CVE-driven step-function axis. Derived
	// from the enriched CVE list with a test-only downgrade-then-step applied
	// before counting. See severityAdjustedVulnScore in risk.go.
	SeverityAdjustedVulnScore int `json:"severity_adjusted_vuln_score"`

	// HeadlineDriver is "mean" or "severity_adjusted" — which axis produced
	// OverallScore. Empty when there are no dependencies.
	HeadlineDriver string `json:"headline_driver,omitempty"`

	// WorstCVEID is the ID of the most-severe enriched CVE on a production-path
	// dep (after test-only downgrade). Surfaces the load-bearing finding at a
	// glance. Empty when no CVEs are present.
	WorstCVEID string `json:"worst_cve_id,omitempty"`

	// WorstCVESeverity is the severity tier (post-downgrade) of WorstCVEID.
	WorstCVESeverity string `json:"worst_cve_severity,omitempty"`

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
	// "required", or "" (empty means backward-compat, treated as "called").
	Reachability string `json:"reachability,omitempty"`
	// ReachabilityDowngrade describes the tier shift applied due to reachability
	// (e.g. "CRITICAL→HIGH (imported)"). Empty when no downgrade was applied.
	ReachabilityDowngrade string `json:"reachability_downgrade,omitempty"`
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

	// Count modules whose maintainer data was unavailable. Used to build a
	// top-level warning so consumers understand the scoring gap.
	maintainerUnavailable := 0

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
	}

	if maintainerUnavailable > 0 {
		ps.Warnings = append(ps.Warnings,
			fmt.Sprintf("GitHub API unauthenticated — maintainer data unavailable for %d module(s); maintainer weight excluded from those scores", maintainerUnavailable),
		)
	}

	// Two-axis headline (Task 10).
	//
	// MeanDepRiskScore is the legacy weighted-mean — answers "how risky is this
	// portfolio on average?" SeverityAdjustedVulnScore is the CVE-driven step
	// function — answers "how bad is the worst-case CVE pile-up?" The headline
	// takes max so a single CRITICAL CVE cannot be diluted by hundreds of clean
	// transitives.
	ps.MeanDepRiskScore = computeOverallScore(ps.Dependencies)

	sevResult := severityAdjustedVulnScore(now, ps.Dependencies)
	ps.SeverityAdjustedVulnScore = sevResult.score
	ps.WorstCVEID = sevResult.worstID
	ps.WorstCVESeverity = sevResult.worstSeverity

	if ps.SeverityAdjustedVulnScore > ps.MeanDepRiskScore {
		ps.OverallScore = ps.SeverityAdjustedVulnScore
		ps.HeadlineDriver = "severity_adjusted"
	} else {
		ps.OverallScore = ps.MeanDepRiskScore
		ps.HeadlineDriver = "mean"
	}
	// HeadlineDriver is meaningless when there are no dependencies (both axes
	// are 0). Clear it once, after the comparison, so the json:omitempty tag
	// produces a clean empty-graph report.
	if len(ps.Dependencies) == 0 {
		ps.HeadlineDriver = ""
	}
	ps.OverallLevel = levelFromScore(ps.OverallScore)

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
	now time.Time,
) *DependencyScore {
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
	resilienceBonus := 0.0
	if resilience != nil && resilience.Score < 30 {
		resilienceBonus = float64(30-resilience.Score) * 0.2 // up to 6 extra points for very low resilience
		ds.RiskFactors = append(ds.RiskFactors, "low_resilience")
	}

	// Weighted total.
	//
	// Normal case: the five weights sum to 1.0 (0.40 + 0.25 + 0.15 + 0.10 + 0.10).
	//
	// Re-normalization: when maintainer data is unavailable (DataAvailable == false),
	// the 0.10 maintainer weight is dropped and the four remaining weights are
	// rescaled by dividing by their sum (0.90) so they still sum to 1.0.
	// NOTE: after re-normalization the five declared WeightMaintainerRisk +
	// remaining weights no longer equal 1.0 — this is intentional and
	// expected; the denominator variable below carries the corrected total.
	weightedBase := ds.VulnScore*WeightVulnerabilities +
		ds.MaintenanceScore*WeightMaintenance +
		ds.DepthScore*WeightDepthRisk +
		ds.MaturityScore*WeightMaturity

	denominator := WeightVulnerabilities + WeightMaintenance + WeightDepthRisk + WeightMaturity

	if maintainerInfo == nil || maintainerInfo.DataAvailable {
		// Maintainer data is present: include its contribution and restore
		// the full denominator so the total weight equals 1.0.
		weightedBase += ds.MaintainerScore * WeightMaintainerRisk
		denominator += WeightMaintainerRisk
	}
	// When maintainerInfo != nil && !maintainerInfo.DataAvailable the
	// maintainer component is silently excluded; denominator stays at 0.90
	// and the division below rescales the remaining four weights to 1.0.

	weighted := weightedBase/denominator +
		typosquatBonus +
		aiGenBonus +
		resilienceBonus

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

	for _, v := range vulns {
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
	}

	// Accumulator: base is the worst CVE; each additional HIGH-or-above adds 5.
	bonus := 0.0
	if highOrAboveCount > 1 {
		bonus = float64(highOrAboveCount-1) * 5
	}

	total := maxWeight + bonus
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
//	CRITICAL or HIGH → 51 (HIGH band)
//	MEDIUM           → 26 (MEDIUM band)
//	LOW              → 0  (no floor; amplifier below may still raise it)
//	UNKNOWN with enrichment failure → 26 (conservative MEDIUM)
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
	hasUnknownFailed := false

	for _, v := range vulns {
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
			// UNKNOWN: conservative if enrichment failed.
			if v.EnrichmentFailed {
				hasUnknownFailed = true
			}
		}
	}

	switch {
	case hasCritical:
		return 51, RiskCritical
	case hasHigh:
		return 51, RiskHigh
	case hasMedium:
		return 26, RiskMedium
	case hasUnknownFailed:
		// We attempted enrichment but could not determine severity.
		// Conservative floor: MEDIUM, because the CVE could be HIGH.
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

	for _, v := range vulns {
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
		return 50 // Single maintainer.
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
			for _, v := range ds.Vulns {
				if v.Reachability != "required" {
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
	score         int
	worstID       string
	worstSeverity string
	stepInputs    StepFunctionInputs
	enrichedCVEs  []DebugCVE
	perDepInputs  []DebugPerDepInput
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

			// Step 1: apply reachability downgrade (rawTier → reachabilityTier).
			// Empty Reachability is treated as "called" (backward compat).
			reachabilityTier, reachDesc := reachabilityDowngrade(rawTier, v.Reachability)

			// Step 2: apply test-only downgrade on top of the reachability tier.
			finalTier := reachabilityTier
			if isTestOnlyConfirmed && finalTier != "" {
				finalTier = downgradeTier(reachabilityTier)
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
			}

			dc := DebugCVE{
				ID:                    v.ID,
				Module:                ds.Module,
				OriginalTier:          rawTier,
				TestOnly:              ds.IsTestOnly,
				EnrichmentFailed:      v.EnrichmentFailed,
				Reachability:          v.Reachability,
				ReachabilityDowngrade: reachDesc,
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
// UNKNOWN is treated as MEDIUM — conservative because the CVE could be HIGH
// or CRITICAL underneath. The user-facing renderer keeps showing "UNKNOWN" so
// data uncertainty stays visible. This collapses both the EnrichmentFailed and
// "scanner never set a tier" cases into MEDIUM, matching the per-dep
// severityFloor() conservative-floor logic.
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

	scores := make([]int, 0, len(deps))
	maxScore := 0
	for _, ds := range deps {
		scores = append(scores, ds.RiskScore)
		if ds.RiskScore > maxScore {
			maxScore = ds.RiskScore
		}
	}

	sort.Ints(scores)
	// Nearest-rank p95: index = ceil(0.95 * N) - 1, clamped to [0, N-1].
	idx := int(math.Ceil(0.95*float64(len(scores)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(scores) {
		idx = len(scores) - 1
	}

	return &Diagnostics{
		MaxDepRiskScore: maxScore,
		P95DepRiskScore: scores[idx],
	}
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
