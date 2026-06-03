package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/unidoc/unisupply/internal/version"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// JSONReport is the top-level JSON output structure.
type JSONReport struct {
	Tool         string      `json:"tool"`
	Version      string      `json:"version"`
	GeneratedAt  string      `json:"generated_at"`
	Project      JSONProject `json:"project"`
	OverallRisk  int         `json:"overall_risk_score"`
	OverallLevel string      `json:"overall_risk_level"`

	// MeanDepRiskScore is the legacy weighted-mean axis (non-normative; retained
	// for dashboards and trend lines). SeverityAdjustedVulnScore is the
	// CVE-driven step-function axis. HeadlineDriver records which of the four
	// candidates produced overall_risk_score: "severity_adjusted", "p95_dep_risk",
	// "archived_floor", or "cve_floor".
	MeanDepRiskScore          int    `json:"mean_dep_risk_score"`
	SeverityAdjustedVulnScore int    `json:"severity_adjusted_vuln_score"`
	HeadlineDriver            string `json:"headline_driver,omitempty"`

	// Headline is the structured headline risk summary. It duplicates
	// OverallRisk/OverallLevel for convenience and adds driver attribution.
	// Backwards-compatible addition — existing consumers may ignore this field.
	Headline JSONHeadline `json:"headline"`

	// WorstCVEID + WorstCVESeverity surface the load-bearing CVE that drove the
	// headline (post test-only downgrade). Empty when no CVEs are present.
	WorstCVEID       string `json:"worst_cve_id,omitempty"`
	WorstCVESeverity string `json:"worst_cve_severity,omitempty"`

	// Diagnostics carries tail aggregates retained for debugging.
	// NON-NORMATIVE: downstream consumers must not build policy gates on this
	// field. Shape may evolve between releases.
	Diagnostics *JSONDiagnostics `json:"diagnostics,omitempty"`

	// DebugScoring is emitted only when --debug-scoring is set. NON-NORMATIVE:
	// schema is internal and may change between releases.
	DebugScoring *scorer.DebugScoring `json:"debug_scoring,omitempty"`

	// Warnings lists data-quality issues encountered during the scan, such as
	// missing GitHub tokens that caused maintainer data to be unavailable.
	Warnings          []string          `json:"warnings,omitempty"`
	Summary           JSONSummary       `json:"summary"`
	Deps              []JSONDependency  `json:"dependencies"`
	CI                *JSONCIReport     `json:"ci_cd_assessment,omitempty"`
	CIFindings        []JSONFlatFinding `json:"ci_findings"`
	BuildFileFindings []JSONFlatFinding `json:"build_file_findings"`
	Takeovers         []JSONTakeover    `json:"takeover_candidates,omitempty"`

	// TimeBombs lists every archived dependency and every CRITICAL CVE across
	// all non-test dependencies, regardless of whether the headline score
	// already reflects them. Emitted as an empty array (never null) when none
	// are found.
	TimeBombs []JSONTimeBomb `json:"time_bombs"`
}

// JSONDiagnostics mirrors scorer.Diagnostics in the JSON output. NON-NORMATIVE:
// downstream consumers must not build policy gates on these fields.
type JSONDiagnostics struct {
	MaxDepRiskScore int `json:"max_dep_risk_score"`
	P95DepRiskScore int `json:"p95_dep_risk_score"`
}

// JSONFlatFinding is a normalized top-level finding entry for CI/CD and build-file
// scan results. It uses a stable shape that consumers can rely on across versions.
//
// Security note (CWE-116): rule_id MUST be sourced from the CI scanner's internal
// rule vocabulary (scanner.CIFinding.Category). It must never be read from scanned
// workflow or Dockerfile content — a crafted description in a scanned file must not
// be able to inject rule IDs into the report output.
type JSONFlatFinding struct {
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Severity string `json:"severity"`
	RuleID   string `json:"rule_id"`
	Message  string `json:"message"`
}

// JSONProject holds project-level info.
type JSONProject struct {
	Module     string `json:"module"`
	GoVersion  string `json:"go_version"`
	DirectDeps int    `json:"direct_dependencies"`
	TransDeps  int    `json:"transitive_dependencies"`
	TotalDeps  int    `json:"total_dependencies"`
}

// JSONSummary holds summary statistics.
type JSONSummary struct {
	CriticalRiskCount int `json:"critical_risk_count"`
	HighRiskCount     int `json:"high_risk_count"`
	MediumRiskCount   int `json:"medium_risk_count"`
	LowRiskCount      int `json:"low_risk_count"`
	TotalVulns        int `json:"total_vulnerabilities"`
	Unmaintained2yr   int `json:"unmaintained_2yr"`
	Unmaintained1yr   int `json:"unmaintained_1yr"`
}

// JSONDependency holds per-dependency info.
type JSONDependency struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	Direct  bool   `json:"direct"`
	// TestOnly is omitted when nil (classification was unavailable — go list
	// failed or was not run). When present it reflects the authoritative
	// go list -m -json -test result: true = confirmed test-only,
	// false = confirmed production. Never infer "false" from absence.
	TestOnly       *bool               `json:"test_only,omitempty"`
	RiskScore      int                 `json:"risk_score"`
	RiskLevel      string              `json:"risk_level"`
	ScoreBreakdown *JSONScoreBreakdown `json:"score_breakdown"`
	DependencyPath []string            `json:"dependency_path"`
	Vulns          []JSONVuln          `json:"vulnerabilities,omitempty"`
	Maintenance    *JSONMaintenance    `json:"maintenance,omitempty"`
	Maintainer     *JSONMaintainer     `json:"maintainer,omitempty"`
	Typosquat      *JSONTyposquat      `json:"typosquat,omitempty"`
	RiskFactors    []string            `json:"risk_factors,omitempty"`
}

// JSONVuln is a vulnerability entry.
// Reachability reflects the govulncheck reachability tier: "called",
// "imported", "required", or absent (absent means backward-compat "called").
type JSONVuln struct {
	ID                  string     `json:"id"`
	Aliases             []string   `json:"aliases"`
	Summary             string     `json:"summary"`
	Severity            string     `json:"severity"`
	FixedVersion        string     `json:"fixed_version,omitempty"`
	EnrichmentAttempted bool       `json:"enrichment_attempted,omitempty"`
	EnrichmentFailed    bool       `json:"enrichment_failed,omitempty"`
	PublishedAt         *time.Time `json:"published_at,omitempty"`
	FixPublishedAt      *time.Time `json:"fix_published_at,omitempty"`
	DaysUnpatched       int        `json:"days_unpatched,omitempty"`
	Reachability        string     `json:"reachability,omitempty"`
	// SeveritySource is "osv", "nvd", "ghsa", or "none" (all tiers failed).
	// Empty when enrichment was not attempted (severity was known from govulncheck).
	SeveritySource string `json:"severity_source,omitempty"`
	// SeverityScored is the tier the scorer assigns: UNKNOWN is promoted to
	// MEDIUM by default, or HIGH when reachability is confirmed "called".
	SeverityScored string `json:"severity_scored,omitempty"`
	// EnrichmentErrors holds the failure summary when all enrichment tiers failed.
	EnrichmentErrors []string `json:"enrichment_errors,omitempty"`
}

// JSONMaintenance is maintenance health info.
type JSONMaintenance struct {
	LastRelease        string `json:"last_release"`
	MonthsSinceRelease int    `json:"months_since_release"`
	Archived           bool   `json:"archived"`
	Deprecated         bool   `json:"deprecated"`
}

// JSONMaintainer holds maintainer analysis info.
type JSONMaintainer struct {
	// DataAvailable is false when the GitHub API was unreachable or rate-limited.
	// When false, numeric fields (Stars, BusFactor, etc.) are zero and must not
	// be interpreted as real measurements.
	DataAvailable    bool     `json:"data_available"`
	OwnerName        string   `json:"owner_name,omitempty"`
	OwnerLocation    string   `json:"owner_location,omitempty"`
	OwnerCompany     string   `json:"owner_company,omitempty"`
	OwnerURL         string   `json:"owner_url,omitempty"`
	IsOrg            bool     `json:"is_org,omitempty"`
	BusinessModel    string   `json:"business_model,omitempty"`
	License          string   `json:"license,omitempty"`
	ContributorCount int      `json:"contributor_count,omitempty"`
	TopContributors  []string `json:"top_contributors,omitempty"`
	BusFactor        int      `json:"bus_factor,omitempty"`
	ActivityPattern  string   `json:"activity_pattern,omitempty"`
	LastCommitDate   string   `json:"last_commit_date,omitempty"`
	Stars            *int     `json:"stars,omitempty"`
	Forks            *int     `json:"forks,omitempty"`
	OpenIssues       *int     `json:"open_issues,omitempty"`
	SubDependencies  int      `json:"sub_dependencies,omitempty"`
}

// JSONScoreBreakdown shows how the risk score was computed.
type JSONScoreBreakdown struct {
	VulnScore        float64 `json:"vuln_score"`
	MaintenanceScore float64 `json:"maintenance_score"`
	DepthScore       float64 `json:"depth_score"`
	MaintainerScore  float64 `json:"maintainer_score"`
	MaturityScore    float64 `json:"maturity_score"`
}

// JSONTyposquat holds typosquatting analysis.
type JSONTyposquat struct {
	SimilarTo      string                 `json:"similar_to"`
	Confidence     float64                `json:"confidence"`
	Indicators     []string               `json:"indicators"`
	SuspectMatches []JSONTyposquatSuspect `json:"suspect_matches,omitempty"`
}

// JSONTyposquatSuspect holds a low-confidence typosquatting match for debuggability.
type JSONTyposquatSuspect struct {
	SimilarTo  string   `json:"similar_to"`
	Confidence float64  `json:"confidence"`
	Indicators []string `json:"indicators"`
}

// JSONCIReport holds CI/CD risk assessment.
type JSONCIReport struct {
	OverallScore      int              `json:"overall_score"`
	OverallLevel      string           `json:"overall_level"`
	UnpinnedActions   int              `json:"unpinned_actions"`
	ThirdPartyActions int              `json:"third_party_actions"`
	TotalFindings     int              `json:"total_findings"`
	Workflows         []JSONCIWorkflow `json:"workflows,omitempty"`
	BuildFindings     []JSONCIFinding  `json:"build_findings,omitempty"`
}

// JSONCIWorkflow holds per-workflow CI risk.
type JSONCIWorkflow struct {
	Name     string          `json:"name"`
	FilePath string          `json:"file_path"`
	Score    int             `json:"score"`
	Level    string          `json:"level"`
	Findings []JSONCIFinding `json:"findings"`
}

// JSONCIFinding holds a single CI/CD finding.
type JSONCIFinding struct {
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	File        string `json:"file"`
	Line        int    `json:"line,omitempty"`
	Remediation string `json:"remediation"`
}

// JSONHeadline holds the project-level headline risk summary, including which
// scoring candidate drove the overall score and its key driving dependency.
type JSONHeadline struct {
	Score       float64 `json:"score"`
	Level       string  `json:"level"`
	Driver      string  `json:"driver"`
	DrivingItem string  `json:"driving_item,omitempty"`
	Reason      string  `json:"reason,omitempty"`
	// Candidates contains the winning candidate only. All four candidate scores
	// will be included here once ProjectScore stores them all; for now use
	// Driver/DrivingItem/Reason for the headline and per-dep data for the rest.
	Candidates []JSONCandidate `json:"candidates"`
}

// JSONCandidate represents a single scoring candidate evaluated during headline
// score selection.
type JSONCandidate struct {
	Name       string  `json:"name"`
	Score      float64 `json:"score"`
	DrivingDep string  `json:"driving_dep,omitempty"`
	Reason     string  `json:"reason,omitempty"`
}

// JSONTimeBomb represents a dependency with an immediate, undeniable risk
// (archived or CRITICAL CVE). Entries are emitted even when the headline score
// already accounts for them — the goal is undeniable visibility.
type JSONTimeBomb struct {
	// Kind is one of "archived" or "critical_cve".
	Kind string `json:"kind"`
	// Module is the module path of the affected dependency.
	Module string `json:"module"`
	// Detail is a human-readable description (e.g. "archived 129 months" or
	// "GO-2024-1234 (CRITICAL, called)").
	Detail string `json:"detail"`
}

// JSONTakeover holds a takeover candidate.
type JSONTakeover struct {
	Owner           string `json:"owner"`
	Repo            string `json:"repo"`
	Stars           int    `json:"stars"`
	BusFactor       int    `json:"bus_factor"`
	ActivityPattern string `json:"activity_pattern"`
	Reason          string `json:"reason"`
}

// JSONOptions configures JSON output.
type JSONOptions struct {
	GoVersion string
	CIReport  *scanner.CIReport
	Takeovers []*scanner.MaintainerInfo
}

// WriteJSON generates JSON output.
func WriteJSON(graph *resolver.Graph, ps *scorer.ProjectScore, opts JSONOptions, w io.Writer) error {
	directCount := graph.DirectCount()
	transitiveCount := graph.TransitiveCount()

	report := JSONReport{
		Tool:        "unisupply",
		Version:     version.Version,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Project: JSONProject{
			Module:     graph.Root,
			GoVersion:  opts.GoVersion,
			DirectDeps: directCount,
			TransDeps:  transitiveCount,
			TotalDeps:  directCount + transitiveCount,
		},
		OverallRisk:               ps.OverallScore,
		OverallLevel:              string(ps.OverallLevel),
		Headline:                  jsonHeadline(ps),
		MeanDepRiskScore:          ps.MeanDepRiskScore,
		SeverityAdjustedVulnScore: ps.SeverityAdjustedVulnScore,
		HeadlineDriver:            ps.HeadlineDriver,
		WorstCVEID:                ps.WorstCVEID,
		WorstCVESeverity:          ps.WorstCVESeverity,
		DebugScoring:              ps.DebugScoring,
		Diagnostics:               jsonDiagnostics(ps.Diagnostics),
		Warnings:                  ps.Warnings,
		TimeBombs:                 collectJSONTimeBombs(ps),
		Summary: JSONSummary{
			CriticalRiskCount: ps.CriticalRiskCount,
			HighRiskCount:     ps.HighRiskCount,
			MediumRiskCount:   ps.MediumRiskCount,
			LowRiskCount:      ps.LowRiskCount,
			TotalVulns:        ps.TotalVulns,
			Unmaintained2yr:   ps.Unmaintained2yr,
			Unmaintained1yr:   ps.Unmaintained1yr,
		},
	}

	for _, ds := range ps.Dependencies {
		jd := JSONDependency{
			Module:    ds.Module,
			Version:   ds.Version,
			Direct:    ds.Direct,
			TestOnly:  ds.IsTestOnly,
			RiskScore: ds.RiskScore,
			RiskLevel: string(ds.RiskLevel),
			ScoreBreakdown: &JSONScoreBreakdown{
				VulnScore:        ds.VulnScore,
				MaintenanceScore: ds.MaintenanceScore,
				DepthScore:       ds.DepthScore,
				MaintainerScore:  ds.MaintainerScore,
				MaturityScore:    ds.MaturityScore,
			},
			DependencyPath: ds.DependencyPath,
			RiskFactors:    ds.RiskFactors,
		}

		for _, v := range ds.Vulns {
			jd.Vulns = append(jd.Vulns, JSONVuln{
				ID:                  v.ID,
				Aliases:             v.Aliases,
				Summary:             v.Summary,
				Severity:            v.Severity,
				FixedVersion:        v.FixedVersion,
				EnrichmentAttempted: v.EnrichmentAttempted,
				EnrichmentFailed:    v.EnrichmentFailed,
				PublishedAt:         v.PublishedAt,
				FixPublishedAt:      v.FixPublishedAt,
				DaysUnpatched:       v.DaysUnpatched,
				Reachability:        v.Reachability,
				SeveritySource:      v.SeveritySource,
				SeverityScored:      scorer.ScoredSeverity(v),
				EnrichmentErrors:    v.EnrichmentErrors,
			})
		}

		if ds.Maintenance != nil {
			lastRelease := ""
			if !ds.Maintenance.LastRelease.IsZero() {
				lastRelease = ds.Maintenance.LastRelease.Format(time.RFC3339)
			}
			jd.Maintenance = &JSONMaintenance{
				LastRelease:        lastRelease,
				MonthsSinceRelease: ds.Maintenance.MonthsSinceRelease,
				Archived:           ds.Maintenance.Archived,
				Deprecated:         ds.Maintenance.Deprecated,
			}
		}

		if ds.MaintainerInfo != nil {
			mi := ds.MaintainerInfo
			jm := &JSONMaintainer{
				DataAvailable: mi.DataAvailable,
			}
			// Only populate measurement fields when the API call succeeded.
			// When DataAvailable is false the GitHub API was unreachable or
			// rate-limited; zero-valued measurements must not appear in output
			// because they would be indistinguishable from real zeros.
			if mi.DataAvailable {
				lastCommit := ""
				if !mi.LastCommitDate.IsZero() {
					lastCommit = mi.LastCommitDate.Format(time.RFC3339)
				}
				stars := mi.Stars
				forks := mi.Forks
				openIssues := mi.OpenIssues
				jm.OwnerName = mi.OwnerName
				jm.OwnerLocation = mi.OwnerLocation
				jm.OwnerCompany = mi.OwnerCompany
				jm.OwnerURL = mi.OwnerURL
				jm.IsOrg = mi.IsOrg
				jm.BusinessModel = mi.BusinessModel
				jm.License = mi.License
				jm.ContributorCount = mi.ContributorCount
				jm.TopContributors = mi.TopContributors
				jm.BusFactor = mi.BusFactor
				jm.ActivityPattern = mi.ActivityPattern
				jm.LastCommitDate = lastCommit
				jm.Stars = &stars
				jm.Forks = &forks
				jm.OpenIssues = &openIssues
				jm.SubDependencies = mi.SubDependencies
			}
			jd.Maintainer = jm
		}

		if ds.Typosquat != nil {
			jt := &JSONTyposquat{
				SimilarTo:  ds.Typosquat.SimilarTo,
				Confidence: ds.Typosquat.Confidence,
				Indicators: ds.Typosquat.Indicators,
			}
			// Add suspect matches if present (for JSON-only debuggability).
			for _, suspect := range ds.Typosquat.SuspectMatches {
				jt.SuspectMatches = append(jt.SuspectMatches, JSONTyposquatSuspect{
					SimilarTo:  suspect.SimilarTo,
					Confidence: suspect.Confidence,
					Indicators: suspect.Indicators,
				})
			}
			jd.Typosquat = jt
		}

		report.Deps = append(report.Deps, jd)
	}

	// CI/CD assessment. When the scanner ran (opts.CIReport != nil) we emit the
	// assessment object and the top-level flat-finding arrays — even with zero
	// findings, so consumers see counts/scores of 0 and empty `[]` arrays. When
	// the scanner did not run, ci_cd_assessment is omitted and the flat arrays
	// stay nil (serialize as null/absent), so "scanner ran with no findings" is
	// distinguishable from "scanner was not invoked".
	if opts.CIReport != nil {
		report.CIFindings = []JSONFlatFinding{}
		report.BuildFileFindings = []JSONFlatFinding{}

		ciJSON := &JSONCIReport{
			OverallScore:      opts.CIReport.OverallScore,
			OverallLevel:      string(opts.CIReport.OverallLevel),
			UnpinnedActions:   opts.CIReport.UnpinnedActions,
			ThirdPartyActions: opts.CIReport.ThirdPartyActions,
			TotalFindings:     opts.CIReport.TotalFindings,
		}

		for _, wr := range opts.CIReport.Workflows {
			jw := JSONCIWorkflow{
				Name:     wr.Name,
				FilePath: wr.FilePath,
				Score:    wr.Score,
				Level:    string(wr.Level),
			}
			for _, f := range wr.Findings {
				jw.Findings = append(jw.Findings, JSONCIFinding{
					Category:    f.Category,
					Severity:    string(f.Severity),
					Description: f.Description,
					File:        f.File,
					Line:        f.Line,
					Remediation: f.Remediation,
				})
				// Populate the top-level flat list for easy machine consumption.
				// rule_id is taken from f.Category which is the scanner's internal
				// vocabulary — see JSONFlatFinding for the CWE-116 security note.
				report.CIFindings = append(report.CIFindings, JSONFlatFinding{
					File:     f.File,
					Line:     f.Line,
					Severity: string(f.Severity),
					RuleID:   f.Category,
					Message:  f.Description,
				})
			}
			ciJSON.Workflows = append(ciJSON.Workflows, jw)
		}

		for _, f := range opts.CIReport.BuildFindings {
			ciJSON.BuildFindings = append(ciJSON.BuildFindings, JSONCIFinding{
				Category:    f.Category,
				Severity:    string(f.Severity),
				Description: f.Description,
				File:        f.File,
				Line:        f.Line,
				Remediation: f.Remediation,
			})
			// Populate the top-level flat list for easy machine consumption.
			// rule_id is taken from f.Category which is the scanner's internal
			// vocabulary — see JSONFlatFinding for the CWE-116 security note.
			report.BuildFileFindings = append(report.BuildFileFindings, JSONFlatFinding{
				File:     f.File,
				Line:     f.Line,
				Severity: string(f.Severity),
				RuleID:   f.Category,
				Message:  f.Description,
			})
		}

		report.CI = ciJSON
	}

	// Takeover candidates.
	for _, t := range opts.Takeovers {
		report.Takeovers = append(report.Takeovers, JSONTakeover{
			Owner:           t.Owner,
			Repo:            t.Repo,
			Stars:           t.Stars,
			BusFactor:       t.BusFactor,
			ActivityPattern: t.ActivityPattern,
			Reason:          t.TakeoverReason,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}

	return nil
}

// jsonDiagnostics maps the scorer's Diagnostics struct to its JSON form.
// Returns nil when the source is nil so the JSON field is omitted.
// collectJSONTimeBombs maps scorer.CollectTimeBombs output to the JSON report
// type, always returning a non-nil slice so the JSON field serialises as []
// rather than null.
func collectJSONTimeBombs(ps *scorer.ProjectScore) []JSONTimeBomb {
	raw := scorer.CollectTimeBombs(ps)
	out := make([]JSONTimeBomb, len(raw))
	for i, tb := range raw {
		out[i] = JSONTimeBomb{
			Kind:   tb.Kind,
			Module: tb.Module,
			Detail: tb.Detail,
		}
	}
	return out
}

// jsonHeadline builds JSONHeadline from ProjectScore. When HeadlineCandidate is
// nil (empty-graph scan), driver and candidates are left empty.
func jsonHeadline(ps *scorer.ProjectScore) JSONHeadline {
	h := JSONHeadline{
		Score:      float64(ps.OverallScore),
		Level:      string(ps.OverallLevel),
		Candidates: []JSONCandidate{},
	}
	if ps.HeadlineCandidate != nil {
		hc := ps.HeadlineCandidate
		h.Driver = hc.Name
		h.DrivingItem = hc.DrivingDep
		h.Reason = hc.Reason
		h.Candidates = []JSONCandidate{{
			Name:       hc.Name,
			Score:      hc.Score,
			DrivingDep: hc.DrivingDep,
			Reason:     hc.Reason,
		}}
	}
	return h
}

func jsonDiagnostics(d *scorer.Diagnostics) *JSONDiagnostics {
	if d == nil {
		return nil
	}
	return &JSONDiagnostics{
		MaxDepRiskScore: d.MaxDepRiskScore,
		P95DepRiskScore: d.P95DepRiskScore,
	}
}
