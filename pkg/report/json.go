package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/unidoc/unisupply/internal/version"
	"github.com/unidoc/unisupply/pkg/grade"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// JSONReport is the top-level JSON output structure.
type JSONReport struct {
	Tool        string      `json:"tool"`
	Version     string      `json:"version"`
	GeneratedAt string      `json:"generated_at"`
	Project     JSONProject `json:"project"`

	// Grade is the published grade (Grading v2): the letter, the row that decides it, every row's score and findings,
	// and Pending when a check the grade needs did not run. null only when grading was not run (a library caller that
	// passes no result); a consumer that gates on the letter MUST treat null and a missing "letter" as "no result".
	Grade *grade.Result `json:"grade"`

	// Deprecated: kept for one release, derived from Grade (see json_deprecated.go). OverallRisk is the worst row's policy
	// value, OverallLevel the coarse band of the letter (UNKNOWN without one) and Headline the deciding row in the old shape.
	OverallRisk      *int         `json:"overall_risk_score,omitempty"`
	OverallLevel     string       `json:"overall_risk_level"`
	Headline         JSONHeadline `json:"headline"`
	DeprecatedFields []string     `json:"deprecated_fields"`

	// Scan is what the vulnerability scan ran with: the platform, the Go release the standard library was matched against,
	// the govulncheck version and the vulnerability database with its last-modified time. Absent when no scan ran.
	Scan *scanner.ScanInfo `json:"scan,omitempty"`

	// Warnings lists data-quality issues encountered during the scan, such as
	// missing GitHub tokens that caused maintainer data to be unavailable.
	Warnings []string `json:"warnings,omitempty"`

	// Notes lists informational messages that do not make the results
	// incomplete, such as go list package errors that leave module
	// classification unaffected. It is absent when there are none.
	Notes   []string         `json:"notes,omitempty"`
	Summary JSONSummary      `json:"summary"`
	Deps    []JSONDependency `json:"dependencies"`

	// StdlibVulns lists vulnerabilities in the Go standard library of the
	// project's toolchain, sorted by advisory ID. They are not part of any
	// dependency's risk score or of the summary counts, and carry no
	// severity_scored because the scorer does not score them. Absent when
	// there are none.
	StdlibVulns []JSONVuln `json:"stdlib_vulnerabilities,omitempty"`

	CI                *JSONCIReport        `json:"ci_cd_assessment,omitempty"`
	CIFindings        []JSONFlatFinding    `json:"ci_findings"`
	BuildFileFindings []JSONFlatFinding    `json:"build_file_findings"`
	Integrity         *JSONIntegrityReport `json:"module_directives,omitempty"`

	// TimeBombs lists every archived dependency and every CRITICAL CVE across
	// all non-test dependencies, regardless of whether the headline score
	// already reflects them. Emitted as an empty array (never null) when none
	// are found.
	TimeBombs []JSONTimeBomb `json:"time_bombs"`
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
	// Deprecated: the number of dependency rows by coarse level, derived from the grade.
	CriticalRiskCount int `json:"critical_risk_count"`
	HighRiskCount     int `json:"high_risk_count"`
	MediumRiskCount   int `json:"medium_risk_count"`
	LowRiskCount      int `json:"low_risk_count"`

	TotalVulns      int `json:"total_vulnerabilities"`
	Unmaintained2yr int `json:"unmaintained_2yr"`
	Unmaintained1yr int `json:"unmaintained_1yr"`
}

// JSONDependency holds per-dependency info.
type JSONDependency struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	Direct  bool   `json:"direct"`
	// Deprecated: the row's policy value and its coarse level, derived from the grade (see json_deprecated.go).
	RiskScore *int   `json:"risk_score,omitempty"`
	RiskLevel string `json:"risk_level"`
	// TestOnly is omitted when nil (classification was unavailable — go list
	// failed or was not run). When present it reflects the main module's own
	// go list -deps ./... and go list -deps -test ./... results: true =
	// confirmed test-only, false = confirmed production. Never infer "false"
	// from absence.
	TestOnly *bool `json:"test_only,omitempty"`
	// InBuild is omitted when nil (classification unavailable or not safe to
	// give). false = confirmed in the module graph only: no package of the
	// module is imported by the main module's code or tests. Never infer
	// "true" from absence.
	InBuild *bool `json:"in_build,omitempty"`
	// Platforms lists the GOOS values on which a production module is built,
	// and is present only when that is a strict subset of the platforms
	// listed (for example a Windows-only import). Absent means all platforms
	// or unknown.
	Platforms      []string         `json:"platforms,omitempty"`
	DependencyPath []string         `json:"dependency_path"`
	Vulns          []JSONVuln       `json:"vulnerabilities,omitempty"`
	Maintenance    *JSONMaintenance `json:"maintenance,omitempty"`
	Maintainer     *JSONMaintainer  `json:"maintainer,omitempty"`
	Typosquat      *JSONTyposquat   `json:"typosquat,omitempty"`
	// ReplaceClass mirrors scorer.DependencyScore.ReplaceClass: the severity of
	// this dependency's go.mod replace directive ("LOW"/"MEDIUM"/"HIGH"), or
	// omitted when the dependency is not replaced.
	ReplaceClass string `json:"replace_class,omitempty"`
	// PseudoVersion mirrors scorer.DependencyScore.PseudoVersion: true when
	// this dependency's pinned go.mod version is a pseudo-version.
	PseudoVersion bool `json:"pseudo_version,omitempty"`
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
	// CallPath is one example of how the project reaches the vulnerable
	// function (outermost frame first). Set only when Reachability is "called".
	// Static-analysis evidence of reachability, not proof of exploitability.
	CallPath []string `json:"call_path,omitempty"`
	// CallTrace is CallPath with a source position per entry, index-aligned
	// with it. A file is relative to its own module's root, so read it together
	// with the frame's module and version. Set only when Reachability is "called".
	CallTrace []scanner.CallFrame `json:"call_trace,omitempty"`
	// CalledSymbols lists every vulnerable symbol found called for this
	// advisory (sorted, capped). Set only when Reachability is "called".
	CalledSymbols []string `json:"called_symbols,omitempty"`
	// SeveritySource is "osv", "nvd", "ghsa", "none" (a lookup failed), or
	// "unscored" (every source consulted answered; none has published a severity).
	// Empty when enrichment was not attempted (severity was known from govulncheck).
	SeveritySource string `json:"severity_source,omitempty"`
	// SeverityAlias is the alias ID (GHSA-* or CVE-*) whose OSV record supplied
	// the severity, when it did not come from the advisory's own ID.
	SeverityAlias string `json:"severity_alias,omitempty"`
	// FixRequiresGo is the `go` directive of the fixed version's go.mod: the Go release the fix needs. Whether that raises the
	// scanned module's minimum Go is in grade.rows[].findings[].response.fix_compat.
	FixRequiresGo string `json:"fix_requires_go,omitempty"`
	// FixReleasedAt is when the first fixed version was released (the later of the advisory's fix date and the module
	// proxy's time for that version); FixDateSource says which ("module_proxy" or "advisory"). Absent = unknown.
	FixReleasedAt *time.Time `json:"fix_released_at,omitempty"`
	FixDateSource string     `json:"fix_date_source,omitempty"`
	// AffectedPackages are the import paths the advisory names; absent = the whole module.
	AffectedPackages []string `json:"affected_packages,omitempty"`
	// Condition is what the project must do to reach the vulnerable code, read from the call path ("reached through ...").
	Condition string `json:"condition,omitempty"`
	// EnrichmentErrors holds the failure summary when all enrichment tiers failed.
	EnrichmentErrors []string `json:"enrichment_errors,omitempty"`
	// EPSSScore is FIRST.org's exploitation probability (0.0–1.0). Absent when
	// the lookup failed or the vuln has no CVE alias; a present 0.0 is a real score.
	EPSSScore *float64 `json:"epss_score,omitempty"`
	// EPSSPercentile is the score's percentile rank against all scored CVEs.
	EPSSPercentile *float64 `json:"epss_percentile,omitempty"`
	// EPSSDate is the date the EPSS score was computed (YYYY-MM-DD).
	EPSSDate string `json:"epss_date,omitempty"`
	// InKEV reports CISA KEV catalog membership. Absent means "not checked"
	// (KEV fetch failed or no CVE alias); false means "checked, not listed".
	InKEV *bool `json:"in_kev,omitempty"`
	// KEVDateAdded is the date CISA added the CVE to the KEV catalog.
	KEVDateAdded string `json:"kev_date_added,omitempty"`
	// KEVRansomware is CISA's knownRansomwareCampaignUse: "Known" | "Unknown".
	KEVRansomware string `json:"kev_known_ransomware,omitempty"`
}

// JSONMaintenance is maintenance health info.
type JSONMaintenance struct {
	LastRelease        string `json:"last_release"`
	MonthsSinceRelease int    `json:"months_since_release"`
	// LastActivity is the commit time of the default branch's head (RFC3339),
	// from the module proxy or, as a fallback, the GitHub commits API; see
	// ActivitySource. Absent when unknown; consumers must not read absence as
	// "no commits". It is not GitHub's pushed_at, which the maintainer object
	// reports as last_commit_date.
	LastActivity string `json:"last_activity,omitempty"`
	// MonthsSinceActivity is omitted together with LastActivity. It is a
	// pointer so a commit this month (0) is still reported.
	MonthsSinceActivity *int `json:"months_since_activity,omitempty"`
	// ActivitySource is "proxy_branch" or "github_commits"; ActivityBranch is
	// the branch whose head was read, when known.
	ActivitySource string `json:"activity_source,omitempty"`
	ActivityBranch string `json:"activity_branch,omitempty"`
	Archived       bool   `json:"archived"`
	Deprecated     bool   `json:"deprecated"`
	// DeprecationMessage is the go.mod `// Deprecated:` notice of the latest
	// version, which usually names the successor.
	DeprecationMessage string `json:"deprecation_message,omitempty"`
	// Retracted is true when the pinned version is retracted by the module's own go.mod; it grades like Deprecated.
	Retracted         bool   `json:"retracted,omitempty"`
	RetractionMessage string `json:"retraction_message,omitempty"`
	// RepositoryURL is the repository the module is published from; ArchivedCheck says whether its archived flag was
	// read ("checked"), could not be read ("failed") or cannot be read for this host ("unsupported"). An unread flag
	// is never reported as "not archived".
	RepositoryURL      string `json:"repository_url,omitempty"`
	ArchivedCheck      string `json:"archived_check,omitempty"`
	RepositoryNotFound bool   `json:"repository_not_found,omitempty"`
}

// JSONMaintainer holds maintainer analysis info.
type JSONMaintainer struct {
	// DataAvailable is false when the GitHub API was unreachable or rate-limited.
	// When false, numeric fields (Stars, BusFactor, etc.) are zero and must not
	// be interpreted as real measurements.
	DataAvailable     bool     `json:"data_available"`
	UnavailableReason string   `json:"unavailable_reason,omitempty"`
	OwnerName         string   `json:"owner_name,omitempty"`
	OwnerLocation     string   `json:"owner_location,omitempty"`
	OwnerCompany      string   `json:"owner_company,omitempty"`
	OwnerURL          string   `json:"owner_url,omitempty"`
	IsOrg             bool     `json:"is_org,omitempty"`
	BusinessModel     string   `json:"business_model,omitempty"`
	License           string   `json:"license,omitempty"`
	ContributorCount  int      `json:"contributor_count,omitempty"`
	TopContributors   []string `json:"top_contributors,omitempty"`
	BusFactor         int      `json:"bus_factor,omitempty"`
	ActivityPattern   string   `json:"activity_pattern,omitempty"`
	LastCommitDate    string   `json:"last_commit_date,omitempty"`
	Stars             *int     `json:"stars,omitempty"`
	Forks             *int     `json:"forks,omitempty"`
	OpenIssues        *int     `json:"open_issues,omitempty"`
	SubDependencies   int      `json:"sub_dependencies,omitempty"`
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

// JSONIntegrityReport holds the go.mod replace/exclude directive audit and
// the go.sum verification outcome.
type JSONIntegrityReport struct {
	ReplaceCount       int `json:"replace_count"`
	ExcludeCount       int `json:"exclude_count"`
	RedirectCount      int `json:"redirect_count"`
	PseudoVersionCount int `json:"pseudo_version_count"`
	// GoSumVerified is the `go mod verify` outcome: "true", "false",
	// "offline", or "skipped" — string-valued so honest-UNKNOWN states are
	// distinguishable from a verified pass/fail. Omitted when verification
	// was never attempted.
	GoSumVerified string                 `json:"gosum_verified,omitempty"`
	Findings      []JSONIntegrityFinding `json:"findings,omitempty"`
}

// JSONIntegrityFinding holds a single go.mod directive finding.
type JSONIntegrityFinding struct {
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Module      string `json:"module"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation"`
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
	// Reachability is the reachability tier for critical_cve entries
	// ("called", "imported", or "required"). Omitted when empty — archived
	// entries never set it, and critical_cve entries omit it when reachability
	// is unknown.
	Reachability string `json:"reachability,omitempty"`
}

// JSONOptions configures JSON output.
type JSONOptions struct {
	GoVersion       string
	CIReport        *scanner.CIReport
	IntegrityReport *scanner.IntegrityReport

	// Grade is the Grading v2 result to publish.
	Grade *grade.Result

	// StdlibVulns are the standard library vulnerabilities, already sorted by
	// the caller. They are reported as given.
	StdlibVulns []scanner.Vulnerability

	// Scan says what the vulnerability scan ran with (platform, Go release, govulncheck version, vulnerability database and
	// its last-modified time, and the age of the CISA catalog when it could not be refreshed). nil when no scan ran.
	Scan *scanner.ScanInfo
}

// toJSONVuln maps a scanned vulnerability to its JSON form. Dependency and
// standard library vulnerabilities share it so the two cannot drift.
func toJSONVuln(v *scanner.Vulnerability) JSONVuln {
	jv := JSONVuln{
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
		CallPath:            v.CallPath,
		CallTrace:           v.CallTrace,
		CalledSymbols:       v.CalledSymbols,
		SeveritySource:      v.SeveritySource,
		SeverityAlias:       v.SeverityAlias,
		FixRequiresGo:       v.FixRequiresGo,
		FixReleasedAt:       v.FixReleasedAt,
		FixDateSource:       v.FixDateSource,
		AffectedPackages:    v.AffectedPackages,
		Condition:           v.Condition,
		EnrichmentErrors:    v.EnrichmentErrors,
		EPSSScore:           v.EPSSScore,
		EPSSPercentile:      v.EPSSPercentile,
		EPSSDate:            v.EPSSDate,
		KEVDateAdded:        v.KEVDateAdded,
		KEVRansomware:       v.KEVRansomware,
	}
	// in_kev is serialized only when the KEV catalog was actually
	// consulted: absent = "not checked", false = "checked, not listed".
	if v.KEVChecked {
		inKEV := v.InKEV
		jv.InKEV = &inKEV
	}
	return jv
}

// WriteJSON generates JSON output.
func WriteJSON(graph *resolver.Graph, ps *scorer.ProjectScore, opts JSONOptions, w io.Writer) error {
	directCount := graph.DirectCount()
	transitiveCount := graph.TransitiveCount()

	crit, high, med, low := deprecatedCounts(opts.Grade)
	headline := deprecatedHeadline(opts.Grade)
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
		Grade:            opts.Grade,
		OverallRisk:      gradeScore(opts.Grade),
		OverallLevel:     headline.Level,
		Headline:         headline,
		DeprecatedFields: deprecatedFields,
		Scan:             opts.Scan,
		Warnings:         publishedWarnings(ps.Warnings),
		Notes:            ps.Notes,
		TimeBombs:        collectJSONTimeBombs(ps),
		Summary: JSONSummary{
			CriticalRiskCount: crit, HighRiskCount: high, MediumRiskCount: med, LowRiskCount: low,
			TotalVulns:      ps.TotalVulns,
			Unmaintained2yr: ps.Unmaintained2yr,
			Unmaintained1yr: ps.Unmaintained1yr,
		},
	}

	rows := deprecatedRows(opts.Grade)
	for _, ds := range ps.Dependencies {
		jd := JSONDependency{
			Module:         ds.Module,
			Version:        ds.Version,
			Direct:         ds.Direct,
			RiskScore:      rowScore(opts.Grade, rows[ds.Module], hasRow(rows, ds.Module)),
			RiskLevel:      deprecatedLevel(rows[ds.Module].Letter),
			TestOnly:       ds.IsTestOnly,
			InBuild:        ds.InBuild,
			Platforms:      ds.Platforms,
			DependencyPath: ds.DependencyPath,
			ReplaceClass:   string(ds.ReplaceClass),
			PseudoVersion:  ds.PseudoVersion,
		}

		for i := range ds.Vulns {
			v := &ds.Vulns[i]
			jv := toJSONVuln(v)
			jd.Vulns = append(jd.Vulns, jv)
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
				DeprecationMessage: ds.Maintenance.DeprecationMessage,

				Retracted:          ds.Maintenance.Retracted,
				RetractionMessage:  ds.Maintenance.RetractionMessage,
				RepositoryURL:      ds.Maintenance.RepositoryURL,
				ArchivedCheck:      ds.Maintenance.ArchivedCheck,
				RepositoryNotFound: ds.Maintenance.RepositoryNotFound,
			}
			if ds.Maintenance.HasActivity() {
				months := ds.Maintenance.MonthsSinceActivity
				jd.Maintenance.LastActivity = ds.Maintenance.LastActivity.Format(time.RFC3339)
				jd.Maintenance.MonthsSinceActivity = &months
				jd.Maintenance.ActivitySource = ds.Maintenance.ActivitySource
				jd.Maintenance.ActivityBranch = ds.Maintenance.ActivityBranch
			}
		}

		if ds.MaintainerInfo != nil {
			mi := ds.MaintainerInfo
			jm := &JSONMaintainer{
				DataAvailable:     mi.DataAvailable,
				UnavailableReason: mi.UnavailableReason,
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

	if len(opts.StdlibVulns) > 0 {
		report.StdlibVulns = make([]JSONVuln, 0, len(opts.StdlibVulns))
		for i := range opts.StdlibVulns {
			jv := toJSONVuln(&opts.StdlibVulns[i])
			report.StdlibVulns = append(report.StdlibVulns, jv)
		}
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

	// Module directives assessment. Always emitted when the scanner ran
	// (opts.IntegrityReport != nil), including zero-finding scans, so
	// consumers can distinguish "no directives" from "scanner not invoked".
	if opts.IntegrityReport != nil {
		integrityJSON := &JSONIntegrityReport{
			ReplaceCount:       opts.IntegrityReport.ReplaceCount,
			ExcludeCount:       opts.IntegrityReport.ExcludeCount,
			RedirectCount:      opts.IntegrityReport.RedirectCount,
			GoSumVerified:      opts.IntegrityReport.GoSumVerified,
			PseudoVersionCount: opts.IntegrityReport.PseudoVersionCount,
		}
		for _, f := range opts.IntegrityReport.Findings {
			integrityJSON.Findings = append(integrityJSON.Findings, JSONIntegrityFinding{
				Category:    f.Category,
				Severity:    string(f.Severity),
				Module:      f.Module,
				Detail:      f.Detail,
				Remediation: f.Remediation,
			})
		}
		report.Integrity = integrityJSON
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}

	return nil
}

// collectJSONTimeBombs maps scorer.CollectTimeBombs output to the JSON report
// type, always returning a non-nil slice so the JSON field serialises as []
// rather than null.
func collectJSONTimeBombs(ps *scorer.ProjectScore) []JSONTimeBomb {
	raw := scorer.CollectTimeBombs(ps)
	out := make([]JSONTimeBomb, len(raw))
	for i, tb := range raw {
		out[i] = JSONTimeBomb{
			Kind:         tb.Kind,
			Module:       tb.Module,
			Detail:       tb.Detail,
			Reachability: tb.Reachability,
		}
	}
	return out
}

// retiredWarningMarkers are phrases the scorer's warnings use for the retired 0-100 risk model (axis weights, score
// comparability). The grade has no such axes, so a warning that carries one of these is not published as written.
var retiredWarningMarkers = []string{"weight excluded", "weight is excluded", "NOT comparable"}

// publishedWarnings returns the scorer's warnings as the report publishes them (text SCAN LIMITATIONS and JSON
// "warnings"). The scorer still writes its own warnings in its retired-model language, and its own tests rely on that,
// so the filter lives here. The rule, decided by text:
//
//   - A warning about data that could not be fetched is kept. If it goes on to explain what the retired model did about
//     it ("; ... weight excluded from those scores", "... NOT comparable to a scan that checked for CVEs"), that
//     trailing clause is cut and the data statement stays, e.g. "vulnerability scan did not run".
//   - "maintainer data unavailable" is kept (only its retired-weight clause is cut): the grade does not read maintainer
//     data, but the strict policy preset (no_single_maintainer) does and skips modules without it, so a report must say
//     the data was missing.
//   - The high-EPSS "verify reachability manually" warning is dropped: EPSS is not an input of the grade. (The KEV one
//     stays: a KEV finding counts in the grade at once.)
//
// The result is de-duplicated and nil when nothing is left.
func publishedWarnings(warnings []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, w := range warnings {
		if strings.HasPrefix(w, "high-EPSS CVE") {
			continue
		}
		cut := -1
		for _, m := range retiredWarningMarkers {
			if i := strings.Index(w, m); i >= 0 && (cut < 0 || i < cut) {
				cut = i
			}
		}
		if cut >= 0 {
			head := w[:cut]
			i := strings.LastIndex(head, "; ")
			if i < 0 {
				continue // nothing but retired-model language
			}
			w = strings.TrimSpace(head[:i])
		}
		if w == "" || seen[w] {
			continue
		}
		seen[w] = true
		out = append(out, w)
	}
	return out
}
