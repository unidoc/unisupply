// Package report generates output in various formats.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/unidoc/unisupply/internal/version"
	"github.com/unidoc/unisupply/pkg/grade"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// ANSI color codes.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorGreen  = "\033[32m"
	colorOrange = "\033[38;5;208m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// TextOptions configures text output.
type TextOptions struct {
	NoColor         bool
	Verbose         bool
	MinRisk         int
	Writer          io.Writer
	CIReport        *scanner.CIReport
	IntegrityReport *scanner.IntegrityReport
	// Takeovers is ignored: the takeover-candidate list is no longer published.
	//
	// Deprecated: kept only so existing callers compile.
	StdlibVulns []scanner.Vulnerability

	// Grade is the published grade (Grading v2). nil prints "No grade: grading was not run" instead of a grade.
	Grade *grade.Result
}

// WriteText generates the human-readable terminal output.
func WriteText(graph *resolver.Graph, ps *scorer.ProjectScore, opts *TextOptions) error {
	if opts == nil {
		return fmt.Errorf("nil TextOptions provided")
	}

	if opts.Writer == nil {
		return fmt.Errorf("nil TextOptions.Writer provided")
	}

	w := opts.Writer
	c := colorFunc(opts.NoColor)

	// Header.
	fmt.Fprintf(w, "%s\n", c(colorBold, fmt.Sprintf("unisupply v%s — Go Supply Chain Risk Assessment", version.String())))
	fmt.Fprintf(w, "%s\n\n", c(colorDim, "by UniDoc (unidoc.io)"))

	fmt.Fprintf(w, "Project: %s\n", graph.Root)
	directCount := graph.DirectCount()
	transitiveCount := graph.TransitiveCount()
	total := directCount + transitiveCount
	fmt.Fprintf(w, "Dependencies: %d direct, %d transitive (%d total, %d graph edges)\n\n", directCount, transitiveCount, total, graph.TotalEdges())

	writeGradeText(w, c, opts.Grade)

	// TIME-BOMBS: archived deps and CRITICAL CVEs listed unconditionally for
	// undeniable visibility, even when the headline already reflects them.
	if timeBombs := scorer.CollectTimeBombs(ps); len(timeBombs) > 0 {
		fmt.Fprintf(w, "TIME-BOMBS (%d)\n", len(timeBombs))
		for _, line := range wrapWords(timeBombScopeNote, 74) {
			fmt.Fprintf(w, "  %s\n", line)
		}
		for _, tb := range timeBombs {
			fmt.Fprintf(w, "  [%-12s] %s — %s\n", tb.Kind, tb.Module, tb.Detail)
		}
		fmt.Fprintf(w, "\n")
	}

	// Debug scoring block (--debug-scoring). NON-NORMATIVE.
	if ps.DebugScoring != nil {
		writeDebugScoring(w, c, ps.DebugScoring)
	}

	// Dependency listing, worst row first. The letter is the grade row's; the old 0-100 score is not shown.
	rows := gradeRowIndex(opts.Grade)
	sorted := make([]*scorer.DependencyScore, len(ps.Dependencies))
	copy(sorted, ps.Dependencies)
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := rows[sorted[i].Module], rows[sorted[j].Module]
		if ri != nil && rj != nil && ri.Score != rj.Score {
			return ri.Score > rj.Score
		}
		return sorted[i].RiskScore > sorted[j].RiskScore
	})
	var listed []*scorer.DependencyScore
	for _, ds := range sorted {
		if ds.RiskScore < opts.MinRisk {
			continue
		}
		listed = append(listed, ds)
	}
	if len(listed) > 0 {
		fmt.Fprintf(w, "%s\n", c(colorBold, fmt.Sprintf("DEPENDENCIES (%d)", len(listed))))
		fmt.Fprintf(w, "%s\n", strings.Repeat("─", 40))
		shown := 0
		for _, ds := range listed {
			letter := gradeRowLabel(rows[ds.Module])
			detail := opts.Verbose || len(ds.Vulns) > 0 || gradeNeedsDetail(rows[ds.Module])
			if detail {
				shown++
			}
			if !detail && !opts.Verbose {
				continue
			}
			writeDependencyDetail(w, ds, c, letter, true)
		}
		if rest := len(listed) - shown; rest > 0 && !opts.Verbose {
			fmt.Fprintf(w, "%s\n", c(colorDim, fmt.Sprintf("[%d more without vulnerabilities — use --verbose]", rest)))
		}
		fmt.Fprintln(w)
	}

	// CI/CD and build-file sections are always rendered when the scanner was invoked,
	// so reviewers can confirm the scanner ran even when there are no findings.
	if opts.CIReport != nil {
		writeCIReportText(w, opts.CIReport, c)
	}

	// Module directives section — always rendered when the scanner ran, so
	// reviewers can confirm the audit happened even when there are no findings.
	if opts.IntegrityReport != nil {
		writeIntegrityReportText(w, opts.IntegrityReport, c)
	}

	// Stdlib vulnerabilities.
	if len(opts.StdlibVulns) > 0 {
		fmt.Fprintf(w, "\n%s\n", c(colorRed, fmt.Sprintf("STDLIB VULNERABILITIES (%d found)", len(opts.StdlibVulns))))
		fmt.Fprintf(w, "%s\n", c(colorRed, strings.Repeat("─", 40)))
		fmt.Fprintf(w, "%s\n", c(colorDim, "These affect the Go standard library used to build dependencies."))
		for i := range opts.StdlibVulns {
			v := &opts.StdlibVulns[i]
			fmt.Fprintf(w, "  %s %s\n", c(colorRed, v.ID), v.Summary)
			if v.FixedVersion != "" {
				fmt.Fprintf(w, "    %s %s\n", c(colorDim, "Fixed in:"), v.FixedVersion)
			}
			if via := reachedVia(v, callPathSepText); via != "" {
				fmt.Fprintf(w, "    %s %s\n", c(colorDim, "Reached via:"), via)
			}
			if syms := calledSymbolsLine(v); syms != "" {
				fmt.Fprintf(w, "    %s %s\n", c(colorDim, "Vulnerable symbols called:"), syms)
			}
		}
		fmt.Fprintln(w)
	}

	// Alias glossary — the one place CVE and GHSA identifiers appear, now
	// that report lines carry the Go advisory ID alone.
	writeVulnAliasGlossary(w, ps, opts.StdlibVulns, c)

	// Summary.
	fmt.Fprintf(w, "──────────────────────────\n")
	fmt.Fprintf(w, "SUMMARY\n")
	if opts.Grade != nil && len(opts.Grade.Rows) > 0 {
		fmt.Fprintf(w, "  Rows by letter: %s\n", gradeLetterCounts(opts.Grade))
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "  Vulnerabilities found: %d across %d dependencies\n", ps.TotalVulns, countWithVulns(listed))
	fmt.Fprintf(w, "  Unmaintained 1–2yr:    %d dependencies\n", ps.Unmaintained1yr)
	fmt.Fprintf(w, "  Unmaintained  >2yr:    %d dependencies\n", ps.Unmaintained2yr)
	// Scan limitations. Without this block a degraded scan — offline, rate
	// limited, vuln DB unreachable — renders identically to a complete one,
	// and "Vulnerabilities found: 0" reads as a clean bill of health rather
	// than as a scan that never looked. Warnings reached JSON only until now.
	if len(ps.Warnings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "SCAN LIMITATIONS — the results above are incomplete\n")
		for _, warning := range ps.Warnings {
			fmt.Fprintf(w, "  ! %s\n", warning)
		}
	}
	// Notes are informational: they say nothing is missing, so they get their
	// own heading rather than sitting under SCAN LIMITATIONS.
	if len(ps.Notes) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "SCAN NOTES — informational, results unaffected\n")
		for _, note := range ps.Notes {
			fmt.Fprintf(w, "  - %s\n", note)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Report generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "Full report: unisupply -f pdf\n")
	fmt.Fprintf(w, "Learn more: https://security.unidoc.io\n")

	return nil
}

func writeDependencyDetail(w io.Writer, ds *scorer.DependencyScore, c func(string, string) string, letter string, detailed bool) {
	label := "transitive"
	if ds.Direct {
		label = "direct"
	}
	// Append [test-only] when the classification is confirmed. When IsTestOnly
	// is nil (unknown, go list failed) we show nothing — silence is better than
	// a wrong label.
	if ds.IsTestOnly != nil && *ds.IsTestOnly {
		label += ", test-only"
	}
	// Same rule for [outside build]: only when InBuild is confirmed false (a
	// module in the graph that no package of the main module imports); nil
	// shows nothing.
	if ds.InBuild != nil && !*ds.InBuild {
		label += ", outside build"
	}

	fmt.Fprintf(w, "● %s %s  %s  (%s)\n",
		ds.Module, ds.Version,
		c(gradeLetterColor(letter), "Grade: "+letter),
		label)

	if !detailed {
		return
	}

	// Vulnerabilities.
	if len(ds.Vulns) > 0 {
		// Compute per-tier counts. Empty Reachability is treated as "called"
		// for backward compatibility with non-govulncheck CVE sources.
		var nCalled, nImported, nRequired int
		for i := range ds.Vulns {
			switch ds.Vulns[i].Reachability {
			case "imported":
				nImported++
			case "required":
				nRequired++
			default:
				nCalled++ // "called" or ""
			}
		}
		// Emit combined count header only when reachability is mixed; the
		// simple "N vulnerabilities" phrasing is implicit from the bullet list
		// when all are called (avoids noise on the common case).
		if nImported > 0 || nRequired > 0 {
			fmt.Fprintf(w, "  ├─ %s %s\n",
				c(colorDim, "Vulnerabilities:"),
				vulnReachabilityCountHeader(nCalled, nImported, nRequired))
		}
		for i := range ds.Vulns {
			v := &ds.Vulns[i]
			tag := reachabilityTag(v.Reachability)
			displaySev := v.Severity
			if strings.EqualFold(v.Severity, "UNKNOWN") || v.Severity == "" {
				displaySev = "UNKNOWN"
			}
			// Threat-intel badges: EPSS exploitation probability and KEV
			// status. KEV is colored like CRITICAL — confirmed exploitation
			// in the wild.
			ti := ""
			if v.InKEV {
				ti = " " + c(colorRed, "[KEV]")
			}
			fmt.Fprintf(w, "  ├─ ⚠ %s (%s)%s%s\n", v.ID, displaySev, tag, ti)
			if strings.EqualFold(v.Severity, "UNKNOWN") || v.Severity == "" {
				fmt.Fprintf(w, "  │  severity unresolved — treated as MEDIUM (HIGH if reachable)\n")
			}
			if v.FixedVersion != "" {
				fmt.Fprintf(w, "  │  Fix available: %s\n", v.FixedVersion)
			}
			if via := reachedVia(v, callPathSepText); via != "" {
				fmt.Fprintf(w, "  │  Reached via: %s\n", via)
			}
			if syms := calledSymbolsLine(v); syms != "" {
				fmt.Fprintf(w, "  │  Vulnerable symbols called: %s\n", syms)
			}
		}
	}

	// Maintenance info.
	if ds.Maintenance != nil {
		if ds.Maintenance.MonthsSinceRelease > 0 {
			fmt.Fprintf(w, "  ├─ Last release: %d months ago\n", ds.Maintenance.MonthsSinceRelease)
		}
		if ds.Maintenance.HasActivity() {
			fmt.Fprintf(w, "  ├─ Last commit%s: %d months ago\n", branchSuffix(ds.Maintenance.ActivityBranch), ds.Maintenance.MonthsSinceActivity)
		}
		if ds.Maintenance.Archived {
			fmt.Fprintf(w, "  ├─ ⚠ Repository archived\n")
		}
		if ds.Maintenance.Deprecated {
			fmt.Fprintf(w, "  ├─ ⚠ Module deprecated%s\n", deprecationSuffix(ds.Maintenance.DeprecationNotice()))
		}
	}

	// Maintainer info.
	if ds.MaintainerInfo != nil {
		mi := ds.MaintainerInfo

		// Owner identity.
		ownerLine := mi.OwnerName
		if ownerLine == "" {
			ownerLine = mi.Owner
		}
		ownerType := "individual"
		if mi.IsOrg {
			ownerType = "organization"
		}
		if mi.OwnerCompany != "" {
			ownerLine += " (" + mi.OwnerCompany + ")"
		}
		fmt.Fprintf(w, "  ├─ Maintainer: %s [%s]\n", ownerLine, ownerType)

		if mi.OwnerLocation != "" {
			fmt.Fprintf(w, "  ├─ Location: %s\n", mi.OwnerLocation)
		}
		if mi.BusinessModel != "" && mi.BusinessModel != "individual" {
			fmt.Fprintf(w, "  ├─ Business model: %s\n", mi.BusinessModel)
		}
		if mi.License != "" {
			fmt.Fprintf(w, "  ├─ License: %s\n", mi.License)
		}

		// Activity. LastCommitDate is GitHub's pushed_at, which moves on a push
		// to any branch; the scored date is the maintenance "Last commit" line.
		if !mi.LastCommitDate.IsZero() {
			fmt.Fprintf(w, "  ├─ Last push (any branch): %s (%s)\n",
				mi.LastCommitDate.Format("2006-01-02"), mi.ActivityPattern)
		} else if mi.ActivityPattern != "" && mi.ActivityPattern != "unknown" {
			fmt.Fprintf(w, "  ├─ Activity: %s\n", mi.ActivityPattern)
		}

		// Bus factor and contributors.
		if mi.BusFactor > 0 {
			contribStr := fmt.Sprintf("Bus factor: %d / %d contributors", mi.BusFactor, mi.ContributorCount)
			if len(mi.TopContributors) > 0 {
				contribStr += " (top: " + strings.Join(mi.TopContributors, ", ") + ")"
			}
			fmt.Fprintf(w, "  ├─ %s\n", contribStr)
		}

		// Stats.
		fmt.Fprintf(w, "  ├─ Stars: %d | Forks: %d | Open issues: %d\n",
			mi.Stars, mi.Forks, mi.OpenIssues)

		// Sub-dependencies.
		if mi.SubDependencies > 0 {
			fmt.Fprintf(w, "  ├─ Pulls in %d sub-dependencies\n", mi.SubDependencies)
		}
	}

	// Resilience.
	if ds.Resilience != nil && ds.Resilience.TotalReleases > 0 {
		fmt.Fprintf(w, "  ├─ Resilience: %d/100 (%s cadence, %d releases, age %d days)\n",
			ds.Resilience.Score, ds.Resilience.ReleaseCadence, ds.Resilience.TotalReleases, ds.Resilience.ProjectAgeDays)
		if ds.Resilience.HasSecurityPolicy {
			fmt.Fprintf(w, "  │  Has SECURITY.md\n")
		}
	}

	// Typosquatting warning.
	if ds.Typosquat != nil {
		fmt.Fprintf(w, "  ├─ ⚠ Typosquatting risk: similar to %s (confidence: %.0f%%)\n",
			ds.Typosquat.SimilarTo, ds.Typosquat.Confidence*100)
	}

	// Trust Index (from unitrust API).
	if ds.TrustIndex != nil {
		ti := ds.TrustIndex
		trustColor := colorGreen
		if ti.TrustScore < 40 {
			trustColor = colorRed
		} else if ti.TrustScore < 70 {
			trustColor = colorYellow
		}
		fmt.Fprintf(w, "  ├─ %s %s (maint=%d resil=%d sec=%d comm=%d)\n",
			c(colorBold, "Trust Index:"), c(trustColor, fmt.Sprintf("%d/100", ti.TrustScore)),
			ti.MaintainerTrust, ti.ResilienceScore, ti.SecurityScore, ti.CommunityScore)
		if ti.MaintainerVerified {
			fmt.Fprintf(w, "  │  ✓ UniDoc verified maintainer\n")
		}
		if ti.IsUnidocMaintained {
			fmt.Fprintf(w, "  │  ✓ UniDoc maintained\n")
		}
		if ti.StewardshipStatus != "" && ti.StewardshipStatus != "none" {
			fmt.Fprintf(w, "  │  Stewardship: %s\n", ti.StewardshipStatus)
		}
		if ti.SaferAlternative != "" {
			fmt.Fprintf(w, "  │  ⚠ Safer alternative: %s\n", ti.SaferAlternative)
		}
	}

	// Dependency path.
	if len(ds.DependencyPath) > 0 {
		fmt.Fprintf(w, "  └─ Used by: %s\n", strings.Join(ds.DependencyPath, " → "))
	}
}

func writeCIReportText(w io.Writer, ciReport *scanner.CIReport, c func(string, string) string) {
	ciColor := ciRiskColor(ciReport.OverallLevel)

	fmt.Fprintf(w, "\n%s\n", c(colorBold, "CI/CD RISK ASSESSMENT"))
	fmt.Fprintf(w, "%s\n", strings.Repeat("─", 40))
	fmt.Fprintf(w, "CI/CD Risk Score: %s\n",
		c(ciColor, fmt.Sprintf("%d/100 (%s)", ciReport.OverallScore, ciReport.OverallLevel)))
	fmt.Fprintf(w, "  Unpinned actions:    %d\n", ciReport.UnpinnedActions)
	fmt.Fprintf(w, "  Third-party actions: %d\n", ciReport.ThirdPartyActions)
	fmt.Fprintf(w, "  Total findings:      %d\n\n", ciReport.TotalFindings)

	// ## CI/CD section — always rendered so reviewers know the scanner ran.
	fmt.Fprintf(w, "## CI/CD\n")
	ciCount := 0
	for _, wr := range ciReport.Workflows {
		if len(wr.Findings) == 0 {
			continue
		}
		wrColor := ciRiskColor(wr.Level)
		fmt.Fprintf(w, "  %s %s\n", c(colorBold, wr.Name), c(wrColor, fmt.Sprintf("(%d/100)", wr.Score)))
		for _, f := range wr.Findings {
			severity := string(f.Severity)
			sColor := ciRiskColor(f.Severity)
			fmt.Fprintf(w, "    %s %s\n", c(sColor, "["+severity+"]"), f.Description)
			fmt.Fprintf(w, "    %s %s\n", c(colorDim, "  Fix:"), f.Remediation)
			ciCount++
		}
		fmt.Fprintln(w)
	}
	if ciCount == 0 {
		fmt.Fprintf(w, "  No findings\n")
	}
	fmt.Fprintln(w)

	// ## Build files section — always rendered so reviewers know the scanner ran.
	fmt.Fprintf(w, "## Build files\n")
	if len(ciReport.BuildFindings) > 0 {
		for _, f := range ciReport.BuildFindings {
			sColor := ciRiskColor(f.Severity)
			loc := f.File
			if f.Line > 0 {
				loc = fmt.Sprintf("%s:%d", f.File, f.Line)
			}
			fmt.Fprintf(w, "    %s %s (%s)\n", c(sColor, "["+string(f.Severity)+"]"), f.Description, loc)
			fmt.Fprintf(w, "    %s %s\n", c(colorDim, "  Fix:"), f.Remediation)
		}
	} else {
		fmt.Fprintf(w, "  No findings\n")
	}
	fmt.Fprintln(w)
}

func writeIntegrityReportText(w io.Writer, ir *scanner.IntegrityReport, c func(string, string) string) {
	fmt.Fprintf(w, "\n%s\n", c(colorBold, "MODULE DIRECTIVES"))
	fmt.Fprintf(w, "%s\n", strings.Repeat("─", 40))
	fmt.Fprintf(w, "  Replace directives: %d (%d redirect to a different module)\n", ir.ReplaceCount, ir.RedirectCount)
	fmt.Fprintf(w, "  Exclude directives: %d\n", ir.ExcludeCount)
	fmt.Fprintf(w, "  Pseudo-version pins: %d\n", ir.PseudoVersionCount)
	if ir.GoSumVerified != "" {
		fmt.Fprintf(w, "  go.sum verification (go mod verify): %s\n", c(gosumColor(ir.GoSumVerified), gosumLabel(ir.GoSumVerified)))
	}
	fmt.Fprintln(w)

	if len(ir.Findings) == 0 {
		fmt.Fprintf(w, "  No findings\n")
		return
	}

	for _, f := range ir.Findings {
		sColor := integrityRiskColor(f.Severity)
		fmt.Fprintf(w, "  %s %s\n", c(sColor, "["+string(f.Severity)+"]"), f.Detail)
		fmt.Fprintf(w, "    %s %s\n", c(colorDim, "Fix:"), f.Remediation)
	}
	fmt.Fprintln(w)
}

func ciRiskColor(level scanner.CIRiskLevel) string {
	switch level {
	case scanner.CIRiskCritical:
		return colorRed
	case scanner.CIRiskHigh:
		return colorOrange
	case scanner.CIRiskMedium:
		return colorYellow
	default:
		return colorGreen
	}
}

// gosumLabel renders IntegrityReport.GoSumVerified in honest-UNKNOWN style:
// only a confirmed pass says "verified", only a confirmed mismatch says
// "FAILED"; everything else is explicitly not-a-result.
func gosumLabel(state string) string {
	switch state {
	case scanner.GoSumVerifiedTrue:
		return "verified"
	case scanner.GoSumVerifiedFalse:
		return "FAILED — checksum mismatch"
	case scanner.GoSumVerifiedOffline:
		return "UNKNOWN (offline — verification skipped)"
	case scanner.GoSumVerifiedSkipped:
		return "UNKNOWN (skipped — verification could not run to completion)"
	default:
		return state
	}
}

func gosumColor(state string) string {
	switch state {
	case scanner.GoSumVerifiedTrue:
		return colorGreen
	case scanner.GoSumVerifiedFalse:
		return colorRed
	default:
		return colorDim
	}
}

func integrityRiskColor(level scanner.IntegrityRiskLevel) string {
	switch level {
	case scanner.IntegrityCritical:
		return colorRed
	case scanner.IntegrityHigh:
		return colorOrange
	case scanner.IntegrityMedium:
		return colorYellow
	case scanner.IntegrityLow:
		return colorGreen
	default:
		return colorDim
	}
}

func colorFunc(noColor bool) func(string, string) string {
	if noColor {
		return func(_, text string) string { return text }
	}
	return func(color, text string) string {
		return color + text + colorReset
	}
}

func formatCount(count, total int) string {
	if total == 0 {
		return fmt.Sprintf("%3d", count)
	}
	pct := float64(count) / float64(total) * 100
	return fmt.Sprintf("%3d (%4.1f%%)", count, pct)
}

func countWithVulns(deps []*scorer.DependencyScore) int {
	count := 0
	for _, ds := range deps {
		if len(ds.Vulns) > 0 {
			count++
		}
	}
	return count
}

// writeDebugScoring emits the --debug-scoring diagnostic block in text form. It lists the advisories as the scanners
// saw them; the old 0-100 scores are not printed. NON-NORMATIVE: layout may change between releases; do not parse it.
func writeDebugScoring(w io.Writer, c func(string, string) string, d *scorer.DebugScoring) {
	fmt.Fprintf(w, "%s\n", c(colorDim, "── debug_scoring (non-normative) ─────────────────"))
	fmt.Fprintf(w, "  step_function_inputs: CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d\n",
		d.StepFunctionInputs.Critical, d.StepFunctionInputs.High,
		d.StepFunctionInputs.Medium, d.StepFunctionInputs.Low)

	if len(d.EnrichedCVEs) > 0 {
		fmt.Fprintf(w, "  enriched_cves (%d):\n", len(d.EnrichedCVEs))
		for _, cve := range d.EnrichedCVEs {
			testOnly := "?"
			if cve.TestOnly != nil {
				if *cve.TestOnly {
					testOnly = "test_only"
				} else {
					testOnly = "production"
				}
			}
			downgrade := ""
			if cve.DowngradedTier != "" {
				downgrade = fmt.Sprintf(" → %s", cve.DowngradedTier)
			}
			enrich := ""
			if cve.EnrichmentFailed {
				enrich = " [enrichment_failed]"
			} else if cve.SeverityUnscored {
				enrich = " [severity_unpublished]"
			}
			reachInfo := ""
			if cve.Reachability != "" {
				reachInfo = fmt.Sprintf(" reach=%s", cve.Reachability)
			}
			if cve.ReachabilityDowngrade != "" {
				reachInfo += fmt.Sprintf(" (%s)", cve.ReachabilityDowngrade)
			}
			fmt.Fprintf(w, "    %s on %s: %s%s [%s]%s%s\n",
				cve.ID, cve.Module, cve.OriginalTier, downgrade, testOnly, enrich, reachInfo)
		}
	}
	fmt.Fprintf(w, "%s\n\n", c(colorDim, "──────────────────────────────────────────────────"))
}

// reachabilityTag returns the bracket tag to append after a CVE ID for
// non-called reachability levels.  Empty string or "called" both return ""
// (backward-compat: suppress the tag on the common case).
func reachabilityTag(r string) string {
	switch r {
	case "imported", "required":
		return fmt.Sprintf(" [%s]", r)
	default:
		// "" (legacy / non-govulncheck) and "called" are both untagged.
		return ""
	}
}

// timeBombScopeNote says what makes a dependency a time bomb, so an archived
// transitive module is not mistaken for an outdated dependency that an update
// would fix. Shared by the text and PDF reports; the weekly issue renderer
// (.github/scripts/render-scan-report.sh) keeps its own copy, which also
// relates it to the workflow's stale-dependency check.
const timeBombScopeNote = "Any dependency, direct or transitive and not confirmed as test-only or outside the build, that is " +
	"archived upstream or has a CISA KEV-listed or CRITICAL CVE. Updating cannot fix an archived module, because " +
	"upstream has stopped: it has to be replaced or removed. Age alone does not make a time bomb: " +
	"modules with no recent release are counted under Unmaintained."

// branchSuffix renders the branch an activity date was read from, " (main)",
// or "" when the branch is not known.
func branchSuffix(branch string) string {
	if branch == "" {
		return ""
	}
	return " (" + branch + ")"
}

// deprecationSuffix renders a deprecation message as ": <message>", or "" when
// there is none (a deprecation signalled by the proxy carries no message).
func deprecationSuffix(msg string) string {
	if msg == "" {
		return ""
	}
	return ": " + msg
}

// wrapWords splits s into lines of at most width runes, breaking at spaces.
// A single word longer than width gets a line of its own.
func wrapWords(s string, width int) []string {
	var lines []string
	var line strings.Builder
	n := 0 // runes in line
	for _, word := range strings.Fields(s) {
		wn := utf8.RuneCountInString(word)
		if n > 0 && n+1+wn > width {
			lines = append(lines, line.String())
			line.Reset()
			n = 0
		}
		if n > 0 {
			line.WriteByte(' ')
			n++
		}
		line.WriteString(word)
		n += wn
	}
	if n > 0 {
		lines = append(lines, line.String())
	}
	return lines
}

// vulnReachabilityCountHeader builds the "X called, Y imported, Z required"
// summary string for the per-dep vulnerability section header.  Only called
// when at least one of imported or required is > 0.
func vulnReachabilityCountHeader(called, imported, required int) string {
	parts := make([]string, 0, 3)
	if called > 0 {
		parts = append(parts, fmt.Sprintf("%d called", called))
	}
	if imported > 0 {
		parts = append(parts, fmt.Sprintf("%d imported", imported))
	}
	if required > 0 {
		parts = append(parts, fmt.Sprintf("%d required", required))
	}
	return strings.Join(parts, ", ")
}

// vulnAliasEntry pairs a Go advisory ID with the external identifiers it is
// also known by.
type vulnAliasEntry struct {
	ID      string
	Aliases []string
}

// collectVulnAliases gathers the ID → aliases mapping for every advisory in
// the report, deduplicated and sorted by ID.
//
// Aliases equal to the ID are dropped: govulncheck sometimes reports an
// advisory whose only alias is itself, which used to render as the tautology
// "GO-2026-5932 — GO-2026-5932". An advisory left with no aliases is omitted
// entirely — there is nothing to translate.
func collectVulnAliases(ps *scorer.ProjectScore, stdlib []scanner.Vulnerability) []vulnAliasEntry {
	seen := make(map[string]map[string]bool)

	collect := func(v *scanner.Vulnerability) {
		for _, alias := range v.Aliases {
			if alias == "" || alias == v.ID {
				continue
			}
			if seen[v.ID] == nil {
				seen[v.ID] = make(map[string]bool)
			}
			seen[v.ID][alias] = true
		}
	}

	for _, ds := range ps.Dependencies {
		for i := range ds.Vulns {
			collect(&ds.Vulns[i])
		}
	}
	for i := range stdlib {
		collect(&stdlib[i])
	}

	entries := make([]vulnAliasEntry, 0, len(seen))
	for id, aliasSet := range seen {
		aliases := make([]string, 0, len(aliasSet))
		for alias := range aliasSet {
			aliases = append(aliases, alias)
		}
		sort.Strings(aliases)
		entries = append(entries, vulnAliasEntry{ID: id, Aliases: aliases})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries
}

// writeVulnAliasGlossary renders the alias mapping. Report lines identify
// advisories by their Go advisory ID, which is the only identifier
// govulncheck guarantees; this section is where a reader translates one into
// the CVE or GHSA their other tooling keys on. Omitted when no advisory in
// the report has an alias.
func writeVulnAliasGlossary(w io.Writer, ps *scorer.ProjectScore, stdlib []scanner.Vulnerability, c func(string, string) string) {
	entries := collectVulnAliases(ps, stdlib)
	if len(entries) == 0 {
		return
	}

	fmt.Fprintf(w, "\n%s\n", c(colorBold, "VULNERABILITY ID ALIASES"))
	fmt.Fprintf(w, "%s\n", c(colorDim, strings.Repeat("─", 40)))
	fmt.Fprintf(w, "%s\n", c(colorDim, "Report lines use the Go advisory ID; these are the same advisories elsewhere."))
	for _, e := range entries {
		fmt.Fprintf(w, "  %s = %s\n", e.ID, strings.Join(e.Aliases, ", "))
	}
	fmt.Fprintln(w)
}
