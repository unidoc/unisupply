// Package report generates output in various formats.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/unidoc/unisupply/internal/version"
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
	NoColor     bool
	Verbose     bool
	MinRisk     int
	Writer      io.Writer
	CIReport    *scanner.CIReport
	Takeovers   []*scanner.MaintainerInfo
	StdlibVulns []scanner.Vulnerability
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

	// Overall score (two-axis headline).
	scoreColor := riskColor(ps.OverallLevel)
	fmt.Fprintf(w, "═══════════════════════════════════════════════════\n")
	fmt.Fprintf(w, "SUPPLY-CHAIN RISK: %s\n",
		c(scoreColor, fmt.Sprintf("%d/100 (%s)", ps.OverallScore, ps.OverallLevel)))
	if ps.HeadlineCandidate != nil {
		hc := ps.HeadlineCandidate
		if hc.DrivingDep != "" && hc.Reason != "" {
			fmt.Fprintf(w, "  Driver: %s — %s (%s)\n", hc.Name, hc.DrivingDep, hc.Reason)
		} else {
			fmt.Fprintf(w, "  Driver: %s\n", hc.Name)
		}
	}
	if ps.WorstCVEID != "" {
		if ps.WorstCVESourceSeverity != "" && !strings.EqualFold(ps.WorstCVESourceSeverity, ps.WorstCVESeverity) {
			fmt.Fprintf(w, "  Worst CVE: %s (scored %s, source %s)\n",
				ps.WorstCVEID, ps.WorstCVESeverity, ps.WorstCVESourceSeverity)
		} else {
			fmt.Fprintf(w, "  Worst CVE: %s (%s)\n", ps.WorstCVEID, ps.WorstCVESeverity)
		}
	}
	fmt.Fprintf(w, "%s\n", overallExplanation(ps.OverallScore, ps.OverallLevel))
	fmt.Fprintf(w, "═══════════════════════════════════════════════════\n\n")

	// TIME-BOMBS: archived deps and CRITICAL CVEs listed unconditionally for
	// undeniable visibility, even when the headline already reflects them.
	if timeBombs := scorer.CollectTimeBombs(ps); len(timeBombs) > 0 {
		fmt.Fprintf(w, "TIME-BOMBS (%d)\n", len(timeBombs))
		for _, tb := range timeBombs {
			fmt.Fprintf(w, "  [%-12s] %s — %s\n", tb.Kind, tb.Module, tb.Detail)
		}
		fmt.Fprintf(w, "\n")
	}

	// Debug scoring block (--debug-scoring). NON-NORMATIVE.
	if ps.DebugScoring != nil {
		writeDebugScoring(w, c, ps.DebugScoring)
	}

	// Sort dependencies by risk score descending.
	sorted := make([]*scorer.DependencyScore, len(ps.Dependencies))
	copy(sorted, ps.Dependencies)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].RiskScore > sorted[j].RiskScore
	})

	// Group by risk level (matches spec: 0-25 LOW, 26-50 MEDIUM, 51-75 HIGH, 76-100 CRITICAL).
	var critical, high, medium, low []*scorer.DependencyScore
	for _, ds := range sorted {
		if ds.RiskScore < opts.MinRisk {
			continue
		}
		switch {
		case ds.RiskScore >= 76:
			critical = append(critical, ds)
		case ds.RiskScore >= 51:
			high = append(high, ds)
		case ds.RiskScore >= 26:
			medium = append(medium, ds)
		default:
			low = append(low, ds)
		}
	}

	// Critical risk.
	if len(critical) > 0 {
		fmt.Fprintf(w, "%s\n", c(colorRed, fmt.Sprintf("CRITICAL RISK (%d dependencies)", len(critical))))
		fmt.Fprintf(w, "%s\n", c(colorRed, strings.Repeat("─", 40)))
		for _, ds := range critical {
			writeDependencyDetail(w, ds, c, true)
		}
		fmt.Fprintln(w)
	}

	// High risk.
	if len(high) > 0 {
		fmt.Fprintf(w, "%s\n", c(colorOrange, fmt.Sprintf("HIGH RISK (%d dependencies)", len(high))))
		fmt.Fprintf(w, "%s\n", c(colorOrange, strings.Repeat("─", 40)))
		for _, ds := range high {
			writeDependencyDetail(w, ds, c, true)
		}
		fmt.Fprintln(w)
	}

	// Medium risk.
	if len(medium) > 0 {
		fmt.Fprintf(w, "%s\n", c(colorYellow, fmt.Sprintf("MEDIUM RISK (%d dependencies)", len(medium))))
		fmt.Fprintf(w, "%s\n", c(colorYellow, strings.Repeat("─", 40)))
		for _, ds := range medium {
			// Always show details if dep has vulns, otherwise respect --verbose.
			showDetail := opts.Verbose || len(ds.Vulns) > 0
			writeDependencyDetail(w, ds, c, showDetail)
		}
		fmt.Fprintln(w)
	}

	// Low risk.
	if len(low) > 0 {
		fmt.Fprintf(w, "%s\n", c(colorGreen, fmt.Sprintf("LOW RISK (%d dependencies)", len(low))))
		fmt.Fprintf(w, "%s\n", c(colorGreen, strings.Repeat("─", 40)))
		if opts.Verbose {
			for _, ds := range low {
				writeDependencyDetail(w, ds, c, false)
			}
		} else {
			// Always show deps with vulns even in low risk.
			hasVulnDeps := false
			for _, ds := range low {
				if len(ds.Vulns) > 0 {
					writeDependencyDetail(w, ds, c, true)
					hasVulnDeps = true
				}
			}
			if !hasVulnDeps {
				fmt.Fprintf(w, "%s\n", c(colorDim, "[use --verbose to see details]"))
			} else {
				lowNoVuln := len(low) - countWithVulns(low)
				if lowNoVuln > 0 {
					fmt.Fprintf(w, "%s\n", c(colorDim, fmt.Sprintf("[%d more without vulnerabilities — use --verbose]", lowNoVuln)))
				}
			}
		}
		fmt.Fprintln(w)
	}

	// CI/CD and build-file sections are always rendered when the scanner was invoked,
	// so reviewers can confirm the scanner ran even when there are no findings.
	if opts.CIReport != nil {
		writeCIReportText(w, opts.CIReport, c)
	}

	// Takeover Candidates section.
	if len(opts.Takeovers) > 0 {
		writeTakeoverText(w, opts.Takeovers, c)
	}

	// Stdlib vulnerabilities.
	if len(opts.StdlibVulns) > 0 {
		fmt.Fprintf(w, "\n%s\n", c(colorRed, fmt.Sprintf("STDLIB VULNERABILITIES (%d found)", len(opts.StdlibVulns))))
		fmt.Fprintf(w, "%s\n", c(colorRed, strings.Repeat("─", 40)))
		fmt.Fprintf(w, "%s\n", c(colorDim, "These affect the Go standard library used to build dependencies."))
		for _, v := range opts.StdlibVulns {
			aliases := strings.Join(v.Aliases, ", ")
			fmt.Fprintf(w, "  %s %s (%s)\n", c(colorRed, v.ID), v.Summary, aliases)
			if v.FixedVersion != "" {
				fmt.Fprintf(w, "    %s %s\n", c(colorDim, "Fixed in:"), v.FixedVersion)
			}
		}
		fmt.Fprintln(w)
	}

	// Summary.
	fmt.Fprintf(w, "──────────────────────────\n")
	fmt.Fprintf(w, "SUMMARY\n")
	if len(critical) > 0 {
		fmt.Fprintf(w, "  Critical:    %s\n", formatCount(len(critical), total))
	}
	fmt.Fprintf(w, "  High risk:   %s\n", formatCount(len(high), total))
	fmt.Fprintf(w, "  Medium risk: %s\n", formatCount(len(medium), total))
	fmt.Fprintf(w, "  Low risk:    %s\n", formatCount(len(low), total))
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  Vulnerabilities found: %d across %d dependencies\n", ps.TotalVulns, countWithVulns(sorted))
	fmt.Fprintf(w, "  Unmaintained (>2yr):   %d dependencies\n", ps.Unmaintained2yr)
	fmt.Fprintf(w, "  Unmaintained (>1yr):   %d dependencies\n", ps.Unmaintained1yr)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Report generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "Full report: unisupply -f pdf\n")
	fmt.Fprintf(w, "Learn more: https://security.unidoc.io\n")

	return nil
}

func writeDependencyDetail(w io.Writer, ds *scorer.DependencyScore, c func(string, string) string, detailed bool) {
	scoreColor := riskColor(ds.RiskLevel)
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

	fmt.Fprintf(w, "● %s %s  %s  (%s)\n",
		ds.Module, ds.Version,
		c(scoreColor, fmt.Sprintf("Risk: %d/100", ds.RiskScore)),
		label)

	if !detailed {
		return
	}

	// What this score means.
	fmt.Fprintf(w, "  ├─ %s\n", c(colorDim, depExplanation(ds)))

	// Vulnerabilities.
	if len(ds.Vulns) > 0 {
		// Compute per-tier counts. Empty Reachability is treated as "called"
		// for backward compatibility with non-govulncheck CVE sources.
		var nCalled, nImported, nRequired int
		for _, v := range ds.Vulns {
			switch v.Reachability {
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
		for _, v := range ds.Vulns {
			aliases := strings.Join(v.Aliases, ", ")
			if aliases == "" {
				aliases = v.ID
			}
			tag := reachabilityTag(v.Reachability)
			displaySev := v.Severity
			if strings.EqualFold(v.Severity, "UNKNOWN") || v.Severity == "" {
				displaySev = "UNKNOWN"
			}
			fmt.Fprintf(w, "  ├─ ⚠ %s (%s)%s — %s\n", v.ID, displaySev, tag, aliases)
			if strings.EqualFold(v.Severity, "UNKNOWN") || v.Severity == "" {
				fmt.Fprintf(w, "  │  severity unresolved — treated as MEDIUM (HIGH if reachable)\n")
			}
			if v.FixedVersion != "" {
				fmt.Fprintf(w, "  │  Fix available: %s\n", v.FixedVersion)
			}
		}
	}

	// Maintenance info.
	if ds.Maintenance != nil {
		if ds.Maintenance.MonthsSinceRelease > 0 {
			fmt.Fprintf(w, "  ├─ Last release: %d months ago\n", ds.Maintenance.MonthsSinceRelease)
		}
		if ds.Maintenance.Archived {
			fmt.Fprintf(w, "  ├─ ⚠ Repository archived\n")
		}
		if ds.Maintenance.Deprecated {
			fmt.Fprintf(w, "  ├─ ⚠ Module deprecated\n")
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

		// Activity.
		if !mi.LastCommitDate.IsZero() {
			fmt.Fprintf(w, "  ├─ Last commit: %s (%s)\n",
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

		if mi.TakeoverCandidate {
			fmt.Fprintf(w, "  ├─ ⚠ Takeover candidate: %s\n", mi.TakeoverReason)
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

	// AI-generated code risk.
	if ds.AIGenRisk != nil && ds.AIGenRisk.Score > 0 {
		fmt.Fprintf(w, "  ├─ ⚠ AI-generated code risk: %s (%d/100)\n", ds.AIGenRisk.RiskLevel, ds.AIGenRisk.Score)
		for _, ind := range ds.AIGenRisk.Indicators {
			fmt.Fprintf(w, "  │  - %s\n", ind)
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

	// Risk score breakdown.
	fmt.Fprintf(w, "  ├─ %s vuln=%.0f×40%% maint=%.0f×25%% depth=%.0f×15%% maintainer=%.0f×10%% maturity=%.0f×10%%\n",
		c(colorDim, "Score breakdown:"),
		ds.VulnScore, ds.MaintenanceScore, ds.DepthScore, ds.MaintainerScore, ds.MaturityScore)

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

func writeTakeoverText(w io.Writer, takeovers []*scanner.MaintainerInfo, c func(string, string) string) {
	fmt.Fprintf(w, "\n%s\n", c(colorCyan, "PACKAGES ELIGIBLE FOR MAINTENANCE TAKEOVER"))
	fmt.Fprintf(w, "%s\n", c(colorCyan, strings.Repeat("─", 40)))
	fmt.Fprintf(w, "%s\n\n", c(colorDim, "These packages are widely used but lack active maintenance."))

	for _, t := range takeovers {
		fmt.Fprintf(w, "  ● %s/%s", t.Owner, t.Repo)
		if t.Stars > 0 {
			fmt.Fprintf(w, " (%d stars)", t.Stars)
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "    Activity: %s | Bus factor: %d | Reason: %s\n",
			t.ActivityPattern, t.BusFactor, t.TakeoverReason)
	}
	fmt.Fprintln(w)
}

func riskColor(level scorer.RiskLevel) string {
	switch level {
	case scorer.RiskCritical:
		return colorRed
	case scorer.RiskHigh:
		return colorOrange
	case scorer.RiskMedium:
		return colorYellow
	default:
		return colorGreen
	}
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

func overallExplanation(score int, level scorer.RiskLevel) string {
	switch level {
	case scorer.RiskCritical:
		return "Immediate action required. Your supply chain has critical vulnerabilities\nor severely compromised dependencies that could be actively exploited."
	case scorer.RiskHigh:
		return "Action recommended. Known vulnerabilities with available fixes, or\ndependencies with serious maintenance/trust concerns."
	case scorer.RiskMedium:
		return "Monitor and plan. Some dependencies have stale maintenance, limited\nbus factor, or minor concerns that should be addressed over time."
	default:
		return "Supply chain is in good shape. Dependencies are well-maintained\nand no known vulnerabilities were found."
	}
}

func depExplanation(ds *scorer.DependencyScore) string {
	// Build a human-readable summary of WHY this score is what it is.
	var reasons []string

	if len(ds.Vulns) > 0 {
		reasons = append(reasons, fmt.Sprintf("%d known vulnerability(ies) with available fixes — update recommended", len(ds.Vulns)))
	}

	if ds.Maintenance != nil {
		switch {
		case ds.Maintenance.Archived:
			reasons = append(reasons, "repository is archived — no future fixes expected, consider replacing")
		case ds.Maintenance.MonthsSinceRelease >= 24:
			reasons = append(reasons, fmt.Sprintf("no release in %d months — may be abandoned, monitor or find alternative", ds.Maintenance.MonthsSinceRelease))
		case ds.Maintenance.MonthsSinceRelease >= 12:
			reasons = append(reasons, fmt.Sprintf("last release %d months ago — maintenance may be slowing", ds.Maintenance.MonthsSinceRelease))
		}
	}

	if ds.MaintainerInfo != nil {
		if ds.MaintainerInfo.BusFactor <= 1 && ds.MaintainerInfo.ContributorCount > 0 {
			reasons = append(reasons, "single key maintainer — if they stop, no one else can fix issues")
		}
		if ds.MaintainerInfo.TakeoverCandidate {
			reasons = append(reasons, "candidate for maintenance takeover — widely used but unmaintained")
		}
	}

	if ds.AIGenRisk != nil && ds.AIGenRisk.Score >= 25 {
		reasons = append(reasons, "shows patterns common in AI-generated supply chain attacks — verify manually")
	}

	if ds.Typosquat != nil && ds.Typosquat.Confidence >= 0.4 {
		reasons = append(reasons, fmt.Sprintf("name suspiciously similar to %s — verify this is the intended package", ds.Typosquat.SimilarTo))
	}

	if ds.Resilience != nil && ds.Resilience.Score < 30 {
		reasons = append(reasons, "low resilience — few releases, no governance files, uncertain long-term viability")
	}

	if len(reasons) == 0 {
		switch ds.RiskLevel {
		case scorer.RiskCritical:
			return "Multiple severe risk factors detected."
		case scorer.RiskHigh:
			return "Significant risk factors — review and plan remediation."
		case scorer.RiskMedium:
			return "Some concerns but manageable — monitor over time."
		default:
			return "No significant concerns found."
		}
	}

	if len(reasons) == 1 {
		return reasons[0]
	}

	// Join first two reasons for conciseness.
	return reasons[0] + "; " + reasons[1]
}

// writeDebugScoring emits the --debug-scoring diagnostic block in text form.
// NON-NORMATIVE: layout may change between releases; do not parse this block.
func writeDebugScoring(w io.Writer, c func(string, string) string, d *scorer.DebugScoring) {
	fmt.Fprintf(w, "%s\n", c(colorDim, "── debug_scoring (non-normative) ─────────────────"))
	fmt.Fprintf(w, "  mean=%d  severity_adjusted=%d  driver=%s\n",
		d.MeanDepRiskScore, d.SeverityAdjustedVulnScore, d.HeadlineDriver)
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

	if len(d.PerDepInputs) > 0 {
		fmt.Fprintf(w, "  per_dep_inputs (%d):\n", len(d.PerDepInputs))
		for _, p := range d.PerDepInputs {
			amp := ""
			if p.FixAgeAmplifier {
				amp = " amp"
			}
			fmt.Fprintf(w, "    %s: worst=%s high+_count=%d floor=%d%s vuln_score=%d risk=%d/%s\n",
				p.Module, p.WorstSeverity, p.HighOrAboveCount, p.FloorApplied, amp,
				p.FinalVulnScore, p.FinalRiskScore, p.FinalRiskLevel)
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
