package scanner

import (
	"context"
	"strings"
	"time"

	"github.com/unidoc/unisupply/pkg/progress"
	"github.com/unidoc/unisupply/pkg/resolver"
)

// chatGPTReleaseDate is the public release date of ChatGPT (2022-11-01).
// Modules first released before this date are excluded from the AI-gen detector
// because the threat model of AI-hallucinated package names only applies to the
// post-ChatGPT era. Revisit this heuristic if the threat model changes.
var chatGPTReleaseDate = time.Date(2022, time.November, 1, 0, 0, 0, 0, time.UTC)

// AIGenRisk holds AI-generated code supply chain attack indicators.
type AIGenRisk struct {
	Module     string   `json:"module"`
	RiskLevel  string   `json:"risk_level"` // "none", "low", "medium", "high"
	Score      int      `json:"score"`      // 0-100
	Indicators []string `json:"indicators"`

	// MeetsPromotionGate is true when all three high-confidence signals are
	// present simultaneously: age_months < 12, release_count <= 2, and
	// generic_name. Only entries with this field set are promoted to the
	// risk_factors list. Single-indicator hits still populate Indicators for
	// transparency but do not trigger the promotion.
	MeetsPromotionGate bool `json:"meets_promotion_gate"`
}

// AIGenScanner detects patterns common in AI-generated supply chain attacks.
type AIGenScanner struct {
	// ScanStart is the reference time used for age-band calculations.
	// Truncated to the start of a UTC day so that two scans on the same calendar
	// day produce identical ageMonths values for the same module. Defaults to
	// time.Now().UTC().Truncate(24*time.Hour) at construction time.
	ScanStart time.Time
}

// NewAIGenScanner creates a new AI-generated code risk scanner.
func NewAIGenScanner() *AIGenScanner {
	return &AIGenScanner{
		ScanStart: time.Now().UTC().Truncate(24 * time.Hour),
	}
}

// ScanAll checks all dependencies for AI-generated attack indicators.
func (s *AIGenScanner) ScanAll(
	ctx context.Context,
	graph *resolver.Graph,
	maintainers map[string]*MaintainerInfo,
	resilience map[string]*ResilienceInfo,
) map[string]*AIGenRisk {
	rep := progress.From(ctx)
	total := len(graph.Dependencies)
	results := make(map[string]*AIGenRisk)

	i := 0
	for _, dep := range graph.Dependencies {
		i++
		risk := s.analyzeModule(dep, maintainers[dep.Module.Path], resilience[dep.Module.Path])
		if risk.Score > 0 {
			results[dep.Module.Path] = risk
		}
		rep.Progress(i, total)
	}

	return results
}

func (s *AIGenScanner) analyzeModule(
	dep *resolver.Dependency,
	mi *MaintainerInfo,
	ri *ResilienceInfo,
) *AIGenRisk {
	risk := &AIGenRisk{
		Module: dep.Module.Path,
	}

	// Hard exclusion: missing resilience data means we cannot determine when
	// the module was first published. Rather than false-flag from missing data,
	// skip the detector entirely. This covers ri == nil, non-GitHub hosts, and
	// cases where the GitHub API was unauthenticated.
	if ri == nil || ri.FirstReleaseDate.IsZero() {
		risk.RiskLevel = "none"
		return risk
	}

	// Hard exclusion: modules first released before ChatGPT's public launch
	// (2022-11-01) cannot be AI-hallucination-registered attack packages.
	// This cutoff is a heuristic — revisit if the threat model changes.
	if ri.FirstReleaseDate.Before(chatGPTReleaseDate) {
		risk.RiskLevel = "none"
		return risk
	}

	// --- Score accumulation (single-indicator hits still populate Indicators
	// for transparency even if they do not meet the promotion gate). ---

	// Track the three high-confidence signals used by the promotion gate.
	var (
		ageMonthsUnder12 bool
		releasesAtMost2  bool
		hasGenericName   bool
	)

	// 1. Recently created module (< 6 months) with a name mimicking established packages.
	ageMonths := monthsSince(s.ScanStart, ri.FirstReleaseDate)
	ageDays := int(s.ScanStart.Sub(ri.FirstReleaseDate).Hours() / 24)

	if ageMonths < 12 {
		ageMonthsUnder12 = true
	}

	if ageMonths < 6 {
		risk.Score += 15
		risk.Indicators = append(risk.Indicators, "module_created_recently")

		// Extra suspicious if very new (< 30 days).
		if ageDays < 30 {
			risk.Score += 15
			risk.Indicators = append(risk.Indicators, "module_created_last_30_days")
		}
	}

	// 2. Module with very few releases but already pulled in as dependency.
	if ri.TotalReleases <= 2 && ri.TotalReleases > 0 {
		releasesAtMost2 = true
		risk.Score += 10
		risk.Indicators = append(risk.Indicators, "very_few_releases")
	}

	// 3. No governance files (no SECURITY.md, no CONTRIBUTING.md).
	if !ri.HasSecurityPolicy && !ri.HasContribGuide && !ri.HasCodeOfConduct {
		if ri.TotalReleases > 0 {
			risk.Score += 5
			risk.Indicators = append(risk.Indicators, "no_governance_files")
		}
	}

	// 4. Single maintainer with no history.
	if mi != nil && mi.BusFactor <= 1 && mi.ContributorCount <= 1 {
		risk.Score += 10
		risk.Indicators = append(risk.Indicators, "single_anonymous_maintainer")

		// Extra suspicious if no profile info.
		if mi.OwnerName == "" && mi.OwnerBio == "" && mi.OwnerLocation == "" {
			risk.Score += 10
			risk.Indicators = append(risk.Indicators, "empty_maintainer_profile")
		}
	}

	// 5. Module name patterns common in AI hallucination attacks.
	// AI models sometimes suggest packages that don't exist, and attackers register them.
	modPath := dep.Module.Path
	pathParts := strings.Split(modPath, "/")
	lastPart := pathParts[len(pathParts)-1]

	// Very generic names that AI might hallucinate.
	genericNames := []string{
		"utils", "helper", "helpers", "common", "shared", "core",
		"tools", "toolkit", "sdk", "client", "api", "lib",
		"go-utils", "go-helper", "go-common", "go-tools",
	}
	for _, name := range genericNames {
		if lastPart == name {
			hasGenericName = true
			risk.Score += 5
			risk.Indicators = append(risk.Indicators, "generic_package_name")
			break
		}
	}

	// 6. Module under a user account (not org) with a name that looks like it should be official.
	if mi != nil && !mi.IsOrg {
		officialPrefixes := []string{"go-", "golang-", "google-", "aws-", "azure-", "k8s-"}
		for _, prefix := range officialPrefixes {
			if strings.HasPrefix(lastPart, prefix) {
				risk.Score += 10
				risk.Indicators = append(risk.Indicators, "unofficial_official_looking_name")
				break
			}
		}
	}

	// 7. Pseudo-version only (no tagged releases) — common for quickly registered attack packages.
	if ri.VersionScheme == "pseudo" && ri.TotalReleases == 0 {
		risk.Score += 10
		risk.Indicators = append(risk.Indicators, "pseudo_version_only")
	}

	// 8. Dependency doesn't match its stated purpose (unusual imports).
	// This is hard to check without source analysis, but we flag modules
	// with network-related names that are pulled in by non-network code.
	// (Simplified heuristic for now.)

	// Cap at 100.
	if risk.Score > 100 {
		risk.Score = 100
	}

	// Classify risk level.
	switch {
	case risk.Score >= 50:
		risk.RiskLevel = "high"
	case risk.Score >= 25:
		risk.RiskLevel = "medium"
	case risk.Score > 0:
		risk.RiskLevel = "low"
	default:
		risk.RiskLevel = "none"
	}

	// Promotion gate: only set when all three high-confidence signals coincide.
	// Single-indicator hits are transparent via Indicators but do not promote
	// to risk_factors (controlled in scorer/risk.go via MeetsPromotionGate).
	risk.MeetsPromotionGate = ageMonthsUnder12 && releasesAtMost2 && hasGenericName

	return risk
}
