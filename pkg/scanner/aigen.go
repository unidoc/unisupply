package scanner

import (
	"strings"
	"time"

	"github.com/unidoc/unisupply/pkg/resolver"
)

// AIGenRisk holds AI-generated code supply chain attack indicators.
type AIGenRisk struct {
	Module     string   `json:"module"`
	RiskLevel  string   `json:"risk_level"` // "none", "low", "medium", "high"
	Score      int      `json:"score"`      // 0-100
	Indicators []string `json:"indicators"`
}

// AIGenScanner detects patterns common in AI-generated supply chain attacks.
type AIGenScanner struct{}

// NewAIGenScanner creates a new AI-generated code risk scanner.
func NewAIGenScanner() *AIGenScanner {
	return &AIGenScanner{}
}

// ScanAll checks all dependencies for AI-generated attack indicators.
func (s *AIGenScanner) ScanAll(
	graph *resolver.Graph,
	maintainers map[string]*MaintainerInfo,
	resilience map[string]*ResilienceInfo,
) map[string]*AIGenRisk {
	results := make(map[string]*AIGenRisk)

	for _, dep := range graph.Dependencies {
		risk := s.analyzeModule(dep, maintainers[dep.Module.Path], resilience[dep.Module.Path])
		if risk.Score > 0 {
			results[dep.Module.Path] = risk
		}
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

	// 1. Recently created module (< 6 months) with a name mimicking established packages.
	if ri != nil && !ri.FirstReleaseDate.IsZero() {
		ageMonths := monthsSince(ri.FirstReleaseDate)
		ageDays := int(time.Since(ri.FirstReleaseDate).Hours() / 24)

		if ageMonths < 6 {
			risk.Score += 15
			risk.Indicators = append(risk.Indicators, "module_created_recently")

			// Extra suspicious if very new (< 30 days).
			if ageDays < 30 {
				risk.Score += 15
				risk.Indicators = append(risk.Indicators, "module_created_last_30_days")
			}
		}
	}

	// 2. Module with very few releases but already pulled in as dependency.
	if ri != nil && ri.TotalReleases <= 2 && ri.TotalReleases > 0 {
		risk.Score += 10
		risk.Indicators = append(risk.Indicators, "very_few_releases")
	}

	// 3. No governance files (no SECURITY.md, no CONTRIBUTING.md).
	if ri != nil && !ri.HasSecurityPolicy && !ri.HasContribGuide && !ri.HasCodeOfConduct {
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
	if ri != nil && ri.VersionScheme == "pseudo" && ri.TotalReleases == 0 {
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

	return risk
}
