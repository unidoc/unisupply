// Package scorer implements the risk scoring algorithm.
package scorer

import (
	"math"
	"strings"

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

	// Component scores (for verbose output).
	VulnScore        float64 `json:"-"`
	MaintenanceScore float64 `json:"-"`
	DepthScore       float64 `json:"-"`
	MaintainerScore  float64 `json:"-"`
	MaturityScore    float64 `json:"-"`
}

// ProjectScore holds the overall project risk assessment.
type ProjectScore struct {
	OverallScore    int                `json:"overall_risk_score"`
	OverallLevel    RiskLevel          `json:"overall_risk_level"`
	Dependencies    []*DependencyScore `json:"dependencies"`
	CriticalRiskCount int              `json:"critical_risk_count"`
	HighRiskCount   int                `json:"high_risk_count"`
	MediumRiskCount int                `json:"medium_risk_count"`
	LowRiskCount    int                `json:"low_risk_count"`
	TotalVulns      int                `json:"total_vulnerabilities"`
	Unmaintained2yr int                `json:"unmaintained_2yr"`
	Unmaintained1yr int                `json:"unmaintained_1yr"`
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
}

// ScoreAll computes risk scores for all dependencies and the overall project.
func ScoreAll(input ScoreInput) *ProjectScore {
	ps := &ProjectScore{}

	for _, dep := range input.Graph.Dependencies {
		ds := scoreDependency(
			dep,
			input.Vulns[dep.Module.Path],
			input.Maintenance[dep.Module.Path],
			input.Maintainers[dep.Module.Path],
			input.Typosquats[dep.Module.Path],
			input.Resilience[dep.Module.Path],
			input.AIGenRisks[dep.Module.Path],
			input.TrustIndex[dep.Module.Path],
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
	}

	ps.OverallScore = computeOverallScore(ps.Dependencies)
	ps.OverallLevel = levelFromScore(ps.OverallScore)

	return ps
}

func scoreDependency(
	dep *resolver.Dependency,
	vulns []scanner.Vulnerability,
	maint *scanner.MaintenanceInfo,
	maintainerInfo *scanner.MaintainerInfo,
	typosquat *scanner.TyposquatResult,
	resilience *scanner.ResilienceInfo,
	aiGenRisk *scanner.AIGenRisk,
	trustIndex *scanner.TrustIndexEntry,
) *DependencyScore {
	ds := &DependencyScore{
		Module:         dep.Module.Path,
		Version:        dep.Module.Version,
		Direct:         dep.Direct,
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
	ds.MaintainerScore = maintainerRiskScore(maintainerInfo, dep.Module.Path)
	if maintainerInfo != nil {
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
	aiGenBonus := 0.0
	if aiGenRisk != nil && aiGenRisk.Score > 0 {
		aiGenBonus = float64(aiGenRisk.Score) * 0.15 // up to 15 extra points
		ds.RiskFactors = append(ds.RiskFactors, "ai_gen_risk:"+aiGenRisk.RiskLevel)
	}

	// Low resilience adds to score.
	resilienceBonus := 0.0
	if resilience != nil && resilience.Score < 30 {
		resilienceBonus = float64(30-resilience.Score) * 0.2 // up to 6 extra points for very low resilience
		ds.RiskFactors = append(ds.RiskFactors, "low_resilience")
	}

	// Weighted total.
	weighted := ds.VulnScore*WeightVulnerabilities +
		ds.MaintenanceScore*WeightMaintenance +
		ds.DepthScore*WeightDepthRisk +
		ds.MaintainerScore*WeightMaintainerRisk +
		ds.MaturityScore*WeightMaturity +
		typosquatBonus +
		aiGenBonus +
		resilienceBonus

	ds.RiskScore = int(math.Round(weighted))

	// Floor: any dependency with a known vulnerability should never be below 51
	// (HIGH risk). A known CVE with a fix available is actionable and must not
	// be buried in MEDIUM/LOW where it looks safe.
	if len(vulns) > 0 && ds.RiskScore < 51 {
		ds.RiskScore = 51
	}

	if ds.RiskScore > 100 {
		ds.RiskScore = 100
	}
	ds.RiskLevel = levelFromScore(ds.RiskScore)

	return ds
}

func vulnScore(vulns []scanner.Vulnerability) float64 {
	if len(vulns) == 0 {
		return 0
	}

	total := 0.0
	for _, v := range vulns {
		switch strings.ToUpper(v.Severity) {
		case "CRITICAL":
			total += 100
		case "HIGH":
			total += 80
		case "MEDIUM":
			total += 50
		case "LOW":
			total += 25
		default:
			total += 50 // Unknown severity treated as medium.
		}
	}

	if total > 100 {
		total = 100
	}
	return total
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
		return 30 // Unknown.
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
			hasVulns = true
			if ds.RiskScore > maxVulnScore {
				maxVulnScore = ds.RiskScore
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
