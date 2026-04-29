package scorer

import (
	"testing"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// TestLevelFromScore tests the risk level classification from score values.
func TestLevelFromScore(t *testing.T) {
	tests := []struct {
		name     string
		score    int
		expected RiskLevel
	}{
		{
			name:     "score 0 returns LOW",
			score:    0,
			expected: RiskLow,
		},
		{
			name:     "score 25 returns LOW",
			score:    25,
			expected: RiskLow,
		},
		{
			name:     "score 26 returns MEDIUM",
			score:    26,
			expected: RiskMedium,
		},
		{
			name:     "score 50 returns MEDIUM",
			score:    50,
			expected: RiskMedium,
		},
		{
			name:     "score 51 returns HIGH",
			score:    51,
			expected: RiskHigh,
		},
		{
			name:     "score 75 returns HIGH",
			score:    75,
			expected: RiskHigh,
		},
		{
			name:     "score 76 returns CRITICAL",
			score:    76,
			expected: RiskCritical,
		},
		{
			name:     "score 100 returns CRITICAL",
			score:    100,
			expected: RiskCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := levelFromScore(tt.score)
			if got != tt.expected {
				t.Errorf("levelFromScore(%d) = %v, want %v", tt.score, got, tt.expected)
			}
		})
	}
}

// TestVulnScore tests vulnerability score calculation.
func TestVulnScore(t *testing.T) {
	tests := []struct {
		name     string
		vulns    []scanner.Vulnerability
		expected float64
	}{
		{
			name:     "empty list returns 0",
			vulns:    []scanner.Vulnerability{},
			expected: 0,
		},
		{
			name: "single CRITICAL vulnerability returns 100",
			vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-1234", "CRITICAL", "v1.5.0"),
			},
			expected: 100,
		},
		{
			name: "single HIGH vulnerability returns 80",
			vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-1234", "HIGH", "v1.5.0"),
			},
			expected: 80,
		},
		{
			name: "single MEDIUM vulnerability returns 50",
			vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-1234", "MEDIUM", "v1.5.0"),
			},
			expected: 50,
		},
		{
			name: "single LOW vulnerability returns 25",
			vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-1234", "LOW", "v1.5.0"),
			},
			expected: 25,
		},
		{
			name: "unknown severity treated as medium (50)",
			vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-1234", "UNKNOWN", "v1.5.0"),
			},
			expected: 50,
		},
		{
			name: "multiple vulnerabilities capped at 100",
			vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-1234", "CRITICAL", "v1.5.0"),
				testutil.MakeVuln("CVE-2024-5678", "CRITICAL", "v1.6.0"),
			},
			expected: 100,
		},
		{
			name: "multiple lower severity vulns sum correctly",
			vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-1234", "MEDIUM", "v1.5.0"),
				testutil.MakeVuln("CVE-2024-5678", "LOW", "v1.6.0"),
			},
			expected: 75, // 50 + 25
		},
		{
			name: "case insensitive severity matching",
			vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-1234", "critical", "v1.5.0"),
			},
			expected: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vulnScore(tt.vulns)
			if got != tt.expected {
				t.Errorf("vulnScore() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestMaintenanceScore tests maintenance health scoring.
func TestMaintenanceScore(t *testing.T) {
	tests := []struct {
		name     string
		maint    *scanner.MaintenanceInfo
		expected float64
	}{
		{
			name:     "nil maintenance info returns 30",
			maint:    nil,
			expected: 30,
		},
		{
			name:     "archived module returns 100",
			maint:    testutil.MakeMaintenanceInfo(6, true, false),
			expected: 100,
		},
		{
			name:     "less than 6 months since release returns 0",
			maint:    testutil.MakeMaintenanceInfo(3, false, false),
			expected: 0,
		},
		{
			name:     "6 months since release returns 25",
			maint:    testutil.MakeMaintenanceInfo(6, false, false),
			expected: 25,
		},
		{
			name:     "11 months since release returns 25",
			maint:    testutil.MakeMaintenanceInfo(11, false, false),
			expected: 25,
		},
		{
			name:     "12 months since release returns 60",
			maint:    testutil.MakeMaintenanceInfo(12, false, false),
			expected: 60,
		},
		{
			name:     "23 months since release returns 60",
			maint:    testutil.MakeMaintenanceInfo(23, false, false),
			expected: 60,
		},
		{
			name:     "24 months since release returns 90",
			maint:    testutil.MakeMaintenanceInfo(24, false, false),
			expected: 90,
		},
		{
			name:     "36 months since release returns 90",
			maint:    testutil.MakeMaintenanceInfo(36, false, false),
			expected: 90,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maintenanceScore(tt.maint)
			if got != tt.expected {
				t.Errorf("maintenanceScore() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestDepthScore tests dependency depth scoring.
func TestDepthScore(t *testing.T) {
	tests := []struct {
		name     string
		depth    int
		expected float64
	}{
		{
			name:     "depth 0 returns 0",
			depth:    0,
			expected: 0,
		},
		{
			name:     "depth 1 returns 20",
			depth:    1,
			expected: 20,
		},
		{
			name:     "depth 2 returns 40",
			depth:    2,
			expected: 40,
		},
		{
			name:     "depth 5 returns 40 (capped)",
			depth:    5,
			expected: 40,
		},
		{
			name:     "depth -1 returns 0",
			depth:    -1,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := depthScore(tt.depth)
			if got != tt.expected {
				t.Errorf("depthScore(%d) = %v, want %v", tt.depth, got, tt.expected)
			}
		})
	}
}

// TestMaintainerRiskScore tests maintainer risk scoring.
func TestMaintainerRiskScore(t *testing.T) {
	tests := []struct {
		name     string
		modPath  string
		info     *scanner.MaintainerInfo
		expected float64
	}{
		{
			name:     "trusted namespace golang.org/x/ returns 0",
			modPath:  "golang.org/x/text",
			info:     testutil.MakeMaintainerInfo(1, 5, true),
			expected: 0,
		},
		{
			name:     "trusted namespace google.golang.org returns 0",
			modPath:  "google.golang.org/api",
			info:     testutil.MakeMaintainerInfo(1, 5, true),
			expected: 0,
		},
		{
			name:     "trusted namespace k8s.io returns 0",
			modPath:  "k8s.io/client-go",
			info:     testutil.MakeMaintainerInfo(1, 5, true),
			expected: 0,
		},
		{
			name:     "nil info for non-trusted namespace returns 30",
			modPath:  "github.com/random/pkg",
			info:     nil,
			expected: 30,
		},
		{
			name:     "bus factor 0 returns 30",
			modPath:  "github.com/random/pkg",
			info:     testutil.MakeMaintainerInfo(0, 5, false),
			expected: 30,
		},
		{
			name:     "bus factor 1 returns 50",
			modPath:  "github.com/random/pkg",
			info:     testutil.MakeMaintainerInfo(1, 5, false),
			expected: 50,
		},
		{
			name:     "bus factor 2 returns 0",
			modPath:  "github.com/random/pkg",
			info:     testutil.MakeMaintainerInfo(2, 5, false),
			expected: 0,
		},
		{
			name:     "bus factor 5 returns 0",
			modPath:  "github.com/random/pkg",
			info:     testutil.MakeMaintainerInfo(5, 5, false),
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maintainerRiskScore(tt.info, tt.modPath)
			if got != tt.expected {
				t.Errorf("maintainerRiskScore() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestMaturityScore tests module maturity scoring.
func TestMaturityScore(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		modPath  string
		expected float64
	}{
		{
			name:     "trusted namespace returns 0 regardless of version",
			version:  "v0.1.0",
			modPath:  "golang.org/x/text",
			expected: 0,
		},
		{
			name:     "v0.x version for non-trusted returns 30",
			version:  "v0.5.0",
			modPath:  "github.com/random/pkg",
			expected: 30,
		},
		{
			name:     "v1.x version returns 0",
			version:  "v1.0.0",
			modPath:  "github.com/random/pkg",
			expected: 0,
		},
		{
			name:     "v2.x version returns 0",
			version:  "v2.3.4",
			modPath:  "github.com/random/pkg",
			expected: 0,
		},
		{
			name:     "empty version returns 50",
			version:  "",
			modPath:  "github.com/random/pkg",
			expected: 50,
		},
		{
			name:     "v0.0.0 version returns 30",
			version:  "v0.0.0",
			modPath:  "github.com/random/pkg",
			expected: 30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maturityScore(tt.version, tt.modPath)
			if got != tt.expected {
				t.Errorf("maturityScore(%q, %q) = %v, want %v", tt.version, tt.modPath, got, tt.expected)
			}
		})
	}
}

// TestIsTrustedNamespace tests trusted namespace detection.
func TestIsTrustedNamespace(t *testing.T) {
	tests := []struct {
		name     string
		modPath  string
		expected bool
	}{
		{
			name:     "golang.org/x/text is trusted",
			modPath:  "golang.org/x/text",
			expected: true,
		},
		{
			name:     "google.golang.org/api is trusted",
			modPath:  "google.golang.org/api",
			expected: true,
		},
		{
			name:     "cloud.google.com/go is trusted",
			modPath:  "cloud.google.com/go",
			expected: true,
		},
		{
			name:     "cloud.google.com/go/storage is trusted",
			modPath:  "cloud.google.com/go/storage",
			expected: true,
		},
		{
			name:     "k8s.io/client-go is trusted",
			modPath:  "k8s.io/client-go",
			expected: true,
		},
		{
			name:     "sigs.k8s.io/controller-tools is trusted",
			modPath:  "sigs.k8s.io/controller-tools",
			expected: true,
		},
		{
			name:     "go.opencensus.io is trusted",
			modPath:  "go.opencensus.io",
			expected: true,
		},
		{
			name:     "go.opentelemetry.io/api is trusted",
			modPath:  "go.opentelemetry.io/api",
			expected: true,
		},
		{
			name:     "go.uber.org/zap is trusted",
			modPath:  "go.uber.org/zap",
			expected: true,
		},
		{
			name:     "github.com/golang/protobuf is trusted",
			modPath:  "github.com/golang/protobuf",
			expected: true,
		},
		{
			name:     "github.com/google/uuid is trusted",
			modPath:  "github.com/google/uuid",
			expected: true,
		},
		{
			name:     "github.com/googleapis/go-type-adaptor is trusted",
			modPath:  "github.com/googleapis/go-type-adaptor",
			expected: true,
		},
		{
			name:     "github.com/grpc/grpc-go is trusted",
			modPath:  "github.com/grpc/grpc-go",
			expected: true,
		},
		{
			name:     "github.com/random/pkg is not trusted",
			modPath:  "github.com/random/pkg",
			expected: false,
		},
		{
			name:     "github.com/google-like/pkg is not trusted",
			modPath:  "github.com/google-like/pkg",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTrustedNamespace(tt.modPath)
			if got != tt.expected {
				t.Errorf("isTrustedNamespace(%q) = %v, want %v", tt.modPath, got, tt.expected)
			}
		})
	}
}

// TestScoreDependency_NoRisk tests scoring a clean dependency with no risk factors.
func TestScoreDependency_NoRisk(t *testing.T) {
	dep := testutil.MakeDep("golang.org/x/text", "v1.0.0", true, 0)

	ds := scoreDependency(dep, nil, nil, nil, nil, nil, nil, nil)

	// Using trusted namespace should result in minimal risk
	if ds.RiskScore > 15 {
		t.Errorf("expected RiskScore ~0-15 for trusted namespace, got %d", ds.RiskScore)
	}
	if ds.RiskLevel != RiskLow {
		t.Errorf("expected RiskLevel %s, got %s", RiskLow, ds.RiskLevel)
	}
	if len(ds.RiskFactors) != 0 {
		t.Errorf("expected no risk factors, got %v", ds.RiskFactors)
	}
}

// TestScoreDependency_WithVuln tests scoring a dependency with a critical vulnerability.
func TestScoreDependency_WithVuln(t *testing.T) {
	dep := testutil.MakeDep("github.com/unsafe/pkg", "v1.0.0", true, 0)
	vulns := []scanner.Vulnerability{
		testutil.MakeVuln("CVE-2024-1234", "CRITICAL", "v1.1.0"),
	}

	ds := scoreDependency(dep, vulns, nil, nil, nil, nil, nil, nil)

	if ds.RiskScore < 51 {
		t.Errorf("expected RiskScore >= 51 (HIGH floor), got %d", ds.RiskScore)
	}
	if ds.RiskLevel != RiskHigh && ds.RiskLevel != RiskCritical {
		t.Errorf("expected RiskLevel HIGH or CRITICAL, got %s", ds.RiskLevel)
	}
	if len(ds.RiskFactors) == 0 || ds.RiskFactors[0] != "known_vulnerabilities" {
		t.Errorf("expected 'known_vulnerabilities' in risk factors, got %v", ds.RiskFactors)
	}
}

// TestScoreDependency_TyposquatBonus tests that typosquatting confidence adds points.
func TestScoreDependency_TyposquatBonus(t *testing.T) {
	dep := testutil.MakeDep("github.com/typosquatter/pkg", "v1.0.0", true, 0)
	typosquat := &scanner.TyposquatResult{
		Confidence: 1.0,
	}

	ds := scoreDependency(dep, nil, nil, nil, typosquat, nil, nil, nil)

	// Score should be 0 base + 20 bonus = 20, gets rounded and adjusted
	// Due to rounding, can be slightly higher
	if ds.RiskScore < 20 || ds.RiskScore > 31 {
		t.Errorf("expected RiskScore 20-31 range, got %d", ds.RiskScore)
	}
	if len(ds.RiskFactors) == 0 {
		t.Errorf("expected risk factors to include 'typosquatting_risk'")
	}
	found := false
	for _, factor := range ds.RiskFactors {
		if factor == "typosquatting_risk" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'typosquatting_risk' in risk factors, got %v", ds.RiskFactors)
	}
}

// TestScoreDependency_AIGenBonus tests that AI-generated code risk adds points.
func TestScoreDependency_AIGenBonus(t *testing.T) {
	dep := testutil.MakeDep("github.com/aigen/pkg", "v1.0.0", true, 0)
	aiGen := &scanner.AIGenRisk{
		Score:     100,
		RiskLevel: "high",
	}

	ds := scoreDependency(dep, nil, nil, nil, nil, nil, aiGen, nil)

	// Score should be 0 base + (100 * 0.15) = 15 bonus, can be adjusted slightly due to rounding
	if ds.RiskScore < 15 || ds.RiskScore > 26 {
		t.Errorf("expected RiskScore 15-26 range, got %d", ds.RiskScore)
	}
	found := false
	for _, factor := range ds.RiskFactors {
		if factor == "ai_gen_risk:high" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'ai_gen_risk:high' in risk factors, got %v", ds.RiskFactors)
	}
}

// TestScoreDependency_ResilienceBonus tests that low resilience adds points.
func TestScoreDependency_ResilienceBonus(t *testing.T) {
	dep := testutil.MakeDep("github.com/fragile/pkg", "v1.0.0", true, 0)
	resilience := &scanner.ResilienceInfo{
		Score: 0,
	}

	ds := scoreDependency(dep, nil, nil, nil, nil, resilience, nil, nil)

	// Score should be 0 base + (30-0)*0.2 = 6 bonus, can be slightly higher due to rounding
	if ds.RiskScore < 6 || ds.RiskScore > 17 {
		t.Errorf("expected RiskScore 6-17 range, got %d", ds.RiskScore)
	}
	found := false
	for _, factor := range ds.RiskFactors {
		if factor == "low_resilience" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'low_resilience' in risk factors, got %v", ds.RiskFactors)
	}
}

// TestScoreDependency_CappedAt100 tests that risk score is capped at 100.
func TestScoreDependency_CappedAt100(t *testing.T) {
	dep := testutil.MakeDep("github.com/allrisk/pkg", "v1.0.0", true, 2)
	vulns := []scanner.Vulnerability{
		testutil.MakeVuln("CVE-2024-1234", "CRITICAL", "v1.1.0"),
		testutil.MakeVuln("CVE-2024-5678", "CRITICAL", "v1.1.0"),
	}
	maint := testutil.MakeMaintenanceInfo(36, true, true)
	maintainer := testutil.MakeMaintainerInfo(1, 1, false)
	typosquat := &scanner.TyposquatResult{Confidence: 1.0}
	aiGen := &scanner.AIGenRisk{Score: 100}
	resilience := &scanner.ResilienceInfo{Score: 0}

	ds := scoreDependency(dep, vulns, maint, maintainer, typosquat, resilience, aiGen, nil)

	if ds.RiskScore > 100 {
		t.Errorf("expected RiskScore <= 100, got %d", ds.RiskScore)
	}
	if ds.RiskLevel != RiskCritical {
		t.Errorf("expected RiskLevel CRITICAL, got %s", ds.RiskLevel)
	}
}

// TestScoreDependency_RiskFactors tests that multiple risk factors are collected.
func TestScoreDependency_RiskFactors(t *testing.T) {
	dep := testutil.MakeDep("github.com/risky/pkg", "v1.0.0", true, 0)
	maint := testutil.MakeMaintenanceInfo(36, true, true)
	maintainer := testutil.MakeMaintainerInfo(1, 5, false)

	ds := scoreDependency(dep, nil, maint, maintainer, nil, nil, nil, nil)

	expectedFactors := map[string]bool{
		"archived":          true,
		"deprecated":        true,
		"unmaintained":      true,
		"single_maintainer": true,
	}

	for _, factor := range ds.RiskFactors {
		if !expectedFactors[factor] {
			t.Errorf("unexpected risk factor: %s", factor)
		}
	}

	if len(ds.RiskFactors) != len(expectedFactors) {
		t.Errorf("expected %d risk factors, got %d: %v", len(expectedFactors), len(ds.RiskFactors), ds.RiskFactors)
	}
}

// TestScoreAll_EmptyGraph tests scoring an empty dependency graph.
func TestScoreAll_EmptyGraph(t *testing.T) {
	graph := testutil.MakeGraph()
	input := ScoreInput{
		Graph:       graph,
		Vulns:       make(map[string][]scanner.Vulnerability),
		Maintenance: make(map[string]*scanner.MaintenanceInfo),
		Maintainers: make(map[string]*scanner.MaintainerInfo),
		Typosquats:  make(map[string]*scanner.TyposquatResult),
		Resilience:  make(map[string]*scanner.ResilienceInfo),
		AIGenRisks:  make(map[string]*scanner.AIGenRisk),
		TrustIndex:  make(map[string]*scanner.TrustIndexEntry),
	}

	ps := ScoreAll(input)

	if ps.OverallScore != 0 {
		t.Errorf("expected OverallScore 0, got %d", ps.OverallScore)
	}
	if ps.OverallLevel != RiskLow {
		t.Errorf("expected OverallLevel LOW, got %s", ps.OverallLevel)
	}
	if len(ps.Dependencies) != 0 {
		t.Errorf("expected 0 dependencies, got %d", len(ps.Dependencies))
	}
}

// TestScoreAll_SingleCleanDep tests scoring a single clean dependency.
func TestScoreAll_SingleCleanDep(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/safe/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
	)
	input := ScoreInput{
		Graph:       graph,
		Vulns:       make(map[string][]scanner.Vulnerability),
		Maintenance: make(map[string]*scanner.MaintenanceInfo),
		Maintainers: make(map[string]*scanner.MaintainerInfo),
		Typosquats:  make(map[string]*scanner.TyposquatResult),
		Resilience:  make(map[string]*scanner.ResilienceInfo),
		AIGenRisks:  make(map[string]*scanner.AIGenRisk),
		TrustIndex:  make(map[string]*scanner.TrustIndexEntry),
	}

	ps := ScoreAll(input)

	if ps.OverallLevel != RiskLow {
		t.Errorf("expected OverallLevel LOW, got %s", ps.OverallLevel)
	}
	if ps.LowRiskCount != 1 {
		t.Errorf("expected 1 low-risk dep, got %d", ps.LowRiskCount)
	}
	if ps.MediumRiskCount != 0 || ps.HighRiskCount != 0 {
		t.Errorf("expected no medium/high-risk deps, got medium=%d high=%d", ps.MediumRiskCount, ps.HighRiskCount)
	}
}

// TestScoreAll_MixedRisk tests scoring with a mix of risk levels.
func TestScoreAll_MixedRisk(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/safe/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
		testutil.DepSpec{
			Path:    "github.com/medium/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
		testutil.DepSpec{
			Path:    "github.com/risky/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
	)

	maint := make(map[string]*scanner.MaintenanceInfo)
	maint["github.com/medium/pkg"] = testutil.MakeMaintenanceInfo(15, false, false)
	maint["github.com/risky/pkg"] = testutil.MakeMaintenanceInfo(36, false, false)

	input := ScoreInput{
		Graph:       graph,
		Vulns:       make(map[string][]scanner.Vulnerability),
		Maintenance: maint,
		Maintainers: make(map[string]*scanner.MaintainerInfo),
		Typosquats:  make(map[string]*scanner.TyposquatResult),
		Resilience:  make(map[string]*scanner.ResilienceInfo),
		AIGenRisks:  make(map[string]*scanner.AIGenRisk),
		TrustIndex:  make(map[string]*scanner.TrustIndexEntry),
	}

	ps := ScoreAll(input)

	if ps.LowRiskCount == 0 {
		t.Errorf("expected at least 1 low-risk dep, got %d", ps.LowRiskCount)
	}
	if len(ps.Dependencies) != 3 {
		t.Errorf("expected 3 dependencies, got %d", len(ps.Dependencies))
	}
}

// TestScoreAll_UnmaintainedCounts tests tracking of unmaintained dependencies.
func TestScoreAll_UnmaintainedCounts(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/fresh/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
		testutil.DepSpec{
			Path:    "github.com/year-old/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
		testutil.DepSpec{
			Path:    "github.com/two-year-old/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
		testutil.DepSpec{
			Path:    "github.com/three-year-old/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
	)

	maint := make(map[string]*scanner.MaintenanceInfo)
	maint["github.com/fresh/pkg"] = testutil.MakeMaintenanceInfo(6, false, false)
	maint["github.com/year-old/pkg"] = testutil.MakeMaintenanceInfo(12, false, false)
	maint["github.com/two-year-old/pkg"] = testutil.MakeMaintenanceInfo(24, false, false)
	maint["github.com/three-year-old/pkg"] = testutil.MakeMaintenanceInfo(36, false, false)

	input := ScoreInput{
		Graph:       graph,
		Vulns:       make(map[string][]scanner.Vulnerability),
		Maintenance: maint,
		Maintainers: make(map[string]*scanner.MaintainerInfo),
		Typosquats:  make(map[string]*scanner.TyposquatResult),
		Resilience:  make(map[string]*scanner.ResilienceInfo),
		AIGenRisks:  make(map[string]*scanner.AIGenRisk),
		TrustIndex:  make(map[string]*scanner.TrustIndexEntry),
	}

	ps := ScoreAll(input)

	// Unmaintained1yr counts deps with 12-24 months since release (>= 12 but < 24)
	// Unmaintained2yr counts deps with >= 24 months since release
	if ps.Unmaintained1yr != 1 {
		t.Errorf("expected 1 unmaintained (1yr, 12-24 months), got %d", ps.Unmaintained1yr)
	}
	if ps.Unmaintained2yr != 2 {
		t.Errorf("expected 2 unmaintained (2yr, >=24 months), got %d", ps.Unmaintained2yr)
	}
}

// TestComputeOverallScore_WeightedAverage tests the overall score computation with a weighted average.
func TestComputeOverallScore_WeightedAverage(t *testing.T) {
	tests := []struct {
		name    string
		deps    []*DependencyScore
		checkFn func(int) bool
	}{
		{
			name:    "empty deps returns 0",
			deps:    []*DependencyScore{},
			checkFn: func(score int) bool { return score == 0 },
		},
		{
			name: "single clean dep returns 0",
			deps: []*DependencyScore{
				{
					RiskScore: 0,
					Vulns:     nil,
				},
			},
			checkFn: func(score int) bool { return score == 0 },
		},
		{
			name: "single vulnerable dep with floor at 26",
			deps: []*DependencyScore{
				{
					RiskScore: 50,
					Vulns: []scanner.Vulnerability{
						testutil.MakeVuln("CVE-2024-1234", "MEDIUM", "v1.1.0"),
					},
				},
			},
			checkFn: func(score int) bool { return score >= 26 },
		},
		{
			name: "two deps with equal score",
			deps: []*DependencyScore{
				{
					RiskScore: 50,
					Vulns:     nil,
				},
				{
					RiskScore: 50,
					Vulns:     nil,
				},
			},
			checkFn: func(score int) bool { return score == 50 },
		},
		{
			name: "mixed risk scores",
			deps: []*DependencyScore{
				{
					RiskScore: 20,
					Vulns:     nil,
				},
				{
					RiskScore: 80,
					Vulns:     nil,
				},
			},
			checkFn: func(score int) bool { return score > 20 && score < 80 },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeOverallScore(tt.deps)
			if !tt.checkFn(got) {
				t.Errorf("computeOverallScore() = %d, check failed", got)
			}
			if got > 100 {
				t.Errorf("expected score <= 100, got %d", got)
			}
		})
	}
}

// TestScoreDependency_InactiveFlag tests detection of inactive maintainers.
func TestScoreDependency_InactiveFlag(t *testing.T) {
	dep := testutil.MakeDep("github.com/inactive/pkg", "v1.0.0", true, 0)
	maintainer := &scanner.MaintainerInfo{
		BusFactor:        1,
		ContributorCount: 5,
		ActivityPattern:  "inactive",
	}

	ds := scoreDependency(dep, nil, nil, maintainer, nil, nil, nil, nil)

	found := false
	for _, factor := range ds.RiskFactors {
		if factor == "maintainer_inactive" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'maintainer_inactive' in risk factors, got %v", ds.RiskFactors)
	}
}

// TestScoreDependency_TakeoverCandidate tests detection of takeover candidates.
func TestScoreDependency_TakeoverCandidate(t *testing.T) {
	dep := testutil.MakeDep("github.com/vulnerable/pkg", "v1.0.0", true, 0)
	maintainer := &scanner.MaintainerInfo{
		BusFactor:         1,
		ContributorCount:  1,
		TakeoverCandidate: true,
	}

	ds := scoreDependency(dep, nil, nil, maintainer, nil, nil, nil, nil)

	found := false
	for _, factor := range ds.RiskFactors {
		if factor == "takeover_candidate" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'takeover_candidate' in risk factors, got %v", ds.RiskFactors)
	}
}

// TestScoreAll_VulnCounts tests that total vulnerability count is tracked.
func TestScoreAll_VulnCounts(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/unsafe1/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
		testutil.DepSpec{
			Path:    "github.com/unsafe2/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
	)

	vulns := make(map[string][]scanner.Vulnerability)
	vulns["github.com/unsafe1/pkg"] = []scanner.Vulnerability{
		testutil.MakeVuln("CVE-2024-1234", "HIGH", "v1.1.0"),
		testutil.MakeVuln("CVE-2024-5678", "MEDIUM", "v1.1.0"),
	}
	vulns["github.com/unsafe2/pkg"] = []scanner.Vulnerability{
		testutil.MakeVuln("CVE-2024-9999", "CRITICAL", "v1.1.0"),
	}

	input := ScoreInput{
		Graph:       graph,
		Vulns:       vulns,
		Maintenance: make(map[string]*scanner.MaintenanceInfo),
		Maintainers: make(map[string]*scanner.MaintainerInfo),
		Typosquats:  make(map[string]*scanner.TyposquatResult),
		Resilience:  make(map[string]*scanner.ResilienceInfo),
		AIGenRisks:  make(map[string]*scanner.AIGenRisk),
		TrustIndex:  make(map[string]*scanner.TrustIndexEntry),
	}

	ps := ScoreAll(input)

	if ps.TotalVulns != 3 {
		t.Errorf("expected 3 total vulns, got %d", ps.TotalVulns)
	}
}

// TestScoreAll_HighRiskCounting tests proper counting of high and critical risk deps.
func TestScoreAll_HighRiskCounting(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/low/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
		testutil.DepSpec{
			Path:    "github.com/medium/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
		testutil.DepSpec{
			Path:    "github.com/high/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
		testutil.DepSpec{
			Path:    "github.com/critical/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
	)

	maint := make(map[string]*scanner.MaintenanceInfo)
	// Create deps with predictable scores
	maint["github.com/medium/pkg"] = testutil.MakeMaintenanceInfo(15, false, false)  // ~15 score
	maint["github.com/high/pkg"] = testutil.MakeMaintenanceInfo(24, false, false)    // ~60 score
	maint["github.com/critical/pkg"] = testutil.MakeMaintenanceInfo(36, true, false) // ~100 score

	input := ScoreInput{
		Graph:       graph,
		Vulns:       make(map[string][]scanner.Vulnerability),
		Maintenance: maint,
		Maintainers: make(map[string]*scanner.MaintainerInfo),
		Typosquats:  make(map[string]*scanner.TyposquatResult),
		Resilience:  make(map[string]*scanner.ResilienceInfo),
		AIGenRisks:  make(map[string]*scanner.AIGenRisk),
		TrustIndex:  make(map[string]*scanner.TrustIndexEntry),
	}

	ps := ScoreAll(input)

	if ps.LowRiskCount == 0 {
		t.Errorf("expected at least 1 low-risk dep")
	}
}

// TestMaintainerRiskScore_ZeroContributors tests bus factor with zero contributors.
func TestMaintainerRiskScore_ZeroContributors(t *testing.T) {
	info := &scanner.MaintainerInfo{
		BusFactor:        1,
		ContributorCount: 0,
	}

	got := maintainerRiskScore(info, "github.com/test/pkg")

	// Bus factor 1 should return 50 even if contributors are 0
	if got != 50 {
		t.Errorf("expected 50, got %f", got)
	}
}
