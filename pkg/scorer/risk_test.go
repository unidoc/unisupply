package scorer

import (
	"fmt"
	"testing"
	"time"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/resolver"
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
			// UNKNOWN weight changed to 40 (more conservative than the old 50,
			// reflecting the cost of not knowing how bad the CVE is).
			name: "unknown severity returns 40",
			vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-1234", "UNKNOWN", "v1.5.0"),
			},
			expected: 40,
		},
		{
			// Two CRITICALs: base=100, bonus=5×(2-1)=5 → capped at 100.
			name: "multiple CRITICAL vulnerabilities capped at 100",
			vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-1234", "CRITICAL", "v1.5.0"),
				testutil.MakeVuln("CVE-2024-5678", "CRITICAL", "v1.6.0"),
			},
			expected: 100,
		},
		{
			// max-plus-accumulator: base=max(50,25)=50; neither is HIGH-or-above,
			// so bonus=0. Total=50 (old sum=75).
			name: "multiple lower severity vulns use max not sum",
			vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-1234", "MEDIUM", "v1.5.0"),
				testutil.MakeVuln("CVE-2024-5678", "LOW", "v1.6.0"),
			},
			expected: 50, // max(MEDIUM=50, LOW=25) + 0 bonus
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

	ds := scoreDependency(dep, nil, nil, nil, nil, nil, nil, nil, time.Now())

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

	ds := scoreDependency(dep, vulns, nil, nil, nil, nil, nil, nil, time.Now())

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

	ds := scoreDependency(dep, nil, nil, nil, typosquat, nil, nil, nil, time.Now())

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

// TestScoreDependency_AIGenBonus tests that AI-generated code risk adds points
// and that the risk_factors entry is gated on MeetsPromotionGate.
func TestScoreDependency_AIGenBonus(t *testing.T) {
	dep := testutil.MakeDep("github.com/aigen/pkg", "v1.0.0", true, 0)

	t.Run("promotion_gate_true", func(t *testing.T) {
		aiGen := &scanner.AIGenRisk{
			Score:              100,
			RiskLevel:          "high",
			MeetsPromotionGate: true,
		}
		ds := scoreDependency(dep, nil, nil, nil, nil, nil, aiGen, nil, time.Now())

		// Score should be 0 base + (100 * 0.15) = 15 bonus.
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
			t.Errorf("expected 'ai_gen_risk:high' in risk factors when MeetsPromotionGate=true, got %v", ds.RiskFactors)
		}
	})

	t.Run("promotion_gate_false", func(t *testing.T) {
		// A non-zero score without the promotion gate still contributes the
		// weighted bonus but must NOT appear in risk_factors.
		aiGen := &scanner.AIGenRisk{
			Score:              100,
			RiskLevel:          "high",
			MeetsPromotionGate: false,
		}
		ds := scoreDependency(dep, nil, nil, nil, nil, nil, aiGen, nil, time.Now())

		// Bonus still applied.
		if ds.RiskScore < 15 {
			t.Errorf("expected weighted bonus even without promotion gate, got RiskScore %d", ds.RiskScore)
		}
		for _, factor := range ds.RiskFactors {
			if factor == "ai_gen_risk:high" {
				t.Errorf("ai_gen_risk must NOT appear in risk_factors when MeetsPromotionGate=false, got %v", ds.RiskFactors)
			}
		}
	})
}

// TestScoreDependency_ResilienceBonus tests that low resilience adds points.
func TestScoreDependency_ResilienceBonus(t *testing.T) {
	dep := testutil.MakeDep("github.com/fragile/pkg", "v1.0.0", true, 0)
	resilience := &scanner.ResilienceInfo{
		Score: 0,
	}

	ds := scoreDependency(dep, nil, nil, nil, nil, resilience, nil, nil, time.Now())

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

	ds := scoreDependency(dep, vulns, maint, maintainer, typosquat, resilience, aiGen, nil, time.Now())

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

	ds := scoreDependency(dep, nil, maint, maintainer, nil, nil, nil, nil, time.Now())

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
			// required-only vulns must not trigger the MEDIUM floor.
			// Mirrors the unitype scenario: one UNKNOWN/required CVE, low dep scores.
			name: "required-only vulns do not trigger floor",
			deps: []*DependencyScore{
				{
					RiskScore: 10,
					Vulns: []scanner.Vulnerability{
						{ID: "GO-2026-0001", Severity: "UNKNOWN", Reachability: "required"},
					},
				},
				{RiskScore: 5},
				{RiskScore: 8},
			},
			// Weighted mean ≈ 8; must stay below 26 because no called/imported vuln.
			checkFn: func(score int) bool { return score < 26 },
		},
		{
			// called vuln alongside required vulns still triggers the floor.
			name: "called vuln alongside required still triggers floor",
			deps: []*DependencyScore{
				{
					RiskScore: 10,
					Vulns: []scanner.Vulnerability{
						{ID: "GO-2026-0002", Severity: "UNKNOWN", Reachability: "required"},
						{ID: "GO-2026-0003", Severity: "LOW", Reachability: "called"},
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
		DataAvailable:    true,
		BusFactor:        1,
		ContributorCount: 5,
		ActivityPattern:  "inactive",
	}

	ds := scoreDependency(dep, nil, nil, maintainer, nil, nil, nil, nil, time.Now())

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
		DataAvailable:     true,
		BusFactor:         1,
		ContributorCount:  1,
		TakeoverCandidate: true,
	}

	ds := scoreDependency(dep, nil, nil, maintainer, nil, nil, nil, nil, time.Now())

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

	// HIGH and CRITICAL must be tracked separately — a HIGH-band dep (51-75)
	// must not be counted under CriticalRiskCount and vice versa.
	for _, ds := range ps.Dependencies {
		switch {
		case ds.RiskScore >= 76:
			if ps.CriticalRiskCount == 0 {
				t.Errorf("dep %s scored %d (CRITICAL) but CriticalRiskCount is 0", ds.Module, ds.RiskScore)
			}
		case ds.RiskScore >= 51:
			if ps.HighRiskCount == 0 {
				t.Errorf("dep %s scored %d (HIGH) but HighRiskCount is 0", ds.Module, ds.RiskScore)
			}
		}
	}

	total := ps.CriticalRiskCount + ps.HighRiskCount + ps.MediumRiskCount + ps.LowRiskCount
	if total != len(ps.Dependencies) {
		t.Errorf("bucket counts sum to %d, want %d", total, len(ps.Dependencies))
	}
}

// TestMaintainerRiskScore_ZeroContributors tests bus factor with zero contributors.
func TestMaintainerRiskScore_ZeroContributors(t *testing.T) {
	info := &scanner.MaintainerInfo{
		DataAvailable:    true,
		BusFactor:        1,
		ContributorCount: 0,
	}

	got := maintainerRiskScore(info, "github.com/test/pkg")

	// Bus factor 1 should return 50 even if contributors are 0
	if got != 50 {
		t.Errorf("expected 50, got %f", got)
	}
}

// TestMaintainerRiskScore_DataUnavailable verifies that a missing-data
// MaintainerInfo (DataAvailable == false) returns 0, not the "unknown" 30.
func TestMaintainerRiskScore_DataUnavailable(t *testing.T) {
	info := &scanner.MaintainerInfo{
		DataAvailable: false, // API call failed
		BusFactor:     0,
	}

	got := maintainerRiskScore(info, "github.com/test/pkg")

	if got != 0 {
		t.Errorf("maintainerRiskScore with DataAvailable=false = %f, want 0 (no penalty for missing data)", got)
	}
}

// TestScoreDependency_MaintainerDataUnavailable verifies that when maintainer
// DataAvailable is false the score uses the re-normalized 4-weight denominator.
//
// Construction: a module with only a maintenance signal (25 months → score=90)
// and no other risk signals.
//
// With nil maintainer (5 weights, denom=1.0):
//
//	maintainerRiskScore(nil, path) = 30 (unknown)
//	score = (0*0.40 + 90*0.25 + 0*0.15 + 30*0.10 + 0*0.10) / 1.0 = 25.5 → 26
//
// With DataAvailable=false (4 weights, denom=0.90):
//
//	maintainerRiskScore is excluded, denominator shrinks to 0.90
//	score = (0*0.40 + 90*0.25 + 0*0.15 + 0*0.10) / 0.90 = 25.0 → 25
//
// The re-normalization correctly removes the "unknown maintainer" penalty
// that would otherwise be applied to rate-limited modules.
func TestScoreDependency_MaintainerDataUnavailable(t *testing.T) {
	dep := testutil.MakeDep("github.com/test/pkg", "v1.0.0", true, 0)
	maint := testutil.MakeMaintenanceInfo(25, false, false) // maintenance score = 90

	// MaintainerInfo present but data unavailable (API returned 403).
	maintainerUnavailable := &scanner.MaintainerInfo{
		DataAvailable: false,
	}

	dsNilMaintainer := scoreDependency(dep, nil, maint, nil, nil, nil, nil, nil, time.Now())
	dsDataUnavailable := scoreDependency(dep, nil, maint, maintainerUnavailable, nil, nil, nil, nil, time.Now())

	// nil maintainer: 5-weight denominator, unknown penalty included → 26
	expectedNil := 26
	// DataAvailable=false: 4-weight denominator, no penalty → 25
	expectedUnavailable := 25

	if dsNilMaintainer.RiskScore != expectedNil {
		t.Errorf("nil maintainer score = %d, want %d (5-weight with unknown penalty)", dsNilMaintainer.RiskScore, expectedNil)
	}
	if dsDataUnavailable.RiskScore != expectedUnavailable {
		t.Errorf("DataAvailable=false score = %d, want %d (4-weight re-normalized)", dsDataUnavailable.RiskScore, expectedUnavailable)
	}
}

// TestScoreAll_WarningsPopulated verifies that ProjectScore.Warnings is
// populated when maintainer data is unavailable for at least one module.
func TestScoreAll_WarningsPopulated(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{Path: "github.com/test/pkg", Version: "v1.0.0", Direct: true, Depth: 0},
	)

	maintainers := map[string]*scanner.MaintainerInfo{
		"github.com/test/pkg": {DataAvailable: false},
	}

	ps := ScoreAll(ScoreInput{
		Graph:       graph,
		Vulns:       make(map[string][]scanner.Vulnerability),
		Maintenance: make(map[string]*scanner.MaintenanceInfo),
		Maintainers: maintainers,
		Typosquats:  make(map[string]*scanner.TyposquatResult),
		Resilience:  make(map[string]*scanner.ResilienceInfo),
		AIGenRisks:  make(map[string]*scanner.AIGenRisk),
		TrustIndex:  make(map[string]*scanner.TrustIndexEntry),
	})

	if len(ps.Warnings) == 0 {
		t.Errorf("expected Warnings to be populated when maintainer data is unavailable, got empty")
	}
}

// TestVulnScoreAccumulator covers the three acceptance-criteria accumulator cases:
//   - 1 CRITICAL → 100
//   - 3 HIGH → min(100, 80 + 5×2) = 90
//   - 1 CRITICAL + 5 LOW → 100 (CRITICAL dominates, LOWs not summed)
func TestVulnScoreAccumulator(t *testing.T) {
	tests := []struct {
		name     string
		vulns    []scanner.Vulnerability
		expected float64
	}{
		{
			name: "1 CRITICAL → vuln_score == 100",
			vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-0001", "CRITICAL", "v1.1.0"),
			},
			expected: 100,
		},
		{
			// base = 80 (HIGH), highOrAboveCount = 3, bonus = 5×(3-1) = 10
			// total = 80 + 10 = 90
			name: "3 HIGH → vuln_score == 90",
			vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-0001", "HIGH", "v1.1.0"),
				testutil.MakeVuln("CVE-2024-0002", "HIGH", "v1.1.0"),
				testutil.MakeVuln("CVE-2024-0003", "HIGH", "v1.1.0"),
			},
			expected: 90,
		},
		{
			// base = 100 (CRITICAL dominates max), highOrAboveCount = 1, bonus = 0
			// LOWs do NOT contribute to highOrAboveCount, so no bonus stacking
			// total = 100 + 0 = 100
			name: "1 CRITICAL + 5 LOW → vuln_score == 100 (CRITICAL dominates)",
			vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-0001", "CRITICAL", "v1.1.0"),
				testutil.MakeVuln("CVE-2024-0002", "LOW", ""),
				testutil.MakeVuln("CVE-2024-0003", "LOW", ""),
				testutil.MakeVuln("CVE-2024-0004", "LOW", ""),
				testutil.MakeVuln("CVE-2024-0005", "LOW", ""),
				testutil.MakeVuln("CVE-2024-0006", "LOW", ""),
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

// TestSeverityFloor verifies that the severity-derived floor and risk_level
// promotion work correctly for all four severity bands.
func TestSeverityFloor(t *testing.T) {
	tests := []struct {
		name          string
		vulns         []scanner.Vulnerability
		wantMinScore  int
		wantRiskLevel RiskLevel
	}{
		{
			name:          "CRITICAL CVE → floor 51, risk_level CRITICAL",
			vulns:         []scanner.Vulnerability{testutil.MakeVuln("CVE-2024-0001", "CRITICAL", "v1.1.0")},
			wantMinScore:  51,
			wantRiskLevel: RiskCritical,
		},
		{
			name:          "HIGH CVE → floor 51, risk_level HIGH minimum",
			vulns:         []scanner.Vulnerability{testutil.MakeVuln("CVE-2024-0001", "HIGH", "v1.1.0")},
			wantMinScore:  51,
			wantRiskLevel: RiskHigh,
		},
		{
			name:          "MEDIUM CVE → floor 26, risk_level MEDIUM minimum",
			vulns:         []scanner.Vulnerability{testutil.MakeVuln("CVE-2024-0001", "MEDIUM", "v1.1.0")},
			wantMinScore:  26,
			wantRiskLevel: RiskMedium,
		},
		{
			// LOW CVE with no age signal: no floor applied, risk_level stays LOW.
			// Use a fresh dep so the base weighted score is LOW.
			name:          "LOW CVE (no age) → no floor, risk_level LOW",
			vulns:         []scanner.Vulnerability{testutil.MakeVuln("CVE-2024-0001", "LOW", "")},
			wantMinScore:  0, // floor check: must not raise to ≥26
			wantRiskLevel: RiskLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := testutil.MakeDep("github.com/test/pkg", "v1.0.0", true, 0)
			ds := scoreDependency(dep, tt.vulns, nil, nil, nil, nil, nil, nil, time.Now())

			if tt.wantMinScore > 0 && ds.RiskScore < tt.wantMinScore {
				t.Errorf("RiskScore = %d, want >= %d", ds.RiskScore, tt.wantMinScore)
			}
			// For LOW with no age signal, verify it does NOT get elevated to MEDIUM.
			if tt.wantRiskLevel == RiskLow && ds.RiskLevel != RiskLow {
				t.Errorf("RiskLevel = %s, want LOW (no floor for bare LOW CVE)", ds.RiskLevel)
			}
			// For CRITICAL/HIGH/MEDIUM, verify promotion is correct.
			if tt.wantRiskLevel != RiskLow && ds.RiskLevel != tt.wantRiskLevel {
				t.Errorf("RiskLevel = %s, want %s", ds.RiskLevel, tt.wantRiskLevel)
			}
		})
	}
}

// TestLowFixAge covers the fix-age amplifier for LOW-severity CVEs.
func TestLowFixAge(t *testing.T) {
	t.Run("LOW with fix 400 days ago → RiskScore >= 26", func(t *testing.T) {
		dep := testutil.MakeDep("github.com/test/pkg", "v1.0.0", true, 0)
		vuln := testutil.MakeVulnWithDates("CVE-2024-0001", "LOW", 500, 400, false)
		ds := scoreDependency(dep, []scanner.Vulnerability{vuln}, nil, nil, nil, nil, nil, nil, time.Now())

		if ds.RiskScore < 26 {
			t.Errorf("RiskScore = %d, want >= 26 (fix available 400 days ago)", ds.RiskScore)
		}
	})

	t.Run("LOW with fix 10 days ago → no amplifier floor", func(t *testing.T) {
		dep := testutil.MakeDep("github.com/test/pkg", "v1.0.0", true, 0)
		vuln := testutil.MakeVulnWithDates("CVE-2024-0001", "LOW", 30, 10, false)
		ds := scoreDependency(dep, []scanner.Vulnerability{vuln}, nil, nil, nil, nil, nil, nil, time.Now())

		// 10 days is below the 30-day threshold: amplifier must NOT raise to 26.
		if ds.RiskScore >= 26 {
			t.Errorf("RiskScore = %d, want < 26 (fix only 10 days old, no amplifier floor)", ds.RiskScore)
		}
	})
}

// TestUnknownSeverityFloor verifies that an UNKNOWN-severity CVE with
// EnrichmentFailed=true gets a conservative MEDIUM floor (>= 26).
func TestUnknownSeverityFloor(t *testing.T) {
	dep := testutil.MakeDep("github.com/test/pkg", "v1.0.0", true, 0)
	vuln := testutil.MakeVulnWithDates("CVE-2024-0001", "UNKNOWN", 90, 0, true)
	// EnrichmentFailed = true, so the scorer must apply the conservative MEDIUM floor.
	ds := scoreDependency(dep, []scanner.Vulnerability{vuln}, nil, nil, nil, nil, nil, nil, time.Now())

	if ds.RiskScore < 26 {
		t.Errorf("RiskScore = %d, want >= 26 (conservative floor for enrichment-failed UNKNOWN)", ds.RiskScore)
	}
}

// TestVulnScore_Unknown_DefaultsToMedium verifies that an UNKNOWN-severity CVE
// with empty reachability (unconfirmed) scores as MEDIUM in both the per-dep
// floor and the project-level step function.
func TestVulnScore_Unknown_DefaultsToMedium(t *testing.T) {
	headline := testutil.DepSpec{
		Path: "github.com/unknownsev/pkg", Version: "v1.0.0",
		Direct: true, Depth: 0, IsTestOnly: testutil.BoolPtr(false),
	}
	graph := testutil.MakeGraph(twoAxisCleanDeps(50, headline)...)
	input := twoAxisEmptyInput(graph)

	v := testutil.MakeVulnWithDates("CVE-2024-0001", "UNKNOWN", 90, 0, true)
	v.Reachability = "" // unconfirmed — must NOT escalate to HIGH
	input.Vulns["github.com/unknownsev/pkg"] = []scanner.Vulnerability{v}

	ps := ScoreAll(input)

	if ps.SeverityAdjustedVulnScore != 40 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 40 (UNKNOWN + empty reachability → MEDIUM step)", ps.SeverityAdjustedVulnScore)
	}
	for _, dep := range ps.Dependencies {
		if dep.Module == "github.com/unknownsev/pkg" {
			if dep.RiskLevel != RiskMedium {
				t.Errorf("dep RiskLevel = %s, want MEDIUM", dep.RiskLevel)
			}
		}
	}
}

// TestVulnScore_Unknown_ReachableTreatedAsHigh verifies that an UNKNOWN-severity
// CVE with confirmed reachability ("called") escalates to HIGH in both the
// per-dep floor and the project-level step function.
func TestVulnScore_Unknown_ReachableTreatedAsHigh(t *testing.T) {
	headline := testutil.DepSpec{
		Path: "github.com/unknownsev/pkg", Version: "v1.0.0",
		Direct: true, Depth: 0, IsTestOnly: testutil.BoolPtr(false),
	}
	graph := testutil.MakeGraph(twoAxisCleanDeps(50, headline)...)
	input := twoAxisEmptyInput(graph)

	v := testutil.MakeVulnWithDates("CVE-2024-0002", "UNKNOWN", 90, 0, true)
	v.Reachability = "called" // confirmed reachable → pessimistic HIGH
	input.Vulns["github.com/unknownsev/pkg"] = []scanner.Vulnerability{v}

	ps := ScoreAll(input)

	if ps.SeverityAdjustedVulnScore != 70 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 70 (UNKNOWN + called → HIGH, stepFunction(High:1)=70)", ps.SeverityAdjustedVulnScore)
	}
	for _, dep := range ps.Dependencies {
		if dep.Module == "github.com/unknownsev/pkg" {
			if dep.RiskLevel != RiskHigh {
				t.Errorf("dep RiskLevel = %s, want HIGH", dep.RiskLevel)
			}
		}
	}
}

// TestScoreAll_NoWarningsWhenDataAvailable verifies that Warnings is empty
// when all maintainer data was successfully fetched.
func TestScoreAll_NoWarningsWhenDataAvailable(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{Path: "github.com/test/pkg", Version: "v1.0.0", Direct: true, Depth: 0},
	)

	maintainers := map[string]*scanner.MaintainerInfo{
		"github.com/test/pkg": testutil.MakeMaintainerInfo(3, 10, true),
	}

	ps := ScoreAll(ScoreInput{
		Graph:       graph,
		Vulns:       make(map[string][]scanner.Vulnerability),
		Maintenance: make(map[string]*scanner.MaintenanceInfo),
		Maintainers: maintainers,
		Typosquats:  make(map[string]*scanner.TyposquatResult),
		Resilience:  make(map[string]*scanner.ResilienceInfo),
		AIGenRisks:  make(map[string]*scanner.AIGenRisk),
		TrustIndex:  make(map[string]*scanner.TrustIndexEntry),
	})

	if len(ps.Warnings) != 0 {
		t.Errorf("expected no Warnings when all maintainer data available, got %v", ps.Warnings)
	}
}

// =============================================================================
// Task 10 — Two-axis aggregate score.
//
// The headline is OverallScore = max(MeanDepRiskScore, SeverityAdjustedVulnScore).
// SeverityAdjustedVulnScore is a CVE-driven step function with a test-only
// downgrade-then-step applied before counting. The tests below cover the seven
// acceptance criteria from plan-29 task 10.
// =============================================================================

// twoAxisCleanDeps builds a graph with n clean-but-not-trusted dependencies
// plus one "headline" dependency. The clean deps are designed to keep the
// weighted-mean axis well below LOW (so the severity-adjusted axis is what
// drives the headline). Each clean dep gets a depth-0 entry with no
// maintenance/maintainer/typosquat/etc. signals.
func twoAxisCleanDeps(n int, headline testutil.DepSpec) []testutil.DepSpec {
	specs := make([]testutil.DepSpec, 0, n+1)
	specs = append(specs, headline)
	for i := 0; i < n; i++ {
		specs = append(specs, testutil.DepSpec{
			Path:    fmt.Sprintf("github.com/clean/pkg%d", i),
			Version: "v1.0.0",
			Direct:  false,
			Depth:   0,
		})
	}
	return specs
}

func twoAxisEmptyInput(graph *resolver.Graph) ScoreInput {
	return ScoreInput{
		Graph:       graph,
		Vulns:       make(map[string][]scanner.Vulnerability),
		Maintenance: make(map[string]*scanner.MaintenanceInfo),
		Maintainers: make(map[string]*scanner.MaintainerInfo),
		Typosquats:  make(map[string]*scanner.TyposquatResult),
		Resilience:  make(map[string]*scanner.ResilienceInfo),
		AIGenRisks:  make(map[string]*scanner.AIGenRisk),
		TrustIndex:  make(map[string]*scanner.TrustIndexEntry),
	}
}

// TestTwoAxis_CriticalOnProdPath verifies that a single CRITICAL CVE on a
// production-path dep produces overall_risk_score == 95, level CRITICAL, and
// headline_driver == "severity_adjusted" — regardless of how many clean deps
// surround it.
func TestTwoAxis_CriticalOnProdPath(t *testing.T) {
	headline := testutil.DepSpec{
		Path:       "github.com/risky/pkg",
		Version:    "v1.0.0",
		Direct:     true,
		Depth:      0,
		IsTestOnly: testutil.BoolPtr(false), // confirmed production
	}
	graph := testutil.MakeGraph(twoAxisCleanDeps(100, headline)...)

	input := twoAxisEmptyInput(graph)
	input.Vulns["github.com/risky/pkg"] = []scanner.Vulnerability{
		testutil.MakeVuln("CVE-2024-9999", "CRITICAL", "v1.0.1"),
	}

	ps := ScoreAll(input)

	if ps.SeverityAdjustedVulnScore != 95 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 95", ps.SeverityAdjustedVulnScore)
	}
	if ps.OverallScore != 95 {
		t.Errorf("OverallScore = %d, want 95", ps.OverallScore)
	}
	if ps.OverallLevel != RiskCritical {
		t.Errorf("OverallLevel = %s, want CRITICAL", ps.OverallLevel)
	}
	if ps.HeadlineDriver != "severity_adjusted" {
		t.Errorf("HeadlineDriver = %q, want %q", ps.HeadlineDriver, "severity_adjusted")
	}
	if ps.WorstCVEID != "CVE-2024-9999" {
		t.Errorf("WorstCVEID = %q, want CVE-2024-9999", ps.WorstCVEID)
	}
	if ps.WorstCVESeverity != "CRITICAL" {
		t.Errorf("WorstCVESeverity = %q, want CRITICAL", ps.WorstCVESeverity)
	}
}

// TestTwoAxis_CriticalOnTestOnly verifies the downgrade-then-step rule: a
// CRITICAL on a test_only==true dep is downgraded to HIGH, the step function
// fires "1–2 HIGH → 70", and the headline is 70 — NOT a halving (which would
// give 47.5).
func TestTwoAxis_CriticalOnTestOnly(t *testing.T) {
	headline := testutil.DepSpec{
		Path:       "github.com/risky/pkg",
		Version:    "v1.0.0",
		Direct:     false,
		Depth:      2,
		IsTestOnly: testutil.BoolPtr(true), // confirmed test-only
	}
	graph := testutil.MakeGraph(twoAxisCleanDeps(100, headline)...)

	input := twoAxisEmptyInput(graph)
	input.Vulns["github.com/risky/pkg"] = []scanner.Vulnerability{
		testutil.MakeVuln("CVE-2024-9999", "CRITICAL", "v1.0.1"),
	}

	ps := ScoreAll(input)

	if ps.SeverityAdjustedVulnScore != 70 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 70 (CRITICAL→HIGH downgrade → 1 HIGH)", ps.SeverityAdjustedVulnScore)
	}
	if ps.SeverityAdjustedVulnScore == 47 || ps.SeverityAdjustedVulnScore == 48 {
		t.Errorf("SeverityAdjustedVulnScore looks like a halving, not a tier downgrade")
	}
	if ps.OverallScore != 70 {
		t.Errorf("OverallScore = %d, want 70", ps.OverallScore)
	}
	if ps.OverallLevel != RiskHigh {
		t.Errorf("OverallLevel = %s, want HIGH", ps.OverallLevel)
	}
	if ps.WorstCVESeverity != "HIGH" {
		t.Errorf("WorstCVESeverity = %q, want HIGH (post-downgrade)", ps.WorstCVESeverity)
	}
}

// TestTwoAxis_CriticalOnUnknownTestOnly verifies the Task 09 fallback: when
// IsTestOnly is nil (classification was unavailable), the discount MUST NOT
// apply. Score stays at 95 (CRITICAL).
func TestTwoAxis_CriticalOnUnknownTestOnly(t *testing.T) {
	headline := testutil.DepSpec{
		Path:       "github.com/risky/pkg",
		Version:    "v1.0.0",
		Direct:     false,
		Depth:      2,
		IsTestOnly: nil, // classification unavailable
	}
	graph := testutil.MakeGraph(twoAxisCleanDeps(100, headline)...)

	input := twoAxisEmptyInput(graph)
	input.Vulns["github.com/risky/pkg"] = []scanner.Vulnerability{
		testutil.MakeVuln("CVE-2024-9999", "CRITICAL", "v1.0.1"),
	}

	ps := ScoreAll(input)

	if ps.SeverityAdjustedVulnScore != 95 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 95 (no discount when IsTestOnly is nil)", ps.SeverityAdjustedVulnScore)
	}
	if ps.OverallLevel != RiskCritical {
		t.Errorf("OverallLevel = %s, want CRITICAL", ps.OverallLevel)
	}
}

// TestTwoAxis_NoCVEsManyDeps verifies that a graph with no CVEs but 500
// clean-but-not-trusted dependencies stays at LOW. The previous max/p95-based
// formula over-promoted such projects; the mean axis correctly dilutes them.
func TestTwoAxis_NoCVEsManyDeps(t *testing.T) {
	specs := make([]testutil.DepSpec, 500)
	for i := range specs {
		specs[i] = testutil.DepSpec{
			Path:    fmt.Sprintf("github.com/clean/pkg%d", i),
			Version: "v1.0.0",
			Direct:  false,
			Depth:   0,
		}
	}
	graph := testutil.MakeGraph(specs...)

	ps := ScoreAll(twoAxisEmptyInput(graph))

	if ps.SeverityAdjustedVulnScore != 0 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 0 (no CVEs)", ps.SeverityAdjustedVulnScore)
	}
	if ps.OverallLevel != RiskLow {
		t.Errorf("OverallLevel = %s, want LOW (500 stale-but-inert deps)", ps.OverallLevel)
	}
	if ps.HeadlineDriver != "mean" {
		t.Errorf("HeadlineDriver = %q, want %q (mean drives when severity_adjusted == 0)", ps.HeadlineDriver, "mean")
	}
}

// TestTwoAxis_EnrichmentFailedCounts verifies that a CVE whose enrichment
// failed (severity stayed UNKNOWN) is counted as MEDIUM in the step function,
// producing severity_adjusted == 40.
func TestTwoAxis_EnrichmentFailedCounts(t *testing.T) {
	headline := testutil.DepSpec{
		Path:       "github.com/unknownseverity/pkg",
		Version:    "v1.0.0",
		Direct:     true,
		Depth:      0,
		IsTestOnly: testutil.BoolPtr(false),
	}
	graph := testutil.MakeGraph(twoAxisCleanDeps(50, headline)...)

	input := twoAxisEmptyInput(graph)
	// EnrichmentFailed=true with UNKNOWN severity — the canonical Task 07
	// fallback case.
	input.Vulns["github.com/unknownseverity/pkg"] = []scanner.Vulnerability{
		testutil.MakeVulnWithDates("CVE-2024-0000", "UNKNOWN", 90, 0, true),
	}

	ps := ScoreAll(input)

	if ps.SeverityAdjustedVulnScore != 40 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 40 (enrichment-failed UNKNOWN → MEDIUM in step function)", ps.SeverityAdjustedVulnScore)
	}
	if ps.OverallLevel != RiskMedium {
		t.Errorf("OverallLevel = %s, want MEDIUM", ps.OverallLevel)
	}
}

// TestTwoAxis_HeadlineDriverPopulated verifies that HeadlineDriver is set
// correctly across the no-CVE, CVE-dominates, and equal-score cases.
func TestTwoAxis_HeadlineDriverPopulated(t *testing.T) {
	t.Run("severity_adjusted wins", func(t *testing.T) {
		headline := testutil.DepSpec{
			Path: "github.com/risky/pkg", Version: "v1.0.0", Direct: true, Depth: 0,
			IsTestOnly: testutil.BoolPtr(false),
		}
		graph := testutil.MakeGraph(twoAxisCleanDeps(100, headline)...)
		input := twoAxisEmptyInput(graph)
		input.Vulns["github.com/risky/pkg"] = []scanner.Vulnerability{
			testutil.MakeVuln("CVE-2024-1", "CRITICAL", "v1.0.1"),
		}
		ps := ScoreAll(input)
		if ps.HeadlineDriver != "severity_adjusted" {
			t.Errorf("HeadlineDriver = %q, want severity_adjusted", ps.HeadlineDriver)
		}
	})

	t.Run("mean wins when no CVEs", func(t *testing.T) {
		graph := testutil.MakeGraph(testutil.DepSpec{
			Path: "github.com/test/pkg", Version: "v1.0.0", Direct: true, Depth: 0,
		})
		ps := ScoreAll(twoAxisEmptyInput(graph))
		if ps.HeadlineDriver != "mean" {
			t.Errorf("HeadlineDriver = %q, want mean (no CVEs)", ps.HeadlineDriver)
		}
	})

	t.Run("empty graph has empty driver", func(t *testing.T) {
		graph := testutil.MakeGraph()
		ps := ScoreAll(twoAxisEmptyInput(graph))
		if ps.HeadlineDriver != "" {
			t.Errorf("HeadlineDriver = %q, want empty (no deps)", ps.HeadlineDriver)
		}
	})
}

// TestTwoAxis_WorstCVEPopulated verifies that WorstCVEID is the most-severe
// post-downgrade CVE across all deps.
func TestTwoAxis_WorstCVEPopulated(t *testing.T) {
	headline := testutil.DepSpec{
		Path: "github.com/multi/pkg", Version: "v1.0.0", Direct: true, Depth: 0,
		IsTestOnly: testutil.BoolPtr(false),
	}
	graph := testutil.MakeGraph(twoAxisCleanDeps(10, headline)...)

	input := twoAxisEmptyInput(graph)
	input.Vulns["github.com/multi/pkg"] = []scanner.Vulnerability{
		testutil.MakeVuln("CVE-2024-LOW", "LOW", ""),
		testutil.MakeVuln("CVE-2024-CRIT", "CRITICAL", "v1.0.1"),
		testutil.MakeVuln("CVE-2024-MED", "MEDIUM", "v1.0.1"),
	}

	ps := ScoreAll(input)

	if ps.WorstCVEID != "CVE-2024-CRIT" {
		t.Errorf("WorstCVEID = %q, want CVE-2024-CRIT", ps.WorstCVEID)
	}
	if ps.WorstCVESeverity != "CRITICAL" {
		t.Errorf("WorstCVESeverity = %q, want CRITICAL", ps.WorstCVESeverity)
	}
}

// TestTwoAxis_MeanWinsWhenLargerThanSeverity verifies that the mean axis can
// drive the headline when it exceeds the severity-adjusted axis (e.g. many
// archived deps without CVEs).
func TestTwoAxis_MeanWinsWhenLargerThanSeverity(t *testing.T) {
	// 3 archived deps — each scores ~40 via maintenance, no CVEs.
	graph := testutil.MakeGraph(
		testutil.DepSpec{Path: "github.com/old/pkg1", Version: "v1.0.0", Direct: true, Depth: 0},
		testutil.DepSpec{Path: "github.com/old/pkg2", Version: "v1.0.0", Direct: true, Depth: 0},
		testutil.DepSpec{Path: "github.com/old/pkg3", Version: "v1.0.0", Direct: true, Depth: 0},
	)
	input := twoAxisEmptyInput(graph)
	input.Maintenance["github.com/old/pkg1"] = testutil.MakeMaintenanceInfo(36, true, false)
	input.Maintenance["github.com/old/pkg2"] = testutil.MakeMaintenanceInfo(36, true, false)
	input.Maintenance["github.com/old/pkg3"] = testutil.MakeMaintenanceInfo(36, true, false)

	ps := ScoreAll(input)

	if ps.SeverityAdjustedVulnScore != 0 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 0 (no CVEs)", ps.SeverityAdjustedVulnScore)
	}
	if ps.MeanDepRiskScore == 0 {
		t.Errorf("MeanDepRiskScore = 0, expected >0 (archived deps)")
	}
	if ps.HeadlineDriver != "mean" {
		t.Errorf("HeadlineDriver = %q, want mean", ps.HeadlineDriver)
	}
	if ps.OverallScore != ps.MeanDepRiskScore {
		t.Errorf("OverallScore = %d, want MeanDepRiskScore = %d", ps.OverallScore, ps.MeanDepRiskScore)
	}
}

// TestTwoAxis_DebugScoringOptIn verifies that DebugScoring is populated only
// when ScoreInput.DebugMode is true. The block is non-normative.
func TestTwoAxis_DebugScoringOptIn(t *testing.T) {
	graph := testutil.MakeGraph(testutil.DepSpec{
		Path: "github.com/x/pkg", Version: "v1.0.0", Direct: true, Depth: 0,
		IsTestOnly: testutil.BoolPtr(false),
	})
	input := twoAxisEmptyInput(graph)
	input.Vulns["github.com/x/pkg"] = []scanner.Vulnerability{
		testutil.MakeVuln("CVE-2024-1", "HIGH", "v1.0.1"),
	}

	t.Run("DebugMode off", func(t *testing.T) {
		input.DebugMode = false
		ps := ScoreAll(input)
		if ps.DebugScoring != nil {
			t.Errorf("DebugScoring should be nil when DebugMode is false")
		}
	})

	t.Run("DebugMode on", func(t *testing.T) {
		input.DebugMode = true
		ps := ScoreAll(input)
		if ps.DebugScoring == nil {
			t.Fatal("DebugScoring should be populated when DebugMode is true")
		}
		if ps.DebugScoring.StepFunctionInputs.High != 1 {
			t.Errorf("StepFunctionInputs.High = %d, want 1", ps.DebugScoring.StepFunctionInputs.High)
		}
		if len(ps.DebugScoring.EnrichedCVEs) != 1 {
			t.Errorf("len(EnrichedCVEs) = %d, want 1", len(ps.DebugScoring.EnrichedCVEs))
		}
		if len(ps.DebugScoring.PerDepInputs) != 1 {
			t.Errorf("len(PerDepInputs) = %d, want 1", len(ps.DebugScoring.PerDepInputs))
		}
	})
}

// TestTwoAxis_DiagnosticsPopulated verifies that the Diagnostics block carries
// MaxDepRiskScore and P95DepRiskScore for non-empty graphs. The block is
// non-normative — these tests guard the shape, not the policy.
func TestTwoAxis_DiagnosticsPopulated(t *testing.T) {
	t.Run("populated for non-empty graph", func(t *testing.T) {
		graph := testutil.MakeGraph(testutil.DepSpec{
			Path: "github.com/x/pkg", Version: "v1.0.0", Direct: true, Depth: 0,
		})
		ps := ScoreAll(twoAxisEmptyInput(graph))
		if ps.Diagnostics == nil {
			t.Fatal("Diagnostics should be populated for non-empty graph")
		}
	})

	t.Run("nil for empty graph", func(t *testing.T) {
		graph := testutil.MakeGraph()
		ps := ScoreAll(twoAxisEmptyInput(graph))
		if ps.Diagnostics != nil {
			t.Errorf("Diagnostics should be nil for empty graph, got %+v", ps.Diagnostics)
		}
	})
}

// TestScoreAll_DeterministicWorstCVE verifies that ScoreAll produces identical
// output across consecutive invocations on the same input, even when two
// dependencies each carry a disjoint CRITICAL CVE (forcing the tie-breaker in
// severityAdjustedVulnScore to operate). The test guards against regressions to
// the non-deterministic map-iteration behavior that was present before the
// sorted-keys fix in ScoreAll.
func TestScoreAll_DeterministicWorstCVE(t *testing.T) {
	// Two deps with distinct CRITICAL CVE IDs on disjoint OSV IDs. The
	// tie-breaker must always choose the CVE from the lexicographically earlier
	// module ("github.com/alpha/pkg" < "github.com/zeta/pkg").
	depAlpha := testutil.DepSpec{
		Path:       "github.com/alpha/pkg",
		Version:    "v1.0.0",
		Direct:     true,
		Depth:      0,
		IsTestOnly: testutil.BoolPtr(false),
	}
	depZeta := testutil.DepSpec{
		Path:       "github.com/zeta/pkg",
		Version:    "v2.0.0",
		Direct:     true,
		Depth:      0,
		IsTestOnly: testutil.BoolPtr(false),
	}
	graph := testutil.MakeGraph(depAlpha, depZeta)

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
	// Each dep has exactly one CRITICAL CVE with a disjoint OSV ID so the
	// tie-breaker cannot fall through to a lower severity.
	input.Vulns["github.com/alpha/pkg"] = []scanner.Vulnerability{
		testutil.MakeVuln("GO-2024-0001", "CRITICAL", "v1.0.1"),
	}
	input.Vulns["github.com/zeta/pkg"] = []scanner.Vulnerability{
		testutil.MakeVuln("GO-2024-9999", "CRITICAL", "v2.0.1"),
	}

	// Run ScoreAll ten times and assert that all results are identical.
	const runs = 10
	first := ScoreAll(input)

	for i := 1; i < runs; i++ {
		got := ScoreAll(input)

		if got.WorstCVEID != first.WorstCVEID {
			t.Errorf("run %d: WorstCVEID = %q, want %q (non-deterministic tie-breaker)",
				i+1, got.WorstCVEID, first.WorstCVEID)
		}

		if len(got.Dependencies) != len(first.Dependencies) {
			t.Fatalf("run %d: len(Dependencies) = %d, want %d",
				i+1, len(got.Dependencies), len(first.Dependencies))
		}
		for j, ds := range got.Dependencies {
			if ds.Module != first.Dependencies[j].Module {
				t.Errorf("run %d: Dependencies[%d].Module = %q, want %q (non-deterministic order)",
					i+1, j, ds.Module, first.Dependencies[j].Module)
			}
		}
	}

	// The tie-breaker must consistently pick the CVE from the
	// lexicographically earlier module path.
	if first.WorstCVEID != "GO-2024-0001" {
		t.Errorf("WorstCVEID = %q, want GO-2024-0001 (alpha < zeta)", first.WorstCVEID)
	}

	// Dependencies must be in sorted module-path order.
	if len(first.Dependencies) != 2 {
		t.Fatalf("len(Dependencies) = %d, want 2", len(first.Dependencies))
	}
	if first.Dependencies[0].Module != "github.com/alpha/pkg" {
		t.Errorf("Dependencies[0].Module = %q, want github.com/alpha/pkg", first.Dependencies[0].Module)
	}
	if first.Dependencies[1].Module != "github.com/zeta/pkg" {
		t.Errorf("Dependencies[1].Module = %q, want github.com/zeta/pkg", first.Dependencies[1].Module)
	}
}

// makeVulnWithReachability constructs a scanner.Vulnerability with the given
// id, severity, and reachability tier. All other fields are left at zero
// values.
func makeVulnWithReachability(id, severity, reachability string) scanner.Vulnerability {
	return scanner.Vulnerability{
		ID:           id,
		Severity:     severity,
		Reachability: reachability,
	}
}

// reachabilityScoreInput builds a ScoreInput containing a single dep at the
// given module path with the provided vulns. It uses 0 clean background deps
// so the step function is driven only by the supplied CVEs.
func reachabilityScoreInput(modPath string, isTestOnly *bool, vulns []scanner.Vulnerability) ScoreInput {
	spec := testutil.DepSpec{
		Path:       modPath,
		Version:    "v1.0.0",
		Direct:     true,
		Depth:      0,
		IsTestOnly: isTestOnly,
	}
	graph := testutil.MakeGraph(spec)
	input := ScoreInput{
		Graph:       graph,
		Vulns:       map[string][]scanner.Vulnerability{modPath: vulns},
		Maintenance: make(map[string]*scanner.MaintenanceInfo),
		Maintainers: make(map[string]*scanner.MaintainerInfo),
		Typosquats:  make(map[string]*scanner.TyposquatResult),
		Resilience:  make(map[string]*scanner.ResilienceInfo),
		AIGenRisks:  make(map[string]*scanner.AIGenRisk),
		TrustIndex:  make(map[string]*scanner.TrustIndexEntry),
	}
	return input
}

// ---------------------------------------------------------------------------
// Step-function tests: reachability downgrade in severityAdjustedVulnScore
// ---------------------------------------------------------------------------

// TestSeverityAdjusted_SingleCalledCritical_StaysAt95 verifies that a called
// (or empty-Reachability) CRITICAL CVE passes through the step function
// unchanged and produces severity_adjusted == 95.
func TestSeverityAdjusted_SingleCalledCritical_StaysAt95(t *testing.T) {
	input := reachabilityScoreInput(
		"github.com/risky/pkg",
		testutil.BoolPtr(false),
		[]scanner.Vulnerability{
			makeVulnWithReachability("CVE-2024-0001", "CRITICAL", "called"),
		},
	)
	ps := ScoreAll(input)
	if ps.SeverityAdjustedVulnScore != 95 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 95 (called CRITICAL → no downgrade → step CRITICAL → 95)",
			ps.SeverityAdjustedVulnScore)
	}
}

// TestSeverityAdjusted_SingleImportedCritical_Becomes70 verifies that a
// CRITICAL CVE with reachability "imported" is downgraded one tier to HIGH and
// produces severity_adjusted == 70 (1–2 HIGH → 70 in the step function).
func TestSeverityAdjusted_SingleImportedCritical_Becomes70(t *testing.T) {
	input := reachabilityScoreInput(
		"github.com/risky/pkg",
		testutil.BoolPtr(false),
		[]scanner.Vulnerability{
			makeVulnWithReachability("CVE-2024-0002", "CRITICAL", "imported"),
		},
	)
	ps := ScoreAll(input)
	if ps.SeverityAdjustedVulnScore != 70 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 70 (imported CRITICAL → HIGH → step 1–2 HIGH → 70)",
			ps.SeverityAdjustedVulnScore)
	}
}

// TestSeverityAdjusted_SingleRequiredCritical_Becomes40 verifies that a
// CRITICAL CVE with reachability "required" is downgraded two tiers to MEDIUM
// and produces severity_adjusted == 40 (any MEDIUM, no HIGH+ → 40).
func TestSeverityAdjusted_SingleRequiredCritical_Becomes40(t *testing.T) {
	input := reachabilityScoreInput(
		"github.com/risky/pkg",
		testutil.BoolPtr(false),
		[]scanner.Vulnerability{
			makeVulnWithReachability("CVE-2024-0003", "CRITICAL", "required"),
		},
	)
	ps := ScoreAll(input)
	if ps.SeverityAdjustedVulnScore != 40 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 40 (required CRITICAL → MEDIUM → step any MEDIUM → 40)",
			ps.SeverityAdjustedVulnScore)
	}
}

// TestSeverityAdjusted_ImportedAndTestOnlyCritical_Becomes40 verifies the
// composed double-downgrade: imported CRITICAL → HIGH (reachability), then
// HIGH → MEDIUM (test-only). The step function produces 40.
func TestSeverityAdjusted_ImportedAndTestOnlyCritical_Becomes40(t *testing.T) {
	input := reachabilityScoreInput(
		"github.com/risky/pkg",
		testutil.BoolPtr(true), // confirmed test-only dep
		[]scanner.Vulnerability{
			makeVulnWithReachability("CVE-2024-0004", "CRITICAL", "imported"),
		},
	)
	ps := ScoreAll(input)
	if ps.SeverityAdjustedVulnScore != 40 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 40 (imported CRITICAL → HIGH, test-only HIGH → MEDIUM → step 40)",
			ps.SeverityAdjustedVulnScore)
	}
}

// TestSeverityAdjusted_RequiredAndTestOnlyCritical_Becomes10 verifies the
// composed triple-downgrade: required CRITICAL → MEDIUM (reachability), then
// MEDIUM → LOW (test-only). The step function produces 10.
func TestSeverityAdjusted_RequiredAndTestOnlyCritical_Becomes10(t *testing.T) {
	input := reachabilityScoreInput(
		"github.com/risky/pkg",
		testutil.BoolPtr(true), // confirmed test-only dep
		[]scanner.Vulnerability{
			makeVulnWithReachability("CVE-2024-0005", "CRITICAL", "required"),
		},
	)
	ps := ScoreAll(input)
	if ps.SeverityAdjustedVulnScore != 10 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 10 (required CRITICAL → MEDIUM, test-only MEDIUM → LOW → step 10)",
			ps.SeverityAdjustedVulnScore)
	}
}

// TestSeverityAdjusted_MixedCalledHighAndImportedHigh_Becomes70 verifies that
// a called HIGH (unchanged) combined with an imported HIGH (downgraded to
// MEDIUM) results in StepFunctionInputs{High:1, Medium:1}. The step function
// fires "1–2 HIGH → 70".
func TestSeverityAdjusted_MixedCalledHighAndImportedHigh_Becomes70(t *testing.T) {
	// Two deps so each CVE lands on a separate dep. We need both to have
	// IsTestOnly=false so neither dep triggers the test-only downgrade.
	const modA = "github.com/alpha/pkg"
	const modB = "github.com/beta/pkg"

	graph := testutil.MakeGraph(
		testutil.DepSpec{Path: modA, Version: "v1.0.0", Direct: true, Depth: 0, IsTestOnly: testutil.BoolPtr(false)},
		testutil.DepSpec{Path: modB, Version: "v1.0.0", Direct: true, Depth: 0, IsTestOnly: testutil.BoolPtr(false)},
	)
	input := ScoreInput{
		Graph: graph,
		Vulns: map[string][]scanner.Vulnerability{
			modA: {makeVulnWithReachability("CVE-2024-A001", "HIGH", "called")},
			modB: {makeVulnWithReachability("CVE-2024-B001", "HIGH", "imported")},
		},
		Maintenance: make(map[string]*scanner.MaintenanceInfo),
		Maintainers: make(map[string]*scanner.MaintainerInfo),
		Typosquats:  make(map[string]*scanner.TyposquatResult),
		Resilience:  make(map[string]*scanner.ResilienceInfo),
		AIGenRisks:  make(map[string]*scanner.AIGenRisk),
		TrustIndex:  make(map[string]*scanner.TrustIndexEntry),
		DebugMode:   true,
	}
	ps := ScoreAll(input)
	if ps.SeverityAdjustedVulnScore != 70 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 70 (called HIGH + imported HIGH→MEDIUM → 1 HIGH → step 70)",
			ps.SeverityAdjustedVulnScore)
	}
	// Verify the step function saw exactly 1 HIGH and 1 MEDIUM.
	if ps.DebugScoring == nil {
		t.Fatal("DebugScoring must be populated in DebugMode")
	}
	if ps.DebugScoring.StepFunctionInputs.High != 1 {
		t.Errorf("StepFunctionInputs.High = %d, want 1", ps.DebugScoring.StepFunctionInputs.High)
	}
	if ps.DebugScoring.StepFunctionInputs.Medium != 1 {
		t.Errorf("StepFunctionInputs.Medium = %d, want 1", ps.DebugScoring.StepFunctionInputs.Medium)
	}
}

// TestSeverityAdjusted_UnisupplySelfRequiredOnly_BecomesZero is the
// load-bearing release gate for v0.5.0. It mirrors the canonical unisupply
// self-scan result: golang.org/x/crypto has a CVE with reachability "required"
// and severity UNKNOWN (mapped to MEDIUM by effectiveTier). Two-tier downgrade:
// MEDIUM → LOW → dropped. The step function sees zero CVEs → 0.
//
// Pre-fix severity_adjusted was 40; post-fix it must be 0.
func TestSeverityAdjusted_UnisupplySelfRequiredOnly_BecomesZero(t *testing.T) {
	// Build an equivalent slim ScoreInput inline rather than loading the
	// govulncheck fixture (parseGovulncheckJSON is unexported from pkg/scanner).
	// The fixture has a single required CVE with UNKNOWN severity on
	// golang.org/x/crypto. That's the exact shape we need.
	const modPath = "golang.org/x/crypto"
	input := reachabilityScoreInput(
		modPath,
		testutil.BoolPtr(false),
		[]scanner.Vulnerability{
			// UNKNOWN severity → effectiveTier → MEDIUM.
			// required reachability → two-tier downgrade: MEDIUM → LOW → dropped.
			{
				ID:           "GO-2026-5005",
				Severity:     "UNKNOWN",
				Reachability: "required",
			},
		},
	)
	ps := ScoreAll(input)
	if ps.SeverityAdjustedVulnScore != 0 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 0 (required UNKNOWN/MEDIUM → dropped by two-tier downgrade)",
			ps.SeverityAdjustedVulnScore)
	}
}

// ---------------------------------------------------------------------------
// Per-dep weight tests: vulnScore reachability factor
// ---------------------------------------------------------------------------

// TestVulnScore_ImportedCritical_Weights70 verifies that a single CRITICAL CVE
// with reachability "imported" contributes 70 to vulnScore (100 × 0.7), not
// the base 100.
func TestVulnScore_ImportedCritical_Weights70(t *testing.T) {
	vulns := []scanner.Vulnerability{
		makeVulnWithReachability("CVE-2024-IMP1", "CRITICAL", "imported"),
	}
	got := vulnScore(vulns)
	if got != 70 {
		t.Errorf("vulnScore([imported CRITICAL]) = %v, want 70 (100 × 0.7)", got)
	}
}

// TestVulnScore_RequiredHigh_Weights24 verifies that a single HIGH CVE with
// reachability "required" contributes 24 to vulnScore (80 × 0.3), not the
// base 80.
func TestVulnScore_RequiredHigh_Weights24(t *testing.T) {
	vulns := []scanner.Vulnerability{
		makeVulnWithReachability("CVE-2024-REQ1", "HIGH", "required"),
	}
	got := vulnScore(vulns)
	if got != 24 {
		t.Errorf("vulnScore([required HIGH]) = %v, want 24 (80 × 0.3)", got)
	}
}

// TestSeverityFloor_RequiredCritical_NoFloor verifies that a dep whose only
// CVE is a required CRITICAL is NOT promoted to the HIGH band by severityFloor.
// Its per-dep RiskLevel must stay at whatever the non-vuln components dictate
// (typically LOW for a dep with no maintenance/maintainer signals).
func TestSeverityFloor_RequiredCritical_NoFloor(t *testing.T) {
	const modPath = "github.com/required-only/pkg"
	input := reachabilityScoreInput(
		modPath,
		testutil.BoolPtr(false),
		[]scanner.Vulnerability{
			makeVulnWithReachability("CVE-2024-RF01", "CRITICAL", "required"),
		},
	)
	ps := ScoreAll(input)

	// Find the dependency score for the tested module.
	var ds *DependencyScore
	for _, d := range ps.Dependencies {
		if d.Module == modPath {
			ds = d
			break
		}
	}
	if ds == nil {
		t.Fatalf("dependency %q not found in scored output", modPath)
	}

	// A required-only CRITICAL must not promote the dep to HIGH or CRITICAL band.
	if ds.RiskLevel == RiskHigh || ds.RiskLevel == RiskCritical {
		t.Errorf("RiskLevel = %s, want LOW or MEDIUM (required CRITICAL must not promote per-dep level to HIGH/CRITICAL)",
			ds.RiskLevel)
	}
}

// TestRequiredOnly_PerDepBandDrivenByLevelFromScore pins the contract that a
// dep whose only CVEs are "required" is never floor-promoted by severityFloor:
// its final RiskLevel is whatever levelFromScore(RiskScore) returns. This
// triple-checks the three invariants that compose to make that true, so a
// future tweak to any one of them surfaces here rather than silently shifting
// the band:
//
//  1. severityFloor returns (0, RiskLow) when every CVE is "required" —
//     regardless of original severity. The required-skip in severityFloor is
//     load-bearing for the "code never links → don't promote the band" design.
//  2. vulnScore caps at severityWeight(worst) × 0.3 because the pile-up gate
//     is w >= 56 and a "required" CRITICAL weighs 30. Adding more required
//     CRITICALs does NOT raise vulnScore — pinned because the gate constant
//     would silently re-enable accumulation if reachabilityFactor("required")
//     is ever retuned upward.
//  3. End-to-end through scoreDependency: ds.RiskLevel == levelFromScore(ds.RiskScore).
//     If a future change adds a floor-promotion path for required CVEs, the
//     equality breaks even when the band happens to coincide.
func TestRequiredOnly_PerDepBandDrivenByLevelFromScore(t *testing.T) {
	requiredVulns := []scanner.Vulnerability{
		makeVulnWithReachability("CVE-2024-RO01", "CRITICAL", "required"),
		makeVulnWithReachability("CVE-2024-RO02", "CRITICAL", "required"),
		makeVulnWithReachability("CVE-2024-RO03", "HIGH", "required"),
	}

	// (1) severityFloor returns (0, RiskLow) for required-only vulns.
	floor, promoted := severityFloor(time.Now(), requiredVulns)
	if floor != 0 {
		t.Errorf("severityFloor(required-only) floor = %d, want 0 (required CVEs must not set a floor)", floor)
	}
	if promoted != RiskLow {
		t.Errorf("severityFloor(required-only) promoted = %s, want %s", promoted, RiskLow)
	}

	// (2) vulnScore caps at the worst single required weight; pile-up does not fire.
	// Worst is CRITICAL: 100 × 0.3 = 30. Three required CVEs must produce the same
	// vulnScore as one — the highOrAboveCount gate (w >= 56) excludes them.
	single := vulnScore(requiredVulns[:1])
	all := vulnScore(requiredVulns)
	if single != 30 {
		t.Errorf("vulnScore([required CRITICAL]) = %v, want 30 (100 × 0.3)", single)
	}
	if all != single {
		t.Errorf("vulnScore(3× required) = %v, want %v (pile-up must not engage when w < 56)", all, single)
	}

	// (3) End-to-end: the per-dep RiskLevel equals levelFromScore(RiskScore).
	// Use a non-trusted namespace so the maturity-trusted shortcut doesn't mask
	// the assertion, and depth 0 / direct so other components are deterministic.
	dep := testutil.MakeDep("github.com/required-only/pkg", "v1.0.0", true, 0)
	ds := scoreDependency(dep, requiredVulns, nil, nil, nil, nil, nil, nil, time.Now())

	wantLevel := levelFromScore(ds.RiskScore)
	if ds.RiskLevel != wantLevel {
		t.Errorf("ds.RiskLevel = %s, want %s (= levelFromScore(%d)); required-only CVEs must not floor-promote",
			ds.RiskLevel, wantLevel, ds.RiskScore)
	}
	// Cross-check the design intent: a required-only dep must not surface as HIGH/CRITICAL.
	if ds.RiskLevel == RiskHigh || ds.RiskLevel == RiskCritical {
		t.Errorf("ds.RiskLevel = %s, want LOW or MEDIUM for required-only CVEs", ds.RiskLevel)
	}
}
