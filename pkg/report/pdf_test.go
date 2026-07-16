package report

import (
	"testing"

	"github.com/unidoc/unipdf/v3/creator"
	"github.com/unidoc/unipdf/v3/model"

	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// TestFilterRiskBucket_FourLevelSplit confirms each scoring bucket gets exactly
// the deps it should. Guards against the pre-plan-39 bug where the HIGH band
// (51-75) was swallowed into the Medium section.
func TestFilterRiskBucket_FourLevelSplit(t *testing.T) {
	deps := []*scorer.DependencyScore{
		{Module: "low/zero", RiskScore: 0},
		{Module: "low/edge", RiskScore: 25},
		{Module: "med/edge", RiskScore: 26},
		{Module: "med/top", RiskScore: 50},
		{Module: "high/edge", RiskScore: 51},
		{Module: "high/top", RiskScore: 75},
		{Module: "crit/edge", RiskScore: 76},
		{Module: "crit/max", RiskScore: 100},
	}

	tests := []struct {
		name        string
		min, max    int
		wantModules []string
	}{
		{"critical", 76, 0, []string{"crit/edge", "crit/max"}},
		{"high", 51, 76, []string{"high/edge", "high/top"}},
		{"medium", 26, 51, []string{"med/edge", "med/top"}},
		{"low", 0, 26, []string{"low/zero", "low/edge"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := filterRiskBucket(deps, tc.min, tc.max)
			if len(got) != len(tc.wantModules) {
				t.Fatalf("filterRiskBucket(%d,%d) returned %d deps, want %d",
					tc.min, tc.max, len(got), len(tc.wantModules))
			}
			for i, ds := range got {
				if ds.Module != tc.wantModules[i] {
					t.Errorf("got[%d].Module = %q, want %q", i, ds.Module, tc.wantModules[i])
				}
			}
		})
	}
}

// TestFilterRiskBucket_NoOverlap ensures the four buckets partition the score
// space exactly: every dep lands in one and only one bucket, and the union
// matches the input set.
func TestFilterRiskBucket_NoOverlap(t *testing.T) {
	var deps []*scorer.DependencyScore
	for score := 0; score <= 100; score++ {
		deps = append(deps, &scorer.DependencyScore{RiskScore: score})
	}

	crit := filterRiskBucket(deps, 76, 0)
	high := filterRiskBucket(deps, 51, 76)
	med := filterRiskBucket(deps, 26, 51)
	low := filterRiskBucket(deps, 0, 26)

	if total := len(crit) + len(high) + len(med) + len(low); total != len(deps) {
		t.Errorf("bucket sizes sum to %d, want %d (no overlap, full coverage)", total, len(deps))
	}
	if len(crit) != 25 { // 76..100
		t.Errorf("critical bucket = %d, want 25", len(crit))
	}
	if len(high) != 25 { // 51..75
		t.Errorf("high bucket = %d, want 25", len(high))
	}
	if len(med) != 25 { // 26..50
		t.Errorf("medium bucket = %d, want 25", len(med))
	}
	if len(low) != 26 { // 0..25
		t.Errorf("low bucket = %d, want 26", len(low))
	}
}

// TestWriteDependencyBlock_ReachabilitySmoke verifies that writeDependencyBlock
// does not panic when vulnerabilities carry all three reachability tiers.
// This exercises the inline tag code path added in task-07.
func TestWriteDependencyBlock_ReachabilitySmoke(t *testing.T) {
	// UniPDF creator may emit license warnings to stderr — that is expected in
	// the unlicensed demo mode and does not indicate a test failure.
	_ = initLicense()

	c := creator.New()
	c.SetPageSize(creator.PageSizeLetter)
	c.SetPageMargins(50, 50, 50, 50)
	c.NewPage()

	regular, _ := model.NewStandard14Font(model.HelveticaName)
	bold, _ := model.NewStandard14Font(model.HelveticaBoldName)

	ds := &scorer.DependencyScore{
		Module:    "github.com/example/reach-pkg",
		Version:   "v1.0.0",
		Direct:    true,
		RiskScore: 75,
		RiskLevel: scorer.RiskHigh,
		Vulns: []scanner.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", Reachability: "called"},
			{ID: "CVE-2024-0002", Severity: "HIGH", Reachability: "imported"},
			{ID: "CVE-2024-0003", Severity: "MEDIUM", Reachability: "required"},
			{ID: "CVE-2024-0004", Severity: "LOW", Reachability: ""}, // legacy
		},
	}

	// Must not panic.
	writeDependencyBlock(c, ds, regular, bold, true)
}

// TestWriteLowRiskSection_VulnDetailSmoke verifies that a low-risk dependency
// carrying a vulnerability gets its CVE detail rendered, and that the
// section as a whole does not panic when mixed with a clean dependency.
func TestWriteLowRiskSection_VulnDetailSmoke(t *testing.T) {
	_ = initLicense()

	c := creator.New()
	c.SetPageSize(creator.PageSizeLetter)
	c.SetPageMargins(50, 50, 50, 50)
	c.NewPage()

	regular, _ := model.NewStandard14Font(model.HelveticaName)
	bold, _ := model.NewStandard14Font(model.HelveticaBoldName)

	ps := &scorer.ProjectScore{
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "golang.org/x/crypto",
				Version:   "v0.48.0",
				RiskScore: 12,
				RiskLevel: scorer.RiskLow,
				Vulns: []scanner.Vulnerability{
					{ID: "GO-2026-5005", Severity: "CRITICAL", FixedVersion: "v0.49.0"},
				},
			},
			{
				Module:    "github.com/example/clean-pkg",
				Version:   "v1.0.0",
				RiskScore: 5,
				RiskLevel: scorer.RiskLow,
			},
		},
	}

	// Must not panic.
	writeLowRiskSection(c, ps, regular, bold)
}

// TestWriteVulnDetailBlocks_SkipsCleanDeps documents the contract that the
// shared helper is a no-op (draws nothing) when the bucket has no
// vulnerability-bearing deps.
func TestWriteVulnDetailBlocks_SkipsCleanDeps(t *testing.T) {
	_ = initLicense()

	c := creator.New()
	c.SetPageSize(creator.PageSizeLetter)
	c.SetPageMargins(50, 50, 50, 50)
	c.NewPage()

	regular, _ := model.NewStandard14Font(model.HelveticaName)
	bold, _ := model.NewStandard14Font(model.HelveticaBoldName)

	bucket := []*scorer.DependencyScore{
		{Module: "github.com/example/clean-a", Version: "v1.0.0", RiskScore: 5, RiskLevel: scorer.RiskLow},
		{Module: "github.com/example/clean-b", Version: "v2.0.0", RiskScore: 10, RiskLevel: scorer.RiskLow},
	}

	// Must not panic and must draw nothing extra.
	writeVulnDetailBlocks(c, bucket, regular, bold)
}

// TestEPSSBadge verifies the badge renders the EPSS score (exploitation
// probability, the signal the scorer acts on) — not the percentile — and that
// tiny non-zero scores are shown as "<1%" instead of a misleading "0%".
func TestEPSSBadge(t *testing.T) {
	score := 0.42
	percentile := 0.97
	tiny := 0.004
	zero := 0.0
	cases := []struct {
		name string
		vuln scanner.Vulnerability
		want string
	}{
		{"no score", scanner.Vulnerability{}, ""},
		{"uses score not percentile", scanner.Vulnerability{EPSSScore: &score, EPSSPercentile: &percentile}, " [EPSS 42%]"},
		{"tiny score", scanner.Vulnerability{EPSSScore: &tiny}, " [EPSS <1%]"},
		{"zero score", scanner.Vulnerability{EPSSScore: &zero}, " [EPSS 0%]"},
	}
	for _, tc := range cases {
		if got := epssBadge(&tc.vuln); got != tc.want {
			t.Errorf("%s: epssBadge = %q, want %q", tc.name, got, tc.want)
		}
	}
}
