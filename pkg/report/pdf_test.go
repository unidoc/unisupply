package report

import (
	"testing"

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
