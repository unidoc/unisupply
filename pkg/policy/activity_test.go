package policy_test

import (
	"strings"
	"testing"
	"time"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/policy"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// activityDep builds a scored dependency with the given release age and, when
// pushedMonths >= 0, a known repository push age.
func activityDep(releaseMonths, pushedMonths int) *scorer.DependencyScore {
	m := testutil.MakeMaintenanceInfo(releaseMonths, false, false)
	if pushedMonths >= 0 {
		m.LastActivity = time.Date(2026, time.August, 3, 0, 0, 0, 0, time.UTC)
		m.MonthsSinceActivity = pushedMonths
	}
	return &scorer.DependencyScore{
		Module: "github.com/some/pkg", Version: "v1.0.0", Direct: true,
		RiskScore: 20, Maintenance: m,
	}
}

func TestEvaluate_NoUnmaintained_RepositoryActivity(t *testing.T) {
	limit := 24
	p := &policy.Policy{NoUnmaintainedMonths: &limit}

	tests := []struct {
		name         string
		release      int
		pushed       int
		wantFail     bool
		wantContains []string
	}{
		{"active repo with an old release passes", 40, 1, false, nil},
		{"stale release and stale push fails with both ages", 40, 30, true,
			[]string{"last release 40 months ago", "last push 30 months ago", "max: 24"}},
		{"recent release with an old push passes", 3, 30, false, nil},
		{"push exactly at the limit passes", 40, 24, false, nil},
		{"push just past the limit fails", 40, 25, true, []string{"40", "25", "24"}},
		{"unknown activity keeps the release-only rule", 40, -1, true,
			[]string{"last release 40 months ago", "max: 24"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := p.Evaluate(makeEvalInput([]*scorer.DependencyScore{activityDep(tt.release, tt.pushed)}, 20))

			if result.Pass == tt.wantFail {
				t.Fatalf("Pass = %v, want %v (violations %v)", result.Pass, !tt.wantFail, result.Violations)
			}
			if !tt.wantFail {
				return
			}
			if len(result.Violations) != 1 || result.Violations[0].Rule != "no_unmaintained" {
				t.Fatalf("violations = %v, want one no_unmaintained", result.Violations)
			}
			for _, want := range tt.wantContains {
				if !strings.Contains(result.Violations[0].Detail, want) {
					t.Errorf("detail %q missing %q", result.Violations[0].Detail, want)
				}
			}
		})
	}
}

// TestEvaluate_NoUnmaintained_UnknownActivityOmitsPush verifies that the
// message does not mention a push when none is known.
func TestEvaluate_NoUnmaintained_UnknownActivityOmitsPush(t *testing.T) {
	limit := 24
	p := &policy.Policy{NoUnmaintainedMonths: &limit}
	result := p.Evaluate(makeEvalInput([]*scorer.DependencyScore{activityDep(40, -1)}, 20))

	if len(result.Violations) != 1 {
		t.Fatalf("violations = %v, want 1", result.Violations)
	}
	if strings.Contains(result.Violations[0].Detail, "push") {
		t.Errorf("detail %q mentions a push with no activity data", result.Violations[0].Detail)
	}
}
