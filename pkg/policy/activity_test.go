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
// commitMonths >= 0, a known default-branch commit age.
func activityDep(releaseMonths, commitMonths int) *scorer.DependencyScore {
	m := testutil.MakeMaintenanceInfo(releaseMonths, false, false)
	if commitMonths >= 0 {
		m.LastActivity = time.Date(2026, time.August, 3, 0, 0, 0, 0, time.UTC)
		m.MonthsSinceActivity = commitMonths
	}
	return &scorer.DependencyScore{
		Module: "github.com/some/pkg", Version: "v1.0.0", Direct: true,
		RiskScore: 20, Maintenance: m,
	}
}

func TestEvaluate_NoUnmaintained_DefaultBranchActivity(t *testing.T) {
	limit := 24
	p := &policy.Policy{NoUnmaintainedMonths: &limit}

	tests := []struct {
		name         string
		release      int
		commit       int
		wantFail     bool
		wantContains []string
		wantAbsent   string
	}{
		{"active default branch with an old release passes", 40, 1, false, nil, ""},
		{"stale release and stale branch fails with both ages", 40, 30, true,
			[]string{"last release 40 months ago", "last default-branch commit 30 months ago", "max: 24"}, ""},
		{"recent release with an old branch passes", 3, 30, false, nil, ""},
		{"commit exactly at the limit passes", 40, 24, false, nil, ""},
		{"commit just past the limit fails", 40, 25, true, []string{"40", "25", "24"}, ""},
		{"unknown activity keeps the release-only rule and wording", 40, -1, true,
			[]string{"last release 40 months ago", "max: 24"}, "commit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := p.Evaluate(makeEvalInput([]*scorer.DependencyScore{activityDep(tt.release, tt.commit)}, 20))
			if result.Pass == tt.wantFail {
				t.Fatalf("Pass = %v, want %v (violations %v)", result.Pass, !tt.wantFail, result.Violations)
			}
			if !tt.wantFail {
				return
			}
			if len(result.Violations) != 1 || result.Violations[0].Rule != "no_unmaintained" {
				t.Fatalf("violations = %v, want one no_unmaintained", result.Violations)
			}
			detail := result.Violations[0].Detail
			for _, want := range tt.wantContains {
				if !strings.Contains(detail, want) {
					t.Errorf("detail %q missing %q", detail, want)
				}
			}
			if tt.wantAbsent != "" && strings.Contains(detail, tt.wantAbsent) {
				t.Errorf("detail %q mentions %q with no activity data", detail, tt.wantAbsent)
			}
		})
	}
}

// no_deprecated names the go.mod deprecation message, which usually says what
// to move to; a proxy-signalled deprecation has none.
func TestEvaluate_NoDeprecated_Message(t *testing.T) {
	p := &policy.Policy{NoDeprecated: true}
	dep := activityDep(31, -1)
	dep.Maintenance.Deprecated = true
	dep.Maintenance.DeprecationMessage = `Use the "google.golang.org/protobuf" module instead.`

	result := p.Evaluate(makeEvalInput([]*scorer.DependencyScore{dep}, 20))
	if len(result.Violations) != 1 || result.Violations[0].Detail != `module is deprecated: Use the "google.golang.org/protobuf" module instead.` {
		t.Errorf("violations = %v, want the deprecation message in the detail", result.Violations)
	}

	// A notice over several go.mod comment lines stays on one line.
	dep.Maintenance.DeprecationMessage = "Use the \"google.golang.org/protobuf\"\nmodule instead."
	result = p.Evaluate(makeEvalInput([]*scorer.DependencyScore{dep}, 20))
	if len(result.Violations) != 1 || result.Violations[0].Detail != `module is deprecated: Use the "google.golang.org/protobuf" module instead.` {
		t.Errorf("violations = %v, want a multi-line message joined on one line", result.Violations)
	}

	dep.Maintenance.DeprecationMessage = ""
	result = p.Evaluate(makeEvalInput([]*scorer.DependencyScore{dep}, 20))
	if len(result.Violations) != 1 || result.Violations[0].Detail != "module is deprecated" {
		t.Errorf("violations = %v, want the plain detail without a message", result.Violations)
	}
}
