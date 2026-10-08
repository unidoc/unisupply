package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// activityScore builds a DependencyScore whose maintenance record carries the
// given release age and, when commitMonths >= 0, a default-branch commit age
// read from main through the module proxy.
func activityScore(releaseMonths, commitMonths int) *scorer.DependencyScore {
	m := testutil.MakeMaintenanceInfo(releaseMonths, false, false)
	if commitMonths >= 0 {
		m.LastActivity = time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
		m.MonthsSinceActivity = commitMonths
		m.ActivitySource = scanner.ActivityViaProxy
		m.ActivityBranch = "main"
	}
	return &scorer.DependencyScore{
		Module: "github.com/example/pkg", Version: "v1.0.0", Direct: true,
		RiskScore: 20, RiskLevel: scorer.RiskLow, Maintenance: m,
	}
}

func jsonMaintenanceOf(t *testing.T, ds *scorer.DependencyScore) map[string]any {
	t.Helper()
	graph := testutil.MakeGraph(testutil.DepSpec{Path: ds.Module, Version: ds.Version, Direct: true})
	ps := &scorer.ProjectScore{
		OverallScore: 20, OverallLevel: scorer.RiskLow,
		Dependencies: []*scorer.DependencyScore{ds}, LowRiskCount: 1,
	}
	var buf bytes.Buffer
	if err := WriteJSON(graph, ps, JSONOptions{GoVersion: "1.21"}, &buf); err != nil {
		t.Fatalf("WriteJSON() failed: %v", err)
	}
	var raw struct {
		Dependencies []struct {
			Maintenance map[string]any `json:"maintenance"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(raw.Dependencies) != 1 || raw.Dependencies[0].Maintenance == nil {
		t.Fatalf("maintenance object missing: %s", buf.String())
	}
	return raw.Dependencies[0].Maintenance
}

func TestWriteJSON_MaintenanceActivity(t *testing.T) {
	t.Run("present when known", func(t *testing.T) {
		m := jsonMaintenanceOf(t, activityScore(40, 2))
		want := map[string]any{
			"last_activity":         "2026-08-03T12:00:00Z",
			"months_since_activity": float64(2),
			"activity_source":       "proxy_branch",
			"activity_branch":       "main",
			"months_since_release":  float64(40),
		}
		for k, v := range want {
			if m[k] != v {
				t.Errorf("%s = %v, want %v", k, m[k], v)
			}
		}
	})

	t.Run("a commit this month is reported as 0", func(t *testing.T) {
		if m := jsonMaintenanceOf(t, activityScore(40, 0)); m["months_since_activity"] != float64(0) {
			t.Errorf("months_since_activity = %v, want 0 present", m["months_since_activity"])
		}
	})

	t.Run("absent when unknown", func(t *testing.T) {
		m := jsonMaintenanceOf(t, activityScore(40, -1))
		for _, k := range []string{"last_activity", "months_since_activity", "activity_source", "activity_branch"} {
			if _, ok := m[k]; ok {
				t.Errorf("%s present with no activity: %v", k, m[k])
			}
		}
	})
}

func TestWriteDependencyDetail_ActivityAndDeprecation(t *testing.T) {
	noColor := func(_, s string) string { return s }
	render := func(ds *scorer.DependencyScore) string {
		var buf bytes.Buffer
		writeDependencyDetail(&buf, ds, noColor, true) // detail lines are verbose-only
		return buf.String()
	}

	if out := render(activityScore(40, 2)); !strings.Contains(out, "Last commit (main): 2 months ago") {
		t.Errorf("missing the default-branch commit line:\n%s", out)
	}
	if out := render(activityScore(40, -1)); strings.Contains(out, "Last commit") {
		t.Errorf("commit line rendered with no activity:\n%s", out)
	}
}

func TestDepExplanation_ActivityAndDeprecation(t *testing.T) {
	tests := []struct {
		name string
		ds   *scorer.DependencyScore
		want string
		not  string
	}{
		{"old release, active branch: no maintenance reason", activityScore(40, 1), "", "release"},
		{"both old: names both ages", activityScore(40, 30), "no release in 40 months and no default-branch commit in 30 months", ""},
		{"no activity: release-only wording", activityScore(40, -1), "no release in 40 months —", "commit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := depExplanation(tt.ds)
			if tt.want != "" && !strings.Contains(got, tt.want) {
				t.Errorf("explanation %q missing %q", got, tt.want)
			}
			if tt.not != "" && strings.Contains(got, tt.not) {
				t.Errorf("explanation %q must not mention %q", got, tt.not)
			}
		})
	}
}
