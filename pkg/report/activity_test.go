package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// activityScore builds a DependencyScore whose maintenance record carries the
// given release age and, when pushedMonths >= 0, a known push age.
func activityScore(releaseMonths, pushedMonths int) *scorer.DependencyScore {
	m := testutil.MakeMaintenanceInfo(releaseMonths, false, false)
	if pushedMonths >= 0 {
		m.LastActivity = time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
		m.MonthsSinceActivity = pushedMonths
	}
	return &scorer.DependencyScore{
		Module: "github.com/example/pkg", Version: "v1.0.0", Direct: true,
		RiskScore: 20, RiskLevel: scorer.RiskLow, Maintenance: m,
	}
}

func TestWriteJSON_MaintenanceActivity(t *testing.T) {
	graph := testutil.MakeGraph(testutil.DepSpec{
		Path: "github.com/example/pkg", Version: "v1.0.0", Direct: true, Depth: 0,
	})

	maintenanceOf := func(t *testing.T, ds *scorer.DependencyScore) map[string]any {
		t.Helper()
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

	t.Run("present when known", func(t *testing.T) {
		m := maintenanceOf(t, activityScore(40, 2))
		if got := m["last_activity"]; got != "2026-08-03T12:00:00Z" {
			t.Errorf("last_activity = %v, want 2026-08-03T12:00:00Z", got)
		}
		if got := m["months_since_activity"]; got != float64(2) {
			t.Errorf("months_since_activity = %v, want 2", got)
		}
		if got := m["months_since_release"]; got != float64(40) {
			t.Errorf("months_since_release = %v, want 40", got)
		}
	})

	t.Run("a push this month is reported as 0", func(t *testing.T) {
		m := maintenanceOf(t, activityScore(40, 0))
		got, ok := m["months_since_activity"]
		if !ok || got != float64(0) {
			t.Errorf("months_since_activity = %v (present %v), want 0 present", got, ok)
		}
	})

	t.Run("omitted when unknown", func(t *testing.T) {
		m := maintenanceOf(t, activityScore(40, -1))
		for _, key := range []string{"last_activity", "months_since_activity"} {
			if _, present := m[key]; present {
				t.Errorf("%s present for unknown activity, want omitted", key)
			}
		}
	})
}

func TestWriteDependencyDetail_LastPush(t *testing.T) {
	noColor := func(_, s string) string { return s }

	tests := []struct {
		name         string
		ds           *scorer.DependencyScore
		wantPush     string
		wantNoPush   bool
		wantsRelease bool
	}{
		{"shown when known", activityScore(40, 2), "Last push: 2 months ago", false, true},
		{"absent when unknown", activityScore(40, -1), "", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			writeDependencyDetail(&buf, tt.ds, noColor, true)
			out := buf.String()
			if tt.wantsRelease && !strings.Contains(out, "Last release: 40 months ago") {
				t.Errorf("missing release line:\n%s", out)
			}
			if tt.wantNoPush && strings.Contains(out, "Last push") {
				t.Errorf("unexpected push line:\n%s", out)
			}
			if tt.wantPush != "" && !strings.Contains(out, tt.wantPush) {
				t.Errorf("missing %q:\n%s", tt.wantPush, out)
			}
		})
	}
}

func TestDepExplanation_Activity(t *testing.T) {
	tests := []struct {
		name         string
		ds           *scorer.DependencyScore
		wantContains []string
		wantEmpty    bool
	}{
		{
			name:      "old release but recent push is not called abandoned",
			ds:        activityScore(40, 1),
			wantEmpty: true,
		},
		{
			name:         "unmaintained mentions both ages",
			ds:           activityScore(40, 30),
			wantContains: []string{"no release in 40 months", "no push in 30 months", "may be abandoned"},
		},
		{
			name:         "slowing mentions both ages",
			ds:           activityScore(40, 15),
			wantContains: []string{"last release 40 months ago", "last push 15 months ago", "slowing"},
		},
		{
			name:         "unknown activity keeps the release-only wording",
			ds:           activityScore(40, -1),
			wantContains: []string{"no release in 40 months", "may be abandoned"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := depExplanation(tt.ds)
			if tt.wantEmpty && strings.Contains(got, "release") {
				t.Errorf("explanation mentions release for an active repo: %q", got)
			}
			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("explanation %q missing %q", got, want)
				}
			}
			if tt.name == "unknown activity keeps the release-only wording" && strings.Contains(got, "push") {
				t.Errorf("explanation %q mentions a push with no activity data", got)
			}
		})
	}
}
