package scorer

import (
	"slices"
	"testing"
	"time"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// activityNow is the scoring clock for the default-branch activity tests.
var activityNow = time.Date(2026, time.October, 9, 0, 0, 0, 0, time.UTC)

// withActivity returns a maintenance record with the given release age and,
// when commitMonths is not negative, a default-branch commit that many months
// old, as MaintenanceScanner.ScanActivity sets it.
func withActivity(releaseMonths, commitMonths int, archived, deprecated bool) *scanner.MaintenanceInfo {
	m := testutil.MakeMaintenanceInfo(releaseMonths, archived, deprecated)
	if commitMonths >= 0 {
		m.LastActivity = activityNow.AddDate(0, -commitMonths, 0)
		m.MonthsSinceActivity = commitMonths
		m.ActivitySource = scanner.ActivityViaProxy
		m.ActivityBranch = "main"
	}
	return m
}

func TestScoreDependency_DefaultBranchActivity(t *testing.T) {
	const noCommit = -1
	tests := []struct {
		name        string
		maint       *scanner.MaintenanceInfo
		wantScore   float64
		wantUnmaint bool
	}{
		{"old release and recent commit scores as active", withActivity(40, 1, false, false), 0, false},
		{"old release and old commit stays unmaintained", withActivity(40, 30, false, false), 90, true},
		{"commit between 12 and 24 months bands as 60", withActivity(40, 15, false, false), 60, false},
		{"recent release beats an old commit", withActivity(2, 30, false, false), 0, false},
		{"no activity keeps release-only behaviour", withActivity(40, noCommit, false, false), 90, true},
		{"archived stays 100 whatever the activity", withActivity(40, 1, true, false), 100, false},
		// golang/protobuf: deprecated in go.mod, default branch still
		// edited. Deprecation must not be undone by a recent commit.
		{"deprecated scores 100 despite a recent commit", withActivity(31, 0, false, true), 100, false},
		{"deprecated without activity scores 100", withActivity(3, noCommit, false, true), 100, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := testutil.MakeDep("github.com/some/pkg", "v1.2.3", true, 1)
			ds := scoreDependency(dep, nil, tt.maint, testutil.MakeMaintainerInfo(3, 5, true),
				nil, nil, nil, nil, "", "", false, activityNow)
			if ds.MaintenanceScore != tt.wantScore {
				t.Errorf("MaintenanceScore = %v, want %v", ds.MaintenanceScore, tt.wantScore)
			}
			if got := slices.Contains(ds.RiskFactors, "unmaintained"); got != tt.wantUnmaint {
				t.Errorf("unmaintained factor = %v, want %v (factors %v)", got, tt.wantUnmaint, ds.RiskFactors)
			}
			if got, want := ds.Maintenance.MonthsSinceRelease, tt.maint.MonthsSinceRelease; got != want {
				t.Errorf("MonthsSinceRelease = %d, want %d: the release age is never rewritten", got, want)
			}
		})
	}
}

// GitHub's pushed_at (MaintainerInfo.LastCommitDate) moves on pushes to any
// branch, Dependabot's included, so it must not make a module read as
// maintained. hashicorp/go-multierror had a Dependabot push two days before a
// scan while its default branch last moved six months earlier.
func TestScoreDependency_PushedAtIsNotActivity(t *testing.T) {
	mi := testutil.MakeMaintainerInfo(3, 5, true)
	mi.LastCommitDate = activityNow.AddDate(0, 0, -2)
	dep := testutil.MakeDep("github.com/hashicorp/go-multierror", "v1.1.1", false, 1)

	ds := scoreDependency(dep, nil, withActivity(64, -1, false, false), mi,
		nil, nil, nil, nil, "", "", false, activityNow)
	if ds.MaintenanceScore != 90 || !slices.Contains(ds.RiskFactors, "unmaintained") {
		t.Errorf("MaintenanceScore = %v, factors %v: a recent pushed_at must not count as maintenance", ds.MaintenanceScore, ds.RiskFactors)
	}
	if ds.Maintenance.HasActivity() {
		t.Error("activity was derived from pushed_at")
	}
}

func TestMaintenanceInfo_MonthsInactive(t *testing.T) {
	tests := []struct {
		name string
		info *scanner.MaintenanceInfo
		want int
	}{
		{"activity unknown uses release", withActivity(40, -1, false, false), 40},
		{"activity newer than release", withActivity(40, 2, false, false), 2},
		{"release newer than activity", withActivity(3, 30, false, false), 3},
		{"commit this month is a known zero", withActivity(40, 0, false, false), 0},
		{"nil receiver", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.info.MonthsInactive(); got != tt.want {
				t.Errorf("MonthsInactive = %d, want %d", got, tt.want)
			}
		})
	}
}

// The summary counts use the same combined value as the per-dependency score.
func TestScoreAll_UnmaintainedCountsUseActivity(t *testing.T) {
	const (
		active   = "github.com/a/active"   // release 40, commit 1: neither bucket
		stale    = "github.com/b/stale"    // release 40, commit 30: >2yr
		slowing  = "github.com/c/slowing"  // release 40, commit 15: 1-2yr
		unknown  = "github.com/d/unknown"  // release 30, no activity: >2yr
		releases = "github.com/e/releases" // release 14, commit 14: 1-2yr
	)
	graph := testutil.MakeGraph(
		testutil.DepSpec{Path: active, Version: "v1.0.0", Direct: true},
		testutil.DepSpec{Path: stale, Version: "v1.0.0", Direct: true},
		testutil.DepSpec{Path: slowing, Version: "v1.0.0", Direct: true},
		testutil.DepSpec{Path: unknown, Version: "v1.0.0", Direct: true},
		testutil.DepSpec{Path: releases, Version: "v1.0.0", Direct: true},
	)
	input := twoAxisEmptyInput(graph)
	input.Now = activityNow
	input.Maintenance[active] = withActivity(40, 1, false, false)
	input.Maintenance[stale] = withActivity(40, 30, false, false)
	input.Maintenance[slowing] = withActivity(40, 15, false, false)
	input.Maintenance[unknown] = withActivity(30, -1, false, false)
	input.Maintenance[releases] = withActivity(14, 14, false, false)

	ps := ScoreAll(input)
	if ps.Unmaintained2yr != 2 {
		t.Errorf("Unmaintained2yr = %d, want 2 (stale and unknown)", ps.Unmaintained2yr)
	}
	if ps.Unmaintained1yr != 2 {
		t.Errorf("Unmaintained1yr = %d, want 2 (slowing and releases)", ps.Unmaintained1yr)
	}
}
