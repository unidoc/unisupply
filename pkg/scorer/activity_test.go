package scorer

import (
	"slices"
	"testing"
	"time"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// activityNow is the scoring clock for the repository-activity tests.
var activityNow = time.Date(2026, time.October, 7, 0, 0, 0, 0, time.UTC)

// pushedMonthsAgo returns a pushed_at date that is exactly the given number of
// calendar months before activityNow.
func pushedMonthsAgo(months int) time.Time {
	return activityNow.AddDate(0, -months, 0)
}

// pushedMaintainer builds a maintainer record whose only relevant field is the
// GitHub pushed_at date. A negative months value leaves the date unknown.
func pushedMaintainer(months int) *scanner.MaintainerInfo {
	mi := testutil.MakeMaintainerInfo(3, 5, true)
	if months >= 0 {
		mi.LastCommitDate = pushedMonthsAgo(months)
	}
	return mi
}

func TestScoreDependency_RepositoryActivity(t *testing.T) {
	const noPush = -1

	tests := []struct {
		name          string
		maint         *scanner.MaintenanceInfo
		pushedMonths  int
		wantScore     float64
		wantUnmaint   bool
		wantArchived  bool
		wantActivity  bool
		wantInactive  int
		wantMonthsAct int
	}{
		{
			name:          "old release and recent push scores as active",
			maint:         testutil.MakeMaintenanceInfo(40, false, false),
			pushedMonths:  1,
			wantScore:     0,
			wantActivity:  true,
			wantInactive:  1,
			wantMonthsAct: 1,
		},
		{
			name:          "old release and old push stays unmaintained",
			maint:         testutil.MakeMaintenanceInfo(40, false, false),
			pushedMonths:  30,
			wantScore:     90,
			wantUnmaint:   true,
			wantActivity:  true,
			wantInactive:  30,
			wantMonthsAct: 30,
		},
		{
			name:          "push between 12 and 24 months bands as 60",
			maint:         testutil.MakeMaintenanceInfo(40, false, false),
			pushedMonths:  15,
			wantScore:     60,
			wantActivity:  true,
			wantInactive:  15,
			wantMonthsAct: 15,
		},
		{
			name:          "recent release beats an old push",
			maint:         testutil.MakeMaintenanceInfo(2, false, false),
			pushedMonths:  30,
			wantScore:     0,
			wantActivity:  true,
			wantInactive:  2,
			wantMonthsAct: 30,
		},
		{
			name:          "archived stays 100 regardless of push",
			maint:         testutil.MakeMaintenanceInfo(40, true, false),
			pushedMonths:  1,
			wantScore:     100,
			wantArchived:  true,
			wantActivity:  true,
			wantInactive:  1,
			wantMonthsAct: 1,
		},
		{
			name:         "no maintainer push date keeps release-only behaviour",
			maint:        testutil.MakeMaintenanceInfo(40, false, false),
			pushedMonths: noPush,
			wantScore:    90,
			wantUnmaint:  true,
			wantInactive: 40,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := testutil.MakeDep("github.com/some/pkg", "v1.2.3", true, 1)
			ds := scoreDependency(dep, nil, tt.maint, pushedMaintainer(tt.pushedMonths),
				nil, nil, nil, nil, "", "", false, activityNow)

			if ds.MaintenanceScore != tt.wantScore {
				t.Errorf("MaintenanceScore = %v, want %v", ds.MaintenanceScore, tt.wantScore)
			}
			if got := slices.Contains(ds.RiskFactors, "unmaintained"); got != tt.wantUnmaint {
				t.Errorf("unmaintained factor = %v, want %v (factors %v)", got, tt.wantUnmaint, ds.RiskFactors)
			}
			if got := slices.Contains(ds.RiskFactors, "archived"); got != tt.wantArchived {
				t.Errorf("archived factor = %v, want %v (factors %v)", got, tt.wantArchived, ds.RiskFactors)
			}
			if ds.Maintenance == nil {
				t.Fatal("Maintenance is nil")
			}
			if got := ds.Maintenance.HasActivity(); got != tt.wantActivity {
				t.Errorf("HasActivity = %v, want %v", got, tt.wantActivity)
			}
			if got := ds.Maintenance.MonthsInactive(); got != tt.wantInactive {
				t.Errorf("MonthsInactive = %d, want %d", got, tt.wantInactive)
			}
			if got := ds.Maintenance.MonthsSinceActivity; got != tt.wantMonthsAct {
				t.Errorf("MonthsSinceActivity = %d, want %d", got, tt.wantMonthsAct)
			}
			// The release age is descriptive and must never be rewritten.
			if got, want := ds.Maintenance.MonthsSinceRelease, tt.maint.MonthsSinceRelease; got != want {
				t.Errorf("MonthsSinceRelease = %d, want %d", got, want)
			}
		})
	}
}

// TestScoreDependency_ActivityUsesScorerClock verifies that MonthsSinceActivity
// is computed against the scorer's now with the scanner's month formula.
func TestScoreDependency_ActivityUsesScorerClock(t *testing.T) {
	pushed := time.Date(2026, time.January, 31, 0, 0, 0, 0, time.UTC)
	mi := testutil.MakeMaintainerInfo(3, 5, true)
	mi.LastCommitDate = pushed

	dep := testutil.MakeDep("github.com/some/pkg", "v1.2.3", true, 1)
	ds := scoreDependency(dep, nil, testutil.MakeMaintenanceInfo(40, false, false), mi,
		nil, nil, nil, nil, "", "", false, activityNow)

	if want := scanner.MonthsSince(activityNow, pushed); ds.Maintenance.MonthsSinceActivity != want {
		t.Errorf("MonthsSinceActivity = %d, want %d", ds.Maintenance.MonthsSinceActivity, want)
	}
	if ds.Maintenance.MonthsSinceActivity != 9 {
		t.Errorf("MonthsSinceActivity = %d, want 9 calendar months from 2026-01 to 2026-10", ds.Maintenance.MonthsSinceActivity)
	}
}

// TestScoreDependency_NilMaintenanceWithActivity verifies that a push date
// alone does not conjure a maintenance record: the proxy lookup failed, so the
// axis stays unmeasured exactly as it did before activity was collected.
func TestScoreDependency_NilMaintenanceWithActivity(t *testing.T) {
	dep := testutil.MakeDep("github.com/some/pkg", "v1.2.3", true, 1)

	withPush := scoreDependency(dep, nil, nil, pushedMaintainer(1),
		nil, nil, nil, nil, "", "", false, activityNow)
	withoutPush := scoreDependency(dep, nil, nil, pushedMaintainer(-1),
		nil, nil, nil, nil, "", "", false, activityNow)

	if withPush.Maintenance != nil {
		t.Errorf("Maintenance = %+v, want nil (not fabricated from activity)", withPush.Maintenance)
	}
	if withPush.MaintenanceScore != 30 {
		t.Errorf("MaintenanceScore = %v, want 30 (unknown)", withPush.MaintenanceScore)
	}
	if !withPush.MaintenanceWeightExcluded {
		t.Error("MaintenanceWeightExcluded = false, want true")
	}
	if withPush.RiskScore != withoutPush.RiskScore {
		t.Errorf("RiskScore = %d with a push date, %d without; a push date must not change an unmeasured axis",
			withPush.RiskScore, withoutPush.RiskScore)
	}
}

// TestScoreDependency_ActivityBackfillIdempotent verifies that scoring one
// shared *MaintenanceInfo repeatedly gives the same result, and that scoring
// leaves the shared record (the maintenance scanner's cache entry) untouched.
func TestScoreDependency_ActivityBackfillIdempotent(t *testing.T) {
	shared := testutil.MakeMaintenanceInfo(40, false, false)
	before := *shared
	dep := testutil.MakeDep("github.com/some/pkg", "v1.2.3", true, 1)

	score := func(mi *scanner.MaintainerInfo, now time.Time) *DependencyScore {
		return scoreDependency(dep, nil, shared, mi, nil, nil, nil, nil, "", "", false, now)
	}

	first := score(pushedMaintainer(1), activityNow)
	second := score(pushedMaintainer(1), activityNow)

	if first.RiskScore != second.RiskScore || first.MaintenanceScore != second.MaintenanceScore {
		t.Errorf("repeated scoring differs: %d/%v then %d/%v",
			first.RiskScore, first.MaintenanceScore, second.RiskScore, second.MaintenanceScore)
	}
	if !slices.Equal(first.RiskFactors, second.RiskFactors) {
		t.Errorf("risk factors differ: %v then %v", first.RiskFactors, second.RiskFactors)
	}
	if *first.Maintenance != *second.Maintenance {
		t.Errorf("Maintenance differs: %+v then %+v", *first.Maintenance, *second.Maintenance)
	}
	if *shared != before {
		t.Errorf("shared record mutated: got %+v, want %+v", *shared, before)
	}

	// A later scoring that has no push date must not inherit the earlier one.
	later := score(pushedMaintainer(-1), activityNow)
	if later.Maintenance.HasActivity() {
		t.Errorf("activity leaked into a later scoring: %+v", *later.Maintenance)
	}
	if later.MaintenanceScore != 90 {
		t.Errorf("MaintenanceScore = %v, want 90 (release-only)", later.MaintenanceScore)
	}

	// A different clock recomputes the age instead of reusing the first one.
	aged := score(pushedMaintainer(1), activityNow.AddDate(0, 12, 0))
	if aged.Maintenance.MonthsSinceActivity != 13 {
		t.Errorf("MonthsSinceActivity = %d, want 13 against the later clock", aged.Maintenance.MonthsSinceActivity)
	}
}

// TestMaintenanceInfo_MonthsInactive covers the combination rule directly.
func TestMaintenanceInfo_MonthsInactive(t *testing.T) {
	tests := []struct {
		name string
		info *scanner.MaintenanceInfo
		want int
	}{
		{"activity unknown uses release", &scanner.MaintenanceInfo{MonthsSinceRelease: 40}, 40},
		{"activity newer than release", &scanner.MaintenanceInfo{
			MonthsSinceRelease: 40, LastActivity: activityNow, MonthsSinceActivity: 2}, 2},
		{"release newer than activity", &scanner.MaintenanceInfo{
			MonthsSinceRelease: 3, LastActivity: activityNow, MonthsSinceActivity: 30}, 3},
		{"push this month is a known zero", &scanner.MaintenanceInfo{
			MonthsSinceRelease: 40, LastActivity: activityNow, MonthsSinceActivity: 0}, 0},
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

// TestScoreAll_UnmaintainedCountsUseActivity verifies that the summary counts
// agree with the per-dependency score by using the combined value.
func TestScoreAll_UnmaintainedCountsUseActivity(t *testing.T) {
	const (
		active   = "github.com/a/active"   // release 40, push 1: neither bucket
		stale    = "github.com/b/stale"    // release 40, push 30: >2yr
		slowing  = "github.com/c/slowing"  // release 40, push 15: 1-2yr
		unknown  = "github.com/d/unknown"  // release 30, no push date: >2yr
		releases = "github.com/e/releases" // release 14, push 14: 1-2yr
	)
	graph := testutil.MakeGraph(
		testutil.DepSpec{Path: active, Version: "v1.0.0", Direct: true, Depth: 0},
		testutil.DepSpec{Path: stale, Version: "v1.0.0", Direct: true, Depth: 0},
		testutil.DepSpec{Path: slowing, Version: "v1.0.0", Direct: true, Depth: 0},
		testutil.DepSpec{Path: unknown, Version: "v1.0.0", Direct: true, Depth: 0},
		testutil.DepSpec{Path: releases, Version: "v1.0.0", Direct: true, Depth: 0},
	)
	input := twoAxisEmptyInput(graph)
	input.Now = activityNow
	input.Maintenance[active] = testutil.MakeMaintenanceInfo(40, false, false)
	input.Maintenance[stale] = testutil.MakeMaintenanceInfo(40, false, false)
	input.Maintenance[slowing] = testutil.MakeMaintenanceInfo(40, false, false)
	input.Maintenance[unknown] = testutil.MakeMaintenanceInfo(30, false, false)
	input.Maintenance[releases] = testutil.MakeMaintenanceInfo(14, false, false)
	input.Maintainers[active] = pushedMaintainer(1)
	input.Maintainers[stale] = pushedMaintainer(30)
	input.Maintainers[slowing] = pushedMaintainer(15)
	input.Maintainers[releases] = pushedMaintainer(14)

	ps := ScoreAll(input)

	if ps.Unmaintained2yr != 2 {
		t.Errorf("Unmaintained2yr = %d, want 2 (stale and unknown)", ps.Unmaintained2yr)
	}
	if ps.Unmaintained1yr != 2 {
		t.Errorf("Unmaintained1yr = %d, want 2 (slowing and releases)", ps.Unmaintained1yr)
	}
}
