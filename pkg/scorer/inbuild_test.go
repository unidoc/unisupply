package scorer

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// p95Dep builds a DependencyScore for the p95 and floor tests. testOnly and
// inBuild are the three-state classifications (nil = unknown).
func p95Dep(module string, score int, testOnly, inBuild *bool) *DependencyScore {
	return &DependencyScore{Module: module, RiskScore: score, IsTestOnly: testOnly, InBuild: inBuild}
}

// TestP95DepRiskCandidate_InBuildFilter verifies that confirmed test-only and
// confirmed outside-the-build modules never set the p95, and that unknown (nil)
// classifications are counted.
func TestP95DepRiskCandidate_InBuildFilter(t *testing.T) {
	yes, no := testutil.BoolPtr(true), testutil.BoolPtr(false)

	// 18 modules at 10 plus two at 90: nearest-rank p95 of 20 is index 18, so
	// the p95 is 90 only while both high scorers are counted.
	build := func(highTestOnly, highInBuild *bool) []*DependencyScore {
		deps := make([]*DependencyScore, 0, 20)
		for i := 0; i < 18; i++ {
			deps = append(deps, p95Dep(fmt.Sprintf("github.com/low/pkg%02d", i), 10, no, yes))
		}
		deps = append(deps,
			p95Dep("github.com/high/a", 90, highTestOnly, highInBuild),
			p95Dep("github.com/high/b", 90, highTestOnly, highInBuild),
		)
		return deps
	}

	tests := []struct {
		name      string
		testOnly  *bool
		inBuild   *bool
		wantScore float64
	}{
		{"high scorers built and production set the p95", no, yes, 90},
		{"outside-build high scorers do not set the p95", no, no, 10},
		{"test-only high scorers do not set the p95", yes, yes, 10},
		{"nil InBuild is counted", no, nil, 90},
		{"nil IsTestOnly is counted", nil, yes, 90},
		{"both nil is counted", nil, nil, 90},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p95DepRiskCandidate(build(tt.testOnly, tt.inBuild))
			if got.Score != tt.wantScore {
				t.Errorf("Score = %.0f, want %.0f (DrivingDep %q)", got.Score, tt.wantScore, got.DrivingDep)
			}
		})
	}
}

// TestP95DepRiskCandidate_AllFilteredReturnsZero verifies that when every
// dependency is filtered out the result is the zero candidate, as for an empty
// graph.
func TestP95DepRiskCandidate_AllFilteredReturnsZero(t *testing.T) {
	yes, no := testutil.BoolPtr(true), testutil.BoolPtr(false)
	deps := []*DependencyScore{
		p95Dep("github.com/a/outside", 80, no, no),
		p95Dep("github.com/b/testonly", 70, yes, yes),
	}
	got := p95DepRiskCandidate(deps)
	want := HeadlineCandidate{Name: "p95_dep_risk"}
	if got != want {
		t.Errorf("candidate = %+v, want %+v", got, want)
	}
}

// TestP95DepRiskCandidate_TieIsDeterministic verifies that a tie at the p95
// index names the same module for every input order, and that TiedWith and the
// reason describe the tie.
func TestP95DepRiskCandidate_TieIsDeterministic(t *testing.T) {
	// 20 modules: 15 at 10, four tied at 32 (sorted positions 15-18), one at
	// 40. idx = ceil(0.95*20)-1 = 18 lands inside the tie, on the last of the
	// four by module path.
	base := make([]*DependencyScore, 0, 20)
	for i := 0; i < 15; i++ {
		base = append(base, p95Dep(fmt.Sprintf("github.com/low/pkg%02d", i), 10, nil, nil))
	}
	for _, name := range []string{"github.com/tie/kr-text", "github.com/tie/atotto", "github.com/tie/kr-pty", "github.com/tie/harmonica"} {
		base = append(base, p95Dep(name, 32, nil, nil))
	}
	base = append(base, p95Dep("github.com/top/one", 40, nil, nil))

	const wantModule = "github.com/tie/kr-text"
	rng := rand.New(rand.NewSource(1))
	for run := 0; run < 100; run++ {
		deps := append([]*DependencyScore(nil), base...)
		rng.Shuffle(len(deps), func(i, j int) { deps[i], deps[j] = deps[j], deps[i] })

		got := p95DepRiskCandidate(deps)
		if got.DrivingDep != wantModule {
			t.Fatalf("run %d: DrivingDep = %q, want %q", run, got.DrivingDep, wantModule)
		}
		if got.Score != 32 {
			t.Fatalf("run %d: Score = %.0f, want 32", run, got.Score)
		}
		if got.TiedWith != 3 {
			t.Fatalf("run %d: TiedWith = %d, want 3", run, got.TiedWith)
		}
		if want := "p95 of dep risk scores (one of 4 modules at 32)"; got.Reason != want {
			t.Fatalf("run %d: Reason = %q, want %q", run, got.Reason, want)
		}
	}
}

// TestP95DepRiskCandidate_NoTie verifies the plain reason and a zero TiedWith
// when the p95 score is unique, and that the caller's slice order is kept.
func TestP95DepRiskCandidate_NoTie(t *testing.T) {
	deps := make([]*DependencyScore, 20)
	for i := range deps {
		deps[i] = p95Dep(fmt.Sprintf("github.com/pkg%02d", 20-i), i+1, nil, nil)
	}
	first := deps[0]

	got := p95DepRiskCandidate(deps)
	if got.Score != 19 || got.TiedWith != 0 {
		t.Errorf("Score = %.0f TiedWith = %d, want 19 and 0", got.Score, got.TiedWith)
	}
	if got.Reason != "p95 of dep risk scores" {
		t.Errorf("Reason = %q, want the plain p95 reason", got.Reason)
	}
	if deps[0] != first {
		t.Error("p95DepRiskCandidate reordered the caller's slice")
	}
}

// TestP95DepRiskCandidate_TiedWithIgnoresFilteredModules verifies that modules
// dropped by the filter are not counted as ties.
func TestP95DepRiskCandidate_TiedWithIgnoresFilteredModules(t *testing.T) {
	no := testutil.BoolPtr(false)
	deps := []*DependencyScore{
		p95Dep("github.com/a/built", 32, nil, nil),
		p95Dep("github.com/b/outside", 32, no, no),
	}
	got := p95DepRiskCandidate(deps)
	if got.TiedWith != 0 {
		t.Errorf("TiedWith = %d, want 0 (the other module at 32 is outside the build)", got.TiedWith)
	}
}

// TestComputeDiagnostics_P95MirrorsHeadlineMaxStaysFullGraph pins the PM
// decision: Max stays over the full graph, P95 mirrors the headline candidate.
func TestComputeDiagnostics_P95MirrorsHeadlineMaxStaysFullGraph(t *testing.T) {
	no := testutil.BoolPtr(false)
	deps := []*DependencyScore{
		p95Dep("github.com/a/built", 20, nil, nil),
		p95Dep("github.com/b/outside", 95, no, no),
	}
	d := computeDiagnostics(deps)
	if d.MaxDepRiskScore != 95 {
		t.Errorf("MaxDepRiskScore = %d, want 95 (full graph)", d.MaxDepRiskScore)
	}
	if want := int(p95DepRiskCandidate(deps).Score); d.P95DepRiskScore != want || want != 20 {
		t.Errorf("P95DepRiskScore = %d, headline p95 = %d, want both 20", d.P95DepRiskScore, want)
	}
}

// TestArchivedFloor_InBuild verifies that the archived floor counts only
// built modules: confirmed outside-the-build and confirmed test-only modules
// do not fire it, while an unknown (nil) InBuild still does.
func TestArchivedFloor_InBuild(t *testing.T) {
	yes, no := testutil.BoolPtr(true), testutil.BoolPtr(false)
	archived := &scanner.MaintenanceInfo{Archived: true, MonthsSinceRelease: 87}

	tests := []struct {
		name      string
		testOnly  *bool
		inBuild   *bool
		wantScore float64
	}{
		{"outside the build does not fire", no, no, 0},
		{"outside the build with unknown test-only does not fire", nil, no, 0},
		{"test-only does not fire", yes, nil, 0},
		{"nil InBuild still fires", no, nil, 51},
		{"both nil still fires", nil, nil, 51},
		{"in build fires", no, yes, 51},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := &DependencyScore{
				Module:      "github.com/kr/pty",
				IsTestOnly:  tt.testOnly,
				InBuild:     tt.inBuild,
				Maintenance: archived,
			}
			got := archivedFloor([]*DependencyScore{ds})
			if got.Score != tt.wantScore {
				t.Errorf("Score = %.0f, want %.0f", got.Score, tt.wantScore)
			}
		})
	}
}

// TestCollectTimeBombs_InBuild verifies that confirmed outside-the-build and
// test-only modules produce no time-bombs, and that nil InBuild does.
func TestCollectTimeBombs_InBuild(t *testing.T) {
	yes, no := testutil.BoolPtr(true), testutil.BoolPtr(false)
	archived := &scanner.MaintenanceInfo{Archived: true}
	critical := []scanner.Vulnerability{{ID: "GO-2024-0001", Severity: "CRITICAL", Reachability: "called"}}

	tests := []struct {
		name     string
		testOnly *bool
		inBuild  *bool
		want     int
	}{
		{"outside the build is skipped", no, no, 0},
		{"test-only is skipped", yes, nil, 0},
		{"nil InBuild is kept", no, nil, 2},
		{"in build is kept", no, yes, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps := &ProjectScore{Dependencies: []*DependencyScore{{
				Module:      "github.com/x/y",
				IsTestOnly:  tt.testOnly,
				InBuild:     tt.inBuild,
				Maintenance: archived,
				Vulns:       critical,
			}}}
			if got := len(CollectTimeBombs(ps)); got != tt.want {
				t.Errorf("len(CollectTimeBombs) = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestCVEFloorAndSeverityAdjusted_IgnoreInBuild pins the deliberate absence of
// InBuild handling: reachability tiers already encode "not linked in", so an
// outside-the-build module with a called CRITICAL CVE is scored exactly like a
// built one.
func TestCVEFloorAndSeverityAdjusted_IgnoreInBuild(t *testing.T) {
	no := testutil.BoolPtr(false)
	vulns := []scanner.Vulnerability{makeVulnWithReachability("CVE-2024-0001", "CRITICAL", "called")}

	in := &DependencyScore{Module: "github.com/x/y", IsTestOnly: no, InBuild: testutil.BoolPtr(true), Vulns: vulns}
	out := &DependencyScore{Module: "github.com/x/y", IsTestOnly: no, InBuild: no, Vulns: vulns}

	if a, b := cveFloor([]*DependencyScore{in}).Score, cveFloor([]*DependencyScore{out}).Score; a != b || a != 60 {
		t.Errorf("cveFloor in-build = %.0f, outside-build = %.0f, want both 60", a, b)
	}
	if a, b := severityAdjustedVulnScore(time.Now(), []*DependencyScore{in}).score,
		severityAdjustedVulnScore(time.Now(), []*DependencyScore{out}).score; a != b || a != 95 {
		t.Errorf("severity_adjusted in-build = %d, outside-build = %d, want both 95", a, b)
	}
}

// TestIntegrityFloor_IgnoresInBuild pins that a replace redirect still floors
// the headline on a graph-only module, and that test-only still skips.
func TestIntegrityFloor_IgnoresInBuild(t *testing.T) {
	yes, no := testutil.BoolPtr(true), testutil.BoolPtr(false)
	mk := func(testOnly, inBuild *bool) *DependencyScore {
		return &DependencyScore{
			Module:       "github.com/fork/y",
			Direct:       true,
			IsTestOnly:   testOnly,
			InBuild:      inBuild,
			ReplaceClass: scanner.IntegrityHigh,
		}
	}
	if got := integrityFloor([]*DependencyScore{mk(no, no)}, false).Score; got != 60 {
		t.Errorf("outside-build redirect floor = %.0f, want 60", got)
	}
	if got := integrityFloor([]*DependencyScore{mk(yes, yes)}, false).Score; got != 0 {
		t.Errorf("test-only redirect floor = %.0f, want 0 (existing skip)", got)
	}
}

// healthOnlyInput builds a scan where the vulnerability scan ran, no CVE or
// integrity candidate fires, and the one dependency still scores above zero on
// depth and maturity, so p95_dep_risk is the sole decider. The dependency is
// confirmed in the build, so build classification counts as available.
func healthOnlyInput() ScoreInput {
	input := twoAxisEmptyInput(testutil.MakeGraph(
		testutil.DepSpec{Path: "github.com/test/pkg", Version: "v0.1.0", Direct: false, Depth: 1, InBuild: testutil.BoolPtr(true)},
	))
	input.Maintainers["github.com/test/pkg"] = &scanner.MaintainerInfo{DataAvailable: false}
	input.Resilience["github.com/test/pkg"] = &scanner.ResilienceInfo{DataAvailable: false}
	return input
}

const healthOnlyReasonPrefix = "no reachable vulnerabilities; grade reflects dependency health (maintenance, maturity) of built modules — "

const healthOnlyUnclassifiedPrefix = "no reachable vulnerabilities; grade reflects dependency health (maintenance, maturity) of all modules in the dependency graph (build classification unavailable) — "

// TestScoreAll_HealthOnlyReason verifies that the headline reason says p95
// alone decided the grade, only when that is true, and that the reason on the
// candidate and the headline driver agree.
func TestScoreAll_HealthOnlyReason(t *testing.T) {
	t.Run("set when p95 is the sole decider", func(t *testing.T) {
		ps := ScoreAll(healthOnlyInput())
		if ps.HeadlineDriver != "p95_dep_risk" {
			t.Fatalf("HeadlineDriver = %q, want p95_dep_risk (test setup)", ps.HeadlineDriver)
		}
		if ps.OverallScore == 0 {
			t.Fatal("OverallScore = 0, want a non-zero p95 (test setup)")
		}
		want := healthOnlyReasonPrefix + "p95 of dep risk scores"
		if ps.HeadlineCandidate == nil || ps.HeadlineCandidate.Reason != want {
			t.Errorf("HeadlineCandidate = %+v, want Reason %q", ps.HeadlineCandidate, want)
		}
		if ps.OverallLevel == RiskUnknown {
			t.Errorf("OverallLevel = UNKNOWN, want a real band (the scan ran)")
		}
	})

	t.Run("says so when build classification is unavailable", func(t *testing.T) {
		// Every InBuild is nil: nothing was filtered by build membership, so
		// "built modules" would overstate the population.
		input := twoAxisEmptyInput(testutil.MakeGraph(
			testutil.DepSpec{Path: "github.com/test/a", Version: "v0.1.0", Depth: 1},
			testutil.DepSpec{Path: "github.com/test/b", Version: "v0.1.0", Depth: 1},
		))
		ps := ScoreAll(input)
		if ps.HeadlineDriver != "p95_dep_risk" || ps.HeadlineCandidate == nil {
			t.Fatalf("HeadlineDriver = %q, want p95_dep_risk (test setup)", ps.HeadlineDriver)
		}
		got := ps.HeadlineCandidate.Reason
		if !strings.HasPrefix(got, healthOnlyUnclassifiedPrefix) || strings.Contains(got, "of built modules") {
			t.Errorf("Reason = %q, want prefix %q and no \"of built modules\"", got, healthOnlyUnclassifiedPrefix)
		}
		if !strings.HasSuffix(got, "p95 of dep risk scores (one of 2 modules at "+fmt.Sprint(ps.OverallScore)+")") {
			t.Errorf("Reason = %q, want the p95 tie wording to be kept", got)
		}
	})

	t.Run("one classified dependency is enough for the built wording", func(t *testing.T) {
		input := twoAxisEmptyInput(testutil.MakeGraph(
			testutil.DepSpec{Path: "github.com/test/a", Version: "v0.1.0", Depth: 1, InBuild: testutil.BoolPtr(true)},
			testutil.DepSpec{Path: "github.com/test/b", Version: "v0.1.0", Depth: 1},
		))
		ps := ScoreAll(input)
		if ps.HeadlineCandidate == nil || !strings.HasPrefix(ps.HeadlineCandidate.Reason, healthOnlyReasonPrefix) {
			t.Errorf("HeadlineCandidate = %+v, want the built-modules prefix", ps.HeadlineCandidate)
		}
	})

	t.Run("keeps the tie wording", func(t *testing.T) {
		input := twoAxisEmptyInput(testutil.MakeGraph(
			testutil.DepSpec{Path: "github.com/test/a", Version: "v0.1.0", Depth: 1, InBuild: testutil.BoolPtr(true)},
			testutil.DepSpec{Path: "github.com/test/b", Version: "v0.1.0", Depth: 1, InBuild: testutil.BoolPtr(true)},
		))
		ps := ScoreAll(input)
		if ps.HeadlineCandidate == nil || ps.HeadlineCandidate.TiedWith != 1 {
			t.Fatalf("HeadlineCandidate = %+v, want TiedWith 1 (test setup)", ps.HeadlineCandidate)
		}
		if !strings.HasPrefix(ps.HeadlineCandidate.Reason, healthOnlyReasonPrefix) ||
			!strings.Contains(ps.HeadlineCandidate.Reason, "(one of 2 modules at") {
			t.Errorf("Reason = %q, want health-only prefix plus tie wording", ps.HeadlineCandidate.Reason)
		}
	})

	t.Run("not set when a CVE candidate is non-zero", func(t *testing.T) {
		input := healthOnlyInput()
		// A called LOW CVE gives severity_adjusted 10, below the dep's p95,
		// so p95_dep_risk still wins while a CVE candidate is non-zero.
		input.Vulns["github.com/test/pkg"] = []scanner.Vulnerability{
			makeVulnWithReachability("CVE-2024-0002", "LOW", "called"),
		}
		ps := ScoreAll(input)
		if ps.SeverityAdjustedVulnScore == 0 {
			t.Fatal("SeverityAdjustedVulnScore = 0, want non-zero (test setup)")
		}
		if ps.HeadlineDriver != "p95_dep_risk" {
			t.Fatalf("HeadlineDriver = %q, want p95_dep_risk (test setup)", ps.HeadlineDriver)
		}
		if strings.Contains(ps.HeadlineCandidate.Reason, "no reachable vulnerabilities") {
			t.Errorf("Reason = %q, must not claim no vulnerabilities", ps.HeadlineCandidate.Reason)
		}
	})

	t.Run("not set when the vulnerability scan did not run", func(t *testing.T) {
		input := healthOnlyInput()
		input.VulnScanUnavailable = true
		ps := ScoreAll(input)
		if ps.OverallLevel != RiskUnknown {
			t.Errorf("OverallLevel = %s, want UNKNOWN (existing path)", ps.OverallLevel)
		}
		if ps.HeadlineCandidate == nil || strings.Contains(ps.HeadlineCandidate.Reason, "no reachable vulnerabilities") {
			t.Errorf("HeadlineCandidate = %+v, Reason must stay plain", ps.HeadlineCandidate)
		}
	})

	t.Run("not set when another candidate wins", func(t *testing.T) {
		input := healthOnlyInput()
		input.Maintainers["github.com/test/pkg"] = &scanner.MaintainerInfo{DataAvailable: true, IsArchived: true}
		ps := ScoreAll(input)
		if ps.HeadlineDriver != "archived_floor" {
			t.Fatalf("HeadlineDriver = %q, want archived_floor (test setup)", ps.HeadlineDriver)
		}
		if strings.Contains(ps.HeadlineCandidate.Reason, "no reachable vulnerabilities") {
			t.Errorf("Reason = %q, must not carry the health-only text", ps.HeadlineCandidate.Reason)
		}
	})
}

// TestScoreDependency_CopiesInBuildAndPlatforms verifies the resolver
// classification reaches DependencyScore through ScoreAll, with nil staying nil.
func TestScoreDependency_CopiesInBuildAndPlatforms(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{Path: "github.com/a/outside", Version: "v1.0.0", Depth: 1, InBuild: testutil.BoolPtr(false)},
		testutil.DepSpec{Path: "github.com/b/unknown", Version: "v1.0.0", Depth: 1},
	)
	graph.Dependencies["github.com/a/outside"].Platforms = []string{"windows"}

	ps := ScoreAll(twoAxisEmptyInput(graph))
	byModule := map[string]*DependencyScore{}
	for _, ds := range ps.Dependencies {
		byModule[ds.Module] = ds
	}
	out := byModule["github.com/a/outside"]
	if out.InBuild == nil || *out.InBuild {
		t.Errorf("outside InBuild = %v, want &false", out.InBuild)
	}
	if len(out.Platforms) != 1 || out.Platforms[0] != "windows" {
		t.Errorf("outside Platforms = %v, want [windows]", out.Platforms)
	}
	if unk := byModule["github.com/b/unknown"]; unk.InBuild != nil || unk.Platforms != nil {
		t.Errorf("unknown InBuild/Platforms = %v/%v, want nil/nil", unk.InBuild, unk.Platforms)
	}
}
