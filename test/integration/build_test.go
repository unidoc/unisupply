package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/report"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// These tests resolve real, checked-in fixture modules under
// testdata/build/<case>/ with full resolution (directOnly=false), the only mode
// in which build membership is classified. Every dependency is a stub module
// in a sibling directory wired in with a local `replace`, so resolution needs
// neither the network nor the module cache. The scanner results (maintenance,
// maintainer) are synthetic: there is no network, and the point is how the
// classification and the scorer interact, not what the scanners find.
//
// Every fixture dependency is replaced, so Dependency.Replaced is true for all
// of them. The Integrity and PseudoVersion score inputs are left empty, which
// keeps replace penalties and the integrity floor out of the numbers.

// buildScoreNow pins the scoring clock so month arithmetic is deterministic.
var buildScoreNow = time.Date(2026, time.October, 8, 0, 0, 0, 0, time.UTC)

// resolveBuildFixture copies testdata/build/<name> into a temporary directory,
// resolves its main module the way the CLI does and returns the graph and the
// resolver warnings. The copy matters: GOFLAGS=-mod=mod lets the go command
// rewrite go.mod, which must never touch the checked-in fixture.
func resolveBuildFixture(t *testing.T, name string) (*resolver.Graph, []string) {
	t.Helper()

	t.Setenv("GOFLAGS", "-mod=mod")
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOSUMDB", "off")

	root := t.TempDir()
	if err := os.CopyFS(root, os.DirFS(testdataPath("build", name))); err != nil {
		t.Fatalf("copying fixture %s: %v", name, err)
	}

	graph, warnings, err := resolver.Resolve(context.Background(), filepath.Join(root, "main", "go.mod"), false)
	if err != nil {
		t.Fatalf("Resolve(%s) failed: %v", name, err)
	}
	return graph, warnings
}

func tri(b *bool) string {
	if b == nil {
		return "nil"
	}
	return fmt.Sprint(*b)
}

// wantClass is the expected resolver classification of one module. isTestOnly
// and inBuild are "nil", "true" or "false".
type wantClass struct {
	direct     bool
	isTestOnly string
	inBuild    string
	platforms  []string
}

func checkClassification(t *testing.T, g *resolver.Graph, want map[string]wantClass) {
	t.Helper()
	if len(g.Dependencies) != len(want) {
		t.Errorf("graph has %d dependencies, want %d: %v", len(g.Dependencies), len(want), g.SortedPaths())
	}
	for mod, w := range want {
		d, ok := g.Dependencies[mod]
		if !ok {
			t.Errorf("%s: not in graph (have %v)", mod, g.SortedPaths())
			continue
		}
		if d.Direct != w.direct {
			t.Errorf("%s: Direct = %v, want %v", mod, d.Direct, w.direct)
		}
		if got := tri(d.IsTestOnly); got != w.isTestOnly {
			t.Errorf("%s: IsTestOnly = %s, want %s", mod, got, w.isTestOnly)
		}
		if got := tri(d.InBuild); got != w.inBuild {
			t.Errorf("%s: InBuild = %s, want %s", mod, got, w.inBuild)
		}
		if !slices.Equal(d.Platforms, w.platforms) {
			t.Errorf("%s: Platforms = %v, want %v", mod, d.Platforms, w.platforms)
		}
	}
}

func buildScoreInput(g *resolver.Graph, months map[string]int) scorer.ScoreInput {
	in := emptyScoreInput(g)
	in.Now = buildScoreNow
	for mod, m := range months {
		in.Maintenance[mod] = testutil.MakeMaintenanceInfo(m, false, false)
	}
	return in
}

func scoreOf(t *testing.T, ps *scorer.ProjectScore, module string) *scorer.DependencyScore {
	t.Helper()
	for _, ds := range ps.Dependencies {
		if ds.Module == module {
			return ds
		}
	}
	t.Fatalf("%s not scored", module)
	return nil
}

func hasFactor(ds *scorer.DependencyScore, factor string) bool {
	return slices.Contains(ds.RiskFactors, factor)
}

func hasTimeBomb(ps *scorer.ProjectScore, kind, module string) bool {
	for _, tb := range scorer.CollectTimeBombs(ps) {
		if tb.Kind == kind && tb.Module == module {
			return true
		}
	}
	return false
}

// A repository that //go:embeds a gitignored build directory (absent from a
// fresh clone) still classifies, and a module that is only in the module graph
// does not drive the p95 headline candidate even though it scores highest.
func TestBuildClassification_MissingEmbedAndGraphOnlyModule(t *testing.T) {
	const (
		built     = "example.com/webkit"
		graphOnly = "example.com/unusedlib"
	)
	graph, warnings := resolveBuildFixture(t, "embed-graphonly")

	// The tolerated package error is informational: Resolve reports it as a
	// note, not as a warning that would be shown as a scan limitation.
	if len(warnings) != 0 {
		t.Fatalf("warnings = %q, want none", warnings)
	}
	if len(graph.Notes) != 1 {
		t.Fatalf("notes = %q, want exactly one", graph.Notes)
	}
	for _, want := range []string{"example.com/embedapp", "web/dist"} {
		if !strings.Contains(graph.Notes[0], want) {
			t.Errorf("note %q does not name %q", graph.Notes[0], want)
		}
	}
	if strings.Contains(graph.Notes[0], "unavailable") {
		t.Errorf("note %q: classification must not be reported unavailable", graph.Notes[0])
	}

	// webkit's used package does not import unusedlib; only a sibling package
	// (webkit/extra) does, so unusedlib is required but never compiled in.
	checkClassification(t, graph, map[string]wantClass{
		built:     {direct: true, isTestOnly: "false", inBuild: "true"},
		graphOnly: {direct: false, isTestOnly: "nil", inBuild: "false"},
	})

	// The graph-only module is the worst by far: unmaintained for 40 months.
	months := map[string]int{built: 6, graphOnly: 40}
	ps := scorer.ScoreAll(buildScoreInput(graph, months))

	builtScore, graphOnlyScore := scoreOf(t, ps, built), scoreOf(t, ps, graphOnly)
	if graphOnlyScore.RiskScore <= builtScore.RiskScore {
		t.Fatalf("precondition: graph-only score %d must exceed the built module's %d, or the test proves nothing",
			graphOnlyScore.RiskScore, builtScore.RiskScore)
	}

	h := ps.HeadlineCandidate
	if h == nil || h.Name != "p95_dep_risk" {
		t.Fatalf("headline candidate = %+v, want p95_dep_risk", h)
	}
	if h.DrivingDep != built {
		t.Errorf("p95 driver = %s, want the built module %s", h.DrivingDep, built)
	}
	if h.Score != float64(builtScore.RiskScore) || ps.OverallScore != builtScore.RiskScore {
		t.Errorf("headline score = %v, overall = %d, want the built module's %d", h.Score, ps.OverallScore, builtScore.RiskScore)
	}
	if h.TiedWith != 0 {
		t.Errorf("TiedWith = %d, want 0", h.TiedWith)
	}
	if !strings.Contains(h.Reason, "no reachable vulnerabilities; grade reflects dependency health") ||
		!strings.Contains(h.Reason, "of built modules") {
		t.Errorf("reason = %q, want the health-only reason scoped to built modules", h.Reason)
	}

	// Control: without the classification the same data makes the graph-only
	// module the driver. This is what the p95 filter prevents.
	graph.Dependencies[graphOnly].InBuild = nil
	ps = scorer.ScoreAll(buildScoreInput(graph, months))
	if got := ps.HeadlineCandidate.DrivingDep; got != graphOnly {
		t.Errorf("control: p95 driver = %s, want %s when InBuild is unknown", got, graphOnly)
	}
	if !strings.Contains(ps.HeadlineCandidate.Reason, "of built modules") {
		// buildClassified still sees verdicts on the other module.
		t.Errorf("control: reason = %q", ps.HeadlineCandidate.Reason)
	}
}

// The issue #135 shape: a go 1.15 main module (whose `go list all` would also
// pull in the packages the dependencies' own tests need), a dependency whose
// only importer is its own test, a module used only by the main module's tests
// and a dependency that imports another module on Windows only.
func TestBuildClassification_CobraGo115(t *testing.T) {
	const (
		cobra     = "example.com/cobra"
		mousetrap = "example.com/mousetrap"
		check     = "example.com/check"
		testify   = "example.com/testify"
	)
	graph, warnings := resolveBuildFixture(t, "cobra-go115")
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %q", warnings)
	}

	checkClassification(t, graph, map[string]wantClass{
		cobra: {direct: true, isTestOnly: "false", inBuild: "true"},
		// Imported only from cobra_windows.go: production, whatever the host.
		mousetrap: {direct: false, isTestOnly: "false", inBuild: "true", platforms: []string{"windows"}},
		// Used only by cobra's own tests: never part of this module's build.
		check: {direct: false, isTestOnly: "nil", inBuild: "false"},
		// Used only by the main module's tests.
		testify: {direct: true, isTestOnly: "true", inBuild: "true"},
	})

	// check and testify are both worse than every built module, so only the
	// classification keeps them from setting the headline.
	months := map[string]int{cobra: 6, mousetrap: 18, check: 30, testify: 30}
	ps := scorer.ScoreAll(buildScoreInput(graph, months))

	mouseScore := scoreOf(t, ps, mousetrap)
	for _, mod := range []string{cobra, check, testify} {
		other := scoreOf(t, ps, mod)
		if mod == cobra && other.RiskScore >= mouseScore.RiskScore {
			t.Fatalf("precondition: %s score %d must be below mousetrap's %d", mod, other.RiskScore, mouseScore.RiskScore)
		}
		if mod != cobra && other.RiskScore <= mouseScore.RiskScore {
			t.Fatalf("precondition: %s score %d must exceed mousetrap's %d", mod, other.RiskScore, mouseScore.RiskScore)
		}
	}

	h := ps.HeadlineCandidate
	if h == nil || h.Name != "p95_dep_risk" || h.DrivingDep != mousetrap {
		t.Fatalf("headline candidate = %+v, want p95_dep_risk driven by %s (a Windows-only module counts as built)", h, mousetrap)
	}
	if ps.OverallScore != mouseScore.RiskScore {
		t.Errorf("overall = %d, want %d", ps.OverallScore, mouseScore.RiskScore)
	}

	// Control: a module outside the build with an unknown classification
	// would have driven the headline.
	graph.Dependencies[check].InBuild = nil
	ps = scorer.ScoreAll(buildScoreInput(graph, months))
	if got := ps.HeadlineCandidate.DrivingDep; got != check {
		t.Errorf("control: p95 driver = %s, want %s when InBuild is unknown", got, check)
	}
	graph.Dependencies[check].InBuild = testutil.BoolPtr(false)

	// The JSON report carries the classification.
	ps = scorer.ScoreAll(buildScoreInput(graph, months))
	var buf bytes.Buffer
	if err := report.WriteJSON(graph, ps, report.JSONOptions{GoVersion: "1.15"}, &buf); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	var out struct {
		Headline struct {
			Driver      string `json:"driver"`
			DrivingItem string `json:"driving_item"`
		} `json:"headline"`
		Deps []map[string]any `json:"dependencies"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}
	if out.Headline.Driver != "p95_dep_risk" || out.Headline.DrivingItem != mousetrap {
		t.Errorf("headline = %+v, want p95_dep_risk / %s", out.Headline, mousetrap)
	}

	byModule := make(map[string]map[string]any, len(out.Deps))
	for _, d := range out.Deps {
		byModule[d["module"].(string)] = d
	}
	// A nil is emitted as an absent key, never as false.
	wantKeys := map[string]map[string]any{
		cobra:     {"test_only": false, "in_build": true, "platforms": nil},
		mousetrap: {"test_only": false, "in_build": true, "platforms": []any{"windows"}},
		check:     {"test_only": nil, "in_build": false, "platforms": nil},
		testify:   {"test_only": true, "in_build": true, "platforms": nil},
	}
	for mod, keys := range wantKeys {
		d, ok := byModule[mod]
		if !ok {
			t.Errorf("%s missing from JSON dependencies", mod)
			continue
		}
		for key, want := range keys {
			got, present := d[key]
			if want == nil {
				if present {
					t.Errorf("%s: %s = %v present, want the key omitted", mod, key, got)
				}
				continue
			}
			if !present || fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("%s: %s = %v (present=%v), want %v", mod, key, got, present, want)
			}
		}
	}
}

// Floors, time bombs and the unmaintained factor against classified modules:
// a graph-only archived module, a vanity-path archived direct module and a
// module whose last tag is old but whose repository is pushed to.
func TestBuildClassification_FloorsAndActivity(t *testing.T) {
	const (
		yaml      = "gopkg.in/yaml.v3"
		rare      = "example.com/rarelytagged"
		stale     = "example.com/stale"
		graphOnly = "example.com/archivedgraphonly"
	)
	graph, warnings := resolveBuildFixture(t, "floors")
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %q", warnings)
	}
	checkClassification(t, graph, map[string]wantClass{
		yaml:      {direct: true, isTestOnly: "false", inBuild: "true"},
		rare:      {direct: true, isTestOnly: "false", inBuild: "true"},
		stale:     {direct: true, isTestOnly: "false", inBuild: "true"},
		graphOnly: {direct: false, isTestOnly: "nil", inBuild: "false"},
	})

	// The scanner derives the repository from the module path alone: no new
	// host is contacted. The maintainer data below is what that scan returns.
	owner, repo, via := scanner.ResolveSourceRepo(yaml, "")
	if owner != "go-yaml" || repo != "yaml" || via != scanner.SourceViaGopkgIn {
		t.Fatalf("ResolveSourceRepo(%s) = %s/%s via %s, want go-yaml/yaml via %s", yaml, owner, repo, via, scanner.SourceViaGopkgIn)
	}
	archivedRepo := func() *scanner.MaintainerInfo {
		return &scanner.MaintainerInfo{
			DataAvailable: true,
			Owner:         owner,
			Repo:          repo,
			SourceRepo:    "github.com/go-yaml/yaml",
			SourceRepoVia: scanner.SourceViaGopkgIn,
			IsArchived:    true,
		}
	}
	months := map[string]int{yaml: 6, rare: 6, stale: 6, graphOnly: 6}

	t.Run("graph-only archived module does not floor", func(t *testing.T) {
		in := buildScoreInput(graph, months)
		in.Maintainers[graphOnly] = archivedRepo()
		ps := scorer.ScoreAll(in)

		if ps.HeadlineDriver == "archived_floor" {
			t.Errorf("headline driver = archived_floor (%+v), want no floor from a module outside the build", ps.HeadlineCandidate)
		}
		if ps.OverallLevel == scorer.RiskHigh {
			t.Errorf("overall level = %s, want below HIGH", ps.OverallLevel)
		}
		if hasTimeBomb(ps, "archived", graphOnly) {
			t.Errorf("%s reported as an archived time bomb, want it exempt outside the build", graphOnly)
		}

		// Control: an unknown classification must not absolve it.
		graph.Dependencies[graphOnly].InBuild = nil
		defer func() { graph.Dependencies[graphOnly].InBuild = testutil.BoolPtr(false) }()
		ps = scorer.ScoreAll(in)
		if ps.HeadlineDriver != "archived_floor" || ps.OverallScore != 51 || ps.HeadlineCandidate.DrivingDep != graphOnly {
			t.Errorf("control: headline = %s %d %+v, want archived_floor 51 on %s", ps.HeadlineDriver, ps.OverallScore, ps.HeadlineCandidate, graphOnly)
		}
		if !hasTimeBomb(ps, "archived", graphOnly) {
			t.Errorf("control: %s not reported as a time bomb with unknown InBuild", graphOnly)
		}
	})

	t.Run("archived vanity-path direct module floors at 60", func(t *testing.T) {
		in := buildScoreInput(graph, months)
		in.Maintainers[yaml] = archivedRepo()
		ps := scorer.ScoreAll(in)

		h := ps.HeadlineCandidate
		if ps.HeadlineDriver != "archived_floor" || ps.OverallScore != 60 || h == nil || h.DrivingDep != yaml {
			t.Fatalf("headline = %s %d %+v, want archived_floor 60 on %s", ps.HeadlineDriver, ps.OverallScore, h, yaml)
		}
		if ps.OverallLevel != scorer.RiskHigh {
			t.Errorf("overall level = %s, want HIGH", ps.OverallLevel)
		}
		if !hasFactor(scoreOf(t, ps, yaml), "archived") {
			t.Errorf("%s: risk factors %v lack archived", yaml, scoreOf(t, ps, yaml).RiskFactors)
		}
		if !hasTimeBomb(ps, "archived", yaml) {
			t.Errorf("%s not reported as an archived time bomb", yaml)
		}
	})

	t.Run("old tag with recent push is not unmaintained", func(t *testing.T) {
		const (
			oldTagMonths = 40
			recentPush   = 1
			stalePush    = 30
		)
		monthsAgo := func(n int) time.Time { return buildScoreNow.AddDate(0, -n, 0) }
		months := map[string]int{yaml: 6, rare: oldTagMonths, stale: oldTagMonths, graphOnly: 6}

		in := buildScoreInput(graph, months)
		in.Maintainers[rare] = &scanner.MaintainerInfo{DataAvailable: true, LastCommitDate: monthsAgo(recentPush)}
		in.Maintainers[stale] = &scanner.MaintainerInfo{DataAvailable: true, LastCommitDate: monthsAgo(stalePush)}
		ps := scorer.ScoreAll(in)

		rareScore, staleScore := scoreOf(t, ps, rare), scoreOf(t, ps, stale)
		if hasFactor(rareScore, "unmaintained") {
			t.Errorf("%s: factors %v include unmaintained despite a push %d month ago", rare, rareScore.RiskFactors, recentPush)
		}
		if got := rareScore.Maintenance.MonthsInactive(); got != recentPush {
			t.Errorf("%s: MonthsInactive = %d, want %d", rare, got, recentPush)
		}
		if rareScore.Maintenance.MonthsSinceRelease != oldTagMonths {
			t.Errorf("%s: MonthsSinceRelease = %d, want the release age %d kept", rare, rareScore.Maintenance.MonthsSinceRelease, oldTagMonths)
		}
		if !hasFactor(staleScore, "unmaintained") {
			t.Errorf("%s: factors %v lack unmaintained for an old tag and an old push", stale, staleScore.RiskFactors)
		}
		if rareScore.RiskScore >= staleScore.RiskScore {
			t.Errorf("active module scored %d, abandoned one %d, want active lower", rareScore.RiskScore, staleScore.RiskScore)
		}

		// Control: without GitHub data the same old tag reads as unmaintained.
		delete(in.Maintainers, rare)
		ps = scorer.ScoreAll(in)
		if !hasFactor(scoreOf(t, ps, rare), "unmaintained") {
			t.Errorf("control: %s lacks unmaintained without activity data", rare)
		}
	})
}
