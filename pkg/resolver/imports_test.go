package resolver

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// hostTarget is the "goos/goarch" of the machine running the tests, with the
// environment overrides cleared so that scanTarget() is the host too. It skips
// the test when the host is not one of the listed targets.
func hostTarget(t *testing.T) string {
	t.Helper()
	t.Setenv("GOOS", "")
	t.Setenv("GOARCH", "")
	host := runtime.GOOS + "/" + runtime.GOARCH
	if !slices.Contains(listTargets(), host) {
		t.Skipf("host target %s is not one of the listed targets", host)
	}
	return host
}

// listTargets is every target listPlatforms lists, as "goos/goarch".
func listTargets() []string {
	var out []string
	for _, goos := range listGOOS {
		for _, goarch := range listGOARCH {
			out = append(out, goos+"/"+goarch)
		}
	}
	return out
}

// resolveImports writes fx and stubs, adds the package files in extra (paths
// relative to the directory that holds main and the stubs) and runs Resolve.
func resolveImports(t *testing.T, fx fixture, stubs map[string]stubOpts, extra map[string]string, directOnly bool) *Graph {
	t.Helper()
	mainDir := writeFixture(t, fx, stubs)
	for path, content := range extra {
		write(t, filepath.Join(filepath.Dir(mainDir), path), content)
	}
	g, _, err := Resolve(context.Background(), filepath.Join(mainDir, "go.mod"), directOnly)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return g
}

func imp(paths ...string) string {
	var b strings.Builder
	for _, p := range paths {
		b.WriteString("import _ \"" + p + "\"\n")
	}
	return b.String()
}

// TestResolvePackageGraphChain checks that Resolve keeps the production import
// graph of the scan target and finds the chain from the main module's package
// through a dependency to a package of a second dependency.
func TestResolvePackageGraphChain(t *testing.T) {
	host := hostTarget(t)
	g := resolveImports(t,
		fixture{
			direct:   []string{"a"},
			indirect: []string{"b"},
			files:    map[string]string{"cmd/x/main.go": "package main\n\n" + imp("example.com/a") + "\nfunc main() {}\n"},
		},
		map[string]stubOpts{"a": {requires: []string{"b"}}, "b": {}},
		map[string]string{
			"a/a.go":         "package a\n\n" + imp("example.com/b/vuln"),
			"b/vuln/vuln.go": "package vuln\n",
		},
		false,
	)

	if g.Packages == nil {
		t.Fatal("Graph.Packages is nil, want the scan target's package graph")
	}
	if g.Packages.Platform != host {
		t.Errorf("Platform = %q, want %q", g.Packages.Platform, host)
	}
	if g.Packages.Partial {
		t.Error("Partial = true, want false for a clean listing")
	}
	if want := []string{"example.com/main/cmd/x"}; !slices.Equal(g.Packages.Roots, want) {
		t.Errorf("Roots = %v, want %v", g.Packages.Roots, want)
	}
	got := g.Packages.ShortestImportPath([]string{"example.com/b/vuln"})
	want := []string{"example.com/main/cmd/x", "example.com/a", "example.com/b/vuln"}
	if !slices.Equal(got, want) {
		t.Errorf("ShortestImportPath = %v, want %v", got, want)
	}
	// A package the project does not import has no chain.
	if got := g.Packages.ShortestImportPath([]string{"example.com/b"}); got != nil {
		t.Errorf("ShortestImportPath(unimported package) = %v, want nil", got)
	}
}

// TestResolvePackageGraphTieIsStable checks that two chains of the same length
// resolve to the same one on every call and on every listing: the first root
// in sorted order, then the first import in sorted order.
func TestResolvePackageGraphTieIsStable(t *testing.T) {
	hostTarget(t)
	g := resolveImports(t,
		fixture{
			direct:   []string{"a", "c"},
			indirect: []string{"b"},
			files: map[string]string{
				"cmd/y/main.go": "package main\n\n" + imp("example.com/c") + "\nfunc main() {}\n",
				"cmd/x/main.go": "package main\n\n" + imp("example.com/c", "example.com/a") + "\nfunc main() {}\n",
			},
		},
		map[string]stubOpts{"a": {requires: []string{"b"}}, "b": {}, "c": {requires: []string{"b"}}},
		map[string]string{
			"a/a.go":         "package a\n\n" + imp("example.com/b/vuln"),
			"c/c.go":         "package c\n\n" + imp("example.com/b/vuln"),
			"b/vuln/vuln.go": "package vuln\n",
		},
		false,
	)
	if g.Packages == nil {
		t.Fatal("Graph.Packages is nil")
	}
	if want := []string{"example.com/main/cmd/x", "example.com/main/cmd/y"}; !slices.Equal(g.Packages.Roots, want) {
		t.Fatalf("Roots = %v, want sorted %v", g.Packages.Roots, want)
	}
	want := []string{"example.com/main/cmd/x", "example.com/a", "example.com/b/vuln"}
	for i := range 5 {
		if got := g.Packages.ShortestImportPath([]string{"example.com/b/vuln"}); !slices.Equal(got, want) {
			t.Fatalf("call %d: ShortestImportPath = %v, want %v", i, got, want)
		}
	}
}

// TestResolvePackageGraphProductionOnly checks that a package imported only
// from a _test.go file of the main module is not in the graph.
func TestResolvePackageGraphProductionOnly(t *testing.T) {
	hostTarget(t)
	g := resolveImports(t,
		fixture{
			direct:   []string{"a"},
			indirect: []string{"b"},
			files: map[string]string{
				"cmd/x/main.go":      "package main\n\n" + imp("example.com/a") + "\nfunc main() {}\n",
				"cmd/x/main_test.go": "package main\n\n" + imp("example.com/b/vuln"),
			},
		},
		map[string]stubOpts{"a": {}, "b": {}},
		map[string]string{"b/vuln/vuln.go": "package vuln\n"},
		false,
	)
	if g.Packages == nil {
		t.Fatal("Graph.Packages is nil")
	}
	if got := g.Packages.ShortestImportPath([]string{"example.com/b/vuln"}); got != nil {
		t.Errorf("ShortestImportPath(test-only import) = %v, want nil", got)
	}
	if got := g.Packages.ShortestImportPath([]string{"example.com/a"}); len(got) != 2 {
		t.Errorf("ShortestImportPath(production import) = %v, want a two-package chain", got)
	}
}

func TestResolvePackageGraphDirectOnly(t *testing.T) {
	hostTarget(t)
	g := resolveImports(t,
		fixture{
			direct: []string{"a"},
			files:  map[string]string{"main.go": "package main\n\n" + imp("example.com/a") + "\nfunc main() {}\n"},
		},
		map[string]stubOpts{"a": {}}, nil, true)
	if g.Packages != nil {
		t.Errorf("Graph.Packages = %+v with directOnly, want nil", g.Packages)
	}
}

// TestResolvePackageGraphUnlistedTarget checks decision D2: a scan target that
// is not one of the listed targets gets no package graph, and the
// classification is unaffected.
func TestResolvePackageGraphUnlistedTarget(t *testing.T) {
	setGoEnv(t)
	t.Setenv("GOOS", "freebsd")
	t.Setenv("GOARCH", "amd64")
	g := resolveImports(t,
		fixture{
			direct: []string{"a"},
			files:  map[string]string{"main.go": "package main\n\n" + imp("example.com/a") + "\nfunc main() {}\n"},
		},
		map[string]stubOpts{"a": {}}, nil, false)
	if g.Packages != nil {
		t.Errorf("Graph.Packages = %+v for an unlisted target, want nil", g.Packages)
	}
	wantState(t, g, "a", "false", "true")
}

func TestShortestImportPath(t *testing.T) {
	g := &PackageGraph{
		Platform: "linux/amd64",
		Roots:    []string{"app/cmd/a", "app/cmd/b"},
		Imports: map[string][]string{
			"app/cmd/a": {"dep/one", "dep/two"},
			"app/cmd/b": {"dep/two", "dep/four"},
			"dep/one":   {"dep/three"},
			"dep/two":   {"dep/three", "dep/five"},
			"dep/three": {"deep/target"},
			"dep/five":  {"deep/target", "dep/six"},
			"dep/six":   {"deep/far"},
			"deep/far":  {"deep/farther"},
			// an import without a node of its own, like cgo's "C"
			"dep/four": {"C"},
		},
	}
	tests := []struct {
		name    string
		g       *PackageGraph
		targets []string
		want    []string
	}{
		{"nil graph", nil, []string{"deep/target"}, nil},
		{"empty graph", &PackageGraph{}, []string{"deep/target"}, nil},
		{"no targets", g, nil, nil},
		{"unreachable", g, []string{"nowhere/pkg"}, nil},
		{"tie goes to the first root and first import", g, []string{"deep/target"}, []string{"app/cmd/a", "dep/one", "dep/three", "deep/target"}},
		{"a root is its own chain", g, []string{"app/cmd/b"}, []string{"app/cmd/b"}},
		{"a root wins over a deeper target", g, []string{"deep/target", "app/cmd/b"}, []string{"app/cmd/b"}},
		{"nearest of several targets", g, []string{"deep/farther", "dep/five"}, []string{"app/cmd/a", "dep/two", "dep/five"}},
		{"a target equally near in two roots: the first root", g, []string{"dep/two"}, []string{"app/cmd/a", "dep/two"}},
		{"a missing node is tolerated", g, []string{"C"}, []string{"app/cmd/b", "dep/four", "C"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for range 3 {
				if got := tt.g.ShortestImportPath(tt.targets); !slices.Equal(got, tt.want) {
					t.Fatalf("ShortestImportPath(%v) = %v, want %v", tt.targets, got, tt.want)
				}
			}
		})
	}
}

// TestShortestImportPathCycle checks that an import cycle (possible with -e
// listings of broken code) ends the search instead of looping.
func TestShortestImportPathCycle(t *testing.T) {
	g := &PackageGraph{
		Roots:   []string{"app"},
		Imports: map[string][]string{"app": {"a"}, "a": {"b"}, "b": {"a"}},
	}
	if got := g.ShortestImportPath([]string{"nowhere"}); got != nil {
		t.Errorf("ShortestImportPath = %v, want nil", got)
	}
	if got, want := g.ShortestImportPath([]string{"b"}), []string{"app", "a", "b"}; !slices.Equal(got, want) {
		t.Errorf("ShortestImportPath = %v, want %v", got, want)
	}
}

// TestPlatformPackageGraph checks how a target's runs merge into one graph:
// the union of the cgo runs, sorted and deduplicated, and Partial from the
// target's cleanliness.
func TestPlatformPackageGraph(t *testing.T) {
	p := &platformList{goos: "linux", goarch: "amd64"}
	p.addGraph(listResult{
		roots: []string{"app/z", "app/a"},
		edges: map[string][]string{"app/a": {"x", "y"}, "app/z": {"y"}},
	})
	p.addGraph(listResult{
		roots: []string{"app/a", "app/cgo"},
		edges: map[string][]string{"app/a": {"y", "w"}, "app/cgo": {"C"}},
	})
	pg := p.packageGraph()
	if pg == nil {
		t.Fatal("packageGraph() = nil")
	}
	if pg.Platform != "linux/amd64" {
		t.Errorf("Platform = %q", pg.Platform)
	}
	if want := []string{"app/a", "app/cgo", "app/z"}; !slices.Equal(pg.Roots, want) {
		t.Errorf("Roots = %v, want %v", pg.Roots, want)
	}
	if want := []string{"w", "x", "y"}; !slices.Equal(pg.Imports["app/a"], want) {
		t.Errorf("Imports[app/a] = %v, want %v", pg.Imports["app/a"], want)
	}
	if pg.Partial {
		t.Error("Partial = true for a clean target")
	}

	p.err = errors.New("a run failed")
	if pg := p.packageGraph(); pg == nil || !pg.Partial {
		t.Errorf("packageGraph() of a failed target = %+v, want a Partial graph", pg)
	}

	if pg := (&platformList{goos: "linux", goarch: "amd64"}).packageGraph(); pg != nil {
		t.Errorf("packageGraph() with no listed package = %+v, want nil", pg)
	}
}

func TestListRunsGraph(t *testing.T) {
	var graphRuns []listRun
	for _, r := range listRuns("linux/arm64") {
		if r.graph {
			graphRuns = append(graphRuns, r)
		}
	}
	if len(graphRuns) != 2 {
		t.Fatalf("graph runs = %+v, want the CGO 0 and CGO 1 production runs of linux/arm64", graphRuns)
	}
	for _, r := range graphRuns {
		if r.goos != "linux" || r.goarch != "arm64" || r.test {
			t.Errorf("graph run %+v is not a production run of linux/arm64", r)
		}
	}
	if graphRuns[0].cgo == graphRuns[1].cgo {
		t.Errorf("graph runs %+v must differ in cgo", graphRuns)
	}
	if n := len(listRuns("linux/arm64")); n != len(listGOOS)*len(listGOARCH)*4 {
		t.Errorf("listRuns returned %d runs, want %d", n, len(listGOOS)*len(listGOARCH)*4)
	}
	for _, r := range listRuns("freebsd/amd64") {
		if r.graph {
			t.Errorf("unlisted target: run %+v asks for the package graph", r)
		}
	}
}

func TestScanTarget(t *testing.T) {
	t.Setenv("GOOS", "")
	t.Setenv("GOARCH", "")
	if got, want := scanTarget(), runtime.GOOS+"/"+runtime.GOARCH; got != want {
		t.Errorf("scanTarget() = %q, want %q", got, want)
	}
	t.Setenv("GOOS", "windows")
	t.Setenv("GOARCH", "arm64")
	if got := scanTarget(); got != "windows/arm64" {
		t.Errorf("scanTarget() = %q, want windows/arm64", got)
	}
	t.Setenv("GOARCH", "")
	if got, want := scanTarget(), "windows/"+runtime.GOARCH; got != want {
		t.Errorf("scanTarget() = %q, want %q", got, want)
	}
}

// TestListArgsGraphFields checks that only a run that feeds the package graph
// asks go list for Imports and DepOnly.
func TestListArgsGraphFields(t *testing.T) {
	jsonArg := func(args []string) string {
		for _, a := range args {
			if strings.HasPrefix(a, "-json=") {
				return strings.TrimPrefix(a, "-json=")
			}
		}
		t.Fatalf("no -json argument in %v", args)
		return ""
	}
	const base = "ImportPath,Standard,Module,Error,EmbedFiles"

	for _, readOnly := range []bool{false, true} {
		got := jsonArg(listArgs(listRun{goos: "linux", goarch: "amd64", graph: true}, readOnly))
		fields := strings.Split(got, ",")
		for _, f := range strings.Split(base+",Imports,DepOnly", ",") {
			if !slices.Contains(fields, f) {
				t.Errorf("graph run (readOnly=%v): fields %q miss %s", readOnly, got, f)
			}
		}
		for _, r := range []listRun{
			{goos: "linux", goarch: "amd64"},
			{goos: "linux", goarch: "amd64", cgo: true},
			{goos: "linux", goarch: "amd64", test: true},
			{goos: "darwin", goarch: "arm64"},
		} {
			if got := jsonArg(listArgs(r, readOnly)); got != base {
				t.Errorf("listArgs(%+v, %v) fields = %q, want exactly %q", r, readOnly, got, base)
			}
		}
	}

	// Across the real run list, only the target's production runs differ.
	for _, r := range listRuns("darwin/arm64") {
		got := jsonArg(listArgs(r, false))
		onTarget := r.goos == "darwin" && r.goarch == "arm64" && !r.test
		if onTarget != (got != base) {
			t.Errorf("run %+v: fields %q, graph fields expected = %v", r, got, onTarget)
		}
	}
}
