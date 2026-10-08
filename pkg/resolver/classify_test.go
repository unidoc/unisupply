package resolver

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/unidoc/unisupply/pkg/parser"
)

// These tests run the real `go list` against throwaway modules. Every
// dependency is a stub module in the same temp directory, wired in with a
// local `replace`, so nothing needs the network or the module cache.

// fixture describes one temporary main module and its stub dependencies.
type fixture struct {
	goVersion string
	direct    []string // stub modules required without "// indirect"
	indirect  []string // stub modules required with "// indirect"
	files     map[string]string
}

// stubOpts overrides parts of a stub module.
type stubOpts struct {
	goVersion string
	requires  []string
	testFile  string // body of an in-package _test.go file, if any
}

// setGoEnv pins the go toolchain to the local, offline mode the tests need.
func setGoEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GOFLAGS", "-mod=mod")
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOSUMDB", "off")
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeStub creates example.com/<name> as a sibling directory of the main
// module.
func writeStub(t *testing.T, root, name string, opts stubOpts) {
	t.Helper()
	goVersion := opts.goVersion
	if goVersion == "" {
		goVersion = "1.21"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "module example.com/%s\n\ngo %s\n", name, goVersion)
	for _, r := range opts.requires {
		fmt.Fprintf(&b, "\nrequire example.com/%s v0.0.0\n", r)
	}
	dir := filepath.Join(root, name)
	write(t, filepath.Join(dir, "go.mod"), b.String())
	write(t, filepath.Join(dir, name+".go"), "package "+name+"\n")
	if opts.testFile != "" {
		write(t, filepath.Join(dir, name+"_test.go"), opts.testFile)
	}
}

// classify writes the fixture, builds a Graph from its go.mod requirements
// the way Resolve does, runs classifyTestOnlyDeps and returns the graph and the
// warning.
func classify(t *testing.T, fx fixture, stubs map[string]stubOpts) (*Graph, string) {
	t.Helper()
	g, warn, _ := classifyWithNote(t, fx, stubs)
	return g, warn
}

// classifyWithNote is classify that also returns the informational note.
func classifyWithNote(t *testing.T, fx fixture, stubs map[string]stubOpts) (*Graph, string, string) {
	t.Helper()
	setGoEnv(t)

	root := t.TempDir()
	mainDir := filepath.Join(root, "main")

	for name, opts := range stubs {
		writeStub(t, root, name, opts)
	}

	goVersion := fx.goVersion
	if goVersion == "" {
		goVersion = "1.21"
	}
	var gomod strings.Builder
	fmt.Fprintf(&gomod, "module example.com/main\n\ngo %s\n\nrequire (\n", goVersion)
	for _, m := range fx.direct {
		fmt.Fprintf(&gomod, "\texample.com/%s v0.0.0\n", m)
	}
	for _, m := range fx.indirect {
		fmt.Fprintf(&gomod, "\texample.com/%s v0.0.0 // indirect\n", m)
	}
	gomod.WriteString(")\n")
	for _, m := range slices.Concat(fx.direct, fx.indirect) {
		fmt.Fprintf(&gomod, "\nreplace example.com/%s => ../%s\n", m, m)
	}
	write(t, filepath.Join(mainDir, "go.mod"), gomod.String())
	for name, content := range fx.files {
		write(t, filepath.Join(mainDir, name), content)
	}

	parsed, err := parser.ParseGoMod(filepath.Join(mainDir, "go.mod"))
	if err != nil {
		t.Fatalf("ParseGoMod: %v", err)
	}
	graph := &Graph{Root: parsed.ModulePath, Dependencies: make(map[string]*Dependency)}
	for _, req := range parsed.Requirements {
		graph.Dependencies[req.Path] = &Dependency{Module: req, Direct: !req.Indirect}
	}

	warn, note := classifyTestOnlyDeps(context.Background(), mainDir, graph)
	return graph, warn, note
}

func dep(t *testing.T, g *Graph, name string) *Dependency {
	t.Helper()
	d, ok := g.Dependencies["example.com/"+name]
	if !ok {
		t.Fatalf("example.com/%s not in graph", name)
	}
	return d
}

func triStr(b *bool) string {
	if b == nil {
		return "nil"
	}
	return fmt.Sprint(*b)
}

// wantState asserts the IsTestOnly and InBuild states of a module; want
// values are "nil", "true" or "false".
func wantState(t *testing.T, g *Graph, name, isTestOnly, inBuild string) {
	t.Helper()
	d := dep(t, g, name)
	if got := triStr(d.IsTestOnly); got != isTestOnly {
		t.Errorf("%s: IsTestOnly = %s, want %s", name, got, isTestOnly)
	}
	if got := triStr(d.InBuild); got != inBuild {
		t.Errorf("%s: InBuild = %s, want %s", name, got, inBuild)
	}
}

func wantPlatforms(t *testing.T, g *Graph, name string, want []string) {
	t.Helper()
	if got := dep(t, g, name).Platforms; !slices.Equal(got, want) {
		t.Errorf("%s: Platforms = %v, want %v", name, got, want)
	}
}

// A //go:embed pattern that matches nothing (a gitignored build output in a
// fresh clone) must not stop classification. The failing package is named in a
// note, not a warning: classification is unaffected, so it is not a limitation
// of the results.
func TestClassify_MissingEmbedIsTolerated(t *testing.T) {
	g, warn, note := classifyWithNote(t, fixture{
		direct: []string{"prod"},
		files: map[string]string{
			"main.go": `package main

import (
	_ "embed"

	_ "example.com/prod"
)

//go:embed missing/dir
var assets string

func main() { _ = assets }
`,
		},
	}, map[string]stubOpts{"prod": {}})

	wantState(t, g, "prod", "false", "true")
	if warn != "" {
		t.Errorf("warning = %q, want none: a tolerated package error is a note", warn)
	}
	if !strings.Contains(note, "example.com/main") || !strings.Contains(note, "missing/dir") {
		t.Errorf("note = %q, want it to name package example.com/main and the pattern", note)
	}
	if strings.Contains(note, "unavailable") {
		t.Errorf("note = %q, classification must not be reported unavailable", note)
	}
}

// An import no module provides makes the package set untrustworthy on every
// platform, so classification is unavailable and nothing is classified.
func TestClassify_UnresolvablePackageFailsClosed(t *testing.T) {
	g, warn := classify(t, fixture{
		direct:   []string{"prod"},
		indirect: []string{"graphonly"},
		files: map[string]string{
			"main.go": `package main

import (
	_ "example.com/nowhere/pkg"
	_ "example.com/prod"
)

func main() {}
`,
		},
	}, map[string]stubOpts{"prod": {}, "graphonly": {}})

	if !strings.Contains(warn, "unavailable") {
		t.Errorf("warning = %q, want the unavailable warning", warn)
	}
	wantState(t, g, "prod", "nil", "nil")
	wantState(t, g, "graphonly", "nil", "nil")
}

// A module imported only by the main module's tests is test-only. This is the
// regression for the `go list all` / `go list -test all` comparison, whose two
// sets are identical and so could never report one.
func TestClassify_ModuleImportedOnlyByTestsIsTestOnly(t *testing.T) {
	g, warn := classify(t, fixture{
		direct:   []string{"prod", "testdep"},
		indirect: []string{"graphonly"},
		files: map[string]string{
			"main.go": `package main

import _ "example.com/prod"

func main() {}
`,
			"main_test.go": `package main

import (
	"testing"

	_ "example.com/testdep"
)

func TestMain(t *testing.T) {}
`,
		},
	}, map[string]stubOpts{"prod": {}, "testdep": {}, "graphonly": {}})

	if warn != "" {
		t.Errorf("unexpected warning: %q", warn)
	}
	wantState(t, g, "prod", "false", "true")
	wantState(t, g, "testdep", "true", "true")
	// Required in the module graph but imported by nothing: outside the build.
	wantState(t, g, "graphonly", "nil", "false")
}

// At go 1.15 `go list all` also lists packages needed by a dependency's own
// tests. Such a module is not part of the main module's build.
func TestClassify_DependencyTestOnlyModuleIsOutsideBuild(t *testing.T) {
	g, warn := classify(t, fixture{
		goVersion: "1.15",
		direct:    []string{"a"},
		indirect:  []string{"atestdep"},
		files: map[string]string{
			"main.go": `package main

import _ "example.com/a"

func main() {}
`,
		},
	}, map[string]stubOpts{
		"a": {
			goVersion: "1.15",
			requires:  []string{"atestdep"},
			testFile: `package a

import _ "example.com/atestdep"
`,
		},
		"atestdep": {goVersion: "1.15"},
	})

	if warn != "" {
		t.Errorf("unexpected warning: %q", warn)
	}
	wantState(t, g, "a", "false", "true")
	wantState(t, g, "atestdep", "nil", "false")
}

// A direct requirement found by no list may be imported only under a custom
// build tag, so it must not be declared outside the build.
func TestClassify_DirectRequirementBehindBuildTagStaysUnknown(t *testing.T) {
	g, warn := classify(t, fixture{
		direct:   []string{"prod", "tagonly"},
		indirect: []string{"graphonly"},
		files: map[string]string{
			"main.go": `package main

import _ "example.com/prod"

func main() {}
`,
			"tagged.go": `//go:build customtag

package main

import _ "example.com/tagonly"
`,
		},
	}, map[string]stubOpts{"prod": {}, "tagonly": {}, "graphonly": {}})

	if warn != "" {
		t.Errorf("unexpected warning: %q", warn)
	}
	wantState(t, g, "tagonly", "nil", "nil")
	// graphonly is not reachable from tagonly, so the guard does not cover it.
	wantState(t, g, "graphonly", "nil", "false")
}

// The modules a tag-gated direct requirement pulls in stay unknown as well:
// the tagged build compiles them. go mod tidy lists them as // indirect
// requirements of the main module, so they also have an edge from the main
// module, and the guard must not be limited to modules reachable only through
// the tagged requirement (gin with -tags=sonic: bytedance/sonic/loader,
// cloudwego/base64x, klauspost/cpuid/v2, ...). A module reachable both from
// the tagged requirement and from a built one is unknown too. A graph-only
// module whose only parent is built stays outside the build.
func TestResolve_TagGatedDirectRequirementKeepsItsSubtreeUnknown(t *testing.T) {
	setGoEnv(t)
	root := t.TempDir()
	writeStub(t, root, "prod", stubOpts{requires: []string{"shared", "graphonly"}})
	writeStub(t, root, "tagged", stubOpts{requires: []string{"deep", "shared"}})
	writeStub(t, root, "deep", stubOpts{requires: []string{"deeper"}})
	for _, name := range []string{"deeper", "shared", "graphonly"} {
		writeStub(t, root, name, stubOpts{})
	}
	mainDir := filepath.Join(root, "main")
	write(t, filepath.Join(mainDir, "go.mod"), `module example.com/main

go 1.21

require (
	example.com/prod v0.0.0
	example.com/tagged v0.0.0
)

require (
	example.com/deep v0.0.0 // indirect
	example.com/deeper v0.0.0 // indirect
	example.com/graphonly v0.0.0 // indirect
	example.com/shared v0.0.0 // indirect
)

replace example.com/prod => ../prod

replace example.com/tagged => ../tagged

replace example.com/deep => ../deep

replace example.com/deeper => ../deeper

replace example.com/graphonly => ../graphonly

replace example.com/shared => ../shared
`)
	write(t, filepath.Join(mainDir, "main.go"), "package main\n\nimport _ \"example.com/prod\"\n\nfunc main() {}\n")
	write(t, filepath.Join(mainDir, "tagged.go"), "//go:build customtag\n\npackage main\n\nimport _ \"example.com/tagged\"\n")

	g, warnings, err := Resolve(context.Background(), filepath.Join(mainDir, "go.mod"), false)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %q", warnings)
	}
	// The case that makes "reachable only through" insufficient: deep has an
	// edge from the main module as well as from tagged.
	if used := dep(t, g, "deep").UsedBy; !slices.Contains(used, g.Root) || !slices.Contains(used, "example.com/tagged") {
		t.Fatalf("deep.UsedBy = %v, want both %s and example.com/tagged", used, g.Root)
	}

	wantState(t, g, "prod", "false", "true")
	wantState(t, g, "tagged", "nil", "nil")
	wantState(t, g, "deep", "nil", "nil")
	wantState(t, g, "deeper", "nil", "nil")
	wantState(t, g, "shared", "nil", "nil")
	wantState(t, g, "graphonly", "nil", "false")
}

// reachableFrom must not walk through the main module: an edge back to it
// would reach every module in the graph.
func TestReachableFrom_SkipsMainModule(t *testing.T) {
	g := &Graph{Root: "example.com/main", Dependencies: map[string]*Dependency{
		"example.com/seed":  {UsedBy: []string{"example.com/main"}},
		"example.com/child": {UsedBy: []string{"example.com/seed"}},
		"example.com/other": {UsedBy: []string{"example.com/main"}},
		// seed requires an older version of the main module.
		"example.com/main": {UsedBy: []string{"example.com/seed"}},
	}}
	got := reachableFrom(g, []string{"example.com/seed"})
	want := map[string]bool{"example.com/seed": true, "example.com/child": true}
	if !maps.Equal(got, want) {
		t.Errorf("reachableFrom = %v, want %v", got, want)
	}
	if got := reachableFrom(g, nil); got != nil {
		t.Errorf("reachableFrom(no seeds) = %v, want nil", got)
	}
}

// A module imported only on some GOOS is production, and Platforms says where.
// The inherited GOOS and CGO_ENABLED of the test process must not leak into
// the listing.
func TestClassify_PlatformSpecificImportIsProduction(t *testing.T) {
	t.Setenv("GOOS", "plan9")
	t.Setenv("CGO_ENABLED", "0")

	g, warn := classify(t, fixture{
		direct: []string{"prod", "winonly", "darwinonly", "unixonly"},
		files: map[string]string{
			"main.go": `package main

import _ "example.com/prod"

func main() {}
`,
			"w_windows.go": `package main

import _ "example.com/winonly"
`,
			"d_darwin.go": `package main

import _ "example.com/darwinonly"
`,
			"u.go": `//go:build linux || darwin

package main

import _ "example.com/unixonly"
`,
		},
	}, map[string]stubOpts{"prod": {}, "winonly": {}, "darwinonly": {}, "unixonly": {}})

	if warn != "" {
		t.Errorf("unexpected warning: %q", warn)
	}
	wantState(t, g, "prod", "false", "true")
	wantState(t, g, "winonly", "false", "true")
	wantState(t, g, "darwinonly", "false", "true")
	wantState(t, g, "unixonly", "false", "true")

	wantPlatforms(t, g, "prod", nil)
	wantPlatforms(t, g, "winonly", []string{"windows"})
	wantPlatforms(t, g, "darwinonly", []string{"darwin"})
	wantPlatforms(t, g, "unixonly", []string{"darwin", "linux"})
}

// Imports gated on cgo and on !cgo are both seen: the lists are unioned over
// CGO_ENABLED=0 and CGO_ENABLED=1.
func TestClassify_CgoGatedImportsAreProduction(t *testing.T) {
	g, warn := classify(t, fixture{
		direct: []string{"cgoonly", "nocgoonly"},
		files: map[string]string{
			"main.go": "package main\n\nfunc main() {}\n",
			"cgo_on.go": `//go:build cgo

package main

import _ "example.com/cgoonly"
`,
			"cgo_off.go": `//go:build !cgo

package main

import _ "example.com/nocgoonly"
`,
		},
	}, map[string]stubOpts{"cgoonly": {}, "nocgoonly": {}})

	if warn != "" {
		t.Errorf("unexpected warning: %q", warn)
	}
	wantState(t, g, "cgoonly", "false", "true")
	wantState(t, g, "nocgoonly", "false", "true")
	// Both are on every GOOS: cgo is not a platform.
	wantPlatforms(t, g, "cgoonly", nil)
	wantPlatforms(t, g, "nocgoonly", nil)
}

// A GOOS that fails to list must not blind the others. The failure is a
// module-resolution error, which on its own fails the run closed; the
// listing for that GOOS is marked failed rather than the whole classification.
// What the failed GOOS cannot do is prove absence, so modules found nowhere
// are left unknown instead of "outside the build", test-only is withheld, and
// Platforms is not asserted.
func TestClassify_OneGOOSFailingKeepsOtherPlatforms(t *testing.T) {
	g, warn := classify(t, fixture{
		direct:   []string{"prod", "testdep", "winonly"},
		indirect: []string{"hidden"},
		files: map[string]string{
			"main.go": `package main

import _ "example.com/prod"

func main() {}
`,
			// hidden is required but lacks the imported package, so the
			// windows listing cannot attribute the package to any module.
			"w_windows.go": `package main

import (
	_ "example.com/hidden/nosuchpkg"
	_ "example.com/winonly"
)
`,
			"main_test.go": `package main

import (
	"testing"

	_ "example.com/testdep"
)

func TestX(t *testing.T) {}
`,
		},
	}, map[string]stubOpts{"prod": {}, "testdep": {}, "winonly": {}, "hidden": {}})

	if !strings.Contains(warn, "GOOS=windows") {
		t.Errorf("warning = %q, want it to name GOOS=windows", warn)
	}
	for _, other := range []string{"darwin", "linux"} {
		if strings.Contains(warn, "GOOS="+other) || strings.Contains(warn, other+":") {
			t.Errorf("warning = %q, must not name the platform that succeeded (%s)", warn, other)
		}
	}
	if strings.Contains(warn, "classification unavailable") {
		t.Errorf("warning = %q, classification must survive one failing GOOS", warn)
	}

	// Seen on the platforms that succeeded: positive evidence stands.
	wantState(t, g, "prod", "false", "true")
	// Seen only by the failed run: still counts, it was resolved.
	wantState(t, g, "winonly", "false", "true")
	// Only in tests on the platforms that succeeded, but windows is unknown.
	wantState(t, g, "testdep", "nil", "true")
	// Hidden behind the unresolved import: must not be declared absent.
	wantState(t, g, "hidden", "nil", "nil")

	wantPlatforms(t, g, "prod", nil)
	wantPlatforms(t, g, "winonly", nil)
}

// Resolve wires classification in: with local replaces, go mod graph and go
// list both work offline, and the new fields reach the Graph.
func TestResolve_ClassifiesInBuild(t *testing.T) {
	setGoEnv(t)
	root := t.TempDir()
	writeStub(t, root, "prod", stubOpts{})
	writeStub(t, root, "graphonly", stubOpts{})
	mainDir := filepath.Join(root, "main")
	write(t, filepath.Join(mainDir, "go.mod"), `module example.com/main

go 1.21

require (
	example.com/prod v0.0.0
	example.com/graphonly v0.0.0 // indirect
)

replace example.com/prod => ../prod

replace example.com/graphonly => ../graphonly
`)
	write(t, filepath.Join(mainDir, "main.go"), "package main\n\nimport _ \"example.com/prod\"\n\nfunc main() {}\n")

	g, _, err := Resolve(context.Background(), filepath.Join(mainDir, "go.mod"), false)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	wantState(t, g, "prod", "false", "true")
	wantState(t, g, "graphonly", "nil", "false")
}
