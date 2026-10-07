package resolver

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/unidoc/unisupply/pkg/offline"
	"github.com/unidoc/unisupply/pkg/parser"
)

// enableOffline turns offline mode on for one test and restores it afterwards.
func enableOffline(t *testing.T) {
	t.Helper()
	offline.Enable()
	t.Cleanup(offline.Disable)
}

func TestListArgs(t *testing.T) {
	const readonly = "-mod=readonly"
	run := listRun{goos: "linux", test: true}

	t.Run("online adds no -mod flag", func(t *testing.T) {
		for _, r := range []listRun{run, {goos: "linux"}} {
			if args := listArgs(r, false); slices.Contains(args, readonly) {
				t.Errorf("listArgs(%+v, false) = %v, want no %s", r, args, readonly)
			}
		}
	})

	t.Run("offline adds -mod=readonly before the package pattern", func(t *testing.T) {
		args := listArgs(run, true)
		i := slices.Index(args, readonly)
		if i < 0 {
			t.Fatalf("listArgs(%+v, true) = %v, want %s", run, args, readonly)
		}
		if args[len(args)-1] != "./..." || i > len(args)-3 {
			t.Errorf("%s must precede -json and the pattern: %v", readonly, args)
		}
	})

	t.Run("test flag is kept", func(t *testing.T) {
		if !slices.Contains(listArgs(run, true), "-test") || slices.Contains(listArgs(listRun{}, true), "-test") {
			t.Error("-test must be present exactly when run.test is set")
		}
	})
}

func TestNeedsModUpdate(t *testing.T) {
	tests := []struct {
		msg  string
		want bool
	}{
		{"go: updates to go.mod needed, disabled by -mod=readonly; to update it:\n\tgo mod tidy", true},
		{"cannot find module providing package example.org/x: import lookup disabled by -mod=readonly", true},
		{"missing go.sum entry for module providing package example.org/x (imported by example.com/main)", true},
		{"module example.com/stub provides package example.com/stub and is replaced but not required; to add it:", true},
		{"cannot find module providing package example.org/x: module lookup disabled by GOPROXY=off", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := needsModUpdate(tt.msg); got != tt.want {
			t.Errorf("needsModUpdate(%q) = %v, want %v", tt.msg, got, tt.want)
		}
	}
}

// TestClassifyOfflineTidyModule checks that read-only listing still classifies
// a module whose go.mod is complete.
func TestClassifyOfflineTidyModule(t *testing.T) {
	enableOffline(t)
	graph, warn := classify(t,
		fixture{
			direct: []string{"prod"},
			files:  map[string]string{"main.go": "package main\n\nimport _ \"example.com/prod\"\n\nfunc main() {}\n"},
		},
		map[string]stubOpts{"prod": {}},
	)
	if warn != "" {
		t.Errorf("warning = %q, want none", warn)
	}
	dep := graph.Dependencies["example.com/prod"]
	if dep == nil || dep.InBuild == nil || !*dep.InBuild || dep.IsTestOnly == nil || *dep.IsTestOnly {
		t.Errorf("example.com/prod = %+v, want in build and not test-only", dep)
	}
}

// TestClassifyOfflineUntidyModule checks that an incomplete go.mod is neither
// rewritten nor misreported as a cold module cache.
func TestClassifyOfflineUntidyModule(t *testing.T) {
	tests := []struct {
		name string
		// goMod is the main module's go.mod; the stub is example.com/stub.
		goMod string
		// mainSrc is main.go.
		mainSrc string
	}{
		{
			name:    "replaced but not required",
			goMod:   "module example.com/main\n\ngo 1.21\n\nreplace example.com/stub => ../stub\n",
			mainSrc: "package main\n\nimport _ \"example.com/stub\"\n\nfunc main() {}\n",
		},
		{
			name:    "indirect requirement missing",
			goMod:   "module example.com/main\n\ngo 1.21\n\nrequire example.com/stub v0.0.0\n\nreplace (\n\texample.com/stub => ../stub\n\texample.com/stub2 => ../stub2\n)\n",
			mainSrc: "package main\n\nimport _ \"example.com/stub2\"\n\nfunc main() {}\n",
		},
		{
			name:    "import not provided by any requirement",
			goMod:   "module example.com/main\n\ngo 1.21\n",
			mainSrc: "package main\n\nimport _ \"example.org/absent/pkg\"\n\nfunc main() {}\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setGoEnv(t)
			enableOffline(t)

			root := t.TempDir()
			mainDir := filepath.Join(root, "main")
			writeStub(t, root, "stub", stubOpts{requires: []string{"stub2"}})
			writeStub(t, root, "stub2", stubOpts{})
			// stub requires stub2 and needs its own replace to build.
			write(t, filepath.Join(root, "stub", "go.mod"),
				"module example.com/stub\n\ngo 1.21\n\nrequire example.com/stub2 v0.0.0\n\nreplace example.com/stub2 => ../stub2\n")
			write(t, filepath.Join(root, "stub", "stub.go"), "package stub\n\nimport _ \"example.com/stub2\"\n")
			write(t, filepath.Join(mainDir, "go.mod"), tt.goMod)
			write(t, filepath.Join(mainDir, "main.go"), tt.mainSrc)

			parsed, err := parser.ParseGoMod(filepath.Join(mainDir, "go.mod"))
			if err != nil {
				t.Fatalf("ParseGoMod: %v", err)
			}
			graph := &Graph{Root: parsed.ModulePath, Dependencies: make(map[string]*Dependency)}
			for _, req := range parsed.Requirements {
				graph.Dependencies[req.Path] = &Dependency{Module: req, Direct: !req.Indirect}
			}

			before, err := os.ReadFile(filepath.Join(mainDir, "go.mod"))
			if err != nil {
				t.Fatal(err)
			}
			warn := classifyTestOnlyDeps(context.Background(), mainDir, graph)

			after, err := os.ReadFile(filepath.Join(mainDir, "go.mod"))
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Errorf("go.mod was modified:\nbefore:\n%s\nafter:\n%s", before, after)
			}
			if _, err := os.Stat(filepath.Join(mainDir, "go.sum")); err == nil {
				t.Error("go.sum was created")
			}

			for path, dep := range graph.Dependencies {
				if dep.IsTestOnly != nil || dep.InBuild != nil {
					t.Errorf("%s classified (IsTestOnly=%v InBuild=%v), want classification unavailable", path, dep.IsTestOnly, dep.InBuild)
				}
			}
			if !strings.Contains(warn, "go.mod or go.sum needs updating") {
				t.Errorf("warning = %q, want it to name go.mod/go.sum needing an update", warn)
			}
			if strings.Contains(warn, "local module cache") {
				t.Errorf("warning = %q, must not blame the module cache", warn)
			}
		})
	}
}
