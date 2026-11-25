package runner

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
)

func testPackageGraph() *resolver.PackageGraph {
	return &resolver.PackageGraph{
		Platform: "linux/amd64",
		Roots:    []string{"example.com/app/cmd/app"},
		Imports: map[string][]string{
			"example.com/app/cmd/app": {"example.com/dep", "net/http"},
			"example.com/dep":         {"example.com/dep/vuln"},
		},
	}
}

func importedFindings() map[string][]scanner.Vulnerability {
	return map[string][]scanner.Vulnerability{
		"example.com/dep": {
			{ID: "GO-T-0001", Reachability: "imported", ImportedPackages: []string{"example.com/dep/vuln"}},
			// an advisory with one imported package and one called: the final tier is called
			{ID: "GO-T-0002", Reachability: "called", ImportedPackages: []string{"example.com/dep/vuln"}},
			{ID: "GO-T-0003", Reachability: "required"},
			// imported but with no package recorded (an analysis stored before the field existed)
			{ID: "GO-T-0004", Reachability: "imported"},
		},
		"stdlib": {
			{ID: "GO-T-0005", Reachability: "imported", ImportedPackages: []string{"net/http"}},
		},
	}
}

func TestFillImportPaths(t *testing.T) {
	vulns := importedFindings()
	fillImportPaths(vulns, testPackageGraph(), "linux/amd64")

	want := map[string][]string{
		"GO-T-0001": {"example.com/app/cmd/app", "example.com/dep", "example.com/dep/vuln"},
		"GO-T-0005": {"example.com/app/cmd/app", "net/http"},
	}
	for mod, list := range vulns {
		for _, v := range list {
			if !slices.Equal(v.ImportPath, want[v.ID]) {
				t.Errorf("%s %s (%s): ImportPath = %v, want %v", mod, v.ID, v.Reachability, v.ImportPath, want[v.ID])
			}
		}
	}
}

func TestFillImportPaths_Guards(t *testing.T) {
	tests := []struct {
		name     string
		pg       *resolver.PackageGraph
		platform string
	}{
		{"nil graph", nil, "linux/amd64"},
		{"platform differs", testPackageGraph(), "darwin/arm64"},
		{"empty platform", testPackageGraph(), ""},
		{"graph without a platform, scan without one", &resolver.PackageGraph{Roots: []string{"a"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulns := importedFindings()
			fillImportPaths(vulns, tt.pg, tt.platform)
			for mod, list := range vulns {
				for _, v := range list {
					if v.ImportPath != nil {
						t.Errorf("%s %s: ImportPath = %v, want none", mod, v.ID, v.ImportPath)
					}
				}
			}
		})
	}
	fillImportPaths(nil, testPackageGraph(), "linux/amd64") // a nil map is fine
}

// importHostTarget is the "goos/goarch" a scan on this machine reports, with the environment overrides cleared. It
// skips the test when the host is not one of the targets the resolver lists, because the graph is kept for those only.
func importHostTarget(t *testing.T) string {
	t.Helper()
	t.Setenv("GOOS", "")
	t.Setenv("GOARCH", "")
	host := runtime.GOOS + "/" + runtime.GOARCH
	if !slices.Contains([]string{"darwin", "linux", "windows"}, runtime.GOOS) || !slices.Contains([]string{"amd64", "arm64"}, runtime.GOARCH) {
		t.Skipf("host target %s is not one the resolver lists", host)
	}
	return host
}

// stubScanOn replaces the scanner like stubScan, but records the given platform, as the real scanner does.
func stubScanOn(t *testing.T, platform string, vulns map[string][]scanner.Vulnerability) {
	t.Helper()
	prev := scanVulns
	t.Cleanup(func() { scanVulns = prev })
	scanVulns = func(_ context.Context, _ string, opts scanner.VulnScanOptions) (map[string][]scanner.Vulnerability, []string, bool, error) {
		if opts.Info != nil {
			*opts.Info = scanner.ScanInfo{Platform: platform, GoVersion: "go1.26.0"}
		}
		out := map[string][]scanner.Vulnerability{}
		for k, v := range vulns {
			out[k] = append([]scanner.Vulnerability(nil), v...)
		}
		return out, nil, true, nil
	}
}

func writeImportFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// importModule writes example.com/main, whose package main imports the packages in imports, and, when withDep, the stub
// module example.com/dep (required through a local replace, so nothing needs the network) whose package imports
// example.com/dep/vuln. It pins the go toolchain to offline, local use and returns the main module's directory.
func importModule(t *testing.T, withDep bool, imports ...string) string {
	t.Helper()
	t.Setenv("GOFLAGS", "-mod=mod")
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOSUMDB", "off")

	root := t.TempDir()
	main := filepath.Join(root, "main")
	gomod := "module example.com/main\n\ngo 1.21\n"
	if withDep {
		gomod += "\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => ../dep\n"
		writeImportFile(t, filepath.Join(root, "dep", "go.mod"), "module example.com/dep\n\ngo 1.21\n")
		writeImportFile(t, filepath.Join(root, "dep", "dep.go"), "package dep\n\nimport _ \"example.com/dep/vuln\"\n")
		writeImportFile(t, filepath.Join(root, "dep", "vuln", "vuln.go"), "package vuln\n")
		imports = append(imports, "example.com/dep")
	}
	var src strings.Builder
	src.WriteString("package main\n\n")
	for _, p := range imports {
		src.WriteString("import _ \"" + p + "\"\n")
	}
	src.WriteString("\nfunc main() {}\n")
	writeImportFile(t, filepath.Join(main, "go.mod"), gomod)
	writeImportFile(t, filepath.Join(main, "main.go"), src.String())
	return main
}

// The zero-dependency branch: the standard library's imported finding names the chain from the project's package.
func TestAnalyse_ImportPath_NoDependencies(t *testing.T) {
	host := importHostTarget(t)
	dir := importModule(t, false, "net/http")
	stubGitHub(t, http.StatusOK)
	stubScanOn(t, host, map[string][]scanner.Vulnerability{"stdlib": {
		{ID: "GO-TEST-0001", Severity: "MEDIUM", Reachability: "imported", ImportedPackages: []string{"net/http"}},
	}})

	an, err := Analyse(context.Background(), Options{Path: dir, Now: gradeDate})
	if err != nil {
		t.Fatal(err)
	}
	if an.Graph.Packages == nil || an.Graph.Packages.Platform != host {
		t.Fatalf("Graph.Packages = %+v, want the graph of %s", an.Graph.Packages, host)
	}
	got := an.Vulns["stdlib"]
	if len(got) != 1 {
		t.Fatalf("Vulns[stdlib] = %+v, want 1 finding", got)
	}
	if want := []string{"example.com/main", "net/http"}; !slices.Equal(got[0].ImportPath, want) {
		t.Errorf("ImportPath = %v, want %v", got[0].ImportPath, want)
	}
}

// A scan on another platform than the graph's gets no chain: the graph is not the one govulncheck saw.
func TestAnalyse_ImportPath_OtherPlatformGetsNone(t *testing.T) {
	importHostTarget(t)
	dir := importModule(t, false, "net/http")
	stubGitHub(t, http.StatusOK)
	stubScanOn(t, "plan9/386", map[string][]scanner.Vulnerability{"stdlib": {
		{ID: "GO-TEST-0001", Severity: "MEDIUM", Reachability: "imported", ImportedPackages: []string{"net/http"}},
	}})
	an, err := Analyse(context.Background(), Options{Path: dir, Now: gradeDate})
	if err != nil {
		t.Fatal(err)
	}
	if got := an.Vulns["stdlib"]; len(got) != 1 || got[0].ImportPath != nil {
		t.Errorf("Vulns[stdlib] = %+v, want the finding without an import path", got)
	}
}

// The dependency branch, with a local stub module: the imported finding gets the chain through the dependency, the
// called finding of the same module gets none.
func TestAnalyse_ImportPath_WithDependency(t *testing.T) {
	host := importHostTarget(t)
	dir := importModule(t, true)
	stubGitHub(t, http.StatusOK)
	stubScanOn(t, host, map[string][]scanner.Vulnerability{"example.com/dep": {
		{ID: "GO-TEST-0002", Severity: "HIGH", Reachability: "imported", ImportedPackages: []string{"example.com/dep/vuln"}},
		{ID: "GO-TEST-0003", Severity: "HIGH", Reachability: "called", ImportedPackages: []string{"example.com/dep/vuln"}},
	}})

	an, err := Analyse(context.Background(), Options{Path: dir, Now: gradeDate})
	if err != nil {
		t.Fatal(err)
	}
	if len(an.Graph.Dependencies) == 0 {
		t.Fatal("the fixture has no dependency, so the dependency branch did not run")
	}
	got := an.Vulns["example.com/dep"]
	if len(got) != 2 {
		t.Fatalf("Vulns = %+v, want 2 findings", got)
	}
	want := []string{"example.com/main", "example.com/dep", "example.com/dep/vuln"}
	for _, v := range got {
		switch v.Reachability {
		case "imported":
			if !slices.Equal(v.ImportPath, want) {
				t.Errorf("%s: ImportPath = %v, want %v", v.ID, v.ImportPath, want)
			}
		default:
			if v.ImportPath != nil {
				t.Errorf("%s (%s): ImportPath = %v, want none", v.ID, v.Reachability, v.ImportPath)
			}
		}
	}
}

// import_path is stored with the analysis, and an analysis stored without it is read and graded the same.
func TestAnalysis_ImportPathStored(t *testing.T) {
	host := importHostTarget(t)
	dir := importModule(t, false, "net/http")
	stubGitHub(t, http.StatusOK)
	stubScanOn(t, host, map[string][]scanner.Vulnerability{"stdlib": {
		{ID: "GO-TEST-0001", Severity: "MEDIUM", Reachability: "imported", ImportedPackages: []string{"net/http"}},
	}})
	an, err := Analyse(context.Background(), Options{Path: dir, Now: gradeDate})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(an)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"import_path":["example.com/main","net/http"]`) {
		t.Errorf("the stored analysis has no import_path: %s", raw)
	}
	if strings.Contains(string(raw), "imported_packages") {
		t.Errorf("the stored analysis carries imported_packages: %s", raw)
	}
	var back Analysis
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if got := back.Vulns["stdlib"]; len(got) != 1 || !slices.Equal(got[0].ImportPath, []string{"example.com/main", "net/http"}) {
		t.Errorf("import_path did not survive the round trip: %+v", got)
	}
	withPath, err := Grade(context.Background(), &back, nil, gradeDate, Options{})
	if err != nil {
		t.Fatal(err)
	}

	// the same analysis as v0.9.0 stored it: no import_path
	for i := range back.Vulns["stdlib"] {
		back.Vulns["stdlib"][i].ImportPath = nil
	}
	without, err := Grade(context.Background(), &back, nil, gradeDate, Options{})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(withPath.Grade)
	b, _ := json.Marshal(without.Grade)
	if string(a) != string(b) {
		t.Errorf("the grade follows import_path:\n%s\n%s", a, b)
	}
}
