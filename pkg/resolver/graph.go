// Package resolver handles dependency graph resolution.
package resolver

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/progress"
)

// Dependency represents a resolved dependency with graph info.
type Dependency struct {
	Module         parser.Module
	Direct         bool
	Depth          int      // 0 = direct, 1 = one level transitive, etc.
	UsedBy         []string // module paths that depend on this
	Replaced       bool     // whether this module is replaced in go.mod
	TransitiveDeps int      // how many dependencies this module itself pulls in

	// IsTestOnly is a three-state field indicating whether this module is
	// exclusively required for testing:
	//
	//   nil          — unknown; go list -m -json -test failed or was not run.
	//                  Task 10's test-only severity discount MUST NOT fire when
	//                  this is nil — under-discounting is safer than a silent
	//                  wrong discount on an unverified classification.
	//   &false       — confirmed production dependency (appears in non-test
	//                  import graph of the main module).
	//   &true        — confirmed test-only dependency (go list reports Test:true,
	//                  meaning it only appears via test imports of the main module).
	IsTestOnly *bool
}

// Graph holds the resolved dependency graph.
type Graph struct {
	Root         string
	Dependencies map[string]*Dependency // keyed by module path
	EdgeCount    int                    // total edges in the dependency graph
}

// Resolve resolves the full dependency graph. It tries `go mod graph` first,
// falling back to parsing go.mod/go.sum if the Go toolchain is unavailable.
func Resolve(ctx context.Context, gomodPath string, directOnly bool) (*Graph, []string, error) {
	rep := progress.From(ctx)
	rep.Step("reading %s", gomodPath)
	gomod, err := parser.ParseGoMod(gomodPath)
	if err != nil {
		return nil, nil, err
	}

	var warnings []string
	graph := &Graph{
		Root:         gomod.ModulePath,
		Dependencies: make(map[string]*Dependency),
	}

	// Build set of direct dependency paths from go.mod (non-indirect require).
	directPaths := make(map[string]bool)
	for _, req := range gomod.Requirements {
		if !req.Indirect {
			directPaths[req.Path] = true
		}
	}

	if directOnly {
		// Only include direct dependencies from go.mod.
		for _, req := range gomod.Requirements {
			if req.Indirect {
				continue
			}
			_, replaced := gomod.Replaces[req.Path]
			graph.Dependencies[req.Path] = &Dependency{
				Module:   req,
				Direct:   true,
				Depth:    0,
				UsedBy:   []string{gomod.ModulePath},
				Replaced: replaced,
			}
		}
		return graph, warnings, nil
	}

	// Try `go mod graph` for full transitive resolution.
	rep.Step("running go mod graph")
	err = resolveWithGoModGraph(ctx, gomodPath, graph, gomod, directPaths)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("Could not run 'go mod graph': %v. Falling back to go.mod/go.sum parsing (may miss transitive dependencies).", err))
		// Fall back: add everything from go.mod.
		for _, req := range gomod.Requirements {
			_, replaced := gomod.Replaces[req.Path]
			graph.Dependencies[req.Path] = &Dependency{
				Module:   req,
				Direct:   !req.Indirect,
				Depth:    depthFromIndirect(req.Indirect),
				UsedBy:   []string{gomod.ModulePath},
				Replaced: replaced,
			}
		}
		// Try go.sum for additional transitive deps.
		sumPath := filepath.Join(filepath.Dir(gomodPath), "go.sum")
		if err := addFromGoSum(sumPath, graph, gomod); err != nil {
			warnings = append(warnings, fmt.Sprintf("Could not parse go.sum: %v", err))
		}
	}

	// Classify test-only deps via `go list -m -json -test all`. This is a
	// best-effort enrichment: if it fails (air-gapped CI, vendor-only mode,
	// network issue), IsTestOnly stays nil on all deps and a warning is
	// appended so the caller knows the discount cannot be applied.
	if listWarn := classifyTestOnlyDeps(filepath.Dir(gomodPath), graph); listWarn != "" {
		warnings = append(warnings, listWarn)
	}

	return graph, warnings, nil
}

func depthFromIndirect(indirect bool) int {
	if indirect {
		return 1
	}
	return 0
}

func resolveWithGoModGraph(ctx context.Context, gomodPath string, graph *Graph, gomod *parser.GoMod, directPaths map[string]bool) error {
	dir := filepath.Dir(gomodPath)
	cmd := exec.CommandContext(ctx, "go", "mod", "graph")
	cmd.Dir = dir

	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("go mod graph: %w", err)
	}

	// Parse all edges from go mod graph output.
	// Format: "parent@version child@version" (root has no @version).
	type edge struct {
		fromPath, fromVer string
		toPath, toVer     string
	}

	var edges []edge
	children := make(map[string][]string) // parent path -> []child paths
	parents := make(map[string][]string)  // child path -> []parent paths
	allModules := make(map[string]string) // path -> highest version seen (MVS)

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}

		fromP := modulePath(parts[0])
		fromV := moduleVersion(parts[0])
		toP := modulePath(parts[1])
		toV := moduleVersion(parts[1])

		// Skip the "go" toolchain pseudo-dependency.
		if fromP == "go" || toP == "go" {
			continue
		}
		// Skip toolchain entries.
		if strings.HasPrefix(fromP, "toolchain") || strings.HasPrefix(toP, "toolchain") {
			continue
		}

		edges = append(edges, edge{fromPath: fromP, fromVer: fromV, toPath: toP, toVer: toV})

		// Track children (deduped by path).
		if !containsStr(children[fromP], toP) {
			children[fromP] = append(children[fromP], toP)
		}

		// Track parents.
		if !containsStr(parents[toP], fromP) {
			parents[toP] = append(parents[toP], fromP)
		}

		// Keep the highest version (Go MVS picks the max).
		if existing, ok := allModules[toP]; !ok || compareVersions(toV, existing) > 0 {
			allModules[toP] = toV
		}
	}

	graph.EdgeCount = len(edges)

	// BFS from root to compute depth.
	depths := make(map[string]int)
	depths[gomod.ModulePath] = -1
	queue := []string{gomod.ModulePath}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, child := range children[current] {
			if _, visited := depths[child]; !visited {
				depths[child] = depths[current] + 1
				queue = append(queue, child)
			}
		}
	}

	// Count how many deps each module itself pulls in.
	transitiveCounts := make(map[string]int)
	for modPath := range allModules {
		transitiveCounts[modPath] = len(children[modPath])
	}

	// Populate graph with ALL modules found in go mod graph.
	for modPath, version := range allModules {
		if modPath == gomod.ModulePath {
			continue
		}

		_, replaced := gomod.Replaces[modPath]
		isDirect := directPaths[modPath]

		depth := 1 // default for modules not reached by BFS (shouldn't happen)
		if d, ok := depths[modPath]; ok && d >= 0 {
			depth = d
		}

		dep := &Dependency{
			Module: parser.Module{
				Path:     modPath,
				Version:  version,
				Indirect: !isDirect,
			},
			Direct:         isDirect,
			Depth:          depth,
			UsedBy:         parents[modPath],
			Replaced:       replaced,
			TransitiveDeps: transitiveCounts[modPath],
		}

		graph.Dependencies[modPath] = dep
	}

	return nil
}

// classifyTestOnlyDeps determines which modules are used exclusively in test
// code by comparing two `go list` package graphs:
//
//  1. Production package graph: `go list -f '{{if .Module}}{{.Module.Path}}{{end}}' all`
//     — modules required to build the main module without any test code.
//  2. Full package graph (including tests): same with the -test flag added.
//
// A module present only in set 2 (and not in set 1) is test-only. A module in
// both sets is a production dependency.
//
// The function sets Dependency.IsTestOnly on each module in graph and returns a
// non-empty warning string if either `go list` call fails. In that case every
// dep's IsTestOnly remains nil — the scorer (Task 10) must not apply a
// test-only discount when the field is nil (unknown). Under-discounting is
// safer than a silent wrong discount on an unverified classification.
func classifyTestOnlyDeps(dir string, graph *Graph) string {
	// Collect production (non-test) module paths.
	prodMods, err := listModulePaths(dir, false)
	if err != nil {
		return fmt.Sprintf("go list (production) failed; test-only classification unavailable (IsTestOnly will be nil for all deps): %v", err)
	}

	// Collect module paths including test imports.
	allMods, err := listModulePaths(dir, true)
	if err != nil {
		return fmt.Sprintf("go list -test failed; test-only classification unavailable (IsTestOnly will be nil for all deps): %v", err)
	}

	// Require at least one module path from each call — an empty result means
	// the go list call succeeded but produced nothing meaningful (e.g. vendor
	// mode with incomplete vendor directory). Treat this as unavailable rather
	// than incorrectly classifying every dep as production.
	if len(prodMods) == 0 && len(allMods) == 0 {
		return "go list returned no module paths; test-only classification unavailable"
	}

	// Classify each dep in the graph.
	classified := 0
	for modPath, dep := range graph.Dependencies {
		_, inProd := prodMods[modPath]
		_, inAll := allMods[modPath]

		if !inProd && !inAll {
			// Module is not in either graph (e.g. from go.sum only). Leave nil.
			continue
		}

		isTest := inAll && !inProd
		dep.IsTestOnly = &isTest
		classified++
	}

	if classified == 0 {
		return "go list produced no matching modules for the dependency graph; test-only classification unavailable"
	}

	return ""
}

// listModulePaths runs `go list -f {{if .Module}}{{.Module.Path}}{{end}} all`
// in dir (with -test if withTest is true) and returns the unique set of module
// paths referenced by the package graph. An error is returned when go list
// fails (non-zero exit, unavailable Go toolchain, network timeout, etc.).
func listModulePaths(dir string, withTest bool) (map[string]struct{}, error) {
	args := []string{"list", "-f", "{{if .Module}}{{.Module.Path}}{{end}}"}
	if withTest {
		args = append(args, "-test")
	}
	args = append(args, "all")

	cmd := exec.Command("go", args...)
	cmd.Dir = dir

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	result := make(map[string]struct{})
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			result[line] = struct{}{}
		}
	}
	return result, nil
}

func addFromGoSum(sumPath string, graph *Graph, gomod *parser.GoMod) error {
	entries, err := parser.ParseGoSum(sumPath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.Path == gomod.ModulePath {
			continue
		}
		if _, exists := graph.Dependencies[entry.Path]; exists {
			continue
		}

		_, replaced := gomod.Replaces[entry.Path]
		graph.Dependencies[entry.Path] = &Dependency{
			Module: parser.Module{
				Path:     entry.Path,
				Version:  entry.Version,
				Indirect: true,
			},
			Direct:   false,
			Depth:    1,
			UsedBy:   []string{"(from go.sum)"},
			Replaced: replaced,
		}
	}

	return nil
}

func modulePath(s string) string {
	at := strings.Index(s, "@")
	if at < 0 {
		return s
	}
	return s[:at]
}

func moduleVersion(s string) string {
	at := strings.Index(s, "@")
	if at < 0 {
		return ""
	}
	return s[at+1:]
}

// compareVersions does a basic string comparison of Go module versions.
// This works for semver because "v1.2.3" < "v1.2.4" lexicographically
// within the same major version. For pseudo-versions it's approximate
// but sufficient for selecting a "higher" version.
func compareVersions(a, b string) int {
	if a == b {
		return 0
	}
	if a > b {
		return 1
	}
	return -1
}

func containsStr(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// DirectCount returns the number of direct dependencies.
func (g *Graph) DirectCount() int {
	count := 0
	for _, dep := range g.Dependencies {
		if dep.Direct {
			count++
		}
	}
	return count
}

// TransitiveCount returns the number of transitive (indirect) dependencies.
func (g *Graph) TransitiveCount() int {
	count := 0
	for _, dep := range g.Dependencies {
		if !dep.Direct {
			count++
		}
	}
	return count
}

// TotalEdges returns the number of edges in the dependency graph.
func (g *Graph) TotalEdges() int {
	return g.EdgeCount
}
