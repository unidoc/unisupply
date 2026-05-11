// Package resolver handles dependency graph resolution.
package resolver

import (
	"bufio"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/unidoc/unisupply/pkg/parser"
)

// Dependency represents a resolved dependency with graph info.
type Dependency struct {
	Module         parser.Module
	Direct         bool
	Depth          int      // 0 = direct, 1 = one level transitive, etc.
	UsedBy         []string // module paths that depend on this
	Replaced       bool     // whether this module is replaced in go.mod
	TransitiveDeps int      // how many dependencies this module itself pulls in
}

// Graph holds the resolved dependency graph.
type Graph struct {
	Root         string
	Dependencies map[string]*Dependency // keyed by module path
	EdgeCount    int                    // total edges in the dependency graph
}

// Resolve resolves the full dependency graph. It tries `go mod graph` first,
// falling back to parsing go.mod/go.sum if the Go toolchain is unavailable.
func Resolve(gomodPath string, directOnly bool) (*Graph, []string, error) {
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
	err = resolveWithGoModGraph(gomodPath, graph, gomod, directPaths)
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

	return graph, warnings, nil
}

func depthFromIndirect(indirect bool) int {
	if indirect {
		return 1
	}
	return 0
}

func resolveWithGoModGraph(gomodPath string, graph *Graph, gomod *parser.GoMod, directPaths map[string]bool) error {
	dir := filepath.Dir(gomodPath)
	cmd := exec.Command("go", "mod", "graph")
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
