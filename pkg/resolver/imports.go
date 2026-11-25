package resolver

import (
	"maps"
	"os"
	"runtime"
	"slices"
)

// PackageGraph is the production import graph of the main module's packages on one target, from go list.
//
// It is the graph govulncheck analyses: no test files, one GOOS/GOARCH, and the union of the CGO_ENABLED=0 and
// CGO_ENABLED=1 listings. Nothing in it is stored with the analysis.
type PackageGraph struct {
	Platform string              // "goos/goarch"
	Roots    []string            // the main module's packages (DepOnly false), sorted
	Imports  map[string][]string // import path -> sorted, deduplicated imports
	Partial  bool                // the target's listing was not clean (a failed run or unresolved packages)
}

// ShortestImportPath returns the shortest chain of imports from one of the main module's packages to the nearest of
// targets: the first entry is a root, the last is the target it reached. A root that is itself a target is a chain of
// one. It returns nil when no target is reachable, and for a nil graph.
//
// The search starts from the roots in sorted order and follows each package's imports in sorted order, so the same graph
// always gives the same chain when several have the same length. An import with no entry of its own (cgo's "C") ends
// that branch.
func (g *PackageGraph) ShortestImportPath(targets []string) []string {
	if g == nil || len(targets) == 0 {
		return nil
	}
	want := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		want[t] = struct{}{}
	}

	// parent[p] is the package that first reached p; a root has no parent.
	parent := make(map[string]string, len(g.Imports))
	queue := make([]string, 0, len(g.Roots))
	for _, r := range g.Roots {
		if _, dup := parent[r]; !dup {
			parent[r] = ""
			queue = append(queue, r)
		}
	}
	for i := 0; i < len(queue); i++ {
		pkg := queue[i]
		if _, ok := want[pkg]; ok {
			var chain []string
			for p := pkg; ; p = parent[p] {
				chain = append(chain, p)
				if parent[p] == "" {
					break
				}
			}
			slices.Reverse(chain)
			return chain
		}
		for _, next := range g.Imports[pkg] {
			if _, seen := parent[next]; !seen {
				parent[next] = pkg
				queue = append(queue, next)
			}
		}
	}
	return nil
}

// scanTarget is the "goos/goarch" govulncheck scans: GOOS and GOARCH from the environment, otherwise the running
// binary's. It repeats scanner.scanPlatform (pkg/scanner/scaninfo.go), which resolver cannot import. The runner
// compares Graph.Packages.Platform with ScanInfo.Platform before it uses the graph, so a drift between the two rules
// leaves a finding without a chain instead of giving it a wrong one.
func scanTarget() string {
	goos, goarch := os.Getenv("GOOS"), os.Getenv("GOARCH")
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	return goos + "/" + goarch
}

// addGraph merges the package graph of one run into the target, a union over its runs.
func (p *platformList) addGraph(res listResult) {
	if p.pkgRoots == nil {
		p.pkgRoots = make(map[string]struct{})
		p.pkgEdges = make(map[string]map[string]struct{})
	}
	for _, r := range res.roots {
		p.pkgRoots[r] = struct{}{}
	}
	for pkg, imports := range res.edges {
		set := p.pkgEdges[pkg]
		if set == nil {
			set = make(map[string]struct{}, len(imports))
			p.pkgEdges[pkg] = set
		}
		for _, imp := range imports {
			set[imp] = struct{}{}
		}
	}
}

// packageGraph returns the target's merged package graph, or nil when no run listed a package of the main module.
func (p *platformList) packageGraph() *PackageGraph {
	if len(p.pkgRoots) == 0 {
		return nil
	}
	pg := &PackageGraph{
		Platform: p.name(),
		Roots:    slices.Sorted(maps.Keys(p.pkgRoots)),
		Imports:  make(map[string][]string, len(p.pkgEdges)),
		Partial:  !p.clean(),
	}
	for pkg, set := range p.pkgEdges {
		pg.Imports[pkg] = slices.Sorted(maps.Keys(set))
	}
	return pg
}
