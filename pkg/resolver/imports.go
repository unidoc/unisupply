package resolver

import (
	"context"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"

	"github.com/unidoc/unisupply/pkg/offline"
)

// PackageGraph is the production import graph of the main module's packages on one target, from go list.
//
// It is the graph govulncheck analyses: no test files, one GOOS/GOARCH, and one CGO_ENABLED setting, the one the go
// command resolves in the project (go env CGO_ENABLED), which govulncheck inherits. When that listing failed, listed
// nothing, or the setting could not be read, it is the union of the CGO_ENABLED=0 and CGO_ENABLED=1 listings instead,
// and may then contain a chain through a file the scan did not compile. Nothing in it is stored with the analysis.
type PackageGraph struct {
	Platform   string              // "goos/goarch"
	CgoEnabled string              // "0" or "1": the CGO_ENABLED listing the graph comes from; "" when the two listings were merged
	Roots      []string            // the main module's packages (DepOnly false), sorted
	Imports    map[string][]string // import path -> sorted, deduplicated imports
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

// goEnvCgo reads the CGO_ENABLED setting the go command resolves in dir. It is a variable so that a test can make it fail.
var goEnvCgo = readGoEnvCgo

// readGoEnvCgo returns "0" or "1": what `go env CGO_ENABLED` prints in dir, so the default the go command applies (off
// without a C compiler) counts. It runs in the environment of the listings without their per-run GOOS, GOARCH and
// CGO_ENABLED, which is the environment govulncheck inherits. Like the other `go env` calls it is not logged: it reads
// local configuration and makes no network request.
func readGoEnvCgo(ctx context.Context, dir string) (string, error) {
	env := offline.Env(os.Environ())
	if env == nil {
		env = os.Environ()
	}
	cmd := exec.CommandContext(ctx, "go", "env", "CGO_ENABLED")
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("go env CGO_ENABLED: %w", err)
	}
	switch v := strings.TrimSpace(string(out)); v {
	case "0", "1":
		return v, nil
	default:
		return "", fmt.Errorf("go env CGO_ENABLED printed %q, want 0 or 1", v)
	}
}

// runGraph is the package graph of one listing run.
type runGraph struct {
	roots  map[string]struct{}
	edges  map[string]map[string]struct{}
	failed bool // the run did not complete (a toolchain-level failure)
}

// addGraph records the package graph of one production run of the target, by its CGO setting.
func (p *platformList) addGraph(cgo bool, res listResult) {
	if p.pkgRuns == nil {
		p.pkgRuns = make(map[bool]*runGraph, 2)
	}
	rg := &runGraph{
		roots:  make(map[string]struct{}, len(res.roots)),
		edges:  make(map[string]map[string]struct{}, len(res.edges)),
		failed: res.err != nil,
	}
	for _, r := range res.roots {
		rg.roots[r] = struct{}{}
	}
	for pkg, imports := range res.edges {
		set := make(map[string]struct{}, len(imports))
		for _, imp := range imports {
			set[imp] = struct{}{}
		}
		rg.edges[pkg] = set
	}
	p.pkgRuns[cgo] = rg
}

// packageGraph returns the target's package graph for the CGO_ENABLED setting cgo ("0" or "1", as the go command
// resolves it): the listing of that setting when its run completed and listed a package of the main module. Otherwise,
// including when cgo is "" because the setting could not be read, it is the union of both listings and CgoEnabled is
// "". It returns nil when no run listed a package of the main module.
func (p *platformList) packageGraph(cgo string) *PackageGraph {
	var use []*runGraph
	picked := ""
	if cgo == "0" || cgo == "1" {
		if rg := p.pkgRuns[cgo == "1"]; rg != nil && !rg.failed && len(rg.roots) > 0 {
			use, picked = []*runGraph{rg}, cgo
		}
	}
	if use == nil {
		for _, rg := range p.pkgRuns {
			use = append(use, rg)
		}
	}

	roots := make(map[string]struct{})
	edges := make(map[string]map[string]struct{})
	for _, rg := range use {
		maps.Copy(roots, rg.roots)
		for pkg, imports := range rg.edges {
			set := edges[pkg]
			if set == nil {
				set = make(map[string]struct{}, len(imports))
				edges[pkg] = set
			}
			maps.Copy(set, imports)
		}
	}
	if len(roots) == 0 {
		return nil
	}
	pg := &PackageGraph{
		Platform:   p.name(),
		CgoEnabled: picked,
		Roots:      slices.Sorted(maps.Keys(roots)),
		Imports:    make(map[string][]string, len(edges)),
	}
	for pkg, set := range edges {
		pg.Imports[pkg] = slices.Sorted(maps.Keys(set))
	}
	return pg
}
