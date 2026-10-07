// Package resolver handles dependency graph resolution.
package resolver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.org/x/mod/semver"

	"github.com/unidoc/unisupply/pkg/netlog"
	"github.com/unidoc/unisupply/pkg/offline"
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
	// exclusively required for testing. It is derived from the main module's
	// own package graph (see classifyTestOnlyDeps), not from the module graph:
	//
	//   nil    - unknown. Classification was unavailable, the module is in
	//            neither package list (see InBuild), or a platform could not be
	//            listed and a test-only verdict could not be proven. A
	//            test-only discount MUST NOT fire on nil: under-discounting is
	//            safer than a silent wrong discount on an unverified
	//            classification.
	//   &false - confirmed production dependency: a package of this module is
	//            imported by non-test code of the main module on at least one
	//            GOOS.
	//   &true  - confirmed test-only dependency: imported by the main module's
	//            tests but by no production package on any GOOS.
	IsTestOnly *bool

	// InBuild is a three-state field indicating whether any package of this
	// module is compiled into the main module's production code or tests
	// (any of linux, darwin, windows, with cgo on or off):
	//
	//   nil    - unknown: classification was unavailable; or the module was
	//            found by no list but the verdict is not safe to give (the
	//            main module requires it directly, so it may be imported only
	//            under a custom build tag, or a platform could not be listed).
	//   &true  - at least one package of the module is in a production or test
	//            package list.
	//   &false - classification succeeded and no package of the module is in
	//            any list: it is in the module graph only (for example it is
	//            required by a dependency that the main module uses only in
	//            part). Dependencies' own tests do not count.
	InBuild *bool

	// Platforms lists the GOOS values on which a production module is built,
	// sorted. It is set only when the module is in the production package
	// list of a strict subset of the GOOS values that were listed, so a nil
	// value means "all listed platforms" (or unknown), not "none". It is left
	// nil when any GOOS could not be listed, because a subset claim over a
	// platform that was not observed cannot be backed.
	Platforms []string
}

// Graph holds the resolved dependency graph.
type Graph struct {
	Root         string
	Dependencies map[string]*Dependency // keyed by module path
	EdgeCount    int                    // total edges in the dependency graph
}

// SortedPaths returns the module paths in Dependencies in ascending order.
// Dependencies is a map, so reports that range it directly would emit
// components in a different order on every run.
func (g *Graph) SortedPaths() []string {
	return slices.Sorted(maps.Keys(g.Dependencies))
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
			_, replaced := gomod.ReplacementFor(req.Path, req.Version)
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
			_, replaced := gomod.ReplacementFor(req.Path, req.Version)
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

	// Classify test-only and in-build deps from the main module's package
	// graph. This is a best-effort enrichment: if it fails (air-gapped CI,
	// vendor-only mode, network issue), IsTestOnly and InBuild stay nil on all
	// deps and a warning is appended so the caller knows the classification
	// cannot be applied.
	if listWarn := classifyTestOnlyDeps(ctx, filepath.Dir(gomodPath), graph); listWarn != "" {
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
	netlog.Subprocess("go mod graph", offline.SubprocessNote("module proxy/VCS may be contacted by the go toolchain; see GOPROXY"))

	cmd := exec.CommandContext(ctx, "go", "mod", "graph")
	cmd.Dir = dir
	cmd.Env = offline.Env(os.Environ())

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

		_, replaced := gomod.ReplacementFor(modPath, version)
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

// listGOOS are the target operating systems whose package graphs are unioned.
// `go list` evaluates build constraints for one GOOS at a time, so a module
// imported only from a _windows.go file is invisible on a darwin or linux host.
// Sorted, so Dependency.Platforms comes out sorted without a further pass.
// GOARCH-only differences are out of scope.
var listGOOS = []string{"darwin", "linux", "windows"}

// maxParallelLists bounds the concurrent `go list` subprocesses. Each one
// loads the whole package graph, so the limit keeps memory and cache
// contention modest while still overlapping the I/O-bound parts.
const maxParallelLists = 4

// listRun identifies one `go list` invocation.
type listRun struct {
	goos string
	cgo  bool // CGO_ENABLED=1; false lists with CGO_ENABLED=0
	test bool // include the main module's tests (-test)
}

// listResult is the outcome of one listRun.
type listResult struct {
	// mods is the set of module paths of every package the run resolved. It
	// is valid positive evidence even when the run also reports unresolved
	// packages: a module that was seen is in the build.
	mods map[string]struct{}

	// unresolved holds the import paths that could not be mapped to a module
	// (no required module provides them, go.sum entry missing, lookup
	// disabled or failed). Each one hides a module, so the run cannot prove
	// anything about modules it did not see.
	unresolved []string

	// tolerated holds "package: reason" notes for per-package errors whose
	// module is still known, such as an unmatched //go:embed pattern.
	tolerated []string

	// err is a toolchain-level failure (the command did not run or exited
	// non-zero); mods is empty in that case.
	err error

	// needsModUpdate is set when the run failed, or left packages unresolved,
	// because go.mod or go.sum would have to be changed. It can only happen
	// under -mod=readonly (see listArgs).
	needsModUpdate bool
}

// platformList merges the runs of one GOOS: production and test module sets
// are the union over CGO_ENABLED=0 and CGO_ENABLED=1.
type platformList struct {
	goos       string
	prod, test map[string]struct{}
	unresolved []string
	err        error

	// needsModUpdate is true when any run of this GOOS reported that go.mod or
	// go.sum needs updating.
	needsModUpdate bool
}

// clean reports whether every run for this GOOS completed and mapped every
// package to a module. Only a clean platform can prove that a module is absent.
func (p *platformList) clean() bool {
	return p.err == nil && len(p.unresolved) == 0
}

// failure describes why the platform is not clean, for the warning text.
func (p *platformList) failure() string {
	if p.err != nil {
		return p.err.Error()
	}
	names := slices.Clone(p.unresolved)
	if len(names) > 3 {
		names = append(names[:3], "...")
	}
	return "unresolved packages: " + strings.Join(names, ", ")
}

// classifyTestOnlyDeps classifies each module in graph against the main
// module's own package graph. It sets Dependency.IsTestOnly, InBuild and
// Platforms and returns a warning ("" when there is nothing to report).
//
// Two lists are taken per target platform, for each of linux, darwin and
// windows with CGO_ENABLED=0 and CGO_ENABLED=1 (the union of the cgo settings
// is what a build on that GOOS may use):
//
//  1. Production: `go list -e -deps ./...`, the modules whose packages the main
//     module's non-test code imports, directly or transitively.
//  2. Production plus tests: `go list -e -deps -test ./...`, which adds only the
//     packages the main module's own tests import. It does not include the
//     tests of dependencies, whatever `go` version go.mod declares.
//
// `go list all` is deliberately not used. For go.mod files declaring go 1.16 or
// newer `all` and `all -test` yield the same modules, so a comparison can never
// report a test-only module; below go 1.16 `all` also includes packages needed
// by dependencies' own tests, which would classify them as production.
//
// A module in a production list on any platform is production (IsTestOnly
// &false). A module only in a test list is test-only (&true). Both are in the
// build (InBuild &true). A module in no list is outside the build (InBuild
// &false), with the exceptions below. Platforms records the GOOS values of a
// production module that is not built on every platform.
//
// Known limit: a package behind a custom build tag (`//go:build integration`)
// is in no list. A module the main module requires directly (no `// indirect`)
// that no list contains may be imported only under such a tag, so it gets
// InBuild nil rather than &false. An indirect module is not guarded this way:
// the main module cannot import it directly, so graph-only is the likely cause.
//
// Failure handling. A platform is clean when all of its runs succeed and every
// package resolves to a module. With -e, a package whose module cannot be
// resolved is listed without a Module, so on its own it would make the module
// that provides it look absent from the build. Such a run is therefore treated
// as failed rather than tolerated; per-package errors with a known module (an
// unmatched //go:embed pattern) are tolerated and named in the warning.
//
// A failing platform does not make classification unavailable for the others
// (a package that does not build on Windows must not blind a Linux scan):
// everything the failed runs did resolve still counts as positive evidence, and
// the platforms that succeeded classify the rest. What a failed platform
// cannot do is prove absence. If any platform failed, a module no list contains
// gets InBuild nil (it may be imported only on the platform that failed), a
// test-only verdict is withheld (the module may be production there) and
// Platforms is left nil (a subset claim needs every platform). Only when every
// platform fails is classification unavailable: all fields stay nil and the
// warning says so, because under-discounting is safer than a silent wrong
// discount on an unverified classification.
func classifyTestOnlyDeps(ctx context.Context, dir string, graph *Graph) string {
	// Offline runs the toolchain with GOPROXY=off, so `go list` fails whenever
	// the module cache is cold. That is the mode working as designed, not a
	// broken environment, so say so rather than report it as a fault.
	unavailable := func(failures []string, needsModUpdate bool) string {
		if offline.Enabled() && needsModUpdate {
			return "offline — go.mod or go.sum needs updating (go mod tidy); go list was run read-only so the project's go.mod and go.sum are not modified; test-only classification unavailable (IsTestOnly and InBuild will be nil for all deps)"
		}
		if offline.Enabled() {
			return "offline — go list could not resolve from the local module cache; test-only classification unavailable (IsTestOnly and InBuild will be nil for all deps)"
		}
		return fmt.Sprintf("go list failed on every platform; test-only classification unavailable (IsTestOnly and InBuild will be nil for all deps): %s", strings.Join(failures, "; "))
	}

	platforms, tolerated := listPlatforms(ctx, dir)

	var failed []string // "GOOS=x (reason)"
	var okOS []string
	needsModUpdate := false
	for _, p := range platforms {
		if p.clean() {
			okOS = append(okOS, p.goos)
			continue
		}
		failed = append(failed, fmt.Sprintf("GOOS=%s (%s)", p.goos, p.failure()))
		needsModUpdate = needsModUpdate || p.needsModUpdate
	}
	if len(okOS) == 0 {
		return unavailable(failed, needsModUpdate)
	}
	partial := len(failed) > 0

	// Require at least one module path: an empty result means go list succeeded
	// but produced nothing meaningful (for example no Go packages, or vendor
	// mode with an incomplete vendor directory). Treat it as unavailable rather
	// than classifying every dep as outside the build. A real listing always
	// contains the main module itself.
	listed := false
	for _, p := range platforms {
		if len(p.prod) > 0 || len(p.test) > 0 {
			listed = true
			break
		}
	}
	if !listed {
		return "go list returned no module paths; test-only classification unavailable"
	}

	for modPath, dep := range graph.Dependencies {
		var prodOn []string
		inTest := false
		for _, p := range platforms {
			if _, ok := p.prod[modPath]; ok {
				prodOn = append(prodOn, p.goos)
			}
			if _, ok := p.test[modPath]; ok {
				inTest = true
			}
		}

		inBuild := true
		switch {
		case len(prodOn) > 0:
			notTest := false
			dep.IsTestOnly = &notTest
			if !partial && len(prodOn) < len(platforms) {
				dep.Platforms = prodOn
			}
		case inTest:
			// A failed platform may build this module in production, so the
			// verdict is only given when every platform was listed.
			if !partial {
				testOnly := true
				dep.IsTestOnly = &testOnly
			}
		case partial || dep.Direct:
			// Not provably absent: see the failure handling and build-tag
			// notes above.
			continue
		default:
			inBuild = false
		}
		dep.InBuild = &inBuild
	}

	var warnings []string
	if partial {
		warnings = append(warnings, fmt.Sprintf(
			"go list failed for %s; classified from %s only. Modules found on no platform are left unclassified (InBuild nil), and test-only and platform-restriction verdicts are withheld",
			strings.Join(failed, "; "), strings.Join(okOS, ",")))
	}
	if len(tolerated) > 0 {
		warnings = append(warnings, "go list reported package errors that do not affect module classification: "+strings.Join(tolerated, "; "))
	}
	return strings.Join(warnings, ". ")
}

// listPlatforms runs the production and test lists for every GOOS in listGOOS
// with CGO_ENABLED=0 and CGO_ENABLED=1 (12 `go list` runs, at most
// maxParallelLists at once) and merges them per GOOS. It also returns the
// deduplicated, sorted per-package errors the runs tolerated.
func listPlatforms(ctx context.Context, dir string) (platforms []*platformList, tolerated []string) {
	runs := make([]listRun, 0, len(listGOOS)*4)
	for _, goos := range listGOOS {
		for _, cgo := range []bool{false, true} {
			for _, test := range []bool{false, true} {
				runs = append(runs, listRun{goos: goos, cgo: cgo, test: test})
			}
		}
	}

	results := make([]listResult, len(runs))
	sem := make(chan struct{}, maxParallelLists)
	var wg sync.WaitGroup
	for i, run := range runs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = listPackages(ctx, dir, run)
		}()
	}
	wg.Wait()

	byOS := make(map[string]*platformList, len(listGOOS))
	platforms = make([]*platformList, 0, len(listGOOS))
	for _, goos := range listGOOS {
		p := &platformList{goos: goos, prod: map[string]struct{}{}, test: map[string]struct{}{}}
		byOS[goos] = p
		platforms = append(platforms, p)
	}
	toleratedSet := make(map[string]struct{})
	for i, run := range runs {
		res, p := results[i], byOS[run.goos]
		dst := p.prod
		if run.test {
			dst = p.test
		}
		maps.Copy(dst, res.mods)
		if res.err != nil && p.err == nil {
			p.err = res.err
		}
		p.needsModUpdate = p.needsModUpdate || res.needsModUpdate
		for _, u := range res.unresolved {
			if !slices.Contains(p.unresolved, u) {
				p.unresolved = append(p.unresolved, u)
			}
		}
		for _, n := range res.tolerated {
			toleratedSet[n] = struct{}{}
		}
	}
	for _, p := range platforms {
		slices.Sort(p.unresolved)
	}
	return platforms, slices.Sorted(maps.Keys(toleratedSet))
}

// listedPackage is the subset of `go list -json` output that classification
// reads.
type listedPackage struct {
	ImportPath string
	Standard   bool
	Module     *struct{ Path string }
	Error      *struct{ Err string }
}

// listFields selects the `go list -json` fields to emit; the full output is
// over a megabyte per run for a small module. EmbedFiles is requested only for
// its side effect: with a field selection, go list resolves //go:embed
// patterns, and so reports an unmatched one as a package Error, only when an
// embed field is asked for. Without it the error is silently dropped and the
// warning could not name the package.
const listFields = "ImportPath,Standard,Module,Error,EmbedFiles"

// listArgs builds the `go list` arguments for run.
//
// Offline mode adds -mod=readonly. offline.Env sets GOFLAGS=-mod=mod, which
// lets the toolchain add missing requirements and go.sum entries, so a scan
// would rewrite the scanned project's go.mod and go.sum, and the concurrent
// runs of listPlatforms could race on those files. A -mod flag on the command
// line takes precedence over the one in GOFLAGS. Online, the user's own
// environment decides, so nothing is added.
func listArgs(run listRun, readOnly bool) []string {
	args := []string{"list", "-e", "-deps"}
	if run.test {
		args = append(args, "-test")
	}
	if readOnly {
		args = append(args, "-mod=readonly")
	}
	return append(args, "-json="+listFields, "./...")
}

// modUpdateMarkers are fragments of the go toolchain's messages that say go.mod
// or go.sum would have to change, which -mod=readonly forbids. They are matched
// against the toolchain's English message text, which has no structured
// equivalent in `go list -json`, so a toolchain that rewords them degrades to
// the generic offline warning. Observed on go1.26:
//
//   - "go: updates to go.mod needed, disabled by -mod=readonly; to update it: ..."
//     (stderr, non-zero exit);
//   - "cannot find module providing package P: import lookup disabled by
//     -mod=readonly";
//   - "missing go.sum entry for module providing package P ...";
//   - "module M provides package P and is replaced but not required ...".
//
// The cold-cache failure ("module lookup disabled by GOPROXY=off") matches none
// of them.
var modUpdateMarkers = []string{
	"disabled by -mod=readonly",
	"missing go.sum entry",
	"is replaced but not required",
}

// needsModUpdate reports whether a go list message says go.mod or go.sum needs
// updating.
func needsModUpdate(msg string) bool {
	return slices.ContainsFunc(modUpdateMarkers, func(m string) bool {
		return strings.Contains(msg, m)
	})
}

// listPackages runs one `go list -e -deps [-test] ./...` for run in dir.
//
// -e keeps per-package errors from failing the whole listing. Whether an error
// is tolerable is decided structurally: every package that resolved carries a
// Module (standard library packages excepted), so a non-standard package with
// an Error and no Module is one whose module could not be resolved. Packages
// with an Error and a Module (an unmatched //go:embed pattern, a build
// constraint excluding all files on this GOOS) are tolerated and noted.
func listPackages(ctx context.Context, dir string, run listRun) listResult {
	cgo := "0"
	if run.cgo {
		cgo = "1"
	}
	args := listArgs(run, offline.Enabled())

	netlog.Subprocess(
		fmt.Sprintf("GOOS=%s CGO_ENABLED=%s go %s", run.goos, cgo, strings.Join(args, " ")),
		offline.SubprocessNote("module proxy/VCS may be contacted by the go toolchain; see GOPROXY"),
	)

	// offline.Env returns nil when offline mode is off, meaning "inherit"; the
	// platform variables must still be set then, so start from the parent's
	// environment. They are appended last because exec.Cmd resolves duplicate
	// keys last-wins, so they override anything inherited.
	env := offline.Env(os.Environ())
	if env == nil {
		env = os.Environ()
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	cmd.Env = append(slices.Clone(env), "GOOS="+run.goos, "CGO_ENABLED="+cgo)

	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			needsUpdate := needsModUpdate(string(exitErr.Stderr))
			if msg := firstLine(string(exitErr.Stderr)); msg != "" {
				err = fmt.Errorf("%w: %s", err, msg)
			}
			return listResult{err: err, needsModUpdate: needsUpdate}
		}
		return listResult{err: err}
	}

	res := listResult{mods: make(map[string]struct{})}
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var pkg listedPackage
		if err := dec.Decode(&pkg); err != nil {
			if !errors.Is(err, io.EOF) {
				res.err = fmt.Errorf("decoding go list output: %w", err)
			}
			break
		}
		if pkg.Module != nil && pkg.Module.Path != "" {
			res.mods[pkg.Module.Path] = struct{}{}
		}
		if pkg.Error == nil {
			continue
		}
		if pkg.Module == nil && !pkg.Standard {
			res.unresolved = append(res.unresolved, pkg.ImportPath)
			res.needsModUpdate = res.needsModUpdate || needsModUpdate(pkg.Error.Err)
			continue
		}
		res.tolerated = append(res.tolerated, fmt.Sprintf("%s: %s", pkg.ImportPath, firstLine(pkg.Error.Err)))
	}
	return res
}

// firstLine returns the first non-empty line of s, trimmed. go list errors can
// span several lines of remediation advice that does not belong in a warning.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
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

		_, replaced := gomod.ReplacementFor(entry.Path, entry.Version)
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

// compareVersions compares Go module versions using semver semantics.
// Fixes the lexical compare bug where v1.9.0 > v1.10.0 incorrectly.
func compareVersions(a, b string) int {
	return semver.Compare(a, b)
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
