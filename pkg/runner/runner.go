// Package runner exposes unisupply's scan-and-score pipeline as a plain Go
// function, independent of the CLI. cmd/unisupply/main.go calls Run
// internally (it is the ONLY implementation of this pipeline — the CLI does
// not duplicate this logic), and any other Go program can import this
// package to run the same scan in-process, without shelling out to the
// unisupply binary. gorisk (UniDoc's continuous-scanning service) is the
// first such caller.
package runner

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/progress"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// Options configures a Run. Mirrors the subset of cmd/unisupply's CLI flags
// that affect the scan/score pipeline itself — output-format flags
// (--format, --output, --no-color, ...) and policy flags (--policy,
// --policy-preset) are CLI-only concerns and stay in cmd/unisupply/main.go,
// applied to the Result after Run returns.
type Options struct {
	// Path is the project directory (or a path inside it) to scan. Same
	// semantics as the CLI's positional argument: parser.FindGoMod walks
	// upward from here to locate go.mod.
	Path string

	// Timeout bounds each scanner's outbound HTTP calls (Go Module Proxy,
	// GitHub API, Trust Index). Defaults to 30s (the CLI's own --timeout
	// default) if zero.
	Timeout time.Duration

	DirectOnly bool

	GithubToken string

	TrustIndexURL          string
	TrustIndexAllowPrivate bool

	ScanWorkflows bool
	ScanCI        bool
	// WorkflowPath defaults to ".github/workflows" (relative to the
	// project directory) if empty, matching the CLI's own default.
	WorkflowPath string

	DebugScoring bool

	// Offline tells the scanners the process makes no network requests: go mod
	// verify is skipped and degraded lookups are reported accordingly. It does
	// NOT block the network itself; the caller installs pkg/offline.Enable (the
	// CLI does) if it wants that enforced.
	Offline bool

	// Now pins scanStart for deterministic scoring (all scanner age/activity
	// classifications are computed against it). Defaults to
	// time.Now().UTC().Truncate(24*time.Hour) if zero — the same
	// floor-to-UTC-day convention the CLI itself uses, so two runs on the
	// same calendar day yield identical results for the same module.
	Now time.Time
}

// Result is everything the scan/score pipeline produces — enough for a
// caller to feed directly into any of pkg/report's Write* functions
// (WriteText, WriteJSON, WritePDF, WriteCycloneDX, WriteSPDX all take
// exactly a *resolver.Graph and *scorer.ProjectScore, plus format-specific
// options that reference CIReport/Takeovers).
type Result struct {
	GoMod        *parser.GoMod
	Graph        *resolver.Graph
	ProjectScore *scorer.ProjectScore

	// CIReport is nil unless Options.ScanWorkflows or Options.ScanCI was set.
	CIReport *scanner.CIReport
	// Takeovers lists maintainers flagged as takeover candidates.
	Takeovers []*scanner.MaintainerInfo
	// StdlibVulns holds vulnerabilities found in the Go standard library
	// itself, separated out of ProjectScore's per-dependency vulns (the
	// stdlib isn't a "dependency" in the graph sense).
	StdlibVulns []scanner.Vulnerability

	// IntegrityReport is the go.mod replace/exclude, pseudo-version and go.sum
	// audit. Always non-nil on a successful Run.
	IntegrityReport *scanner.IntegrityReport

	// VulnScanErr is non-nil when the vulnerability scan did not complete
	// (govulncheck failed, or produced no usable output). Run still returns a
	// Result in that case - the dependency graph and the other scanners ran -
	// but the vulnerability data is EMPTY, which a caller must not present as
	// "no vulnerabilities".
	VulnScanErr error
	// Interrupted is true when the context ended before every scanner finished,
	// so the report may be incomplete.
	Interrupted bool

	// Maintainers and Typosquats are the raw per-module scanner outputs
	// (keyed by module path) — ProjectScore folds their signal into each
	// DependencyScore, but callers doing their own policy evaluation (see
	// pkg/policy.EvalInput, which cmd/unisupply's CLI feeds these into
	// directly) need the maps themselves, not just the derived score.
	Maintainers map[string]*scanner.MaintainerInfo
	Typosquats  map[string]*scanner.TyposquatResult
}

// Run executes unisupply's full scan-and-score pipeline: parse go.mod,
// resolve the dependency graph, run every applicable scanner, and compute
// the project's risk score. Returns a Result with an empty
// ProjectScore.Dependencies (but otherwise-valid, scored ProjectScore) when
// the project has no dependencies at all — callers that want the CLI's
// exact "No dependencies found." skip-the-report behavior should check
// len(result.Graph.Dependencies) == 0 themselves, since whether to skip
// writing output is a presentation decision, not a scanning one.
//
// Progress events go through progress.From(ctx): pass a context wrapped
// with progress.WithReporter for CLI-style stage output; a plain context
// (as any library caller will pass) gets progress.From's built-in no-op
// reporter, so Run is silent by default.
func Run(ctx context.Context, opts Options) (*Result, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	scanStart := opts.Now
	if scanStart.IsZero() {
		scanStart = time.Now().UTC().Truncate(24 * time.Hour)
	}

	rep := progress.From(ctx)

	rep.Stage("Parsing go.mod")
	gomodPath, err := parser.FindGoMod(opts.Path)
	if err != nil {
		return nil, err
	}
	gomod, err := parser.ParseGoMod(gomodPath)
	if err != nil {
		return nil, err
	}
	projectDir := filepath.Dir(gomodPath)
	rep.Done("%s", gomodPath)

	// Audit replace/exclude directives (pure go.mod analysis, no network).
	rep.Stage("Auditing go.mod directives")
	integrityScanner := scanner.NewIntegrityScanner()
	integrityScanner.Offline = opts.Offline
	integrityReport, integrityClasses := integrityScanner.ScanDirectives(gomod)
	rep.Done("%d replace, %d exclude (%d redirect)", integrityReport.ReplaceCount, integrityReport.ExcludeCount, integrityReport.RedirectCount)

	rep.Stage("Resolving dependency graph")
	graph, resolverWarnings, err := resolver.Resolve(ctx, gomodPath, opts.DirectOnly)
	if err != nil {
		return nil, fmt.Errorf("resolving dependencies: %w", err)
	}
	for _, w := range resolverWarnings {
		rep.Warn("%s", w)
	}
	rep.Done("%d modules", len(graph.Dependencies))

	if len(graph.Dependencies) == 0 {
		// Same shortcut as the original CLI code: nothing to scan, so skip
		// every scanner's outbound calls entirely rather than running them
		// against an empty graph. scorer.ScoreAll (not a hand-built zero
		// value) still computes ProjectScore, so its shape matches exactly
		// what a real empty-graph score looks like.
		projectScore := scorer.ScoreAll(scorer.ScoreInput{
			Graph:     graph,
			Now:       scanStart,
			DebugMode: opts.DebugScoring,
		})
		return &Result{GoMod: gomod, Graph: graph, ProjectScore: projectScore, IntegrityReport: integrityReport}, nil
	}

	// Pseudo-version audit needs the resolved graph (Direct/IsTestOnly).
	rep.Stage("Auditing pseudo-version pins")
	pseudoVersionClasses := integrityScanner.ScanPseudoVersions(graph, integrityReport)
	rep.Done("%d pseudo-version pins", integrityReport.PseudoVersionCount)

	rep.Stage("Verifying go.sum (go mod verify)")
	integrityScanner.ScanGoSum(gomodPath, gomod, graph, integrityReport)
	integrityScanner.VerifyGoSum(ctx, gomodPath, integrityReport)
	rep.Done("go.sum verify: %s", integrityReport.GoSumVerified)

	rep.Stage("Scanning vulnerabilities (govulncheck)")
	vulns, vulnWarnings, vulnScanned, err := scanner.ScanVulns(ctx, projectDir, opts.GithubToken)
	// The scanner reports availability directly: govulncheck failures come back
	// as a warning with a nil error, so err alone reads a failed scan as clean.
	vulnScanUnavailable := !vulnScanned
	if err != nil {
		rep.Warn("Vulnerability scan failed: %v", err)
	}
	vulnScanErr := vulnScanFailure(err, vulnScanned, vulnWarnings)
	for _, w := range vulnWarnings {
		rep.Warn("%s", w)
	}
	rep.Done("%d affected modules", len(vulns))

	rep.Stage("Checking maintenance health")
	maintScanner := scanner.NewMaintenanceScanner(timeout)
	maintScanner.ScanStart = scanStart
	maintenance, err := maintScanner.ScanAll(ctx, graph)
	var maintWarnings []string
	if err != nil {
		if opts.Offline {
			// The scorer emits the authoritative report warning for this.
			rep.Warn("%v", err)
		} else {
			// The wrapped error embeds the module proxy URL (a module path),
			// so it goes to the progress reporter only, not into the report.
			maintWarnings = append(maintWarnings,
				"maintenance lookups failed for some modules (module proxy unreachable or erroring) — see stderr for the underlying error")
			rep.Warn("Some maintenance checks failed: %v", err)
		}
	}
	rep.Done("")

	if opts.GithubToken == "" && !opts.Offline {
		// 60 unauthenticated req/hr ÷ ~3 API calls per dep ≈ 20 deps before truncation
		if n := scanner.CountGitHubDeps(graph); n > 20 {
			rep.Warn("found %d GitHub-hosted deps but GITHUB_TOKEN is unset — maintainer data may be truncated; see https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api", n)
		}
	}

	rep.Stage("Analyzing maintainers (GitHub API)")
	maintainerScanner := scanner.NewMaintainerScanner(timeout, opts.GithubToken)
	maintainerScanner.ScanStart = scanStart
	maintainers := maintainerScanner.ScanAll(ctx, graph)
	rep.Done("")

	rep.Stage("Detecting typosquats")
	typosquatScanner := scanner.NewTyposquatScanner()
	typosquats := typosquatScanner.ScanAll(ctx, graph)
	rep.Done("%d suspicious", len(typosquats))

	rep.Stage("Scoring resilience")
	resilienceScanner := scanner.NewResilienceScanner(timeout)
	resilienceScanner.ScanStart = scanStart
	resilience := resilienceScanner.ScanAll(ctx, graph, maintainers)
	rep.Done("")

	rep.Stage("Assessing AI-generation risk")
	aiGenScanner := scanner.NewAIGenScanner()
	aiGenScanner.ScanStart = scanStart
	aiGenRisks, aiGenWarnings := aiGenScanner.ScanAll(ctx, graph, maintainers, resilience)
	for _, w := range aiGenWarnings {
		rep.Warn("%s", w)
	}
	rep.Done("%d flagged", len(aiGenRisks))

	var trustIndex map[string]*scanner.TrustIndexEntry
	trustClient, err := scanner.NewTrustIndexClient(opts.TrustIndexURL, timeout, opts.TrustIndexAllowPrivate)
	if err != nil {
		return nil, fmt.Errorf("trust index: %w", err)
	}
	if trustClient != nil {
		rep.Stage("Querying Trust Index")
		var tiErr error
		trustIndex, tiErr = trustClient.LookupAll(ctx, graph)
		if tiErr != nil {
			rep.Warn("Trust Index lookup failed: %v", tiErr)
		}
		rep.Done("%d entries", len(trustIndex))
		scanner.EnrichMaintainersFromTrustIndex(maintainers, trustIndex)
	}

	rep.Stage("Computing risk scores")
	projectScore := scorer.ScoreAll(scorer.ScoreInput{
		Graph:         graph,
		Vulns:         vulns,
		Maintenance:   maintenance,
		Maintainers:   maintainers,
		Typosquats:    typosquats,
		Resilience:    resilience,
		AIGenRisks:    aiGenRisks,
		TrustIndex:    trustIndex,
		Integrity:     integrityClasses,
		PseudoVersion: pseudoVersionClasses,
		GoSumMismatch: integrityReport.GoSumVerified == scanner.GoSumVerifiedFalse,

		VulnScanUnavailable: vulnScanUnavailable,

		DebugMode: opts.DebugScoring,
		Now:       scanStart,
	})
	// Resolver degradations change the numbers, so they belong in the report.
	projectScore.Warnings = append(projectScore.Warnings, resolverWarnings...)
	projectScore.Warnings = append(projectScore.Warnings, vulnWarnings...)
	projectScore.Warnings = append(projectScore.Warnings, maintWarnings...)
	projectScore.Warnings = append(projectScore.Warnings, aiGenWarnings...)
	rep.Done("")

	var ciReport *scanner.CIReport
	if opts.ScanWorkflows || opts.ScanCI {
		rep.Stage("Auditing CI/CD pipelines")
		ciScanner := scanner.NewCIScanner()

		wfPath := opts.WorkflowPath
		if wfPath == "" {
			wfPath = ".github/workflows"
		}
		if !filepath.IsAbs(wfPath) {
			wfPath = filepath.Join(projectDir, wfPath)
		}

		ciReport, err = ciScanner.ScanWorkflows(ctx, wfPath)
		if err != nil {
			rep.Warn("Workflow scanning failed: %v", err)
		}

		if opts.ScanCI && ciReport != nil {
			buildFindings := ciScanner.ScanBuildFiles(ctx, projectDir)
			ciReport.BuildFindings = buildFindings
			ciReport.TotalFindings += len(buildFindings)
		}
		rep.Done("")
	}

	var takeovers []*scanner.MaintainerInfo
	for _, mi := range maintainers {
		if mi.TakeoverCandidate {
			takeovers = append(takeovers, mi)
		}
	}

	var stdlibVulns []scanner.Vulnerability
	if stdlibList, ok := vulns["stdlib"]; ok {
		stdlibVulns = stdlibList
		delete(vulns, "stdlib")
	}

	interrupted := ctx.Err() != nil
	if interrupted {
		rep.Warn("scan was interrupted — report may be incomplete (some scanners were cancelled)")
	}

	return &Result{
		GoMod:           gomod,
		Graph:           graph,
		ProjectScore:    projectScore,
		CIReport:        ciReport,
		Takeovers:       takeovers,
		StdlibVulns:     stdlibVulns,
		IntegrityReport: integrityReport,
		VulnScanErr:     vulnScanErr,
		Interrupted:     interrupted,
		Maintainers:     maintainers,
		Typosquats:      typosquats,
	}, nil
}

// vulnScanFailure reports whether a ScanVulns outcome means the vulnerability
// scan did not complete: it returned an error, or it reports itself as not
// having run (the scanner downgrades govulncheck failures to a warning and
// carries on with an empty result).
func vulnScanFailure(err error, scanned bool, warnings []string) error {
	if err != nil {
		return err
	}
	if scanned {
		return nil
	}
	for _, w := range warnings {
		line, _, _ := strings.Cut(w, "\n")
		return errors.New(line)
	}
	return errors.New("vulnerability scan did not run")
}
