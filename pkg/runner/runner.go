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
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/unidoc/unisupply/internal/safego"
	"github.com/unidoc/unisupply/pkg/grade"
	"github.com/unidoc/unisupply/pkg/offline"
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

	// Timeout bounds each outbound HTTP request of the scanners (Go Module Proxy,
	// GitHub API, Trust Index), one request at a time. It is never the scan's
	// limit: pass that as the deadline of the context given to Run. A scan limit
	// passed here lets one stalled request use the whole scan time, and a request
	// still ends at the context's deadline when that comes first. Zero means the
	// scanners' own default.
	//
	// Two things are bounded only by the context: govulncheck's own fetch of the
	// vulnerability database (it uses http.DefaultClient) and the module
	// downloads of the go command.
	Timeout time.Duration

	DirectOnly bool

	GithubToken string

	// NVDAPIKey is sent as the apiKey header to services.nvd.nist.gov only,
	// raising the rate limit of the CVE severity fallback. Empty means
	// unauthenticated. It is never written to reports, logs or the cache.
	NVDAPIKey string

	// RequireGithubToken makes Run fail with an error wrapping
	// ErrGithubTokenPrecondition when GithubToken is empty, rejected by GitHub
	// (401), or cannot be validated (network error, or any status other than
	// 200 and 401). Without it, a rejected token is dropped and the scan runs
	// unauthenticated (see Result.GithubTokenRejected), and a token that
	// cannot be validated is used as is; both add a report warning. Offline,
	// the token is never probed.
	RequireGithubToken bool

	TrustIndexURL          string
	TrustIndexAllowPrivate bool

	ScanWorkflows bool
	ScanCI        bool
	// WorkflowPath defaults to ".github/workflows" (relative to the
	// project directory) if empty, matching the CLI's own default.
	WorkflowPath string

	// StrictArchivedStatus makes an archived flag that could not be read (GitHub's 60 unauthenticated requests an hour) make the
	// grade Pending when it could change the letter. By default the grade is given on what is known, with a note: an archived
	// dependency adds at most 20 to its row, so the letter may be one band better than it would be with the flag. A service
	// that publishes letters (gorisk) sets it: a letter without the data is not published.
	StrictArchivedStatus bool

	// GradeStdlib grades the Go standard library as a row named "stdlib". It is off by default, as in the agreed
	// grading rules: the standard library's advisories are always listed in Result.StdlibVulns (with the Go release they
	// were matched against), but they decide the letter only when this is set. They follow the Go toolchain the scan runs
	// with, which is not necessarily the one the project is built with, so the same project can grade differently on
	// another machine.
	GradeStdlib bool

	// SelfVersion is the version of the module being scanned, as published (a tag such as v1.4.0). It lets the grade
	// look up the module's own advisories (OSV) and its own archived/deprecated status. Empty means the module is not
	// assessed as a published module: the grade then covers its dependencies only, and says so.
	SelfVersion string

	// ResponseHistory turns on the fix-response-history lookup (extra module proxy and OSV requests): how fast the
	// project has adopted its dependencies' fixes in the past. Needs SelfVersion. Off by default.
	ResponseHistory bool

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
// options that reference CIReport).
type Result struct {
	GoMod        *parser.GoMod
	Graph        *resolver.Graph
	ProjectScore *scorer.ProjectScore

	// Grade is the Grading v2 result: the letter, the row that decides it and the evidence behind every row. It is the
	// published grade; ProjectScore is the scorer's internal measure and is no longer what a report headlines.
	Grade *grade.Result

	// CIReport is nil unless Options.ScanWorkflows or Options.ScanCI was set.
	CIReport *scanner.CIReport
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
	// "no vulnerabilities". A module with no dependencies still runs govulncheck
	// (the standard library is part of every build), so it can fail there too;
	// IntegrityReport.GoSumVerified is empty on that path, as there is no go.sum to verify.
	VulnScanErr error
	// ScanInfo is what the vulnerability scan ran with: platform, Go version,
	// govulncheck and vulnerability-database versions. Nil when no scan ran
	// (offline mode). Fields govulncheck did not report are empty.
	ScanInfo *scanner.ScanInfo
	// KEVStaleSince is the date of the CISA KEV catalog copy used when the
	// catalog could not be refreshed. Zero when the catalog was fresh or
	// unavailable.
	KEVStaleSince time.Time
	// Interrupted is true when the context ended before every scanner finished,
	// so the report may be incomplete.
	Interrupted bool

	// GithubTokenRejected is true when GitHub answered 401 to
	// Options.GithubToken and the scanners ran without a token. The report
	// warnings say so too.
	GithubTokenRejected bool

	// Maintainers and Typosquats are the raw per-module scanner outputs
	// (keyed by module path) — ProjectScore folds their signal into each
	// DependencyScore, but callers doing their own policy evaluation (see
	// pkg/policy.EvalInput, which cmd/unisupply's CLI feeds these into
	// directly) need the maps themselves, not just the derived score.
	Maintainers map[string]*scanner.MaintainerInfo
	Typosquats  map[string]*scanner.TyposquatResult
}

// scanVulns is the vulnerability scan; tests replace it.
var scanVulns = scanner.ScanVulnsWithOptions

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
//
// A panic on Run's own goroutine, or in one of unisupply's worker goroutines (their panics are carried back to this
// goroutine), fails the scan: Run returns a nil Result and a *scanner.ScanError with Reason internal_panic whose Err
// is the panic value and the stack of the goroutine it happened in. It does not catch panics inside govulncheck's own
// goroutines, fatal runtime errors such as "concurrent map writes", or the process being killed (out of memory): a
// caller that must survive those has to do so itself.
func Run(ctx context.Context, opts Options) (res *Result, runErr error) {
	defer func() {
		if r := recover(); r != nil {
			res, runErr = nil, panicScanError(r)
		}
	}()
	// Timeout is passed through unchanged: the scanner clients map 0 to their
	// own default, exactly as the CLI's --timeout 0 always has.
	timeout := opts.Timeout
	scanStart := opts.Now
	if scanStart.IsZero() {
		scanStart = time.Now().UTC().Truncate(24 * time.Hour)
	}

	rep := progress.From(ctx)
	// Offline mode is process-wide (pkg/offline swaps http.DefaultTransport), so
	// read the same switch the vulnerability scanner, resolver and scorer read.
	// A caller that wants an offline scan calls offline.Enable() before Run.
	offlineMode := offline.Enabled()

	if opts.RequireGithubToken && opts.GithubToken == "" {
		return nil, fmt.Errorf("%w: no GitHub token was provided", ErrGithubTokenPrecondition)
	}

	rep.Stage("Parsing go.mod")
	gomodPath, err := parser.FindGoMod(opts.Path)
	if err != nil {
		return nil, &scanner.ScanError{Kind: scanner.FailPermanent, Reason: scanner.ReasonNoGoMod, Err: err}
	}
	gomod, err := parser.ParseGoMod(gomodPath)
	if err != nil {
		return nil, &scanner.ScanError{Kind: scanner.FailPermanent, Reason: scanner.ReasonUnknown, Err: err}
	}
	projectDir := filepath.Dir(gomodPath)
	rep.Done("%s", gomodPath)

	// Audit replace/exclude directives (pure go.mod analysis, no network).
	rep.Stage("Auditing go.mod directives")
	integrityScanner := scanner.NewIntegrityScanner()
	integrityScanner.Offline = offlineMode
	integrityReport, integrityClasses := integrityScanner.ScanDirectives(gomod)
	rep.Done("%d replace, %d exclude (%d redirect)", integrityReport.ReplaceCount, integrityReport.ExcludeCount, integrityReport.RedirectCount)

	rep.Stage("Resolving dependency graph")
	graph, resolverWarnings, err := resolver.Resolve(ctx, gomodPath, opts.DirectOnly)
	if err != nil {
		return nil, scanner.WrapScanFailure(fmt.Errorf("resolving dependencies: %w", err), ctx.Err())
	}
	for _, w := range resolverWarnings {
		rep.Warn("%s", w)
	}
	for _, n := range graph.Notes {
		rep.Step("%s", n)
	}
	rep.Done("%d modules", len(graph.Dependencies))

	// Validate the token after Resolve, so a bad path or an empty project
	// reports its own error first, and before any scanner is constructed,
	// since a rejected token is cleared and the scanners below must get the
	// cleared value. An empty graph uses no token, so it is only probed when
	// the caller made a valid token a precondition.
	tokenStatus := tokenCheck{token: opts.GithubToken}
	if len(graph.Dependencies) > 0 || opts.RequireGithubToken || opts.SelfVersion != "" {
		tokenStatus, err = checkGitHubToken(ctx, opts.GithubToken, opts.RequireGithubToken, offlineMode, timeout)
		if err != nil {
			return nil, err
		}
	}
	githubToken := tokenStatus.token

	if len(graph.Dependencies) == 0 {
		// No dependency means no per-dependency scanner has anything to do, but the standard library is part of every
		// build: govulncheck still runs, and its standard-library advisories are listed (with the Go release they were
		// matched against and the scan block). They decide the letter only when the caller grades the standard library
		// (Options.GradeStdlib). A scan that failed is Pending only then; otherwise it is a warning and the letter is the
		// module's own row.
		rep.Stage("Scanning vulnerabilities (govulncheck)")
		var scanInfo scanner.ScanInfo
		vulns, vulnWarnings, vulnScanned, verr := scanVulns(ctx, projectDir, scanner.VulnScanOptions{GitHubToken: githubToken, NVDAPIKey: opts.NVDAPIKey, Info: &scanInfo})
		if verr != nil && !saidByWarnings(vulnWarnings, verr) {
			rep.Warn("Vulnerability scan failed: %s", errString(verr))
		}
		emptyVulnErr := vulnScanFailure(verr, vulnScanned, vulnWarnings)
		for _, w := range vulnWarnings {
			rep.Warn("%s", w)
		}
		rep.Done("%d standard library advisories", len(vulns["stdlib"]))
		resolveAllFixDates(ctx, scanner.FixDateOptions{Timeout: timeout, Now: func() time.Time { return scanStart }}, fixDateStageTimeout, vulns)
		stdlibVulns := takeStdlibVulns(vulns)

		// scorer.ScoreAll (not a hand-built zero value) still computes ProjectScore, so its shape matches exactly what a
		// real empty-graph score looks like.
		projectScore := scorer.ScoreAll(scorer.ScoreInput{
			Graph:               graph,
			Now:                 scanStart,
			VulnScanUnavailable: opts.GradeStdlib && emptyVulnErr != nil,
		})
		if emptyVulnErr != nil {
			// not graded (no --grade-stdlib): the failed scan is said, but the letter is the module's own row
			projectScore.Warnings = appendScanFailure(projectScore.Warnings, vulnWarnings, emptyVulnErr)
		}
		// a failed scan is a missing check only when its result takes part in the grade
		scanMissing := emptyVulnErr
		if !opts.GradeStdlib {
			scanMissing = nil
		}
		g := gradeAll(ctx, &gradeRun{
			Opts: opts, GoMod: gomod, Graph: graph, Integrity: integrityReport, Token: githubToken,
			Timeout: timeout, ScanStart: scanStart, ProjectDir: projectDir,
			Stdlib:      gradedStdlib(&opts, stdlibVulns),
			VulnScanned: scanMissing == nil, VulnScanReason: errString(scanMissing), StdlibScanned: emptyVulnErr == nil,
			KEVStaleSince: kevStaleSince(&scanInfo),
		})
		return &Result{GoMod: gomod, Graph: graph, ProjectScore: projectScore, Grade: g, IntegrityReport: integrityReport,
			StdlibVulns: stdlibVulns, VulnScanErr: emptyVulnErr,
			ScanInfo: scanInfoPtr(&scanInfo), KEVStaleSince: kevStaleSince(&scanInfo)}, nil
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
	var scanInfo scanner.ScanInfo
	vulns, vulnWarnings, vulnScanned, err := scanVulns(ctx, projectDir, scanner.VulnScanOptions{GitHubToken: githubToken, NVDAPIKey: opts.NVDAPIKey, Info: &scanInfo})
	// The scanner reports availability directly: a scan that did not run must
	// not read as clean, whether it came back with an error or only a warning.
	vulnScanUnavailable := !vulnScanned
	if err != nil && !saidByWarnings(vulnWarnings, err) {
		rep.Warn("Vulnerability scan failed: %s", errString(err))
	}
	vulnScanErr := vulnScanFailure(err, vulnScanned, vulnWarnings)
	for _, w := range vulnWarnings {
		rep.Warn("%s", w)
	}
	rep.Done("%d affected modules", len(vulns))

	// The date each fix was released (from the module proxy), so a finding can say whether it is inside the response
	// window. Best effort: a failed lookup leaves the advisory's own date, or none.
	resolveAllFixDates(ctx, scanner.FixDateOptions{Timeout: timeout, Now: func() time.Time { return scanStart }}, fixDateStageTimeout, vulns)

	rep.Stage("Checking maintenance health")
	maintScanner := scanner.NewMaintenanceScanner(timeout)
	maintScanner.ScanStart = scanStart
	maintenance, err := maintScanner.ScanAll(ctx, graph)
	var maintWarnings []string
	if err != nil {
		if offlineMode {
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

	if githubToken == "" && !offlineMode {
		// 60 unauthenticated req/hr ÷ ~3 API calls per dep ≈ 20 deps before truncation
		if n := scanner.CountGitHubDeps(graph); n > 20 {
			// A rejected token was cleared above, so the token is empty here
			// too; "unset" would tell that user to set a token they did set.
			reason := "GITHUB_TOKEN is unset"
			if tokenStatus.rejected {
				reason = "the GitHub token was rejected (401)"
			}
			rep.Warn("found %d GitHub-hosted deps but %s — maintainer data may be truncated; see https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api", n, reason)
		}
	}

	rep.Stage("Analyzing maintainers (GitHub API)")
	maintainerScanner := scanner.NewMaintainerScanner(timeout, githubToken)
	maintainerScanner.ScanStart = scanStart
	maintainerScanner.TokenRejected = tokenStatus.rejected
	maintainers := maintainerScanner.ScanAll(ctx, graph)
	rep.Done("")

	// Archived status comes from the repository each module is published from, so it needs the maintainer scan's
	// repository cache and runs before the activity scan (which skips archived modules).
	if err := maintScanner.ScanArchived(ctx, maintenance, maintainerScanner); err != nil {
		maintWarnings = append(maintWarnings, err.Error())
		rep.Warn("%v", err)
	}

	// Activity reads the default branch the maintainer scan found, so it runs
	// after it.
	rep.Stage("Checking default-branch activity")
	commitFallback := activityFallback(githubToken, offlineMode, maintainerScanner)
	if err := maintScanner.ScanActivity(ctx, graph, maintenance, maintainers, commitFallback); err != nil {
		maintWarnings = append(maintWarnings, err.Error())
		rep.Warn("%v", err)
	}
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
		TrustIndex:    trustIndex,
		Integrity:     integrityClasses,
		PseudoVersion: pseudoVersionClasses,
		GoSumMismatch: integrityReport.GoSumVerified == scanner.GoSumVerifiedFalse,

		VulnScanUnavailable: vulnScanUnavailable,

		Now: scanStart,
	})
	// Resolver degradations change the numbers, so they belong in the report.
	// So does the token outcome: under --progress none, or for a library
	// caller with no reporter, the report is the only place it shows.
	if tokenStatus.warning != "" {
		projectScore.Warnings = append(projectScore.Warnings, tokenStatus.warning)
	}
	projectScore.Warnings = append(projectScore.Warnings, resolverWarnings...)
	projectScore.Warnings = appendScanFailure(projectScore.Warnings, vulnWarnings, vulnScanErr)
	projectScore.Warnings = append(projectScore.Warnings, maintWarnings...)
	// Resolver notes are informational and kept apart from the warnings, so a
	// report does not present them as a limitation of the results.
	projectScore.Notes = append(projectScore.Notes, graph.Notes...)
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

	stdlibVulns := takeStdlibVulns(vulns)

	interrupted := ctx.Err() != nil
	if interrupted {
		rep.Warn("scan was interrupted — report may be incomplete (some scanners were cancelled)")
	}

	gradeResult := gradeAll(ctx, &gradeRun{
		Opts: opts, GoMod: gomod, Graph: graph, Integrity: integrityReport, Token: githubToken,
		Timeout: timeout, ScanStart: scanStart,
		ProjectDir: projectDir,
		Vulns:      vulns, Stdlib: gradedStdlib(&opts, stdlibVulns), Maintenance: maintenance,
		VulnScanned: vulnScanErr == nil, VulnScanReason: errString(vulnScanErr), Interrupted: interrupted,
		StdlibScanned: vulnScanErr == nil, TokenMissing: githubToken == "", KEVStaleSince: kevStaleSince(&scanInfo),
	})

	return &Result{
		GoMod:           gomod,
		Graph:           graph,
		ProjectScore:    projectScore,
		Grade:           gradeResult,
		CIReport:        ciReport,
		StdlibVulns:     stdlibVulns,
		IntegrityReport: integrityReport,
		VulnScanErr:     vulnScanErr,
		ScanInfo:        scanInfoPtr(&scanInfo),
		KEVStaleSince:   kevStaleSince(&scanInfo),
		Interrupted:     interrupted,

		GithubTokenRejected: tokenStatus.rejected,
		Maintainers:         maintainers,
		Typosquats:          typosquats,
	}, nil
}

// panicScanError is the failure for a recovered panic. A panic from a worker goroutine arrives as a *safego.Panic that
// has its own stack, which is the one that shows where it happened; the stack of this goroutine would only show Run.
// The text is not cut to a tail: the top frames are the ones that matter.
func panicScanError(r any) *scanner.ScanError {
	p, ok := r.(*safego.Panic)
	if !ok {
		p = &safego.Panic{Value: r, Stack: debug.Stack()}
	}
	return &scanner.ScanError{Kind: scanner.FailPermanent, Reason: scanner.ReasonInternalPanic, Err: errors.New(p.Error())}
}

// activityFallback returns the GitHub commits lookup the activity scan may ask
// when the module proxy cannot answer. It is offered only with a token, since
// the unauthenticated quota belongs to the maintainer scan, and never offline.
func activityFallback(githubToken string, offlineMode bool, maintainers *scanner.MaintainerScanner) scanner.CommitLookup {
	if githubToken == "" || offlineMode {
		return nil
	}
	return maintainers
}

// vulnScanFailure reports whether a ScanVulns outcome means the vulnerability
// scan did not complete: it returned an error (a *scanner.ScanError, passed on
// as it is, with its whole cause), or it reports itself as not having run
// without one (offline mode skips the scan with a warning, and tests stub it):
// the fallback then is the first line of its first warning.
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

// appendScanFailure adds the scanner's warnings to the report warnings, and the text of the failure itself when no
// warning carries it: a refused toolchain check is an error, not a warning, and would otherwise reach stderr only.
func appendScanFailure(dst, warnings []string, failure error) []string {
	dst = append(dst, warnings...)
	if failure == nil || saidByWarnings(warnings, failure) {
		return dst
	}
	return append(dst, "Vulnerability scan failed: "+errString(failure))
}

// saidByWarnings reports whether one of the scanner's warnings already carries the text of failure: a package-loading
// failure comes back both as the error and as a warning, and is said once.
func saidByWarnings(warnings []string, failure error) bool {
	line := errString(failure)
	// A scan error's summary is not the first line of its warning, but its detail line is somewhere in it.
	var se *scanner.ScanError
	detail := line
	if errors.As(failure, &se) {
		detail = strings.TrimPrefix(line, se.Reason+": ")
	}
	for _, w := range warnings {
		if first, _, _ := strings.Cut(w, "\n"); first == line || (detail != line && strings.Contains(w, detail)) {
			return true
		}
	}
	return false
}

// takeStdlibVulns removes the Go standard library's vulnerabilities from vulns
// and returns them, or nil when there are none. They are sorted by ID so that
// the text, JSON and PDF reports share one deterministic order instead of
// govulncheck's finding order.
func takeStdlibVulns(vulns map[string][]scanner.Vulnerability) []scanner.Vulnerability {
	list, ok := vulns["stdlib"]
	if !ok {
		return nil
	}
	delete(vulns, "stdlib")
	slices.SortStableFunc(list, func(a, b scanner.Vulnerability) int {
		return strings.Compare(a.ID, b.ID)
	})
	return list
}

// fixDateStageTimeout bounds the whole fix-date stage, all modules together. The
// stage is best effort, so a slow or stalled proxy must not hold the scan for
// the per-module timeout times the number of affected modules.
const fixDateStageTimeout = 60 * time.Second

// resolveAllFixDates resolves the fix-release dates of every module's findings
// under one shared deadline of stage. Lookups still pending at the deadline
// leave their findings on the advisory date. Modules are visited in sorted
// order so the outcome does not depend on map order.
func resolveAllFixDates(ctx context.Context, opts scanner.FixDateOptions, stage time.Duration, vulns map[string][]scanner.Vulnerability) {
	ctx, cancel := context.WithTimeout(ctx, stage)
	defer cancel()
	paths := make([]string, 0, len(vulns))
	for path := range vulns {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		// Past the deadline the calls still run, instantly and without a
		// request, so each finding falls back to its advisory date.
		if path == stdlibModule {
			scanner.ResolveStdlibFixDates(ctx, opts, vulns[path])
		} else {
			scanner.ResolveFixDates(ctx, opts, path, vulns[path])
			// the Go release each fix needs, so the report can say when taking it raises the module's minimum Go
			scanner.ResolveFixGoRequirements(ctx, opts, path, vulns[path])
		}
	}
}

// scanInfoPtr is info when a scan started (Platform is set as it starts), else nil.
func scanInfoPtr(info *scanner.ScanInfo) *scanner.ScanInfo {
	if info.Platform == "" {
		return nil
	}
	return info
}

// kevStaleSince is the stale KEV catalog date recorded in info, or the zero time.
func kevStaleSince(info *scanner.ScanInfo) time.Time {
	if info.KEVStaleSince == nil {
		return time.Time{}
	}
	return *info.KEVStaleSince
}
