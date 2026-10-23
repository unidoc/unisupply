// Package runner exposes unisupply's scan-and-score pipeline as a plain Go
// function, independent of the CLI. cmd/unisupply/main.go calls Run
// internally (it is the ONLY implementation of this pipeline — the CLI does
// not duplicate this logic), and any other Go program can import this
// package to run the same scan in-process, without shelling out to the
// unisupply binary. gorisk (UniDoc's continuous-scanning service) is the
// first such caller.
//
// Run is two steps that can also be called apart: Analyse does what depends on the module's code (the build list, the
// vulnerability scan) and returns an Analysis that can be stored, and Grade applies Grading v2 to it with the facts and the
// date of the day, so that one analysis serves a grade every day.
package runner

import (
	"context"
	"errors"
	"maps"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/unidoc/unisupply/internal/safego"
	"github.com/unidoc/unisupply/pkg/facts"
	"github.com/unidoc/unisupply/pkg/grade"
	"github.com/unidoc/unisupply/pkg/offline"
	"github.com/unidoc/unisupply/pkg/parser"
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

	// CalledPass is when govulncheck's called pass (which vulnerable functions the code reaches) runs. The zero value is
	// scanner.CalledPassAuto: the imported pass (which vulnerable packages it imports) runs first, and the called pass only
	// when grade.CalledPassCanChangeLetter says it can change the letter. Findings that skip it are reported as imported,
	// and Result.ScanInfo says the called pass was skipped and why. scanner.CalledPassAlways is the behaviour before the
	// imported pass existed; scanner.CalledPassNever runs the imported pass only.
	CalledPass scanner.CalledPassMode

	// Commit is the source commit of the tree being analysed, for a tree that is not a published version (Options.SelfVersion
	// is empty). It is only recorded, in Analysis.Identity: unisupply does not read it from git.
	Commit string

	// PrivatePatterns are the module path patterns of private modules, Go's GOPRIVATE syntax (comma-separated globs matched
	// with module.MatchPrefixPatterns): modules the customer owns. When it has any entry it replaces the environment (GOPRIVATE
	// and GONOPROXY, which are read when it is empty). A private module's path appears in no request to any host (module
	// proxy, GitHub, Trust Index, OSV) and no facts store call; its upkeep is not assessed, and it is marked private in the
	// grade. The go command's own downloads follow GOPRIVATE by themselves. The CLI flag is --private-modules.
	PrivatePatterns []string

	// Facts is the store Run and RunAnalysed read facts through when they grade (see Grade). Nil looks everything up. Analyse
	// does not read it.
	Facts facts.Store

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
	// ScanStatus is whether this result is final: complete, pending, interrupted or failed, with the stable reason code.
	// Pass it to report.JSONOptions.ScanStatus.
	ScanStatus scanner.ScanStatus
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
// Run is Analyse followed by Grade at the scan date, with the facts looked up as they always were: what depends on the code
// (the build list, the vulnerability scan) is analysed, and what depends on the day (maintenance status, fix dates, the
// grade) is graded. A caller that stores analyses calls the two itself.
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
	an, st, err := analyse(ctx, opts, false)
	if err != nil {
		return nil, err
	}
	return gradeAnalysis(ctx, an, st, opts.Facts, st.scanStart, opts)
}

// RunAnalysed is Run that also returns the Analysis it graded, made as Analyse makes it (the advisory fingerprint in its
// Identity included, which costs one request to vuln.go.dev). The Result is the one Run would give. The Analysis is returned
// whenever one was made, so it is non-nil next to a Result whose scan failed; on an error before an analysis exists both are nil.
func RunAnalysed(ctx context.Context, opts Options) (res *Result, an *Analysis, runErr error) {
	defer func() {
		if r := recover(); r != nil {
			res, an, runErr = nil, nil, panicScanError(r)
		}
	}()
	an, st, err := analyse(ctx, opts, true)
	if err != nil {
		return nil, nil, err
	}
	res, err = gradeAnalysis(ctx, an, st, opts.Facts, st.scanStart, opts)
	if err != nil {
		return nil, an, err
	}
	return res, an, nil
}

// scanStatusOf is the status of a finished Run. A vulnerability scan that failed is a failed scan even when the grade does
// not rest on it (a module with no dependencies and no --grade-stdlib still has a letter): the listing of its standard-library
// findings is missing, and the typed reason is what a caller wants to see.
//
// Offline mode skips the vulnerability scan on purpose (there is no database to read without the network), which is not a
// failure: the grade is Pending (vulnerability_scan) and the status is "pending".
func scanStatusOf(g *grade.Result, vulnErr error, interrupted bool) scanner.ScanStatus {
	var se *scanner.ScanError
	if offline.Enabled() && !errors.As(vulnErr, &se) {
		vulnErr = nil
	}
	in := scanner.StatusInput{VulnErr: vulnErr, Interrupted: interrupted, Graded: g != nil}
	if g != nil && g.Pending != nil {
		in.PendingCheck, in.PendingReason = g.Pending.Check, g.Pending.Reason
	}
	return scanner.ScanStatusOf(in)
}

// vulnScanOptions is what the vulnerability scan runs with: the credentials, the called-pass setting and the grading
// code's test for when the called pass can matter.
func vulnScanOptions(opts *Options, githubToken string, info *scanner.ScanInfo) scanner.VulnScanOptions {
	return scanner.VulnScanOptions{
		GitHubToken: githubToken, NVDAPIKey: opts.NVDAPIKey, Info: info,
		CalledPass: opts.CalledPass, NeedsCalledPass: calledPassTest(opts.GradeStdlib),
	}
}

// calledPassTest is grade.CalledPassCanChangeLetter for this scan. The standard library's findings are listed but not graded
// unless the caller grades them (Options.GradeStdlib), so they cannot change the letter and are left out of the test; the
// reason says so when they were there, because they are then shown as imported.
func calledPassTest(gradeStdlib bool) scanner.NeedsCalledPassFunc {
	return func(found map[string][]scanner.Vulnerability) (bool, string) {
		listed := len(found[stdlibModule]) > 0
		if !gradeStdlib && listed {
			found = maps.Clone(found)
			delete(found, stdlibModule)
		}
		needed, reason := grade.CalledPassCanChangeLetter(found)
		if !needed && !gradeStdlib && listed {
			reason += "; the standard library's advisories are listed, not graded, and are shown as imported"
		}
		return needed, reason
	}
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
