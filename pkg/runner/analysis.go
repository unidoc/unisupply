package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/unidoc/unisupply/internal/version"
	"github.com/unidoc/unisupply/pkg/offline"
	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/progress"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/vulndb"
)

// AnalysisSchemaVersion is the version of the Analysis JSON. It changes when a stored analysis can no longer be read by the
// code that grades it; a reader that finds another value must analyse again.
const AnalysisSchemaVersion = 1

// Analysis is what unisupply learns from a module's code and nothing that depends on the day: the build list with how each
// module is reached, the requirement graph, the integrity audit of go.mod and go.sum, and govulncheck's findings with their
// tiers (called, imported, graph-only), call paths and the severity and known-exploited status they had at AnalysedAt.
// It is JSON-serialisable and meant to be stored: Grade turns it into a Result using the facts and the date of the day it
// is graded, so one analysis serves every daily grade until something in its Identity changes.
//
// An analysis whose VulnScan did not run, or that was Interrupted, is not final; Complete says so.
type Analysis struct {
	SchemaVersion int `json:"schema_version"`
	// Identity is everything the analysis depends on; Identity.Key() is its key in a store.
	Identity Identity `json:"identity"`
	// AnalysedAt is when the analysis was made.
	AnalysedAt time.Time `json:"analysed_at"`

	// GoMod is the parsed go.mod of the analysed module, Graph its build list and requirement graph (Graph.Edges lists the
	// edges) with the test-only, in-build and platform classification of each module.
	GoMod            *parser.GoMod            `json:"go_mod"`
	Graph            *resolver.Graph          `json:"graph"`
	ResolverWarnings []string                 `json:"resolver_warnings,omitempty"`
	Integrity        *scanner.IntegrityReport `json:"integrity,omitempty"`
	// IntegrityClasses and PseudoVersionClasses are the severities of the replace directives and pseudo-version pins by module.
	IntegrityClasses     map[string]scanner.IntegrityRiskLevel `json:"integrity_classes,omitempty"`
	PseudoVersionClasses map[string]scanner.IntegrityRiskLevel `json:"pseudo_version_classes,omitempty"`

	// Vulns are govulncheck's findings by module path, with the standard library's under "stdlib". Reachability is "called",
	// "imported" or "required" (graph-only); CallPath and CallTrace are set for called findings. When Scan.CalledPass is
	// "skipped", every reached finding is "imported" and none has a call path.
	Vulns        map[string][]scanner.Vulnerability `json:"vulnerabilities,omitempty"`
	VulnWarnings []string                           `json:"vulnerability_warnings,omitempty"`
	// VulnScan says whether the vulnerability scan ran, and why not when it did not.
	VulnScan VulnScanOutcome `json:"vulnerability_scan"`
	// Scan is what the scan ran with (platform, Go, govulncheck, database, called pass); nil when no scan ran.
	Scan *scanner.ScanInfo `json:"scan,omitempty"`
	// ToolchainVersion is the Go release the standard library was matched against, as the go command reports it in the
	// module's directory ("go1.26.9"); empty when it could not be read.
	ToolchainVersion string `json:"toolchain_version,omitempty"`

	// CI is the CI/CD audit, present when workflows or CI scanning were asked for. It reads the module's files, so it is part
	// of the analysis.
	CI *scanner.CIReport `json:"ci_cd_assessment,omitempty"`

	// Interrupted is true when the context ended before the analysis finished.
	Interrupted bool `json:"interrupted,omitempty"`
}

// Identity is what an analysis depends on: when none of it has changed, a stored analysis is still the analysis. The code
// of a published module version never changes, so the module version (or the commit, for a tree that has no release) and the
// hash of go.mod and go.sum say whether the build list is the same. The Go release, govulncheck and unisupply decide how the
// code is analysed, and the advisory fingerprint says whether the advisories that apply to the build list are the same.
type Identity struct {
	Module string `json:"module"`
	// Version is the published version of the module (Options.SelfVersion), Commit the commit of the analysed tree
	// (Options.Commit). Either may be empty; a tree with neither is identified by its go.mod and go.sum alone.
	Version string `json:"version,omitempty"`
	Commit  string `json:"commit,omitempty"`
	// GoModHash and GoSumHash are the SHA-256 of the files; GoSumHash is "none" when the module has no go.sum.
	GoModHash string `json:"go_mod_hash"`
	GoSumHash string `json:"go_sum_hash"`
	// GoVersion is the Go release the scan ran with, GovulncheckVersion the golang.org/x/vuln it ran, UnisupplyVersion this
	// library's version.
	GoVersion          string `json:"go_version,omitempty"`
	GovulncheckVersion string `json:"govulncheck_version,omitempty"`
	UnisupplyVersion   string `json:"unisupply_version"`
	// CalledPass and DirectOnly are the settings that change what the analysis contains.
	CalledPass string `json:"called_pass"`
	DirectOnly bool   `json:"direct_only,omitempty"`
	// AdvisoryFingerprint is vulndb.Index.Fingerprint of the build list and the standard library at AnalysedAt: it changes
	// when an advisory for any of those modules is added, changed or removed. Empty when the index could not be read (or the
	// analysis was made by Run, which does not ask for it): Key then cannot tell advisory changes apart.
	AdvisoryFingerprint string `json:"advisory_fingerprint,omitempty"`
	// AdvisoryDBModified is the vulnerability database's last-modified time as govulncheck read it. It is not part of the key.
	AdvisoryDBModified string `json:"advisory_db_modified,omitempty"`
}

// Key is the identity as one string: the hex SHA-256 of every field that decides what the analysis contains. Two analyses with
// the same key are interchangeable.
func (i Identity) Key() string {
	h := sha256.New()
	for _, f := range []string{
		"unisupply-analysis-v1", i.Module, i.Version, i.Commit, i.GoModHash, i.GoSumHash, i.GoVersion, i.GovulncheckVersion,
		i.UnisupplyVersion, i.CalledPass, fmt.Sprint(i.DirectOnly), i.AdvisoryFingerprint,
	} {
		fmt.Fprintf(h, "%d:%s\n", len(f), f)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// VulnScanOutcome is whether the vulnerability scan ran, in a form that survives storage.
type VulnScanOutcome struct {
	// Scanned is true when govulncheck ran to the end.
	Scanned bool `json:"scanned"`
	// Reason, Kind and Error describe a scan that did not complete: the stable reason code (scanner.Reason*), whether a
	// retry can help ("transient", "permanent", "too_large"), and the whole text of the failure. All empty when it ran.
	Reason string `json:"reason,omitempty"`
	Kind   string `json:"kind,omitempty"`
	Error  string `json:"error,omitempty"`
}

// err is the failure as an error again: a *scanner.ScanError when it had a reason.
func (o VulnScanOutcome) err() error {
	if o.Error == "" && o.Reason == "" {
		return nil
	}
	if o.Reason == "" {
		return errors.New(o.Error)
	}
	var inner error
	if o.Error != "" {
		inner = errors.New(strings.TrimPrefix(o.Error, o.Reason+": "))
	}
	return &scanner.ScanError{Kind: failKind(o.Kind), Reason: o.Reason, Err: inner}
}

func failKind(s string) scanner.FailKind {
	switch s {
	case "transient":
		return scanner.FailTransient
	case "too_large":
		return scanner.FailTooLarge
	}
	return scanner.FailPermanent
}

func vulnOutcomeOf(scanned bool, err error) VulnScanOutcome {
	o := VulnScanOutcome{Scanned: scanned}
	if err == nil {
		return o
	}
	o.Error = err.Error()
	var se *scanner.ScanError
	if errors.As(err, &se) {
		o.Reason, o.Kind = se.Reason, se.Kind.String()
	}
	return o
}

// Complete reports whether the analysis can be stored as final: the vulnerability scan ran and nothing cut it short. An
// analysis that is not complete can still be graded (the grade is then Pending or says why), but a store should not keep
// it, because running again may give a whole one.
func (a *Analysis) Complete() bool {
	return a != nil && a.VulnScan.Scanned && a.VulnScan.err() == nil && !a.Interrupted
}

// Status is the machine-readable state of the analysis alone: "complete", "interrupted" or "failed". Whether the grade is
// pending is known only once it is graded (Result.ScanStatus).
func (a *Analysis) Status() scanner.ScanStatus {
	if a == nil {
		return scanner.ScanStatus{Status: scanner.StatusFailed, Reason: scanner.ReasonUnknown, Detail: "no analysis"}
	}
	in := scanner.StatusInput{VulnErr: a.VulnScan.err(), Interrupted: a.Interrupted, Graded: true}
	if !a.VulnScan.Scanned || in.VulnErr != nil {
		in.PendingCheck = "vulnerability_scan"
	}
	return scanner.ScanStatusOf(in)
}

// analysisState is what Run carries from the analysis to the grade in the same process, so it does not look up again what
// it just learned: the outcome of the GitHub token probe, the scan's real error, and the scan date.
type analysisState struct {
	token     tokenCheck
	vulnErr   error
	scanStart time.Time
}

// fetchVulnIndex reads the vulnerability database's module index; tests replace it.
var fetchVulnIndex = func(ctx context.Context, timeout time.Duration) (*vulndb.Index, error) {
	return (&vulndb.Client{Timeout: timeout}).FetchIndex(ctx)
}

// Analyse analyses the module at opts.Path: everything that does not depend on today's date. See Analysis. Of the options it
// reads Path, DirectOnly, Timeout, GithubToken and NVDAPIKey (the severity lookups), RequireGithubToken, ScanWorkflows,
// ScanCI and WorkflowPath, CalledPass, Now (the clock the analysis is made at), SelfVersion and Commit (the identity).
//
// Like Run, it fails (nil Analysis) only when nothing can be said: no go.mod, the dependency graph cannot be resolved, a
// panic. A vulnerability scan that fails is recorded in Analysis.VulnScan, and the error is a *scanner.ScanError when the
// cause is known. Progress events go through progress.From(ctx).
//
//nolint:gocritic // public API: Options is passed by value, as Run takes it
func Analyse(ctx context.Context, opts Options) (an *Analysis, err error) {
	defer func() {
		if r := recover(); r != nil {
			an, err = nil, panicScanError(r)
		}
	}()
	an, _, err = analyse(ctx, &opts, true)
	return an, err
}

// analyse is Analyse and the state Run reuses. withIndex asks for the advisory fingerprint (one request to vuln.go.dev).
func analyse(ctx context.Context, opts *Options, withIndex bool) (*Analysis, *analysisState, error) {
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
		return nil, nil, fmt.Errorf("%w: no GitHub token was provided", ErrGithubTokenPrecondition)
	}

	rep.Stage("Parsing go.mod")
	gomodPath, err := parser.FindGoMod(opts.Path)
	if err != nil {
		return nil, nil, &scanner.ScanError{Kind: scanner.FailPermanent, Reason: scanner.ReasonNoGoMod, Err: err}
	}
	gomod, err := parser.ParseGoMod(gomodPath)
	if err != nil {
		return nil, nil, &scanner.ScanError{Kind: scanner.FailPermanent, Reason: scanner.ReasonUnknown, Err: err}
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
		// Resolve fails only when go.mod cannot be read, and it was just read above. The package errors of go list
		// ("build constraints exclude all Go files in ...") come back as a note, so build_constraints and cgo_dependency
		// are decided by the vulnerability scan alone.
		return nil, nil, scanner.WrapScanFailure(fmt.Errorf("resolving dependencies: %w", err), ctx.Err(), projectDir)
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
			return nil, nil, err
		}
	}
	githubToken := tokenStatus.token

	an := &Analysis{
		SchemaVersion: AnalysisSchemaVersion, AnalysedAt: time.Now().UTC(),
		GoMod: gomod, Graph: graph, ResolverWarnings: resolverWarnings,
		Integrity: integrityReport, IntegrityClasses: integrityClasses,
	}
	if !opts.Now.IsZero() {
		an.AnalysedAt = opts.Now
	}
	st := &analysisState{token: tokenStatus, scanStart: scanStart}
	var scanInfo scanner.ScanInfo

	if len(graph.Dependencies) == 0 {
		// No dependency means no per-dependency scanner has anything to do, but the standard library is part of every
		// build: govulncheck still runs, and its standard-library advisories are listed (with the Go release they were
		// matched against and the scan block). They decide the letter only when the caller grades the standard library
		// (Options.GradeStdlib). A scan that failed is Pending only then; otherwise it is a warning and the letter is the
		// module's own row.
		rep.Stage("Scanning vulnerabilities (govulncheck)")
		vulns, vulnWarnings, vulnScanned, verr := scanVulns(ctx, projectDir, vulnScanOptions(opts, githubToken, &scanInfo))
		if verr != nil && !saidByWarnings(vulnWarnings, verr) {
			rep.Warn("Vulnerability scan failed: %s", errString(verr))
		}
		emptyVulnErr := vulnScanFailure(verr, vulnScanned, vulnWarnings)
		for _, w := range vulnWarnings {
			rep.Warn("%s", w)
		}
		rep.Done("%d standard library advisories", len(vulns["stdlib"]))
		an.Vulns, an.VulnWarnings = vulns, vulnWarnings
		an.VulnScan = vulnOutcomeOf(vulnScanned, emptyVulnErr)
		st.vulnErr = emptyVulnErr
	} else {
		// Pseudo-version audit needs the resolved graph (Direct/IsTestOnly).
		rep.Stage("Auditing pseudo-version pins")
		an.PseudoVersionClasses = integrityScanner.ScanPseudoVersions(graph, integrityReport)
		rep.Done("%d pseudo-version pins", integrityReport.PseudoVersionCount)

		rep.Stage("Verifying go.sum (go mod verify)")
		integrityScanner.ScanGoSum(gomodPath, gomod, graph, integrityReport)
		integrityScanner.VerifyGoSum(ctx, gomodPath, integrityReport)
		rep.Done("go.sum verify: %s", integrityReport.GoSumVerified)

		rep.Stage("Scanning vulnerabilities (govulncheck)")
		vulns, vulnWarnings, vulnScanned, err := scanVulns(ctx, projectDir, vulnScanOptions(opts, githubToken, &scanInfo))
		if err != nil && !saidByWarnings(vulnWarnings, err) {
			rep.Warn("Vulnerability scan failed: %s", errString(err))
		}
		vulnScanErr := vulnScanFailure(err, vulnScanned, vulnWarnings)
		for _, w := range vulnWarnings {
			rep.Warn("%s", w)
		}
		rep.Done("%d affected modules", len(vulns))
		an.Vulns, an.VulnWarnings = vulns, vulnWarnings
		an.VulnScan = vulnOutcomeOf(vulnScanned, vulnScanErr)
		st.vulnErr = vulnScanErr

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

			ciReport, err := ciScanner.ScanWorkflows(ctx, wfPath)
			if err != nil {
				rep.Warn("Workflow scanning failed: %v", err)
			}

			if opts.ScanCI && ciReport != nil {
				buildFindings := ciScanner.ScanBuildFiles(ctx, projectDir)
				ciReport.BuildFindings = buildFindings
				ciReport.TotalFindings += len(buildFindings)
			}
			an.CI = ciReport
			rep.Done("")
		}
		an.Interrupted = ctx.Err() != nil
	}
	an.Scan = scanInfoPtr(&scanInfo)
	an.ToolchainVersion = scanToolchainVersion(ctx, projectDir)
	if an.Scan != nil && an.Scan.GoVersion == "" {
		// govulncheck is given this release as its GOVERSION, so it is the one the standard library was matched against even
		// when its output (a scan that failed early, or an old govulncheck) does not say so
		an.Scan.GoVersion = an.ToolchainVersion
	}
	an.Identity = identityOf(ctx, opts, an, gomodPath, projectDir, withIndex)
	return an, st, nil
}

// identityOf fills the identity of a finished analysis.
func identityOf(ctx context.Context, opts *Options, an *Analysis, gomodPath, projectDir string, withIndex bool) Identity {
	mode := opts.CalledPass
	if mode == "" {
		mode = scanner.CalledPassAuto
	}
	id := Identity{
		Module: an.GoMod.ModulePath, Version: opts.SelfVersion, Commit: opts.Commit,
		GoModHash: fileHash(gomodPath), GoSumHash: fileHash(filepath.Join(projectDir, "go.sum")),
		GoVersion: an.ToolchainVersion, UnisupplyVersion: version.Version,
		CalledPass: string(mode), DirectOnly: opts.DirectOnly,
	}
	if an.Scan != nil {
		id.GovulncheckVersion, id.AdvisoryDBModified = an.Scan.GovulncheckVersion, an.Scan.VulnDBLastModified
		if an.Scan.GoVersion != "" {
			id.GoVersion = an.Scan.GoVersion
		}
	}
	if withIndex && !offline.Enabled() {
		// best effort: without the index the key cannot see advisory changes, and says so by leaving the fingerprint empty
		if idx, err := fetchVulnIndex(ctx, opts.Timeout); err == nil {
			mods := append(an.Graph.SortedPaths(), "stdlib")
			id.AdvisoryFingerprint = idx.Fingerprint(mods)
		}
	}
	return id
}

// fileHash is the hex SHA-256 of the file, or "none" when it cannot be read (a module without go.sum).
func fileHash(path string) string {
	data, err := os.ReadFile(path) //#nosec G304 -- the module's own go.mod and go.sum
	if err != nil {
		return "none"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// BuildListModules is the module paths of the analysis's build list, sorted: the keys to look up in vulndb.Index.ChangedSince
// to find out whether an advisory changed for it ("stdlib" is always affected by the Go release, and is added by the caller
// when it matters).
func (a *Analysis) BuildListModules() []string {
	if a == nil || a.Graph == nil {
		return nil
	}
	return slices.Clone(a.Graph.SortedPaths())
}
