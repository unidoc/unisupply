package runner

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/unidoc/unisupply/pkg/facts"
	"github.com/unidoc/unisupply/pkg/offline"
	"github.com/unidoc/unisupply/pkg/progress"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// Grade applies Grading v2 to an analysis with the facts and the date of the day it is graded: the maintenance status of
// each module (archived, deprecated, last release and activity), the fix dates, the severities and the known-exploited status
// of its findings, and the module's own advisories. The analysis is read, never changed, so one stored analysis can be
// graded every day.
//
// f is where facts are read first and written back to (see package facts). A fact that is in f and fresh on date is used
// instead of a lookup; a lookup that had to be made is stored. A fact in f that is newer than the analysis replaces the
// analysis's own value of a severity or of the known-exploited status. A nil f looks everything up, as Run does, with the
// scanners' own disk caches underneath. With an f, the maintainer analysis (contributors, bus factor), which the grade does not
// use but the policy and the internal scorer do, is made only for the modules that had no fresh status in f.
//
// date is the day the grade is for: it is the clock of every age in the result (months of inactivity, days since a fix) and
// of the facts' freshness; zero means today, UTC. Of the options, Grade reads Timeout, GithubToken, NVDAPIKey,
// RequireGithubToken, TrustIndexURL, TrustIndexAllowPrivate, StrictArchivedStatus, GradeStdlib, SelfVersion (the analysis's
// own version when empty) and ResponseHistory. Path, DirectOnly, ScanWorkflows, ScanCI and CalledPass belong to the analysis,
// and Now is replaced by date.
//
// It fails (nil Result) only for an analysis it cannot read (nil, or of another schema), the token precondition and a
// panic. A grade that cannot be completed is a Result whose Grade is Pending, and whose ScanStatus says why.
//
//nolint:gocritic // public API: Options is passed by value, as Run takes it
func Grade(ctx context.Context, an *Analysis, f facts.Store, date time.Time, opts Options) (res *Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, panicScanError(r)
		}
	}()
	if an == nil || an.GoMod == nil || an.Graph == nil {
		return nil, errors.New("grade: no analysis")
	}
	if an.SchemaVersion != AnalysisSchemaVersion {
		return nil, fmt.Errorf("grade: the analysis has schema version %d, this unisupply reads %d: analyse again", an.SchemaVersion, AnalysisSchemaVersion)
	}
	if date.IsZero() {
		date = time.Now().UTC().Truncate(24 * time.Hour)
	}
	if opts.SelfVersion == "" {
		opts.SelfVersion = an.Identity.Version
	}
	if opts.RequireGithubToken && opts.GithubToken == "" {
		return nil, fmt.Errorf("%w: no GitHub token was provided", ErrGithubTokenPrecondition)
	}
	st := &analysisState{token: tokenCheck{token: opts.GithubToken}, scanStart: date, vulnErr: an.VulnScan.err()}
	if len(an.Graph.Dependencies) > 0 || opts.RequireGithubToken || opts.SelfVersion != "" {
		st.token, err = checkGitHubToken(ctx, opts.GithubToken, opts.RequireGithubToken, offline.Enabled(), opts.Timeout)
		if err != nil {
			return nil, err
		}
	}
	return gradeAnalysis(ctx, an, st, f, date, &opts)
}

// gradeAnalysis is Grade for an analysis whose token has been checked.
func gradeAnalysis(ctx context.Context, an *Analysis, st *analysisState, f facts.Store, date time.Time, opts *Options) (*Result, error) {
	timeout := opts.Timeout
	scanStart := date
	rep := progress.From(ctx)
	offlineMode := offline.Enabled()
	gomod, graph, integrityReport := an.GoMod, an.Graph, an.Integrity
	githubToken, tokenStatus := st.token.token, st.token
	vulnScanErr := st.vulnErr
	vulnWarnings := an.VulnWarnings

	var scanInfo scanner.ScanInfo
	if an.Scan != nil {
		scanInfo = *an.Scan
	}
	// the analysis is read-only: grading changes fix dates and, from the facts, severities
	vulns := cloneVulns(an.Vulns)
	fixOpts := scanner.FixDateOptions{Timeout: timeout, Now: func() time.Time { return scanStart }}
	fr := &factReader{store: f, date: date, analysed: an.AnalysedAt}
	// Private modules are the customer's own code: their paths are in no request and no facts store call.
	private := scanner.NewPrivateModules(opts.PrivatePatterns)
	privSet, _ := privateModules(graph, private)
	lookupGraph := publicGraph(graph, privSet)

	if len(graph.Dependencies) == 0 {
		// see analyse: the standard library is graded only when the caller says so
		emptyVulnErr := vulnScanErr
		fr.applyAdvisories(ctx, publicVulns(vulns, private))
		resolveFixes(ctx, fr, fixOpts, publicVulns(vulns, private))
		fr.storeAdvisories(ctx, publicVulns(vulns, private))
		calledPassStale := staleCalledPass(an, vulns, opts.GradeStdlib)
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
		missingCode, missingKind := scanFailureCode(scanMissing)
		g := gradeAll(ctx, &gradeRun{
			Opts: *opts, GoMod: gomod, Graph: graph, Integrity: integrityReport, Token: githubToken,
			Timeout: timeout, ScanStart: scanStart, Toolchain: an.ToolchainVersion, Facts: fr, Private: private,
			Stdlib:      gradedStdlib(opts, stdlibVulns),
			VulnScanned: scanMissing == nil, VulnScanReason: errString(scanMissing), StdlibScanned: emptyVulnErr == nil,
			VulnScanCode: missingCode, VulnScanKind: missingKind, CalledPassStale: calledPassStale, CalledPassNever: calledPassNever(&scanInfo),
			KEVStaleSince: kevStaleSince(&scanInfo),
		})
		return &Result{GoMod: gomod, Graph: graph, ProjectScore: projectScore, Grade: g, IntegrityReport: integrityReport,
			StdlibVulns: stdlibVulns, VulnScanErr: emptyVulnErr,
			ScanInfo: scanInfoPtr(&scanInfo), KEVStaleSince: kevStaleSince(&scanInfo),
			ScanStatus: scanStatusOf(g, emptyVulnErr, false)}, nil
	}

	// A scan that did not run must not read as clean, whether it came back with an error or only a warning.
	vulnScanUnavailable := !an.VulnScan.Scanned

	// The date each fix was released (from the module proxy), so a finding can say whether it is inside the response
	// window. Best effort: a failed lookup leaves the advisory's own date, or none.
	fr.applyAdvisories(ctx, publicVulns(vulns, private))
	resolveFixes(ctx, fr, fixOpts, publicVulns(vulns, private))
	fr.storeAdvisories(ctx, publicVulns(vulns, private))
	calledPassStale := staleCalledPass(an, vulns, opts.GradeStdlib)

	rep.Stage("Checking maintenance health")
	// With a facts store, only the modules without a fresh status are looked up
	scanGraph, cached := fr.splitModules(ctx, lookupGraph)
	maintScanner := scanner.NewMaintenanceScanner(timeout)
	maintScanner.ScanStart = scanStart
	maintenance, err := maintScanner.ScanAll(ctx, scanGraph)
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
		if n := scanner.CountGitHubDeps(scanGraph); n > 20 {
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
	maintainers := maintainerScanner.ScanAll(ctx, scanGraph)
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
	if err := maintScanner.ScanActivity(ctx, scanGraph, maintenance, maintainers, commitFallback); err != nil {
		maintWarnings = append(maintWarnings, err.Error())
		rep.Warn("%v", err)
	}
	rep.Done("")
	fr.storeModules(ctx, scanGraph, maintenance)
	maps.Copy(maintenance, cached)

	rep.Stage("Detecting typosquats")
	typosquatScanner := scanner.NewTyposquatScanner()
	typosquats := typosquatScanner.ScanAll(ctx, graph)
	rep.Done("%d suspicious", len(typosquats))

	rep.Stage("Scoring resilience")
	resilienceScanner := scanner.NewResilienceScanner(timeout)
	resilienceScanner.ScanStart = scanStart
	resilience := resilienceScanner.ScanAll(ctx, scanGraph, maintainers)
	rep.Done("")

	var trustIndex map[string]*scanner.TrustIndexEntry
	trustClient, err := scanner.NewTrustIndexClient(opts.TrustIndexURL, timeout, opts.TrustIndexAllowPrivate)
	if err != nil {
		return nil, fmt.Errorf("trust index: %w", err)
	}
	if trustClient != nil {
		rep.Stage("Querying Trust Index")
		var tiErr error
		trustIndex, tiErr = trustClient.LookupAll(ctx, lookupGraph)
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
		Integrity:     an.IntegrityClasses,
		PseudoVersion: an.PseudoVersionClasses,
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
	projectScore.Warnings = append(projectScore.Warnings, an.ResolverWarnings...)
	projectScore.Warnings = appendScanFailure(projectScore.Warnings, vulnWarnings, vulnScanErr)
	projectScore.Warnings = append(projectScore.Warnings, maintWarnings...)
	// Resolver notes are informational and kept apart from the warnings, so a
	// report does not present them as a limitation of the results.
	projectScore.Notes = append(projectScore.Notes, graph.Notes...)
	rep.Done("")

	stdlibVulns := takeStdlibVulns(vulns)

	interrupted := an.Interrupted || ctx.Err() != nil
	if interrupted {
		rep.Warn("scan was interrupted — report may be incomplete (some scanners were cancelled)")
	}

	vulnCode, vulnKind := scanFailureCode(vulnScanErr)
	gradeResult := gradeAll(ctx, &gradeRun{
		Opts: *opts, GoMod: gomod, Graph: graph, Integrity: integrityReport, Token: githubToken,
		Timeout: timeout, ScanStart: scanStart,
		Toolchain: an.ToolchainVersion, Facts: fr, Private: private,
		Vulns: vulns, Stdlib: gradedStdlib(opts, stdlibVulns), Maintenance: maintenance,
		VulnScanned: vulnScanErr == nil, VulnScanReason: errString(vulnScanErr), Interrupted: interrupted,
		VulnScanCode: vulnCode, VulnScanKind: vulnKind, CalledPassStale: calledPassStale, CalledPassNever: calledPassNever(&scanInfo),
		StdlibScanned: vulnScanErr == nil, TokenMissing: githubToken == "", KEVStaleSince: kevStaleSince(&scanInfo),
	})

	return &Result{
		GoMod:           gomod,
		Graph:           graph,
		ProjectScore:    projectScore,
		Grade:           gradeResult,
		CIReport:        an.CI,
		StdlibVulns:     stdlibVulns,
		IntegrityReport: integrityReport,
		VulnScanErr:     vulnScanErr,
		ScanInfo:        scanInfoPtr(&scanInfo),
		KEVStaleSince:   kevStaleSince(&scanInfo),
		Interrupted:     interrupted,
		ScanStatus:      scanStatusOf(gradeResult, vulnScanErr, interrupted),

		GithubTokenRejected: tokenStatus.rejected,
		Maintainers:         maintainers,
		Typosquats:          typosquats,
	}, nil
}

// calledPassNever says the analysis ran with --called-pass never.
func calledPassNever(info *scanner.ScanInfo) bool {
	return info.CalledPassMode == string(scanner.CalledPassNever)
}

// staleCalledPass is the Pending reason when the analysis skipped the called pass (auto) and, with the severities and
// known-exploited status of the day, the called pass could now change the letter: only analysing again can say. The
// advisory fingerprint in the analysis's identity does not see a re-rated advisory, so the grade has to.
func staleCalledPass(an *Analysis, vulns map[string][]scanner.Vulnerability, gradeStdlib bool) string {
	if an.Scan == nil || an.Scan.CalledPass != scanner.CalledPassSkipped || an.Scan.CalledPassMode != string(scanner.CalledPassAuto) {
		return ""
	}
	if needed, reason := calledPassTest(gradeStdlib)(vulns); needed {
		return "the analysis skipped govulncheck's called pass, and with today's facts it could change the letter (" + reason + "): analyse again"
	}
	return ""
}

// cloneVulns copies the findings so that grading does not change the analysis. The structs are copied; the slices and
// pointers inside them are only ever replaced, never written through, by what grades them.
func cloneVulns(in map[string][]scanner.Vulnerability) map[string][]scanner.Vulnerability {
	out := make(map[string][]scanner.Vulnerability, len(in))
	for k, v := range in {
		out[k] = slices.Clone(v)
	}
	return out
}

// subgraph is the graph restricted to the given modules.
func subgraph(g *resolver.Graph, paths map[string]bool) *resolver.Graph {
	out := &resolver.Graph{Root: g.Root, Dependencies: make(map[string]*resolver.Dependency, len(paths)), Source: g.Source}
	for p := range paths {
		out.Dependencies[p] = g.Dependencies[p]
	}
	return out
}
