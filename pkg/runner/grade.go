package runner

import (
	"context"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/unidoc/unisupply/pkg/grade"
	"github.com/unidoc/unisupply/pkg/offline"
	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// selfReleaseTime looks up when the scanned module version was published; a variable so tests need no network.
var selfReleaseTime = scanner.ModuleVersionTime

// lookupSelfRelease is when the scanned module version was published, or nil. Context only: an unknown release time just
// leaves the "before this version was released" figure out of the findings.
func lookupSelfRelease(ctx context.Context, r *gradeRun) *time.Time {
	if r.Opts.SelfVersion == "" || offline.Enabled() {
		return nil
	}
	t, ok := selfReleaseTime(ctx, scanner.FixDateOptions{Timeout: r.Timeout}, r.GoMod.ModulePath, r.Opts.SelfVersion)
	if !ok {
		return nil
	}
	return &t
}

// stdlibModule is the row name of the Go standard library: it is part of every build, so its findings are graded like a
// direct dependency's.
const stdlibModule = "stdlib"

// gradeInputs is what buildGradeInput reads: the scanners' raw outputs, not the 0-100 scores derived from them.
type gradeInputs struct {
	Graph       *resolver.Graph
	Vulns       map[string][]scanner.Vulnerability // stdlib already taken out
	Stdlib      []scanner.Vulnerability
	Maintenance map[string]*scanner.MaintenanceInfo

	Self      grade.Row
	GoSumBad  bool
	GoSumInfo string

	Checks  grade.Checks
	History map[string]*scanner.ResponseHistory
	Now     time.Time

	// SelfReleasedAt is when the scanned module version was published (nil: unknown or no --module-version).
	SelfReleasedAt *time.Time

	// StdlibVersion is the Go release the standard library row was graded at.
	StdlibVersion string

	// ProjectGo is the module's own go directive ("1.24").
	ProjectGo string

	// StrictArchived makes an unread archived flag Missing (the grade may be Pending) instead of grading without it.
	StrictArchived bool

	// LocalReplaced holds the modules a replace directive points at a local directory: they are the project's own code, so
	// there is no published module to look up.
	LocalReplaced map[string]bool
}

// buildGradeInput maps the scanner outputs onto the rows of the grade.
func buildGradeInput(in *gradeInputs) grade.Input {
	out := grade.Input{
		Self:             in.Self,
		ChecksumMismatch: in.GoSumBad,
		ChecksumDetail:   in.GoSumInfo,
		Checks:           in.Checks,
		History:          in.History,
		Now:              in.Now,
		ProjectGo:        in.ProjectGo,
		SelfReleasedAt:   in.SelfReleasedAt,
	}
	if in.Graph != nil {
		for _, path := range in.Graph.SortedPaths() {
			d := in.Graph.Dependencies[path]
			upkeep := upkeepOfRule(in.Maintenance[path], in.StrictArchived)
			if in.LocalReplaced[path] {
				// the project's own code: nobody to ask (the proxy has no such module), so not assessed, never Missing
				upkeep = grade.Upkeep{NotAssessed: true}
			}
			row := grade.Row{
				Module:   path,
				Version:  d.Module.Version,
				Direct:   d.Direct,
				TestOnly: d.IsTestOnly,
				InBuild:  d.InBuild,
				Findings: findingsOf(path, in.Vulns[path]),
				Upkeep:   upkeep,
			}
			out.Deps = append(out.Deps, row)
		}
	}
	if len(in.Stdlib) > 0 {
		out.Deps = append(out.Deps, grade.Row{
			Module:   stdlibModule,
			Version:  in.StdlibVersion,
			Direct:   true,
			Findings: findingsOf(stdlibModule, in.Stdlib),
			// the standard library has no upkeep of its own to read
			Upkeep: grade.Upkeep{NotAssessed: true},
		})
	}
	return out
}

func findingsOf(module string, vulns []scanner.Vulnerability) []grade.Finding {
	var out []grade.Finding
	for i := range vulns {
		out = append(out, FindingFromVuln(module, &vulns[i]))
	}
	return out
}

// FindingFromVuln maps one scanned vulnerability onto a graded finding. It reads the raw severity: the scorer's own
// adjustments (EPSS, tier promotion) are not part of the v2 grade.
func FindingFromVuln(module string, v *scanner.Vulnerability) grade.Finding {
	return grade.Finding{
		ID:           v.ID,
		Aliases:      v.Aliases,
		Module:       module,
		Summary:      v.Summary,
		Severity:     strings.ToUpper(v.Severity),
		Reachability: v.Reachability,
		Exploited:    v.InKEV,
		// a lookup that failed is a check that did not run (Pending), not an unpublished severity (an estimate)
		SeverityLookupFailed: v.EnrichmentFailed && (strings.TrimSpace(v.Severity) == "" || strings.EqualFold(v.Severity, "UNKNOWN")),
		FixedVersion:         v.FixedVersion,
		FixRequiresGo:        v.FixRequiresGo,
		FixReleasedAt:        v.FixReleasedAt,
		FixDateSource:        v.FixDateSource,
		AffectedPackages:     v.AffectedPackages,
		Condition:            v.Condition,
	}
}

// upkeepOf maps maintenance data onto the upkeep facts; nil means the lookup produced nothing.
func upkeepOf(m *scanner.MaintenanceInfo) grade.Upkeep { return upkeepOfRule(m, true) }

// upkeepOfRule is upkeepOf with the caller's rule for an unread archived flag: strict makes it Missing (the grade may be
// Pending); otherwise, when the archived flag is the only thing missing, the row is graded on what is known and marked
// ArchivedUnread, so the result says so.
func upkeepOfRule(m *scanner.MaintenanceInfo, strict bool) grade.Upkeep {
	if m == nil {
		return grade.Upkeep{Missing: true}
	}
	msg := m.DeprecationMessage
	if msg == "" {
		msg = m.RetractionMessage
	}
	return grade.Upkeep{
		Archived:     m.Archived,
		Deprecated:   m.Deprecated,
		Retracted:    m.Retracted,
		Message:      msg,
		LastRelease:  m.LastRelease,
		LastActivity: m.LastActivity,
		// An archived flag we could not check is not "not archived": the state is unknown.
		// A repository that does not exist cannot be asked again, so it is not held against the grade as Pending.
		Missing: !m.Archived && (m.ModCheckFailed || (strict && archivedFlagFailed(m))),
		// the archived flag alone could not be read, and the caller grades without it (see upkeepOfRule)
		ArchivedUnread: !strict && !m.Archived && !m.ModCheckFailed && archivedFlagFailed(m),
	}
}

// archivedFlagFailed is true when the GitHub call for the archived flag failed (a repository that does not exist cannot
// be asked again, and is not a failure).
func archivedFlagFailed(m *scanner.MaintenanceInfo) bool {
	return m.ArchivedCheck == scanner.ArchivedCheckFailed && !m.RepositoryNotFound
}

// archiveUnchecked lists, sorted, the modules whose archived flag was never read for a reason other than a failed
// GitHub call: no repository is known for them, it is on a host GitHub's API cannot answer for ("unsupported"), or
// GitHub says it does not exist. A failed call is not listed: it is Missing in upkeepOf and makes the grade Pending
// instead. A module whose lookup was not attempted although a GitHub repository is known (offline, no lookup) is not
// listed either: that is a degraded scan, which the scan's own warnings already say.
func archiveUnchecked(maintenance map[string]*scanner.MaintenanceInfo, local map[string]bool) []string {
	var out []string
	for path, m := range maintenance {
		if m == nil || m.Archived || local[path] {
			continue
		}
		switch {
		case m.RepositoryNotFound,
			m.ArchivedCheck == scanner.ArchivedUnsupported,
			m.ArchivedCheck == "" && m.RepositoryURL == "":
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}

// moduleDependencies lists the dependency module paths worth a response-history lookup: the direct ones, sorted.
func moduleDependencies(g *resolver.Graph) []string {
	if g == nil {
		return nil
	}
	var out []string
	for p, d := range g.Dependencies {
		if d.Direct {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// gradeRun is what gradeAll needs from a finished (or empty) scan.
type gradeRun struct {
	Opts      Options
	GoMod     *parser.GoMod
	Graph     *resolver.Graph
	Integrity *scanner.IntegrityReport
	Token     string
	Timeout   time.Duration
	ScanStart time.Time
	// ProjectDir is the scanned module's directory: the Go toolchain version the standard library was graded at is
	// asked of the go command there.
	ProjectDir string

	Vulns       map[string][]scanner.Vulnerability
	Stdlib      []scanner.Vulnerability
	Maintenance map[string]*scanner.MaintenanceInfo

	// VulnScanned is false when the vulnerability scan did not complete; the reason goes to the Pending line.
	VulnScanned    bool
	VulnScanReason string
	Interrupted    bool

	// StdlibScanned is true when govulncheck ran (the standard library was matched against the scan's Go release).
	StdlibScanned bool
	// TokenMissing is true when no GitHub token was used: the archived flags then come from the 60 unauthenticated requests
	// an hour, and a missing one says so.
	TokenMissing bool
	// KEVStaleSince is the date of the CISA catalog copy used when it could not be refreshed (zero: fresh or none).
	KEVStaleSince time.Time
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	line, _, _ := strings.Cut(err.Error(), "\n")
	return line
}

// gradeAll builds the grade: the module's own row (status and advisories), every dependency's row, and the checks the
// grade depends on. It never fails: a lookup that did not work is recorded in Checks, and the grade says Pending.
func gradeAll(ctx context.Context, r *gradeRun) *grade.Result {
	local := localReplaced(r.GoMod, r.Graph)
	in := gradeInputs{
		LocalReplaced:  local,
		ProjectGo:      goDirective(r.GoMod),
		StrictArchived: r.Opts.StrictArchivedStatus,
		Graph:          r.Graph,
		Vulns:          r.Vulns,
		Stdlib:         r.Stdlib,
		Maintenance:    r.Maintenance,
		Now:            r.ScanStart,
		Checks: grade.Checks{
			VulnScanFailed: !r.VulnScanned,
			VulnScanReason: r.VulnScanReason,
			ScanTimedOut:   r.Interrupted,

			ArchiveUnchecked: archiveUnchecked(r.Maintenance, local),
		},
	}
	if r.Integrity != nil {
		in.GoSumBad = r.Integrity.GoSumVerified == scanner.GoSumVerifiedFalse
		if in.GoSumBad {
			in.GoSumInfo = "go mod verify reported a checksum mismatch"
		}
	}
	in.Checks.KEVStaleSince = r.KEVStaleSince
	in.Checks.KEVUnchecked = kevUnchecked(r.Vulns, r.Stdlib, r.Graph)
	// `go mod verify` that could not complete leaves a checksum mismatch (an F) unruled-out; a module with no
	// dependencies has no go.sum to verify.
	// Only a module that has a checksum counts: a locally replaced one is the project's own code, and a project that has
	// nothing but those has no go.sum at all.
	in.Checks.ChecksumUnverified = r.Integrity != nil && r.Integrity.GoSumVerified == scanner.GoSumVerifiedSkipped &&
		countChecksummed(r.Graph, local) > 0
	if r.StdlibScanned {
		// recorded whenever the standard library was scanned, whether or not it had findings: a clean result holds for this
		// Go release only
		in.StdlibVersion = scanToolchainVersion(ctx, r.ProjectDir)
		in.Checks.StdlibVersion = in.StdlibVersion
		in.Checks.StdlibGraded = r.Opts.GradeStdlib
	}
	if r.TokenMissing && !offline.Enabled() {
		for _, m := range r.Maintenance {
			if m != nil && m.ArchivedCheck == scanner.ArchivedCheckFailed {
				in.Checks.MaintenanceHint = "GitHub allows 60 unauthenticated requests an hour, so most archived flags could not be read: set GITHUB_TOKEN"
				break
			}
		}
	}
	in.Self = assessSelf(ctx, r, &in.Checks)
	in.SelfReleasedAt = lookupSelfRelease(ctx, r)

	if r.Opts.ResponseHistory && r.Opts.SelfVersion != "" && !offline.Enabled() {
		// Context only: a failed lookup leaves the labels at "Not enough response history", never a Pending grade.
		in.History, _ = scanner.ScanResponseHistory(ctx, scanner.ResponseHistoryOptions{Timeout: r.Timeout}, r.GoMod.ModulePath, moduleDependencies(r.Graph))
	}
	gi := buildGradeInput(&in)
	res := grade.Grade(&gi)
	return &res
}

// assessSelf builds the module's own row. Without a published version the module is not assessed as a published
// module: no own advisories (OSV needs a version) and no archived lookup, said plainly in the result.
func assessSelf(ctx context.Context, r *gradeRun, checks *grade.Checks) grade.Row {
	row := grade.Row{Module: r.GoMod.ModulePath, Version: r.Opts.SelfVersion, Self: true}
	if r.Opts.SelfVersion == "" {
		checks.SelfAdvisoriesSkipped = true
		row.Upkeep.NotAssessed = true // nobody looked at the module's own status: say so, not "finished"
		return row
	}

	// The module's own maintenance status, through the same scanners as a dependency's.
	mini := &resolver.Graph{Root: r.GoMod.ModulePath, Dependencies: map[string]*resolver.Dependency{
		r.GoMod.ModulePath: {Module: parser.Module{Path: r.GoMod.ModulePath, Version: r.Opts.SelfVersion}, Direct: true},
	}}
	ms := scanner.NewMaintenanceScanner(r.Timeout)
	ms.ScanStart = r.ScanStart
	maint, err := ms.ScanAll(ctx, mini)
	info := maint[r.GoMod.ModulePath]
	if err != nil || info == nil {
		checks.SelfStatusFailed = true
		checks.SelfStatusReason = selfStatusFailureReason(r.GoMod.ModulePath)
		row.Upkeep.Missing = true
	} else {
		mr := scanner.NewMaintainerScanner(r.Timeout, r.Token)
		mr.ScanStart = r.ScanStart
		maintainers := mr.ScanAll(ctx, mini)
		if aerr := ms.ScanArchived(ctx, maint, mr); aerr != nil {
			checks.SelfStatusFailed = true
			checks.SelfStatusReason = "archived status could not be read: " + errString(aerr)
		}
		_ = ms.ScanActivity(ctx, mini, maint, maintainers, activityFallback(r.Token, offline.Enabled(), mr))
		row.Upkeep = upkeepOf(info)
		if row.Upkeep.Missing {
			checks.SelfStatusFailed = true
			checks.SelfStatusReason = "archived status could not be read"
			if info != nil && info.ModCheckFailed {
				checks.SelfStatusReason = "its go.mod notices (deprecation, retraction) could not be read"
			}
		}
	}

	// The module's own advisories: govulncheck does not check the module it starts from, so OSV is asked for exactly
	// this version, and the grade assumes they are called.
	var warn []string
	var now func() time.Time // nil: wall clock, for a caller that sets no scan start
	if !r.ScanStart.IsZero() {
		now = func() time.Time { return r.ScanStart }
	}
	own, err := scanner.ScanModuleAdvisories(ctx, scanner.SelfAdvisoryOptions{
		GitHubToken: r.Token, NVDAPIKey: r.Opts.NVDAPIKey, Timeout: r.Timeout, Now: now,
		OnWarning: func(w string) { warn = append(warn, w) },
	}, r.GoMod.ModulePath, r.Opts.SelfVersion)
	if err != nil {
		checks.SelfAdvisoriesFailed = true
		checks.SelfAdvisoriesReason = errString(err)
		return row
	}
	scanner.ResolveFixDates(ctx, scanner.FixDateOptions{Timeout: r.Timeout, Now: now}, r.GoMod.ModulePath, own)
	row.Findings = findingsOf(r.GoMod.ModulePath, own)
	return row
}

// gradedStdlib is the standard library advisories that take part in the grade.
func gradedStdlib(opts *Options, vulns []scanner.Vulnerability) []scanner.Vulnerability {
	if !opts.GradeStdlib {
		return nil
	}
	return vulns
}

// selfStatusFailureReason says why the module's own status has no data: offline
// mode makes no request at all, which is not the proxy failing to answer.
func selfStatusFailureReason(modulePath string) string {
	if offline.Enabled() {
		return "offline: no network requests were made"
	}
	return "the module proxy did not answer for " + modulePath
}

// kevUnchecked counts the findings that could be a known-exploited F (reached, with a CVE) whose catalog check did not run.
// A finding of a confirmed test-only dependency is left out: such a row can never reach F. A check against a stale
// catalog counts as run (KEVChecked is true).
func kevUnchecked(vulns map[string][]scanner.Vulnerability, stdlib []scanner.Vulnerability, graph *resolver.Graph) int {
	n := 0
	count := func(list []scanner.Vulnerability) {
		for i := range list {
			v := &list[i]
			if v.KEVChecked || (v.Reachability != "called" && v.Reachability != "") {
				continue
			}
			for _, a := range append([]string{v.ID}, v.Aliases...) {
				if strings.HasPrefix(a, "CVE-") {
					n++
					break
				}
			}
		}
	}
	for mod, list := range vulns {
		if graph != nil {
			if d := graph.Dependencies[mod]; d != nil && d.IsTestOnly != nil && *d.IsTestOnly {
				continue
			}
		}
		count(list)
	}
	count(stdlib)
	return n
}

// scanToolchainVersion is the Go release the scan ran with ("go1.26.9"), as the go command in dir reports it, or "" when
// it cannot be read. The standard library's advisories are matched against it.
func scanToolchainVersion(ctx context.Context, dir string) string {
	cmd := exec.CommandContext(ctx, "go", "env", "GOVERSION")
	cmd.Dir = dir
	cmd.Env = os.Environ()
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// localReplaced is the set of dependencies of the graph that a replace directive points at a local directory (./lib,
// ../lib, /abs/lib), under go.mod's own rule (GoMod.ReplacementFor): a replace scoped to one version applies only when the
// graph selected that version. For any other version the module comes from the proxy and is not local.
func localReplaced(gm *parser.GoMod, g *resolver.Graph) map[string]bool {
	out := map[string]bool{}
	if gm == nil || g == nil {
		return out
	}
	for path, d := range g.Dependencies {
		version := ""
		if d != nil {
			version = d.Module.Version
		}
		if rep, ok := gm.ReplacementFor(path, version); ok && isLocalPath(rep.New.Path) {
			out[path] = true
		}
	}
	return out
}

func isLocalPath(p string) bool {
	return p == "." || p == ".." || strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") ||
		strings.HasPrefix(p, `.\`) || strings.HasPrefix(p, `..\`) || (len(p) > 2 && p[1] == ':' && (p[2] == '\\' || p[2] == '/'))
}

// countChecksummed is the number of modules of the graph that have a go.sum entry to verify (not locally replaced).
func countChecksummed(g *resolver.Graph, local map[string]bool) int {
	if g == nil {
		return 0
	}
	n := 0
	for path := range g.Dependencies {
		if !local[path] {
			n++
		}
	}
	return n
}

// goDirective is the module's own go directive ("1.24"), or "" without one.
func goDirective(gm *parser.GoMod) string {
	if gm == nil {
		return ""
	}
	return strings.TrimSpace(gm.GoVersion)
}
