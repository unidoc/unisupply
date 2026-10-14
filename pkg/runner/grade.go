package runner

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/unidoc/unisupply/pkg/grade"
	"github.com/unidoc/unisupply/pkg/offline"
	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
)

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
	}
	if in.Graph != nil {
		for _, path := range in.Graph.SortedPaths() {
			d := in.Graph.Dependencies[path]
			row := grade.Row{
				Module:   path,
				Version:  d.Module.Version,
				Direct:   d.Direct,
				TestOnly: d.IsTestOnly,
				InBuild:  d.InBuild,
				Findings: findingsOf(path, in.Vulns[path]),
				Upkeep:   upkeepOf(in.Maintenance[path]),
			}
			out.Deps = append(out.Deps, row)
		}
	}
	if len(in.Stdlib) > 0 {
		out.Deps = append(out.Deps, grade.Row{
			Module:   stdlibModule,
			Direct:   true,
			Findings: findingsOf(stdlibModule, in.Stdlib),
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
		ID:               v.ID,
		Aliases:          v.Aliases,
		Module:           module,
		Summary:          v.Summary,
		Severity:         strings.ToUpper(v.Severity),
		Reachability:     v.Reachability,
		Exploited:        v.InKEV,
		FixedVersion:     v.FixedVersion,
		FixReleasedAt:    v.FixReleasedAt,
		FixDateSource:    v.FixDateSource,
		AffectedPackages: v.AffectedPackages,
		Condition:        v.Condition,
	}
}

// upkeepOf maps maintenance data onto the upkeep facts; nil means the lookup produced nothing.
func upkeepOf(m *scanner.MaintenanceInfo) grade.Upkeep {
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
		Missing: m.ArchivedCheck == scanner.ArchivedCheckFailed && !m.Archived && !m.RepositoryNotFound,
	}
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

	Vulns       map[string][]scanner.Vulnerability
	Stdlib      []scanner.Vulnerability
	Maintenance map[string]*scanner.MaintenanceInfo

	// VulnScanned is false when the vulnerability scan did not complete; the reason goes to the Pending line.
	VulnScanned    bool
	VulnScanReason string
	Interrupted    bool
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
	in := gradeInputs{
		Graph:       r.Graph,
		Vulns:       r.Vulns,
		Stdlib:      r.Stdlib,
		Maintenance: r.Maintenance,
		Now:         r.ScanStart,
		Checks: grade.Checks{
			VulnScanFailed: !r.VulnScanned,
			VulnScanReason: r.VulnScanReason,
			ScanTimedOut:   r.Interrupted,
		},
	}
	if r.Integrity != nil {
		in.GoSumBad = r.Integrity.GoSumVerified == scanner.GoSumVerifiedFalse
		if in.GoSumBad {
			in.GoSumInfo = "go mod verify reported a checksum mismatch"
		}
	}
	in.Self = assessSelf(ctx, r, &in.Checks)

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
		checks.SelfStatusReason = "the module proxy did not answer for " + r.GoMod.ModulePath
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
		}
	}

	// The module's own advisories: govulncheck does not check the module it starts from, so OSV is asked for exactly
	// this version, and the grade assumes they are called.
	var warn []string
	own, err := scanner.ScanModuleAdvisories(ctx, scanner.SelfAdvisoryOptions{
		GitHubToken: r.Token, NVDAPIKey: r.Opts.NVDAPIKey, Timeout: r.Timeout,
		OnWarning: func(w string) { warn = append(warn, w) },
	}, r.GoMod.ModulePath, r.Opts.SelfVersion)
	if err != nil {
		checks.SelfAdvisoriesFailed = true
		checks.SelfAdvisoriesReason = errString(err)
		return row
	}
	scanner.ResolveFixDates(ctx, scanner.FixDateOptions{Timeout: r.Timeout}, r.GoMod.ModulePath, own)
	row.Findings = findingsOf(r.GoMod.ModulePath, own)
	return row
}
