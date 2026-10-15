package runner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/grade"
	"github.com/unidoc/unisupply/pkg/offline"
	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
)

func tp(b bool) *bool { return &b }

func TestBuildGradeInput_MapsTheScannerOutput(t *testing.T) {
	released := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	g := &resolver.Graph{Root: "example.com/app", Dependencies: map[string]*resolver.Dependency{
		"example.com/a": {Module: parser.Module{Path: "example.com/a", Version: "v1.2.3"}, Direct: true, IsTestOnly: tp(true), InBuild: tp(true)},
		"example.com/b": {Module: parser.Module{Path: "example.com/b", Version: "v0.1.0"}},
	}}
	in := buildGradeInput(&gradeInputs{
		Graph: g,
		Vulns: map[string][]scanner.Vulnerability{"example.com/a": {{
			ID: "GO-1", Severity: "high", Reachability: "called", InKEV: true, FixedVersion: "v1.2.4",
			FixReleasedAt: &released, FixDateSource: "module_proxy", Condition: "reached through x.Y",
		}}},
		Stdlib: []scanner.Vulnerability{{ID: "GO-2", Severity: "MEDIUM", Reachability: "imported"}},
		Maintenance: map[string]*scanner.MaintenanceInfo{
			"example.com/a": {Archived: true, ArchivedCheck: scanner.ArchivedChecked, LastRelease: released},
			"example.com/b": {ArchivedCheck: scanner.ArchivedCheckFailed},
		},
		Now: released,
	})
	if len(in.Deps) != 3 || in.Deps[0].Module != "example.com/a" || in.Deps[2].Module != stdlibModule {
		t.Fatalf("rows (sorted, stdlib last): %+v", in.Deps)
	}
	a := in.Deps[0]
	f := a.Findings[0]
	if !a.Direct || a.TestOnly == nil || !*a.TestOnly || a.Version != "v1.2.3" || !a.Upkeep.Archived {
		t.Errorf("%+v", a)
	}
	if f.Severity != "HIGH" || !f.Exploited || f.FixReleasedAt == nil || f.Condition != "reached through x.Y" || f.FixDateSource != "module_proxy" {
		t.Errorf("%+v", f)
	}
	// by default the grade is given without an archived flag that could not be read, and says so (it is never "not archived")
	if in.Deps[1].Upkeep.Missing || !in.Deps[1].Upkeep.ArchivedUnread {
		t.Errorf("an unread archived flag is marked ArchivedUnread, not Missing, by default: %+v", in.Deps[1].Upkeep)
	}
	strict := buildGradeInput(&gradeInputs{Graph: g, Maintenance: map[string]*scanner.MaintenanceInfo{"example.com/b": {ArchivedCheck: scanner.ArchivedCheckFailed}}, StrictArchived: true})
	if !strict.Deps[1].Upkeep.Missing || strict.Deps[1].Upkeep.ArchivedUnread {
		t.Errorf("the strict rule makes it Missing: %+v", strict.Deps[1].Upkeep)
	}
	if in.Deps[2].Findings[0].Reachability != "imported" {
		t.Errorf("%+v", in.Deps[2])
	}
}

func TestUpkeepOf(t *testing.T) {
	if u := upkeepOf(nil); !u.Missing {
		t.Error("no maintenance data is Missing")
	}
	if u := upkeepOf(&scanner.MaintenanceInfo{Retracted: true, RetractionMessage: "oops"}); !u.Retracted || u.Message != "oops" || u.Missing {
		t.Errorf("%+v", u)
	}
	if u := upkeepOf(&scanner.MaintenanceInfo{Deprecated: true, DeprecationMessage: "use new"}); u.Message != "use new" {
		t.Errorf("%+v", u)
	}
	// a repository that is gone cannot be asked again: not held against the grade as Pending
	if u := upkeepOf(&scanner.MaintenanceInfo{ArchivedCheck: scanner.ArchivedCheckFailed, RepositoryNotFound: true}); u.Missing {
		t.Error("repository_not_found must not make the grade Pending")
	}
	// an archived module stays archived even when the check is marked failed
	if u := upkeepOf(&scanner.MaintenanceInfo{Archived: true, ArchivedCheck: scanner.ArchivedCheckFailed}); u.Missing || !u.Archived {
		t.Errorf("%+v", u)
	}
}

func TestGrade_EndToEndThroughTheEngine(t *testing.T) {
	g := &resolver.Graph{Dependencies: map[string]*resolver.Dependency{
		"golang.org/x/image": {Module: parser.Module{Path: "golang.org/x/image", Version: "v0.1.0"}, Direct: true, InBuild: tp(true)},
	}}
	in := buildGradeInput(&gradeInputs{
		Graph: g,
		Vulns: map[string][]scanner.Vulnerability{"golang.org/x/image": {
			{ID: "A", Severity: "HIGH", Reachability: "called", FixedVersion: "v9"},
			{ID: "B", Severity: "HIGH", Reachability: "called", FixedVersion: "v9"},
			{ID: "C", Severity: "HIGH", Reachability: "called", FixedVersion: "v9"},
		}},
		Maintenance: map[string]*scanner.MaintenanceInfo{"golang.org/x/image": {LastRelease: time.Now()}},
		Now:         time.Now(),
		Self:        grade.Row{Module: "example.com/app", Self: true},
	})
	r := grade.Grade(&in)
	if r.Letter != grade.LetterF || r.Score != 80 {
		t.Fatalf("%s %d", r.Letter, r.Score)
	}
}

func TestErrString(t *testing.T) {
	if errString(nil) != "" {
		t.Error("nil")
	}
	if got := errString(errTest("first line\nsecond")); got != "first line" {
		t.Errorf("%q", got)
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }

func TestGradeAll_NoModuleVersionSkipsTheModuleItself(t *testing.T) {
	gm := &parser.GoMod{ModulePath: "example.com/app"}
	res := gradeAll(t.Context(), &gradeRun{GoMod: gm, Graph: &resolver.Graph{}, Integrity: &scanner.IntegrityReport{}, VulnScanned: true, ScanStart: time.Now()})
	if res.Pending != nil || res.Letter != grade.LetterA {
		t.Fatalf("a module with nothing to scan is graded: %+v", res)
	}
	if len(res.Notes) != 1 {
		t.Errorf("the grade must say that the module's own advisories were not looked up: %v", res.Notes)
	}
}

func TestGradeAll_OfflineWithModuleVersionIsPendingNotAnA(t *testing.T) {
	offline.Enable()
	t.Cleanup(offline.Disable)
	gm := &parser.GoMod{ModulePath: "example.com/app"}
	res := gradeAll(t.Context(), &gradeRun{
		Opts: Options{SelfVersion: "v1.0.0"}, GoMod: gm, Graph: &resolver.Graph{}, Integrity: &scanner.IntegrityReport{},
		VulnScanned: true, ScanStart: time.Now(),
	})
	if res.Pending == nil || res.Letter != "" {
		t.Fatalf("own status and advisories could not be read, so no letter: %+v", res)
	}
}

func TestGradeAll_FailedVulnScanIsPending(t *testing.T) {
	gm := &parser.GoMod{ModulePath: "example.com/app"}
	g := &resolver.Graph{Dependencies: map[string]*resolver.Dependency{"example.com/a": {Module: parser.Module{Path: "example.com/a", Version: "v1.0.0"}, Direct: true}}}
	res := gradeAll(t.Context(), &gradeRun{
		GoMod: gm, Graph: g, Integrity: &scanner.IntegrityReport{}, ScanStart: time.Now(),
		Maintenance: map[string]*scanner.MaintenanceInfo{"example.com/a": {LastRelease: time.Now()}},
		VulnScanned: false, VulnScanReason: "govulncheck: loading packages",
	})
	if res.Pending == nil || res.Pending.Check != "vulnerability_scan" {
		t.Fatalf("%+v", res)
	}
}

func TestGradeAll_ChecksumMismatchIsF(t *testing.T) {
	gm := &parser.GoMod{ModulePath: "example.com/app"}
	g := &resolver.Graph{Dependencies: map[string]*resolver.Dependency{"example.com/a": {Module: parser.Module{Path: "example.com/a", Version: "v1.0.0"}, Direct: true}}}
	res := gradeAll(t.Context(), &gradeRun{
		GoMod: gm, Graph: g, Integrity: &scanner.IntegrityReport{GoSumVerified: scanner.GoSumVerifiedFalse}, ScanStart: time.Now(),
		Maintenance: map[string]*scanner.MaintenanceInfo{"example.com/a": {LastRelease: time.Now()}}, VulnScanned: true,
	})
	if res.Letter != grade.LetterF {
		t.Fatalf("%+v", res)
	}
}

func TestGradedStdlib(t *testing.T) {
	v := []scanner.Vulnerability{{ID: "GO-1", Severity: "CRITICAL", Reachability: "called"}}
	if got := gradedStdlib(&Options{}, v); got != nil {
		t.Errorf("the standard library is listed, not graded, by default: %v", got)
	}
	if got := gradedStdlib(&Options{GradeStdlib: true}, v); len(got) != 1 {
		t.Errorf("graded when asked: %v", got)
	}
}

// Modules whose archived flag was never read, for a reason that is not a failed GitHub call, are named in one note on
// the grade; a failed call and a read flag are not, and none of it makes the grade Pending.
func TestGradeAll_ArchiveUncheckedNote(t *testing.T) {
	maint := map[string]*scanner.MaintenanceInfo{
		"gitlab.example/z/unsupported": {RepositoryURL: "https://gitlab.example/z/unsupported", ArchivedCheck: scanner.ArchivedUnsupported},
		"vanity.example/nowhere":       {},
		"github.com/gone/repo":         {RepositoryURL: "https://github.com/gone/repo", ArchivedCheck: scanner.ArchivedCheckFailed, RepositoryNotFound: true},
		"github.com/ok/checked":        {RepositoryURL: "https://github.com/ok/checked", ArchivedCheck: scanner.ArchivedChecked},
		"github.com/rate/limited":      {RepositoryURL: "https://github.com/rate/limited", ArchivedCheck: scanner.ArchivedCheckFailed},
	}
	for _, m := range maint {
		m.LastRelease = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	got := archiveUnchecked(maint, nil)
	want := []string{"github.com/gone/repo", "gitlab.example/z/unsupported", "vanity.example/nowhere"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("archiveUnchecked = %v, want %v", got, want)
	}

	g := &resolver.Graph{Root: "example.com/app", Dependencies: map[string]*resolver.Dependency{}}
	for p := range maint {
		g.Dependencies[p] = &resolver.Dependency{Module: parser.Module{Path: p, Version: "v1.0.0"}, Direct: true}
	}
	res := gradeAll(context.Background(), &gradeRun{
		Opts: Options{}, GoMod: &parser.GoMod{ModulePath: "example.com/app"}, Graph: g,
		Maintenance: maint, VulnScanned: true, ScanStart: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})
	var notes []string
	for _, n := range res.Notes {
		if strings.HasPrefix(n, "Archived status was not checked") {
			notes = append(notes, n)
		}
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "for 3 module(s)") || !strings.Contains(notes[0], "github.com/gone/repo, gitlab.example/z/unsupported, vanity.example/nowhere.") {
		t.Errorf("notes = %q, want one note naming the three modules", notes)
	}
}

// A go.mod that could not be read is unknown upkeep, not "not deprecated, not retracted", unless the module is
// archived anyway.
func TestUpkeepOf_ModCheckFailedIsMissing(t *testing.T) {
	if !upkeepOf(&scanner.MaintenanceInfo{ModCheckFailed: true}).Missing {
		t.Error("ModCheckFailed did not map to Missing")
	}
	if upkeepOf(&scanner.MaintenanceInfo{ModCheckFailed: true, Archived: true, ArchivedCheck: scanner.ArchivedChecked}).Missing {
		t.Error("an archived module reads as Missing although its state is known")
	}
	if upkeepOf(&scanner.MaintenanceInfo{}).Missing {
		t.Error("a clean module reads as Missing")
	}
}

// Offline, the reason for a missing own status is that nothing was asked, not that the proxy did not answer.
func TestSelfStatusFailureReason_Offline(t *testing.T) {
	if got := selfStatusFailureReason("example.com/app"); !strings.Contains(got, "module proxy did not answer") {
		t.Errorf("online reason = %q", got)
	}
	offline.Enable()
	t.Cleanup(offline.Disable)
	got := selfStatusFailureReason("example.com/app")
	if got != "offline: no network requests were made" {
		t.Errorf("offline reason = %q", got)
	}
}

// End to end: an offline run with a module version says offline in the Pending reason, and makes no request.
func TestGradeAll_OfflineSelfStatusReason(t *testing.T) {
	offline.Enable()
	t.Cleanup(offline.Disable)
	res := gradeAll(context.Background(), &gradeRun{
		Opts:        Options{SelfVersion: "v1.0.0"},
		GoMod:       &parser.GoMod{ModulePath: "example.com/app"},
		Graph:       &resolver.Graph{Root: "example.com/app", Dependencies: map[string]*resolver.Dependency{}},
		VulnScanned: true, ScanStart: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})
	if res.Pending == nil || !strings.Contains(res.Pending.Reason, "offline: no network requests were made") || strings.Contains(res.Pending.Reason, "proxy did not answer") {
		t.Errorf("Pending = %+v, want the offline reason", res.Pending)
	}
}

func TestKEVUnchecked(t *testing.T) {
	vulns := map[string][]scanner.Vulnerability{"example.com/a": {
		{ID: "GO-1", Aliases: []string{"CVE-2026-1"}, Reachability: "called"},                   // counts
		{ID: "GO-2", Aliases: []string{"CVE-2026-2"}, Reachability: "called", KEVChecked: true}, // checked
		{ID: "GO-3", Aliases: []string{"CVE-2026-3"}, Reachability: "required"},                 // graph-only: not reached
		{ID: "GO-4", Aliases: []string{"GHSA-xxxx"}, Reachability: "called"},                    // no CVE: cannot be listed
		{ID: "GO-5", Aliases: []string{"CVE-2026-5"}, Reachability: ""},                         // undetermined is scored as called
	}}
	if got := kevUnchecked(vulns, nil, nil); got != 2 {
		t.Errorf("got %d, want 2", got)
	}
}

func TestLocalReplaced(t *testing.T) {
	gm := &parser.GoMod{Replaces: map[string]parser.Replace{
		"a/lib": {New: parser.Module{Path: "../lib"}},
		"b/lib": {New: parser.Module{Path: "./staging/b"}},
		"c/lib": {New: parser.Module{Path: "/abs/c"}},
		"d/lib": {New: parser.Module{Path: "github.com/fork/d", Version: "v1.0.0"}},
		"e/lib": {New: parser.Module{Path: "example.com/e"}},
		"f/lib": {New: parser.Module{Path: ".."}},
	}}
	got := localReplaced(gm)
	for _, p := range []string{"a/lib", "b/lib", "c/lib", "f/lib"} {
		if !got[p] {
			t.Errorf("%s is a local replacement", p)
		}
	}
	for _, p := range []string{"d/lib", "e/lib"} {
		if got[p] {
			t.Errorf("%s is a published replacement, not a local one", p)
		}
	}
	if len(localReplaced(nil)) != 0 {
		t.Error("nil go.mod")
	}
}

// A dependency replaced by a local directory is the project's own code: the proxy has no such module, so its maintenance
// data is absent for ever. It must not make the grade Pending (monorepos), and no go.sum is expected when that is all there is.
func TestGradeAll_LocalReplaceDoesNotMakeThePendingGrade(t *testing.T) {
	gm := &parser.GoMod{ModulePath: "example.com/app", Replaces: map[string]parser.Replace{"example.com/lib": {New: parser.Module{Path: "../lib"}}}}
	g := &resolver.Graph{Dependencies: map[string]*resolver.Dependency{"example.com/lib": {Module: parser.Module{Path: "example.com/lib", Version: "v0.0.0"}, Direct: true}}}
	res := gradeAll(t.Context(), &gradeRun{
		GoMod: gm, Graph: g, ScanStart: time.Now(), VulnScanned: true,
		Integrity:   &scanner.IntegrityReport{GoSumVerified: scanner.GoSumVerifiedSkipped}, // no go.sum: only local code
		Maintenance: map[string]*scanner.MaintenanceInfo{},                                 // the proxy answered 404: nothing for the local module
	})
	if res.Pending != nil || res.Letter != grade.LetterA {
		t.Fatalf("a locally replaced dependency made the grade %+v %s", res.Pending, res.Letter)
	}
	lib := res.Rows[0]
	for _, r := range res.Rows {
		if r.Module == "example.com/lib" {
			lib = r
		}
	}
	if lib.UpkeepState != "not_assessed" {
		t.Errorf("%+v", lib)
	}
	// control: the same dependency replaced by a published module IS missing data (Pending), and with a go.sum that could
	// not be verified the checksum check applies
	gm.Replaces["example.com/lib"] = parser.Replace{New: parser.Module{Path: "github.com/fork/lib", Version: "v1.0.0"}}
	if p := gradeAll(t.Context(), &gradeRun{GoMod: gm, Graph: g, ScanStart: time.Now(), VulnScanned: true,
		Integrity: &scanner.IntegrityReport{GoSumVerified: scanner.GoSumVerifiedSkipped}, Maintenance: map[string]*scanner.MaintenanceInfo{}}); p.Pending == nil {
		t.Error("a published replacement with no data and an unverified go.sum must stay Pending")
	}
}

func TestGradeAll_TokenHintInThePendingReason(t *testing.T) {
	gm := &parser.GoMod{ModulePath: "example.com/app"}
	g := &resolver.Graph{Dependencies: map[string]*resolver.Dependency{"github.com/x/y": {Module: parser.Module{Path: "github.com/x/y", Version: "v1.0.0"}, Direct: true}}}
	res := gradeAll(t.Context(), &gradeRun{Opts: Options{StrictArchivedStatus: true}, GoMod: gm, Graph: g, ScanStart: time.Now(), VulnScanned: true, TokenMissing: true,
		Integrity:   &scanner.IntegrityReport{GoSumVerified: scanner.GoSumVerifiedTrue},
		Maintenance: map[string]*scanner.MaintenanceInfo{"github.com/x/y": {ArchivedCheck: scanner.ArchivedCheckFailed}}})
	if res.Pending == nil || !strings.Contains(res.Pending.Reason, "set GITHUB_TOKEN") {
		t.Errorf("%+v", res.Pending)
	}
	with := gradeAll(t.Context(), &gradeRun{Opts: Options{StrictArchivedStatus: true}, GoMod: gm, Graph: g, ScanStart: time.Now(), VulnScanned: true, TokenMissing: false,
		Integrity:   &scanner.IntegrityReport{GoSumVerified: scanner.GoSumVerifiedTrue},
		Maintenance: map[string]*scanner.MaintenanceInfo{"github.com/x/y": {ArchivedCheck: scanner.ArchivedCheckFailed}}})
	if with.Pending == nil || strings.Contains(with.Pending.Reason, "set GITHUB_TOKEN") {
		t.Errorf("with a token the hint is wrong: %+v", with.Pending)
	}
}

func TestKEVUnchecked_ExcludesConfirmedTestOnly(t *testing.T) {
	v := scanner.Vulnerability{ID: "GO-1", Aliases: []string{"CVE-2026-1"}, Reachability: "called"}
	vulns := map[string][]scanner.Vulnerability{"example.com/test": {v}, "example.com/prod": {v}, "example.com/unknown": {v}}
	g := &resolver.Graph{Dependencies: map[string]*resolver.Dependency{
		"example.com/test":    {IsTestOnly: tp(true)},
		"example.com/prod":    {IsTestOnly: tp(false)},
		"example.com/unknown": {},
	}}
	if got := kevUnchecked(vulns, nil, g); got != 2 {
		t.Errorf("got %d, want 2 (confirmed test-only excluded, production and unknown counted)", got)
	}
	stale := time.Now()
	checked := v
	checked.KEVChecked, checked.KEVCatalogStaleSince = true, &stale
	if got := kevUnchecked(map[string][]scanner.Vulnerability{"example.com/prod": {checked}}, nil, g); got != 0 {
		t.Errorf("a finding checked against a stale catalog counted as unchecked: %d", got)
	}
}

// By default (the CLI) a grade is given when the only gap is the archived flag of a dependency, with a note: an archived
// dependency adds at most 20 to its row. The strict rule (a service that publishes letters) makes it Pending instead.
func TestGradeAll_ArchivedFlagGapIsGradedWithANoteByDefault(t *testing.T) {
	gm := &parser.GoMod{ModulePath: "example.com/app"}
	g := &resolver.Graph{Dependencies: map[string]*resolver.Dependency{
		"github.com/x/y": {Module: parser.Module{Path: "github.com/x/y", Version: "v1.0.0"}, Direct: true},
		"github.com/x/z": {Module: parser.Module{Path: "github.com/x/z", Version: "v1.0.0"}, Direct: true},
	}}
	run := func(strict bool) *grade.Result {
		return gradeAll(t.Context(), &gradeRun{Opts: Options{StrictArchivedStatus: strict}, GoMod: gm, Graph: g, ScanStart: time.Now(), VulnScanned: true, TokenMissing: true,
			Integrity: &scanner.IntegrityReport{GoSumVerified: scanner.GoSumVerifiedTrue},
			Maintenance: map[string]*scanner.MaintenanceInfo{
				"github.com/x/y": {ArchivedCheck: scanner.ArchivedCheckFailed},
				"github.com/x/z": {ArchivedCheck: scanner.ArchivedCheckFailed},
			}})
	}
	res := run(false)
	if res.Pending != nil || res.Letter != grade.LetterA {
		t.Fatalf("graded on what is known: %+v %s", res.Pending, res.Letter)
	}
	if len(res.ArchivedUnread) != 2 || res.ArchivedUnread[0] != "github.com/x/y" {
		t.Errorf("%v", res.ArchivedUnread)
	}
	found := false
	for _, n := range res.Notes {
		if strings.Contains(n, "could not be read") && strings.Contains(n, "at most 20") && strings.Contains(n, "set GITHUB_TOKEN") {
			found = true
		}
	}
	if !found {
		t.Errorf("the note must say what is missing, the size of the gap and what to do: %v", res.Notes)
	}
	if s := run(true); s.Pending == nil || s.Pending.Check != "dependency_maintenance" {
		t.Errorf("the strict rule is Pending: %+v", s.Pending)
	}
	// a gap in the proxy's data (not just the flag) is still Pending in the default mode
	missing := gradeAll(t.Context(), &gradeRun{GoMod: gm, Graph: g, ScanStart: time.Now(), VulnScanned: true,
		Integrity:   &scanner.IntegrityReport{GoSumVerified: scanner.GoSumVerifiedTrue},
		Maintenance: map[string]*scanner.MaintenanceInfo{"github.com/x/y": {ModCheckFailed: true}}})
	if missing.Pending == nil {
		t.Error("an unreadable go.mod notice is missing data, not just the archived flag")
	}
}

func TestFindingFromVuln_SeverityLookupFailedOnlyWhenTheLookupFailed(t *testing.T) {
	failed := FindingFromVuln("m", &scanner.Vulnerability{ID: "GO-1", Severity: "UNKNOWN", EnrichmentFailed: true})
	unscored := FindingFromVuln("m", &scanner.Vulnerability{ID: "GO-2", Severity: "UNKNOWN", EnrichmentAttempted: true})
	known := FindingFromVuln("m", &scanner.Vulnerability{ID: "GO-3", Severity: "HIGH", EnrichmentFailed: true})
	if !failed.SeverityLookupFailed || unscored.SeverityLookupFailed || known.SeverityLookupFailed {
		t.Errorf("failed=%v unscored=%v known=%v", failed.SeverityLookupFailed, unscored.SeverityLookupFailed, known.SeverityLookupFailed)
	}
}

func TestFindingFromVuln_CarriesTheGoTheFixNeeds(t *testing.T) {
	f := FindingFromVuln("golang.org/x/image", &scanner.Vulnerability{ID: "GO-1", FixedVersion: "v0.46.0", FixRequiresGo: "1.26.0"})
	if f.FixRequiresGo != "1.26.0" {
		t.Errorf("%+v", f)
	}
	if got := goDirective(&parser.GoMod{GoVersion: " 1.24 "}); got != "1.24" || goDirective(nil) != "" {
		t.Errorf("%q", got)
	}
}
