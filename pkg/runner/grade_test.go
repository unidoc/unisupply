package runner

import (
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
	if !in.Deps[1].Upkeep.Missing {
		t.Error("an archived flag that could not be read is unknown, not 'not archived'")
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
