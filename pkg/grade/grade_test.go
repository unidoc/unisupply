package grade

import (
	"encoding/json"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/scanner"
)

var now = time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)

func ptr[T any](v T) *T { return &v }

func called(id, module, sev string) Finding {
	return Finding{ID: id, Module: module, Severity: sev, Reachability: "called", FixedVersion: "v9.9.9"}
}

func dep(module string, f ...Finding) Row {
	return Row{Module: module, Version: "v1.0.0", Direct: true, InBuild: ptr(true), Findings: f,
		Upkeep: Upkeep{LastRelease: now.AddDate(0, -3, 0)}}
}

func self(f ...Finding) Row {
	return Row{Module: "example.com/app", Self: true, Findings: f, Upkeep: Upkeep{LastRelease: now.AddDate(0, -2, 0), LastActivity: now.AddDate(0, 0, -5)}}
}

func run(in Input) Result {
	if in.Now.IsZero() {
		in.Now = now
	}
	return Grade(&in)
}

func row(t *testing.T, r Result, module string) RowResult {
	t.Helper()
	for _, x := range r.Rows {
		if x.Module == module {
			return x
		}
	}
	t.Fatalf("no row for %s in %+v", module, r.Rows)
	return RowResult{}
}

func TestBands(t *testing.T) {
	for score, want := range map[int]Letter{0: LetterA, 10: LetterA, 11: LetterB, 25: LetterB, 26: LetterC, 50: LetterC, 51: LetterD, 75: LetterD, 76: LetterF, 100: LetterF} {
		if got := bandOf(score); got != want {
			t.Errorf("band(%d) = %s, want %s", score, got, want)
		}
	}
}

// ---- the worked examples of the proposal ----

// unidoc/unipdf/v5 was F (85) with no row above 51. Now: x/image has three called highs: 70 + 5 + 5 = 80, the deciding row.
// Together with x/text there are four called highs across two modules, so the tree rule agrees but does not decide.
func TestWorkedExample_Unipdf(t *testing.T) {
	r := run(Input{Self: self(), Deps: []Row{
		dep("golang.org/x/image", called("GO-2026-0101", "golang.org/x/image", "HIGH"), called("GO-2026-0102", "golang.org/x/image", "HIGH"), called("GO-2026-0103", "golang.org/x/image", "HIGH")),
		dep("golang.org/x/text", called("GO-2026-0201", "golang.org/x/text", "HIGH")),
		dep("github.com/quiet/lib"),
	}})
	if r.Letter != LetterF || r.Score != 80 || r.Pending != nil {
		t.Fatalf("%+v", r)
	}
	if r.Deciding == nil || r.Deciding.Module != "golang.org/x/image" || r.Deciding.Score != 80 || len(r.TreeRows) != 0 {
		t.Fatalf("deciding = %+v, tree = %+v (the row decides; the tree rule agrees without being needed)", r.Deciding, r.TreeRows)
	}
	if !strings.Contains(r.Deciding.Reason, "called high GO-2026-0101 (70)") || !strings.Contains(r.Deciding.Reason, "+10 for 2 more called high or critical advisories") {
		t.Errorf("the reason must show the arithmetic: %q", r.Deciding.Reason)
	}
	if x := row(t, r, "golang.org/x/image"); x.VulnScore != 80 || x.UpkeepScore != 0 || x.Letter != LetterF {
		t.Errorf("%+v", x)
	}
}

// prometheus/client_golang was D (60) from an archived floor, with no row above 31. Now: B (20), deciding row json-iterator.
func TestWorkedExample_ClientGolang(t *testing.T) {
	archived := dep("github.com/json-iterator/go")
	archived.Upkeep = Upkeep{Archived: true, LastRelease: now.AddDate(0, -61, 0)}
	r := run(Input{Self: self(), Deps: []Row{archived, dep("github.com/beorn7/perks"), dep("github.com/cespare/xxhash/v2")}})
	if r.Letter != LetterB || r.Score != 20 || r.Deciding == nil || r.Deciding.Module != "github.com/json-iterator/go" || r.Deciding.Reason != "archived dependency (20)" {
		t.Fatalf("%+v / %+v", r.Letter, r.Deciding)
	}
	if x := row(t, r, "github.com/json-iterator/go"); x.UpkeepState != StateArchived || x.VulnScore != 0 || x.UpkeepScore != 20 {
		t.Errorf("%+v", x)
	}
}

// spf13/cobra was C (26) from the 95th percentile, set by quiet blackfriday. Now: A, nothing found; check.v1 is graph-only.
func TestWorkedExample_Cobra(t *testing.T) {
	quiet := func(m string) Row {
		d := dep(m)
		d.Upkeep = Upkeep{LastRelease: now.AddDate(-5, 0, 0)} // quiet for years, nothing open
		return d
	}
	graphOnly := quiet("gopkg.in/check.v1")
	graphOnly.Findings = []Finding{{ID: "GO-2026-0301", Module: "gopkg.in/check.v1", Severity: "CRITICAL", Reachability: "required", FixedVersion: "v1.0.1"}}
	r := run(Input{Self: self(), Deps: []Row{quiet("github.com/russross/blackfriday/v2"), quiet("github.com/inconshreveable/mousetrap"), graphOnly}})
	if r.Letter != LetterA || r.Score != 0 || r.Deciding != nil {
		t.Fatalf("%+v / %+v", r.Letter, r.Deciding)
	}
	if x := row(t, r, "github.com/russross/blackfriday/v2"); x.UpkeepState != StateFinished || x.Score != 0 {
		t.Errorf("a quiet library with nothing open is finished and scores 0: %+v", x)
	}
	x := row(t, r, "gopkg.in/check.v1")
	if len(x.Findings) != 1 || x.Findings[0].Counted || x.Findings[0].Score != 0 || x.Findings[0].VEX.Justification != "vulnerable_code_not_present" || x.Findings[0].Tier != TierGraphOnly {
		t.Errorf("graph-only: shown, not graded, VEX not present: %+v", x.Findings)
	}
}

// dgrijalva/jwt-go had no report at all. Now: D (70): its own unfixed high advisory, assumed called, beats being archived (35).
func TestWorkedExample_JwtGo(t *testing.T) {
	s := self(Finding{ID: "GO-2020-0017", Module: "github.com/dgrijalva/jwt-go", Severity: "HIGH", AffectedPackages: []string{"github.com/dgrijalva/jwt-go"}})
	s.Module = "github.com/dgrijalva/jwt-go"
	s.Upkeep = Upkeep{Archived: true, LastRelease: now.AddDate(-6, 0, 0)}
	r := run(Input{Self: s})
	if r.Letter != LetterD || r.Score != 70 || r.Deciding == nil || !r.Deciding.Self || !strings.Contains(r.Deciding.Reason, "called high GO-2020-0017 (70)") {
		t.Fatalf("%+v / %+v", r.Letter, r.Deciding)
	}
	x := row(t, r, "github.com/dgrijalva/jwt-go")
	if x.VulnScore != 70 || x.UpkeepScore != 35 || x.UpkeepState != StateArchived {
		t.Errorf("%+v", x)
	}
	f := x.Findings[0]
	if !f.TierAssumed || f.Tier != TierCalled || f.Response.Status != "no_fix" || !strings.Contains(f.Note, "Reachability is assumed") || !strings.Contains(f.Note, "Only if you import github.com/dgrijalva/jwt-go") {
		t.Errorf("the card says the reachability is assumed and names the package: %+v", f)
	}
}

// ---- synthetic cases (task 2.7) ----

func TestImportedCodeAloneCannotReachD(t *testing.T) {
	imp := func(id, sev string) Finding {
		return Finding{ID: id, Module: "example.com/x", Severity: sev, Reachability: "imported", FixedVersion: "v2"}
	}
	for _, c := range []struct {
		f     Finding
		score int
		l     Letter
	}{{imp("A", "HIGH"), 49, LetterC}, {imp("B", "CRITICAL"), 50, LetterC}, {imp("C", "MEDIUM"), 32, LetterC}, {imp("D", "LOW"), 11, LetterB}} {
		r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", c.f)}})
		if r.Score != c.score || r.Letter != c.l {
			t.Errorf("imported %s: %d %s, want %d %s", c.f.Severity, r.Score, r.Letter, c.score, c.l)
		}
	}
	// many imported highs on ONE row are capped at C
	r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", imp("1", "HIGH"), imp("2", "HIGH"), imp("3", "HIGH"), imp("4", "CRITICAL"))}})
	if r.Score != 50 || r.Letter != LetterC {
		t.Errorf("capped at 50: %+v", r.Score)
	}
}

func TestCalledFindingsScore(t *testing.T) {
	for _, c := range []struct {
		sev   string
		score int
		l     Letter
	}{{"CRITICAL", 90, LetterF}, {"HIGH", 70, LetterD}, {"MEDIUM", 45, LetterC}, {"LOW", 15, LetterB}} {
		r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", called("X", "example.com/x", c.sev))}})
		if r.Score != c.score || r.Letter != c.l {
			t.Errorf("called %s: %d %s, want %d %s", c.sev, r.Score, r.Letter, c.score, c.l)
		}
	}
	// one called high is D, two sit at the top of D, three are F
	d2 := run(Input{Self: self(), Deps: []Row{dep("example.com/x", called("1", "example.com/x", "HIGH"), called("2", "example.com/x", "HIGH"))}})
	d3 := run(Input{Self: self(), Deps: []Row{dep("example.com/x", called("1", "example.com/x", "HIGH"), called("2", "example.com/x", "HIGH"), called("3", "example.com/x", "HIGH"))}})
	if d2.Score != 75 || d2.Letter != LetterD || d3.Score != 80 || d3.Letter != LetterF {
		t.Errorf("two called highs %d %s, three %d %s", d2.Score, d2.Letter, d3.Score, d3.Letter)
	}
	// thirty called mediums grade like one: only high and critical advisories add
	var many []Finding
	for i := 0; i < 30; i++ {
		many = append(many, called(string(rune('a'+i%26))+string(rune('A'+i/26)), "example.com/x", "MEDIUM"))
	}
	if r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", many...)}}); r.Score != 45 {
		t.Errorf("30 called mediums = %d", r.Score)
	}
	// the same advisory twice counts once
	if r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", called("1", "example.com/x", "HIGH"), called("1", "example.com/x", "HIGH"))}}); r.Score != 70 {
		t.Errorf("duplicate advisory counted twice: %d", r.Score)
	}
}

func TestKnownExploitedAndTestOnly(t *testing.T) {
	kev := called("K", "example.com/x", "LOW")
	kev.Exploited = true
	if r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", kev)}}); r.Letter != LetterF || r.Score != 76 {
		t.Errorf("a called known-exploited finding is F: %d %s", r.Score, r.Letter)
	}
	testOnly := dep("example.com/x", kev)
	testOnly.TestOnly = ptr(true)
	r := run(Input{Self: self(), Deps: []Row{testOnly}})
	if r.Letter != LetterC || r.Score != 38 || len(r.TreeRows) != 0 {
		t.Errorf("a test-only known-exploited finding lands at C: %d %s tree=%v", r.Score, r.Letter, r.TreeRows)
	}
	// unknown test-only (nil) gets no discount
	unknown := dep("example.com/x", called("H", "example.com/x", "HIGH"))
	if r := run(Input{Self: self(), Deps: []Row{unknown}}); r.Score != 70 {
		t.Errorf("unknown test-only status must not discount: %d", r.Score)
	}
	// a confirmed test-only called critical: halved to 45
	crit := dep("example.com/x", called("C", "example.com/x", "CRITICAL"))
	crit.TestOnly = ptr(true)
	if r := run(Input{Self: self(), Deps: []Row{crit}}); r.Score != 45 || r.Letter != LetterC {
		t.Errorf("test-only critical: %d %s", r.Score, r.Letter)
	}
	// test-only dependencies are left out of the tree counts
	var rows []Row
	for _, m := range []string{"a", "b", "c"} {
		d := dep("example.com/"+m, called("H"+m, "example.com/"+m, "HIGH"))
		d.TestOnly = ptr(true)
		rows = append(rows, d)
	}
	if r := run(Input{Self: self(), Deps: rows}); r.Letter == LetterF || len(r.TreeRows) != 0 {
		t.Errorf("three test-only called highs must not make F: %s %v", r.Letter, r.TreeRows)
	}
}

func TestWholeTreeRules(t *testing.T) {
	// three called highs on three modules: each row is D (70), together F
	rows := []Row{dep("example.com/a", called("1", "example.com/a", "HIGH")), dep("example.com/b", called("2", "example.com/b", "HIGH")), dep("example.com/c", called("3", "example.com/c", "HIGH"))}
	r := run(Input{Self: self(), Deps: rows})
	if r.Letter != LetterF || len(r.TreeRows) != 1 || r.TreeRows[0].Rule != "called_findings" || r.TreeRows[0].Score != 76 || r.Deciding == nil || r.Deciding.Tree != "called_findings" ||
		r.TreeRows[0].Reason != "3 called high or critical findings across 3 modules" {
		t.Fatalf("%+v %+v", r.TreeRows, r.Deciding)
	}
	// splitting one risky dependency into small modules must not lower the letter: one module with 3 -> F (80); three modules -> F (76)
	one := run(Input{Self: self(), Deps: []Row{dep("example.com/a", called("1", "example.com/a", "HIGH"), called("2", "example.com/a", "HIGH"), called("3", "example.com/a", "HIGH"))}})
	if one.Letter != LetterF {
		t.Fatal(one.Letter)
	}
	// five imported highs on five modules: each C (49), together at least D (51)
	var imp []Row
	for _, m := range []string{"a", "b", "c", "d", "e"} {
		imp = append(imp, dep("example.com/"+m, Finding{ID: "I" + m, Module: "example.com/" + m, Severity: "HIGH", Reachability: "imported", FixedVersion: "v2"}))
	}
	r = run(Input{Self: self(), Deps: imp})
	if r.Letter != LetterD || r.Score != 51 || len(r.TreeRows) != 1 || r.TreeRows[0].Rule != "imported_and_called_findings" {
		t.Fatalf("%d %s %+v", r.Score, r.Letter, r.TreeRows)
	}
	// four do not
	if r := run(Input{Self: self(), Deps: imp[:4]}); r.Letter != LetterC || len(r.TreeRows) != 0 {
		t.Errorf("four imported highs: %s %v", r.Letter, r.TreeRows)
	}
	// a tree rule decides only when it raises the letter: the worst row is already F
	r = run(Input{Self: self(), Deps: append(rows, dep("example.com/d", called("4", "example.com/d", "CRITICAL")))})
	if len(r.TreeRows) != 0 || r.Deciding == nil || r.Deciding.Module != "example.com/d" {
		t.Errorf("%+v %+v", r.TreeRows, r.Deciding)
	}
	// a checksum mismatch is F, also from a test-only dependency (integrity applies in full)
	to := dep("example.com/t")
	to.TestOnly = ptr(true)
	r = run(Input{Self: self(), Deps: []Row{to}, ChecksumMismatch: true, ChecksumDetail: "example.com/t v1.0.0"})
	if r.Letter != LetterF || len(r.TreeRows) != 1 || r.TreeRows[0].Rule != "checksum_mismatch" || !strings.Contains(r.TreeRows[0].Reason, "example.com/t") {
		t.Fatalf("%s %+v", r.Letter, r.TreeRows)
	}
}

func TestUpkeepCountsOnlyUpToC(t *testing.T) {
	archivedSelf := self()
	archivedSelf.Upkeep = Upkeep{Archived: true}
	if r := run(Input{Self: archivedSelf}); r.Letter != LetterC || r.Score != 35 {
		t.Errorf("an archived module is at best C: %d %s", r.Score, r.Letter)
	}
	deprecatedSelf := self()
	deprecatedSelf.Upkeep = Upkeep{Deprecated: true, Message: "use example.com/new", LastRelease: now}
	r := run(Input{Self: deprecatedSelf})
	if r.Letter != LetterC || row(t, r, "example.com/app").UpkeepNote != "use example.com/new" || row(t, r, "example.com/app").UpkeepState != StateDeprecated {
		t.Errorf("%+v", r.Rows[0])
	}
	retracted := self()
	retracted.Upkeep = Upkeep{Retracted: true, Message: "published by mistake"}
	if r := run(Input{Self: retracted}); r.Letter != LetterC || !strings.Contains(r.Rows[0].Reason, "retracted") {
		t.Errorf("a retracted version reads as deprecated: %s %q", r.Letter, r.Rows[0].Reason)
	}
	for name, d := range map[string]Row{"archived dep": {Module: "example.com/d", Direct: true, InBuild: ptr(true), Upkeep: Upkeep{Archived: true}},
		"deprecated dep": {Module: "example.com/d", Direct: true, InBuild: ptr(true), Upkeep: Upkeep{Deprecated: true}}} {
		if r := run(Input{Self: self(), Deps: []Row{d}}); r.Letter != LetterB || r.Score != 20 {
			t.Errorf("%s: %d %s, want B 20", name, r.Score, r.Letter)
		}
	}
	// 10 when test-only or not compiled in
	for name, d := range map[string]Row{"test-only": {Module: "example.com/d", TestOnly: ptr(true), Upkeep: Upkeep{Archived: true}}, "not built": {Module: "example.com/d", InBuild: ptr(false), Upkeep: Upkeep{Archived: true}}} {
		if r := run(Input{Self: self(), Deps: []Row{d}}); r.Letter != LetterA || r.Score != 10 {
			t.Errorf("%s: %d %s, want A 10", name, r.Score, r.Letter)
		}
	}
	// unknown build status gets no discount
	if r := run(Input{Self: self(), Deps: []Row{{Module: "example.com/d", Upkeep: Upkeep{Archived: true}}}}); r.Score != 20 {
		t.Errorf("unknown build status: %d", r.Score)
	}
}

func TestUpkeepStates(t *testing.T) {
	old := now.AddDate(-5, 0, 0)
	cases := []struct {
		name string
		row  Row
		want string
	}{
		{"self: released recently", Row{Self: true, Upkeep: Upkeep{LastRelease: now.AddDate(0, -11, 0)}}, StateActive},
		{"self: committed recently, released long ago", Row{Self: true, Upkeep: Upkeep{LastRelease: old, LastActivity: now.AddDate(0, -3, 0)}}, StateActive},
		{"self: quiet 13 months", Row{Self: true, Upkeep: Upkeep{LastRelease: now.AddDate(0, -13, 0), LastActivity: now.AddDate(0, -13, 0)}}, StateFinished},
		{"dependency: released 23 months ago", Row{Upkeep: Upkeep{LastRelease: now.AddDate(0, -23, 0)}}, StateActive},
		{"dependency: released 25 months ago, a recent commit does not make it active", Row{Upkeep: Upkeep{LastRelease: now.AddDate(0, -25, 0), LastActivity: now.AddDate(0, -1, 0)}}, StateFinished},
		{"quiet with an unfixed advisory is parked", Row{Upkeep: Upkeep{LastRelease: old}, Findings: []Finding{{ID: "X", Severity: "LOW", Reachability: "required"}}}, StateParked},
		{"quiet with only fixed advisories is finished", Row{Upkeep: Upkeep{LastRelease: old}, Findings: []Finding{{ID: "X", Severity: "LOW", FixedVersion: "v2"}}}, StateFinished},
		{"archived beats deprecated and active", Row{Upkeep: Upkeep{Archived: true, Deprecated: true, LastRelease: now}}, StateArchived},
		{"missing data is unknown, not finished", Row{Upkeep: Upkeep{Missing: true}}, StateUnknown},
		{"an archived row is archived even when its data is partly missing", Row{Upkeep: Upkeep{Archived: true, Missing: true}}, StateArchived},
	}
	for _, c := range cases {
		if got := upkeepState(c.row, now); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestUnknownSeverityIsEstimatedAndMarked(t *testing.T) {
	r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", called("U", "example.com/x", "UNKNOWN"))}})
	if r.Letter != LetterC || r.Score != 45 || !r.Estimated {
		t.Fatalf("unknown severity is scored as medium and the letter is marked: %d %s %v", r.Score, r.Letter, r.Estimated)
	}
	if f := row(t, r, "example.com/x").Findings[0]; !f.Estimated || !strings.Contains(f.Note, "scored as medium") {
		t.Errorf("%+v", f)
	}
	// an unknown severity elsewhere marks even a letter that a known severity decides
	r = run(Input{Self: self(), Deps: []Row{dep("example.com/x", called("H", "example.com/x", "HIGH")), dep("example.com/y", called("U", "example.com/y", ""))}})
	// the unknown severity on y could be a critical: the D could be an F, so the letter carries the star
	if !r.Estimated || r.Letter != LetterD {
		t.Errorf("%s %v", r.Letter, r.Estimated)
	}
}

func TestUndeterminedReachabilityIsScoredAsCalled(t *testing.T) {
	r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", Finding{ID: "R", Module: "example.com/x", Severity: "HIGH", FixedVersion: "v2"})}})
	f := row(t, r, "example.com/x").Findings[0]
	if r.Letter != LetterD || !f.TierAssumed || f.Tier != TierCalled || !strings.Contains(f.Note, "not determined") {
		t.Errorf("%s %+v", r.Letter, f)
	}
}

func TestTiesDecideByVulnerabilityThenSelfThenDirectThenPath(t *testing.T) {
	// all four rows score 20 or the same value: vulnerability beats upkeep
	archived := Row{Module: "example.com/aaa", Direct: true, InBuild: ptr(true), Upkeep: Upkeep{Archived: true}} // upkeep 20
	vuln := dep("example.com/zzz", called("V", "example.com/zzz", "LOW"))
	vuln.Findings[0].Severity = "LOW" // 15, not 20: make it tie
	vuln.Findings = []Finding{{ID: "V", Module: "example.com/zzz", Severity: "LOW", Reachability: "called", FixedVersion: "v2"},
		{ID: "W", Module: "example.com/zzz", Severity: "HIGH", Reachability: "imported", FixedVersion: "v2"}} // imported high 49: too high; use low pair instead
	vuln.Findings = []Finding{{ID: "V", Module: "example.com/zzz", Severity: "CRITICAL", Reachability: "imported", FixedVersion: "v2"}}
	vuln.Upkeep = Upkeep{LastRelease: now}
	// imported critical = 50; make upkeep tie impossible at 50, so compare the rule directly
	a := RowResult{Module: "m/b", VulnScore: 20, UpkeepScore: 0, Score: 20}
	b := RowResult{Module: "m/a", VulnScore: 0, UpkeepScore: 20, Score: 20}
	if !preferVuln(a, b) || preferVuln(b, a) {
		t.Error("a vulnerability beats upkeep")
	}
	selfRow := RowResult{Module: "m/z", Self: true, VulnScore: 20, Score: 20}
	dirRow := RowResult{Module: "m/a", Direct: true, VulnScore: 20, Score: 20}
	if !preferVuln(selfRow, dirRow) {
		t.Error("then the module itself")
	}
	indirect := RowResult{Module: "m/a", VulnScore: 20, Score: 20}
	if !preferVuln(dirRow, indirect) {
		t.Error("then a direct dependency")
	}
	p, q := RowResult{Module: "m/a", VulnScore: 20, Score: 20}, RowResult{Module: "m/b", VulnScore: 20, Score: 20}
	if !preferVuln(p, q) || preferVuln(q, p) {
		t.Error("then alphabetical by module path")
	}
	_ = archived
	_ = vuln
}

// A failed vulnerability scan carries its reason code and kind into the Pending, as their own JSON fields; no other
// Pending has them.
func TestPending_ScanFailureCodeAndKind(t *testing.T) {
	failed := run(Input{Self: self(), Deps: []Row{dep("example.com/x")}, Checks: Checks{
		VulnScanFailed: true, VulnScanReason: "multiple_mains: b.go:3:6: main redeclared in this block",
		VulnScanCode: "multiple_mains", VulnScanKind: "permanent",
	}})
	if failed.Pending == nil || failed.Pending.Check != "vulnerability_scan" || failed.Pending.Code != "multiple_mains" || failed.Pending.Kind != "permanent" {
		t.Fatalf("Pending = %+v, want vulnerability_scan with code multiple_mains and kind permanent", failed.Pending)
	}
	if want := "the vulnerability scan did not run: multiple_mains: b.go:3:6: main redeclared in this block"; failed.Pending.Reason != want {
		t.Errorf("Reason = %q, want %q: the text keeps its code prefix", failed.Pending.Reason, want)
	}
	out, err := json.Marshal(failed.Pending)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"code":"multiple_mains","kind":"permanent"`) {
		t.Errorf("JSON = %s, want code and kind", out)
	}

	// no code and no kind: a failure that is not a typed scan failure
	untyped := run(Input{Self: self(), Deps: []Row{dep("example.com/x")}, Checks: Checks{VulnScanFailed: true, VulnScanReason: "offline"}})
	// every other check
	others := map[string]Input{
		"scan_incomplete": {Self: self(), Deps: []Row{dep("example.com/x")}, Checks: Checks{ScanTimedOut: true}},
		"checksum":        {Self: self(), Checks: Checks{ChecksumUnverified: true}},
		"known_exploited": {Self: self(), Deps: []Row{dep("example.com/x", called("M", "example.com/x", "MEDIUM"))}, Checks: Checks{KEVUnchecked: 1}},
	}
	pendings := map[string]*Pending{"vulnerability_scan without a code": untyped.Pending}
	for name, in := range others {
		// the scan's code and kind never leak into another check
		in.Checks.VulnScanCode, in.Checks.VulnScanKind = "multiple_mains", "permanent"
		pendings[name] = run(in).Pending
	}
	for name, p := range pendings {
		if p == nil {
			t.Errorf("%s: not Pending", name)
			continue
		}
		out, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), `"code"`) || strings.Contains(string(out), `"kind"`) {
			t.Errorf("%s: JSON = %s, want neither code nor kind", name, out)
		}
	}
}

// A grade whose analysis skipped the called pass, and for which today's facts mean it could change the letter, has no
// letter: the imported finding would otherwise keep the letter a called one would not get.
func TestPending_CalledPassStale(t *testing.T) {
	in := Input{Self: self(), Deps: []Row{dep("example.com/x", Finding{ID: "M", Module: "example.com/x", Severity: "MEDIUM", Reachability: "imported", FixedVersion: "v9.9.9"})},
		Checks: Checks{CalledPassStale: "the analysis skipped govulncheck's called pass: analyse again"}}
	g := run(in)
	if g.Pending == nil || g.Pending.Check != "called_pass" || g.Letter != "" || !strings.Contains(g.Pending.Reason, "analyse again") {
		t.Fatalf("grade = %+v, pending = %+v, want Pending on called_pass and no letter", g, g.Pending)
	}
	in.Checks.CalledPassStale = ""
	if g := run(in); g.Pending != nil || g.Letter == "" {
		t.Errorf("without the stale mark the grade has a letter: %+v", g)
	}
	// a scan that failed or did not finish is named first
	in.Checks.CalledPassStale, in.Checks.ScanTimedOut = "stale", true
	if g := run(in); g.Pending == nil || g.Pending.Check != "scan_incomplete" {
		t.Errorf("pending = %+v, want scan_incomplete first", g.Pending)
	}
}

func TestPending(t *testing.T) {
	selfArchived := self()
	selfArchived.Upkeep = Upkeep{Archived: true}
	cases := []struct {
		name   string
		in     Input
		check  string
		reason string
		known  string
	}{
		{"vulnerability scan failed", Input{Self: selfArchived, Deps: []Row{dep("example.com/x")}, Checks: Checks{VulnScanFailed: true, VulnScanReason: "govulncheck: loading packages"}}, "vulnerability_scan", "govulncheck: loading packages", "Archived"},
		{"scan timed out", Input{Self: self(), Deps: []Row{dep("example.com/x")}, Checks: Checks{ScanTimedOut: true}}, "scan_incomplete", "did not finish", ""},
		{"own status failed", Input{Self: self(), Checks: Checks{SelfStatusFailed: true, SelfStatusReason: "GitHub rate limit"}}, "module_status", "GitHub rate limit", ""},
		{"own advisories failed", Input{Self: self(), Checks: Checks{SelfAdvisoriesFailed: true}}, "module_advisories", "own advisories", ""},
		{"a dependency's maintenance data is missing and could beat the worst row", Input{Self: self(), Deps: []Row{{Module: "example.com/m", Direct: true, InBuild: ptr(true), Upkeep: Upkeep{Missing: true}}}}, "dependency_maintenance", "example.com/m", ""},
	}
	for _, c := range cases {
		r := run(c.in)
		if r.Pending == nil || r.Letter != "" || r.Pending.Check != c.check || !strings.Contains(r.Pending.Reason, c.reason) {
			t.Errorf("%s: %+v letter=%q", c.name, r.Pending, r.Letter)
			continue
		}
		if c.known != "" && (len(r.Pending.Known) == 0 || r.Pending.Known[0] != c.known) {
			t.Errorf("%s: known %v, want %s first (what we do know)", c.name, r.Pending.Known, c.known)
		}
	}

	// missing maintenance data does NOT make it Pending when it cannot change the letter: the worst row is already worse (45 > 20)
	worse := Input{Self: self(), Deps: []Row{dep("example.com/x", called("M", "example.com/x", "MEDIUM")), {Module: "example.com/m", Direct: true, InBuild: ptr(true), Upkeep: Upkeep{Missing: true}}}}
	if r := run(worse); r.Pending != nil || r.Letter != LetterC {
		t.Errorf("%+v %s", r.Pending, r.Letter)
	}
	// ... and for a test-only dependency the worst it could be is 10, which does not beat a 12
	small := Input{Self: self(), Deps: []Row{dep("example.com/x", called("L", "example.com/x", "LOW")), {Module: "example.com/m", TestOnly: ptr(true), Upkeep: Upkeep{Missing: true}}}}
	if r := run(small); r.Pending != nil || r.Letter != LetterB {
		t.Errorf("%+v %s", r.Pending, r.Letter)
	}
	// a module with no dependencies is not Pending: it has nothing to scan (and its own row is graded)
	if r := run(Input{Self: selfArchived}); r.Pending != nil || r.Letter != LetterC {
		t.Errorf("%+v %s", r.Pending, r.Letter)
	}
	// own advisories skipped (no module version): not a failure, said plainly
	if r := run(Input{Self: self(), Checks: Checks{SelfAdvisoriesSkipped: true}}); r.Pending != nil || len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "no module version") {
		t.Errorf("%+v %v", r.Pending, r.Notes)
	}
}

func TestResponseContext(t *testing.T) {
	two := now.Add(-2 * 24 * time.Hour)
	twenty := now.Add(-20 * 24 * time.Hour)
	mk := func(fixedAt *time.Time, fixed string, exploited bool) Result {
		f := Finding{ID: "GO-2026-0777", Module: "golang.org/x/net", Severity: "HIGH", Reachability: "called", FixedVersion: fixed, FixReleasedAt: fixedAt, FixDateSource: "module_proxy", Exploited: exploited}
		return run(Input{Self: self(), Deps: []Row{dep("golang.org/x/net", f)}, History: map[string]*scanner.ResponseHistory{
			"golang.org/x/net": {Dependency: "golang.org/x/net", MedianDays: 30, Samples: 3, From: time.Date(2025, 1, 3, 0, 0, 0, 0, time.UTC), To: time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)}}})
	}
	get := func(r Result) Response { return row(t, r, "golang.org/x/net").Findings[0].Response }

	r := mk(&two, "v0.60.0", false)
	if resp := get(r); resp.Status != "within_window" || resp.Text != "Fix released 8 October · response window ends 22 October." || resp.DaysSinceFix != 2 ||
		resp.History != "Historically adopted comparable fixes in about 30 days (3 fixes, Jan 2025 to Sep 2026)." {
		t.Errorf("%+v", resp)
	}
	// the response label never changes the letter: F while the window is open, F after
	if r.Letter != LetterD {
		t.Errorf("one called high is D: %s", r.Letter)
	}
	if resp := get(mk(&twenty, "v0.60.0", false)); resp.Status != "past_window" || resp.Text != "Fix available for 20 days; the graded version still requires the affected golang.org/x/net version." {
		t.Errorf("%+v", resp)
	}
	if resp := get(mk(nil, "v0.60.0", false)); resp.Status != "date_unknown" || resp.Text != "Fix release date unavailable." || resp.WindowEnds != nil {
		t.Errorf("no deadline when the date is unknown: %+v", resp)
	}
	if resp := get(mk(nil, "", false)); resp.Status != "no_fix" || resp.Text != "No fix available." || resp.WindowEnds != nil {
		t.Errorf("no clock without a fix: %+v", resp)
	}
	if resp := get(mk(&two, "v0.60.0", true)); resp.Status != "exploited" || strings.Contains(resp.Text, "window") {
		t.Errorf("a known-exploited finding has no response label: %+v", resp)
	}
	// without history the label says so
	noHist := run(Input{Self: self(), Deps: []Row{dep("golang.org/x/net", Finding{ID: "X", Module: "golang.org/x/net", Severity: "HIGH", Reachability: "called", FixedVersion: "v1", FixReleasedAt: &two})}})
	if resp := row(t, noHist, "golang.org/x/net").Findings[0].Response; resp.History != "Not enough response history." {
		t.Errorf("%+v", resp)
	}
	// another year is named
	old := time.Date(2025, 12, 28, 0, 0, 0, 0, time.UTC)
	oldHist := run(Input{Self: self(), Deps: []Row{dep("golang.org/x/net", Finding{ID: "X", Module: "golang.org/x/net", Severity: "HIGH", Reachability: "called", FixedVersion: "v1", FixReleasedAt: &old})}})
	if resp := row(t, oldHist, "golang.org/x/net").Findings[0].Response; !strings.Contains(resp.Text, "Fix available for") {
		t.Errorf("%+v", resp)
	}
}

func TestDeterministicWhateverTheOrder(t *testing.T) {
	var deps []Row
	for i, m := range []string{"example.com/a", "example.com/b", "example.com/c", "example.com/d", "example.com/e", "example.com/f"} {
		deps = append(deps, dep(m, called("F"+m, m, []string{"HIGH", "MEDIUM", "LOW", "HIGH", "CRITICAL", "MEDIUM"}[i])))
	}
	want := run(Input{Self: self(), Deps: deps})
	rnd := rand.New(rand.NewSource(3))
	for i := 0; i < 50; i++ {
		shuffled := append([]Row(nil), deps...)
		rnd.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		if got := run(Input{Self: self(), Deps: shuffled}); !reflect.DeepEqual(got, want) {
			t.Fatalf("the grade depends on the order of the input:\n%+v\n%+v", got.Rows, want.Rows)
		}
	}
}

func TestVEXStatuses(t *testing.T) {
	r := run(Input{Self: self(), Deps: []Row{dep("example.com/x",
		Finding{ID: "C", Severity: "LOW", Reachability: "called", FixedVersion: "v2"},
		Finding{ID: "I", Severity: "LOW", Reachability: "imported", FixedVersion: "v2"},
		Finding{ID: "G", Severity: "LOW", Reachability: "required", FixedVersion: "v2"})}})
	got := map[string]VEXStatus{}
	for _, f := range row(t, r, "example.com/x").Findings {
		got[f.ID] = f.VEX
	}
	want := map[string]VEXStatus{
		"C": {Status: "affected"},
		"I": {Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path"},
		"G": {Status: "not_affected", Justification: "vulnerable_code_not_present"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%v", got)
	}
}

// The same vulnerability under a Go and a GitHub identifier counts once (found on the real dgrijalva/jwt-go).
func TestSameVulnerabilityUnderTwoIDsCountsOnce(t *testing.T) {
	a := Finding{ID: "GHSA-w73w-5m7g-f7qc", Aliases: []string{"CVE-2020-26160"}, Severity: "HIGH"}
	b := Finding{ID: "GO-2020-0017", Aliases: []string{"CVE-2020-26160", "GHSA-w73w-5m7g-f7qc"}, Severity: "HIGH", AffectedPackages: []string{"github.com/dgrijalva/jwt-go"}}
	for _, order := range [][]Finding{{a, b}, {b, a}} {
		s := self(order...)
		s.Module = "github.com/dgrijalva/jwt-go"
		s.Upkeep = Upkeep{Archived: true}
		r := run(Input{Self: s})
		if r.Score != 70 || r.Letter != LetterD {
			t.Fatalf("one vulnerability, two IDs: %d %s (want 70 D, not 75)", r.Score, r.Letter)
		}
		x := row(t, r, s.Module)
		if len(x.Findings) != 1 || x.Findings[0].ID != "GO-2020-0017" || !reflect.DeepEqual(x.Findings[0].Aliases, []string{"CVE-2020-26160", "GHSA-w73w-5m7g-f7qc"}) {
			t.Fatalf("one merged finding named by its Go ID: %+v", x.Findings)
		}
	}
	// two different advisories that merely share a module still count separately
	r := run(Input{Self: self(Finding{ID: "GO-1", Severity: "HIGH"}, Finding{ID: "GO-2", Severity: "HIGH"})})
	if r.Score != 75 {
		t.Errorf("distinct advisories: %d", r.Score)
	}
	// the merge keeps the worst severity and reachability of the group
	m := mergeAdvisories([]Finding{{ID: "GO-1", Aliases: []string{"CVE-1"}, Severity: "", Reachability: "imported"}, {ID: "GHSA-1", Aliases: []string{"CVE-1"}, Severity: "CRITICAL", Reachability: "called", Exploited: true}})
	if len(m) != 1 || m[0].Severity != "CRITICAL" || m[0].Reachability != "called" || !m[0].Exploited {
		t.Errorf("%+v", m)
	}
}

// An unreadable archived flag cannot change a letter that is already worse than the worst upkeep score (35).
func TestOwnStatusFailureOnlyPendingWhenItCouldChangeTheLetter(t *testing.T) {
	checks := Checks{SelfStatusFailed: true, SelfStatusReason: "GitHub rate limit"}
	if r := run(Input{Self: self(), Checks: checks}); r.Pending == nil || r.Pending.Check != "module_status" {
		t.Errorf("an A could still become a C: %+v", r.Pending)
	}
	bad := self(Finding{ID: "GO-1", Severity: "HIGH", Reachability: "called"})
	bad.Upkeep.Missing = true
	if r := run(Input{Self: bad, Checks: checks}); r.Pending != nil || r.Letter != LetterD {
		t.Errorf("a D (70) is decided whatever the archived flag says: %+v %s", r.Pending, r.Letter)
	}
	if r := run(Input{Self: bad, Checks: Checks{SelfAdvisoriesFailed: true}}); r.Pending == nil {
		t.Error("an unread advisory list can always change the letter")
	}
}

// F35: a failed severity lookup on one alias is not Pending once another alias of the same vulnerability supplies a severity.
func TestMergeAdvisories_LookupFailureDroppedWhenAnAliasHasSeverity(t *testing.T) {
	a := Finding{ID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2026-1"}, SeverityLookupFailed: true, Reachability: "called"}
	b := Finding{ID: "GO-2026-1", Aliases: []string{"CVE-2026-1"}, Severity: "LOW", Reachability: "called"}
	for _, in := range [][]Finding{{a, b}, {b, a}} {
		m := mergeAdvisories(in)
		if len(m) != 1 || m[0].SeverityLookupFailed || m[0].Severity != "LOW" {
			t.Errorf("%+v", m)
		}
	}
	// both unknown and one failed: still failed
	c := Finding{ID: "GO-2026-1", Aliases: []string{"CVE-2026-1"}, Reachability: "called"}
	if m := mergeAdvisories([]Finding{a, c}); len(m) != 1 || !m[0].SeverityLookupFailed {
		t.Errorf("%+v", m)
	}
	r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", a, b)}})
	if r.Pending != nil {
		t.Errorf("a severity is known, so not Pending: %+v", r.Pending)
	}
}

// The fix's age when the scanned version was released is said next to the age to the scan date.
func TestResponseContext_FixAgeAtRelease(t *testing.T) {
	fixed := now.Add(-120 * 24 * time.Hour)
	released := now.Add(-33 * 24 * time.Hour) // the fix had existed 87 days
	after := now.Add(-200 * 24 * time.Hour)   // the version predates the fix
	mk := func(rel *time.Time) Response {
		f := Finding{ID: "GO-2026-0777", Module: "golang.org/x/net", Severity: "HIGH", Reachability: "called", FixedVersion: "v0.60.0", FixReleasedAt: &fixed, FixDateSource: "module_proxy"}
		r := run(Input{Self: self(), SelfReleasedAt: rel, Deps: []Row{dep("golang.org/x/net", f)}})
		return row(t, r, "golang.org/x/net").Findings[0].Response
	}
	resp := mk(&released)
	if resp.FixAgeAtReleaseDays != 87 || resp.DaysSinceFix != 120 ||
		resp.Text != "Fix available for 87 days before this version was released (120 days to the scan date); the graded version still requires the affected golang.org/x/net version." {
		t.Errorf("%+v", resp)
	}
	for name, rel := range map[string]*time.Time{"unknown": nil, "fix after release": &after} {
		if r := mk(rel); r.FixAgeAtReleaseDays != 0 || strings.Contains(r.Text, "before this version") {
			t.Errorf("%s: %+v", name, r)
		}
	}
	b, _ := json.Marshal(mk(nil))
	if strings.Contains(string(b), "fix_age_at_release_days") {
		t.Errorf("omitted when unknown: %s", b)
	}
	b, _ = json.Marshal(resp)
	if !strings.Contains(string(b), `"fix_age_at_release_days":87`) {
		t.Errorf("%s", b)
	}
}

// With --called-pass never every finding is imported, so the letter is a floor: the grade says so, for a gate that reads
// only the letter.
func TestNote_CalledPassNeverIsAFloor(t *testing.T) {
	in := Input{Self: self(), Deps: []Row{dep("example.com/x")}}
	if g := run(in); strings.Contains(strings.Join(g.Notes, "\n"), "called pass") {
		t.Errorf("notes without the mode: %v", g.Notes)
	}
	in.Checks.CalledPassNever = true
	g := run(in)
	if !strings.Contains(strings.Join(g.Notes, "\n"), "this letter is a floor") {
		t.Errorf("notes = %v, want one that says the letter is a floor", g.Notes)
	}
}
