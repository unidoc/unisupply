package grade

import (
	"encoding/json"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"
)

func fnd(id, sev, reach string) Finding {
	return Finding{ID: id, Module: "example.com/x", Severity: sev, Reachability: reach, FixedVersion: "v2"}
}

// 1 InBuild=false ignored for vuln scoring
func TestRegression_NotBuiltRowIsGraded(t *testing.T) {
	d := dep("example.com/x", fnd("H", "HIGH", ""))
	d.InBuild = ptr(false)
	r := run(Input{Self: self(), Deps: []Row{d}})
	if r.Letter != LetterA {
		t.Errorf("not-built module with undetermined reachability graded %s (%d)", r.Letter, r.Score)
	}
}

// 2 VulnScore overflow
func TestRegression_Overflow(t *testing.T) {
	var fs []Finding
	for i := 0; i < 8; i++ {
		fs = append(fs, fnd(string(rune('a'+i)), "CRITICAL", "called"))
	}
	r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", fs...)}})
	x := row(t, r, "example.com/x")
	if x.VulnScore > 100 {
		t.Errorf("VulnScore %d > 100 (score %d) reason %q", x.VulnScore, x.Score, x.Reason)
	}
}

// 3 imported further bonus
func TestRegression_ImportedFurther(t *testing.T) {
	r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", fnd("a", "HIGH", "imported"), fnd("b", "HIGH", "imported"))}})
	if r.Score != 49 {
		t.Errorf("two imported highs score %d, table says 49 (further bonus is called-only); reason %q", r.Score, r.Deciding.Reason)
	}
}

// 4 KEV order dependence
func TestRegression_KEVOrder(t *testing.T) {
	k1 := fnd("K1", "LOW", "called")
	k1.Exploited = true
	k2 := fnd("K2", "", "called")
	k2.Exploited = true
	a := run(Input{Self: self(), Deps: []Row{dep("example.com/x", k1, k2)}})
	b := run(Input{Self: self(), Deps: []Row{dep("example.com/x", k2, k1)}})
	if a.Deciding.Reason != b.Deciding.Reason || a.Estimated != b.Estimated {
		t.Errorf("order dependent: %q est=%v vs %q est=%v", a.Deciding.Reason, a.Estimated, b.Deciding.Reason, b.Estimated)
	}
}

// 5 Estimated on non-C letters
func TestRegression_EstimatedNotC(t *testing.T) {
	k := fnd("K", "", "called")
	k.Exploited = true
	r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", k)}})
	if r.Letter == LetterF && r.Estimated {
		t.Errorf("F marked estimated (C*)")
	}
	d := dep("example.com/y", fnd("U", "", "called"))
	d.TestOnly = ptr(true)
	r = run(Input{Self: self(), Deps: []Row{d}})
	// the star means "the letter would change if the severity were different": a test-only unknown called finding is a B
	// that a critical would make a C, so it IS marked; an F by the KEV floor above is not
	if r.Letter != LetterB || !r.Estimated {
		t.Errorf("letter %s estimated=%v, want B*", r.Letter, r.Estimated)
	}
}

// 5b estimated tie with a known row
func TestRegression_EstimatedTie(t *testing.T) {
	a := dep("example.com/a", fnd("U", "", "called")) // 45 estimated
	b := dep("example.com/b", fnd("M", "MEDIUM", "called"))
	for _, deps := range [][]Row{{a, b}, {b, a}} {
		r := run(Input{Self: self(), Deps: deps})
		// the star follows the estimate, not the tiebreak: if the unknown severity on a were critical the letter would be F
		if !r.Estimated {
			t.Errorf("a could be critical: the C must carry the star in every order")
		}
		if r.Deciding.Module != "example.com/b" {
			t.Errorf("the row that does not rest on an estimate decides the tie, whatever the module names (deciding %s)", r.Deciding.Module)
		}
	}
}

// 6 self row Upkeep.Missing without SelfStatusFailed
func TestRegression_SelfMissing(t *testing.T) {
	s := self()
	s.Upkeep = Upkeep{Missing: true}
	r := run(Input{Self: s})
	if r.Pending == nil {
		t.Errorf("self upkeep missing but not pending, letter %s", r.Letter)
	}
}

// 7 pending when letter can't change
func TestRegression_PendingLetterUnchanged(t *testing.T) {
	m := Row{Module: "example.com/m", Direct: true, InBuild: ptr(true), Upkeep: Upkeep{Missing: true}}
	r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", fnd("L", "LOW", "called")), m}}) // B (15); missing could be 20 = still B
	if r.Pending != nil {
		t.Errorf("pending although B stays B: %+v", r.Pending)
	}
	r = run(Input{Self: self(), Deps: []Row{dep("example.com/x", fnd("L", "LOW", "imported")), {Module: "example.com/m", TestOnly: ptr(true), Upkeep: Upkeep{Missing: true}}}})
	_ = r
	r = run(Input{Self: self(), Deps: []Row{dep("example.com/x", fnd("L", "LOW", "called")), {Module: "example.com/m", TestOnly: ptr(true), Upkeep: Upkeep{Missing: true}}}})
}

// 8 Pending when worst is known upkeep-missing row
func TestRegression_KnownFactsOmitsVuln(t *testing.T) {
	m := dep("example.com/m", fnd("H", "HIGH", "called"))
	m.Upkeep = Upkeep{Missing: true}
	r := run(Input{Self: self(), Deps: []Row{m}, Checks: Checks{ScanTimedOut: true}})
	if len(r.Pending.Known) == 0 {
		t.Errorf("a known called high (70) is omitted from Known because the row's upkeep is missing")
	}
}

// 9 nil input
func TestRegression_Nil(t *testing.T) {
	defer func() {
		if recover() != nil {
			t.Errorf("Grade(nil) panics")
		}
	}()
	Grade(nil)
}

// 10 reachability case in merge
func TestRegression_MergeReachCase(t *testing.T) {
	m := mergeAdvisories([]Finding{{ID: "GO-1", Aliases: []string{"C"}, Severity: "HIGH", Reachability: "Called"}, {ID: "GO-2", Aliases: []string{"C"}, Severity: "HIGH", Reachability: "imported"}})
	r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", m...)}})
	if r.Score != 70 {
		t.Errorf("score %d", r.Score)
	}
}

// Real tied rows through Grade: a vulnerability beats upkeep, then the module itself, then a direct dependency, then the
// module path, whatever the order of the input.
func TestRegression_TiesThroughGrade(t *testing.T) {
	a := Row{Module: "example.com/b", Direct: true, InBuild: ptr(true), Findings: []Finding{{ID: "1", Severity: "LOW", Reachability: "called", FixedVersion: "v2"}}}
	b := Row{Module: "example.com/a", InBuild: ptr(true), Findings: []Finding{{ID: "2", Severity: "LOW", Reachability: "called", FixedVersion: "v2"}}}
	for i := 0; i < 20; i++ {
		deps := []Row{a, b}
		rand.New(rand.NewSource(int64(i))).Shuffle(len(deps), func(x, y int) { deps[x], deps[y] = deps[y], deps[x] })
		r := run(Input{Self: self(), Deps: deps})
		if r.Rows[0].Module != "example.com/b" || r.Rows[1].Module != "example.com/a" {
			t.Fatalf("a direct dependency must come before an indirect one at the same score: %s, %s", r.Rows[0].Module, r.Rows[1].Module)
		}
	}
	// the same row: vulnerability score equals upkeep score (both 20); the reason names the vulnerability
	tie := Row{Module: "example.com/t", Direct: true, InBuild: ptr(true), Upkeep: Upkeep{Archived: true}, Findings: []Finding{{ID: "1", Severity: "HIGH", Reachability: "imported", FixedVersion: "v2"}}}
	tie.Findings[0].Severity = "LOW" // imported low 11 < 20: upkeep wins here, text says archived
	r := run(Input{Self: self(), Deps: []Row{tie}})
	if r.Rows[0].Reason != "archived dependency (20)" {
		t.Errorf("%q", r.Rows[0].Reason)
	}
}

// Findings within a row in any order give the same result.
func TestRegression_FindingOrderWithinARow(t *testing.T) {
	fs := []Finding{fnd("a", "HIGH", "called"), fnd("b", "LOW", "called"), fnd("c", "", "called"), fnd("d", "CRITICAL", "imported"), fnd("e", "MEDIUM", "called")}
	fs[1].Exploited, fs[4].Exploited = true, true
	want := run(Input{Self: self(), Deps: []Row{dep("example.com/x", fs...)}})
	rnd := rand.New(rand.NewSource(7))
	for i := 0; i < 50; i++ {
		sh := append([]Finding(nil), fs...)
		rnd.Shuffle(len(sh), func(x, y int) { sh[x], sh[y] = sh[y], sh[x] })
		got := run(Input{Self: self(), Deps: []Row{dep("example.com/x", sh...)}})
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("findings order changed the result:\n%+v\n%+v", got.Deciding, want.Deciding)
		}
	}
}

// A confirmed-not-built row also stays out of the whole-tree counts.
func TestRegression_NotBuiltStaysOutOfTreeRules(t *testing.T) {
	var deps []Row
	for _, m := range []string{"a", "b", "c"} {
		d := dep("example.com/"+m, fnd("H"+m, "HIGH", "called"))
		d.InBuild = ptr(false)
		deps = append(deps, d)
	}
	if r := run(Input{Self: self(), Deps: deps}); r.Letter != LetterA || len(r.TreeRows) != 0 {
		t.Errorf("%s %v", r.Letter, r.TreeRows)
	}
}

// A checksum mismatch is never lost: when another row already scores F, there is no tree row but the result says so.
func TestRegression_ChecksumMismatchSurvivesAnF(t *testing.T) {
	r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", fnd("C", "CRITICAL", "called"))}, ChecksumMismatch: true, ChecksumDetail: "example.com/t v1.0.0"})
	if r.Letter != LetterF || len(r.TreeRows) != 0 {
		t.Fatalf("%s %v", r.Letter, r.TreeRows)
	}
	if !r.ChecksumMismatch || r.ChecksumDetail != "example.com/t v1.0.0" || len(r.Notes) != 1 {
		t.Errorf("%+v %v", r.ChecksumMismatch, r.Notes)
	}
	// when the rule is what decides, it is the tree row, with no duplicate note
	r = run(Input{Self: self(), ChecksumMismatch: true})
	if len(r.TreeRows) != 1 || len(r.Notes) != 0 || !r.ChecksumMismatch {
		t.Errorf("%v %v", r.TreeRows, r.Notes)
	}
}

// A row whose upkeep could not be read has no letter when that could change it (it must not read as a clean A).
func TestRegression_UnreadUpkeepRowHasNoLetter(t *testing.T) {
	m := dep("example.com/m")
	m.Upkeep = Upkeep{Missing: true}
	r := run(Input{Self: self(), Deps: []Row{m}})
	x := row(t, r, "example.com/m")
	if x.Letter != "" || x.UpkeepState != StateUnknown {
		t.Errorf("a clean A for an unread row: %q %s", x.Letter, x.UpkeepState)
	}
	// a row whose vulnerability score is already past what upkeep could make it keeps its letter
	h := dep("example.com/h", fnd("H", "HIGH", "called"))
	h.Upkeep = Upkeep{Missing: true}
	if x := row(t, run(Input{Self: self(), Deps: []Row{h}}), "example.com/h"); x.Letter != LetterD {
		t.Errorf("%q", x.Letter)
	}
	// a test-only row could only be 10: still an A, so it keeps it
	to := dep("example.com/t")
	to.TestOnly, to.Upkeep = ptr(true), Upkeep{Missing: true}
	if x := row(t, run(Input{Self: self(), Deps: []Row{to}}), "example.com/t"); x.Letter != LetterA {
		t.Errorf("%q", x.Letter)
	}
}

func TestRegression_KEVUncheckedIsPending(t *testing.T) {
	r := run(Input{Self: self(), Checks: Checks{KEVUnchecked: 2}})
	if r.Pending == nil || r.Pending.Check != "known_exploited" || r.Letter != "" {
		t.Errorf("a called finding on the KEV list is an F: with the catalog unread the grade is Pending: %+v", r.Pending)
	}
	// when the letter is already F the catalog cannot change it
	f := run(Input{Self: self(), Deps: []Row{dep("example.com/x", fnd("C", "CRITICAL", "called"))}, Checks: Checks{KEVUnchecked: 1}})
	if f.Pending != nil || f.Letter != LetterF {
		t.Errorf("%+v %s", f.Pending, f.Letter)
	}
}

func TestRegression_ChecksumUnverifiedIsPending(t *testing.T) {
	r := run(Input{Self: self(), Checks: Checks{ChecksumUnverified: true}})
	if r.Pending == nil || r.Pending.Check != "checksum" {
		t.Errorf("%+v", r.Pending)
	}
	if f := run(Input{Self: self(), ChecksumMismatch: true, Checks: Checks{ChecksumUnverified: true}}); f.Pending != nil || f.Letter != LetterF {
		t.Errorf("a mismatch that is known is an F: %+v %s", f.Pending, f.Letter)
	}
}

func TestRegression_NotAssessedRowsAreNotFinished(t *testing.T) {
	s := self()
	s.Upkeep = Upkeep{NotAssessed: true}
	x := row(t, run(Input{Self: s}), "example.com/app")
	if x.UpkeepState != StateNotAssessed || x.Reason != "not assessed" || x.Letter != LetterA {
		t.Errorf("%+v", x)
	}
}

func TestRegression_StdlibVersionNote(t *testing.T) {
	std := Row{Module: "stdlib", Direct: true, Findings: []Finding{{ID: "GO-1", Severity: "LOW", Reachability: "imported", FixedVersion: "go1.26.9"}}}
	r := run(Input{Self: self(), Deps: []Row{std}, Checks: Checks{StdlibVersion: "go1.26.3", StdlibGraded: true}})
	if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "graded at go1.26.3") {
		t.Errorf("%v", r.Notes)
	}
	// the version is said when the standard library is clean too, and when it is only listed
	clean := run(Input{Self: self(), Checks: Checks{StdlibVersion: "go1.26.3", StdlibGraded: true}})
	listed := run(Input{Self: self(), Checks: Checks{StdlibVersion: "go1.26.3"}})
	if len(clean.Notes) != 1 || len(listed.Notes) != 1 || !strings.Contains(listed.Notes[0], "listed, not graded") {
		t.Errorf("%v / %v", clean.Notes, listed.Notes)
	}
}

// A Go advisory without a severity whose GitHub alias is rated HIGH is one finding with a published severity: nothing
// it rests on is estimated, so the critical recomputation must not star the letter.
func TestRegression_MergeBeforeTheEstimateCheck(t *testing.T) {
	goAdv := Finding{ID: "GO-1", Aliases: []string{"CVE-1", "GHSA-1"}, Severity: "", Reachability: "called", FixedVersion: "v2"}
	ghsa := Finding{ID: "GHSA-1", Aliases: []string{"CVE-1", "GO-1"}, Severity: "HIGH", Reachability: "called", FixedVersion: "v2"}
	for _, fs := range [][]Finding{{goAdv, ghsa}, {ghsa, goAdv}} {
		r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", fs...)}})
		if r.Letter != LetterD || r.Estimated {
			t.Errorf("%s estimated=%v (the merged finding is HIGH, published)", r.Letter, r.Estimated)
		}
	}
}

// A Pending result publishes no score; a graded one always does, also when it is 0.
func TestRegression_PendingJSONHasNoScore(t *testing.T) {
	p := run(Input{Self: self(), Checks: Checks{VulnScanFailed: true}})
	b, _ := json.Marshal(p)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, has := m["score"]; has || m["pending"] == nil {
		t.Errorf("%s", b)
	}
	g := run(Input{Self: self()})
	b, _ = json.Marshal(g)
	_ = json.Unmarshal(b, &m)
	if v, has := m["score"]; !has || v.(float64) != 0 || m["letter"] != "A" {
		t.Errorf("a real 0 stays published: %s", b)
	}
}

func TestRegression_MaintenanceHintIsInThePendingReason(t *testing.T) {
	m := Row{Module: "example.com/m", Direct: true, InBuild: ptr(true), Upkeep: Upkeep{Missing: true}}
	r := run(Input{Self: self(), Deps: []Row{m}, Checks: Checks{MaintenanceHint: "GitHub allows 60 unauthenticated requests an hour: set GITHUB_TOKEN."}})
	if r.Pending == nil || !strings.Contains(r.Pending.Reason, "set GITHUB_TOKEN") {
		t.Errorf("%+v", r.Pending)
	}
}

// Merging aliases gives the same finding whatever order the group arrives in (fixed version, condition, reachability note).
func TestRegression_AliasMergeIsOrderIndependent(t *testing.T) {
	a := Finding{ID: "GO-1", Aliases: []string{"CVE-1"}, Severity: "HIGH", FixedVersion: "v1.0.2", Condition: "reached through z.F", Reachability: "", AffectedPackages: nil}
	b := Finding{ID: "GHSA-1", Aliases: []string{"CVE-1"}, Severity: " high ", FixedVersion: "v1.0.1", Condition: "reached through a.F", Reachability: "called", AffectedPackages: []string{"x/y"}}
	c := Finding{ID: "GHSA-2", Aliases: []string{"CVE-1"}, Severity: "HIGH", Reachability: "weird"}
	want := mergeAdvisories([]Finding{a, b, c})
	for _, order := range [][]Finding{{a, c, b}, {b, a, c}, {b, c, a}, {c, a, b}, {c, b, a}} {
		if got := mergeAdvisories(order); !reflect.DeepEqual(got, want) {
			t.Fatalf("order changed the merge:\n%+v\n%+v", got, want)
		}
	}
	if want[0].Reachability != "called" {
		t.Errorf("a finding that is called outranks an undetermined one: %q", want[0].Reachability)
	}
	// out-of-contract strings are scored as the scorer scores them: severity trimmed, unknown reachability as called
	m := mergeAdvisories([]Finding{{ID: "GO-9", Aliases: []string{"C9"}, Severity: "", Reachability: "required"}, {ID: "GHSA-9", Aliases: []string{"C9"}, Severity: " critical ", Reachability: "weird"}})
	if r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", m...)}}); r.Letter != LetterF {
		t.Errorf("%s %d", r.Letter, r.Score)
	}
}

// A Pending grade publishes no letter, no score and no deciding row: what is known is in Pending.Known.
func TestRegression_PendingPublishesNoDecidingRow(t *testing.T) {
	r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", fnd("H", "HIGH", "called"))}, Checks: Checks{VulnScanFailed: true}})
	if r.Pending == nil || r.Letter != "" || r.Deciding != nil || r.Score != 0 {
		t.Errorf("%+v", r)
	}
}

func TestRegression_StaleKEVCatalogNote(t *testing.T) {
	r := run(Input{Self: self(), Checks: Checks{KEVStaleSince: time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)}})
	if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "2026-10-12") || r.Pending != nil {
		t.Errorf("%v %+v", r.Notes, r.Pending)
	}
}

// G11: a severity lookup that FAILED is a check that did not run, not an unpublished severity: when the letter depends on it
// the grade is Pending, not an estimate. (Found on the real replay: 23 modules hit by the 8 Oct x/net advisories graded C*
// instead of F because the NVD lookups were rate limited.)
func TestRegression_FailedSeverityLookupIsPendingNotAnEstimate(t *testing.T) {
	failed := fnd("GO-2026-6603", "", "called")
	failed.SeverityLookupFailed = true
	r := run(Input{Self: self(), Deps: []Row{dep("example.com/x", failed)}})
	if r.Pending == nil || r.Pending.Check != "severity_lookup" || r.Letter != "" || r.Estimated || !strings.Contains(r.Pending.Reason, "GO-2026-6603") {
		t.Fatalf("%+v letter=%q estimated=%v", r.Pending, r.Letter, r.Estimated)
	}
	// unscored (nobody published a severity; the lookup answered): still an estimate with a star, never Pending
	unscored := fnd("GO-2026-7", "", "called")
	u := run(Input{Self: self(), Deps: []Row{dep("example.com/y", unscored)}})
	if u.Pending != nil || u.Letter != LetterC || !u.Estimated {
		t.Errorf("an unpublished severity is an estimate: %+v %s %v", u.Pending, u.Letter, u.Estimated)
	}
	// when the letter cannot depend on it, a failed lookup is not Pending: an F by the KEV floor, or a graph-only finding
	k := fnd("GO-K", "", "called")
	k.SeverityLookupFailed, k.Exploited = true, true
	if f := run(Input{Self: self(), Deps: []Row{dep("example.com/k", k)}}); f.Pending != nil || f.Letter != LetterF {
		t.Errorf("KEV makes it F whatever the severity: %+v %s", f.Pending, f.Letter)
	}
	g := fnd("GO-G", "", "required")
	g.SeverityLookupFailed = true
	if o := run(Input{Self: self(), Deps: []Row{dep("example.com/g", g)}}); o.Pending != nil || o.Letter != LetterA {
		t.Errorf("a graph-only finding is not graded: %+v %s", o.Pending, o.Letter)
	}
	// another finding already makes it F: the lookup cannot change the letter
	crit := dep("example.com/c", fnd("GO-C", "CRITICAL", "called"), failed)
	if c := run(Input{Self: self(), Deps: []Row{crit}}); c.Pending != nil || c.Letter != LetterF {
		t.Errorf("%+v %s", c.Pending, c.Letter)
	}
}

// A fix that exists only in a version needing a newer Go than the module supports: the grade does not change for it, but the
// report says it (the x/* modules raise their minimum to the previous Go release soon after each Go release; found by the
// UniPDF/UniOffice release policy of supporting three Go versions).
func TestRegression_FixThatNeedsANewerGoIsSaidAndDoesNotChangeTheLetter(t *testing.T) {
	need := func(goVer string) Finding {
		f := fnd("GO-2026-1", "HIGH", "called")
		f.Module, f.FixRequiresGo = "golang.org/x/image", goVer
		return f
	}
	base := run(Input{Self: self(), Deps: []Row{dep("golang.org/x/image", need(""))}})
	r := run(Input{Self: self(), ProjectGo: "1.24", Deps: []Row{dep("golang.org/x/image", need("1.26.0"))}})
	if r.Letter != base.Letter || r.Score != base.Score {
		t.Fatalf("the letter must not change for the Go requirement: %s %d vs %s %d", r.Letter, r.Score, base.Letter, base.Score)
	}
	f := row(t, r, "golang.org/x/image").Findings[0]
	if f.Response.FixCompat != FixRaisesMinimum || f.Response.FixRequiresGo != "1.26.0" ||
		!strings.Contains(f.Response.Text, "requires Go 1.26.0 or newer") || !strings.Contains(f.Response.Text, "supports Go 1.24") {
		t.Errorf("%+v", f.Response)
	}
	if r.FixesNeedNewerGo != 1 || len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "go 1.24") || !strings.Contains(r.Notes[0], "does not change") {
		t.Errorf("%d %v", r.FixesNeedNewerGo, r.Notes)
	}
	// a fix the module can take: compatible, nothing said, no note
	c := run(Input{Self: self(), ProjectGo: "1.26", Deps: []Row{dep("golang.org/x/image", need("1.26.0"))}})
	cf := row(t, c, "golang.org/x/image").Findings[0]
	if cf.Response.FixCompat != FixCompatible || strings.Contains(cf.Response.Text, "requires Go") || c.FixesNeedNewerGo != 0 || len(c.Notes) != 0 {
		t.Errorf("%+v %v", cf.Response, c.Notes)
	}
	// the module's go line is unknown: the requirement is still said, no judgement about it
	u := run(Input{Self: self(), Deps: []Row{dep("golang.org/x/image", need("1.26"))}})
	uf := row(t, u, "golang.org/x/image").Findings[0]
	if uf.Response.FixCompat != "" || !strings.Contains(uf.Response.Text, "requires Go 1.26 or newer") {
		t.Errorf("%+v", uf.Response)
	}
	// graph-only findings are shown, not graded: they are not counted in the note
	g := need("1.26")
	g.Reachability = "required"
	if go1 := run(Input{Self: self(), ProjectGo: "1.24", Deps: []Row{dep("golang.org/x/image", g)}}); go1.FixesNeedNewerGo != 0 {
		t.Errorf("a graph-only finding is not counted: %d", go1.FixesNeedNewerGo)
	}
	if _, ok := compareGo("1.26rc1", "1.24"); ok {
		t.Error("a release candidate is not a go directive")
	}
}
