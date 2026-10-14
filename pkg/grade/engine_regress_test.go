package grade

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
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
	r := run(Input{Self: self(), Deps: []Row{std}, Checks: Checks{StdlibVersion: "go1.26.3"}})
	if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "go1.26.3") {
		t.Errorf("%v", r.Notes)
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
