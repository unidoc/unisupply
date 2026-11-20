package grade

import (
	"strings"
	"testing"
	"time"
)

// Rules version 3 ("Grading v2.1"): a row counts per upgrade, a fix under 14 days old does not count yet, a fix that has
// been available for 60 days or more weighs 5. Every test pins Now (`now`, 2026-10-10) and gives each finding the age of its
// fix as a duration before it.

const day = 24 * time.Hour

// aged is a finding whose fix (fixedIn) was released age before now. fixedIn "" is a finding with no fix and no fix date.
func aged(id, module, sev, reach, fixedIn string, age time.Duration) Finding {
	f := Finding{ID: id, Module: module, Severity: sev, Reachability: reach, FixedVersion: fixedIn}
	if fixedIn != "" {
		f.FixReleasedAt = ptr(now.Add(-age))
		f.FixDateSource = "module_proxy"
	}
	return f
}

func days(n int) time.Duration { return time.Duration(n) * day }

func gradeDeps(rows ...Row) Result { return run(Input{Self: self(), Deps: rows}) }

func wantRow(t *testing.T, name string, r Result, module string, score int, letter Letter) {
	t.Helper()
	x := row(t, r, module)
	if x.Score != score || x.Letter != letter || r.Letter != letter || r.Score != score {
		t.Errorf("%s: row %d %s, result %d %s, want %d %s (reason %q)", name, x.Score, x.Letter, r.Score, r.Letter, score, letter, x.Reason)
	}
}

// a. unioffice/v2: x/image has three called highs, fixed in v0.41.0, v0.43.0 and v0.43.0, released 174, 154 and 146 days ago.
// Two upgrades fix all three: one problem (70), plus 5 for a fix that has waited 60 days or more.
func TestV21_UniofficeCase(t *testing.T) {
	m := "golang.org/x/image"
	r := gradeDeps(dep(m,
		aged("GO-2026-5032", m, "HIGH", "called", "v0.41.0", days(174)),
		aged("GO-2026-5062", m, "HIGH", "called", "v0.43.0", days(154)),
		aged("GO-2026-5066", m, "HIGH", "called", "v0.43.0", days(146))))
	wantRow(t, "unioffice", r, m, 75, LetterD)
	if len(r.TreeRows) != 0 {
		t.Errorf("three called highs in ONE module are not a tree rule: %+v", r.TreeRows)
	}
	if x := row(t, r, m); x.VulnScore != 75 || !strings.Contains(x.Reason, "+5: fix for GO-2026-5032 available 174 days") {
		t.Errorf("the reason must show the overdue +5: %q", x.Reason)
	}
}

// b. pkg/sftp: x/crypto has three called highs, fixes 83, 78 and 78 days old.
func TestV21_SftpCase(t *testing.T) {
	m := "golang.org/x/crypto"
	r := gradeDeps(dep(m,
		aged("GO-2026-6303", m, "HIGH", "called", "v0.55.0", days(83)),
		aged("GO-2026-6354", m, "HIGH", "called", "v0.56.0", days(78)),
		aged("GO-2026-6355", m, "HIGH", "called", "v0.56.0", days(78))))
	wantRow(t, "sftp", r, m, 75, LetterD)
}

// c. Three called highs in two modules are F by the whole-tree rule; in one module they are not.
func TestV21_TreeRuleNeedsTwoModules(t *testing.T) {
	a, b := "example.com/a", "example.com/b"
	r := gradeDeps(
		dep(a, aged("A1", a, "HIGH", "called", "v2", days(30)), aged("A2", a, "HIGH", "called", "v2", days(30))),
		dep(b, aged("B1", b, "HIGH", "called", "v2", days(30))))
	if r.Letter != LetterF || len(r.TreeRows) != 1 || r.TreeRows[0].Rule != "called_findings" || r.TreeRows[0].Reason != "3 called high or critical findings across 2 modules" {
		t.Fatalf("%s %d %+v", r.Letter, r.Score, r.TreeRows)
	}
	if r.Deciding == nil || r.Deciding.Tree != "called_findings" {
		t.Errorf("deciding = %+v", r.Deciding)
	}
	// the same three in one module: one upgrade, D
	one := gradeDeps(dep(a, aged("A1", a, "HIGH", "called", "v2", days(30)), aged("A2", a, "HIGH", "called", "v2", days(30)), aged("A3", a, "HIGH", "called", "v2", days(30))))
	wantRow(t, "one module", one, a, 70, LetterD)
	if len(one.TreeRows) != 0 {
		t.Errorf("%+v", one.TreeRows)
	}
}

// d. gorm.io/driver/postgres: x/text has two called highs, fixes 128 and 43 days old: one upgrade, overdue: 70 + 5.
// With one of the two WITHOUT a fix, each is its own problem: 70 + 5 + 5.
func TestV21_GormCaseAndNoFixCountsAlone(t *testing.T) {
	m := "golang.org/x/text"
	r := gradeDeps(dep(m, aged("GO-2026-5970", m, "HIGH", "called", "v0.35.0", days(128)), aged("GO-2026-6629", m, "HIGH", "called", "v0.36.0", days(43))))
	wantRow(t, "gorm", r, m, 75, LetterD)

	noFix := aged("GO-2026-7000", m, "HIGH", "called", "", 0)
	r = gradeDeps(dep(m, noFix, aged("GO-2026-5970", m, "HIGH", "called", "v0.35.0", days(100))))
	wantRow(t, "one without a fix, one overdue", r, m, 80, LetterF)
	if x := row(t, r, m); !strings.Contains(x.Reason, "+5 for 1 more called high or critical problem") || !strings.Contains(x.Reason, "+5: fix for GO-2026-5970 available 100 days") {
		t.Errorf("the reason must show both additions: %q", x.Reason)
	}
	// two without a fix are two problems, plus the one with a fix: 70 + 5 + 5, and not overdue
	r = gradeDeps(dep(m, noFix, aged("GO-2026-7001", m, "HIGH", "called", "", 0), aged("GO-2026-5970", m, "HIGH", "called", "v0.35.0", days(20))))
	wantRow(t, "two without a fix", r, m, 80, LetterF)
}

// e. viper / bluemonday: one imported high with a fix: 49, and 54 (D) once the fix has waited 60 days (decision: the overdue
// +5 is added after the imported cap).
func TestV21_ImportedHighOverdue(t *testing.T) {
	m := "golang.org/x/text"
	r := gradeDeps(dep(m, aged("GO-2026-5970", m, "HIGH", "imported", "v0.35.0", days(128))))
	wantRow(t, "imported, 128 days", r, m, 54, LetterD)
	if x := row(t, r, m); !strings.Contains(x.Reason, "imported high GO-2026-5970 (49)") || !strings.Contains(x.Reason, "+5: fix for GO-2026-5970 available 128 days") {
		t.Errorf("reason %q", x.Reason)
	}
	r = gradeDeps(dep(m, aged("GO-2026-5970", m, "HIGH", "imported", "v0.35.0", days(30))))
	wantRow(t, "imported, 30 days", r, m, 49, LetterC)
}

// f. A fix under 14 days old does not count: it is listed, with the day it starts to count.
func TestV21_GraceForAFreshFix(t *testing.T) {
	m := "golang.org/x/net"
	r := gradeDeps(dep(m, aged("GO-2026-8000", m, "HIGH", "called", "v0.60.0", days(8))))
	if r.Letter != LetterA || r.Score != 0 || r.Deciding != nil || len(r.TreeRows) != 0 {
		t.Fatalf("a called high with a fix 8 days old is not counted: %s %d %+v %+v", r.Letter, r.Score, r.Deciding, r.TreeRows)
	}
	f := row(t, r, m).Findings[0]
	if f.Counted || f.Score != 70 || f.Tier != TierCalled || f.VEX.Status != "affected" || f.Response.Status != "within_window" {
		t.Errorf("%+v", f)
	}
	if want := "Fix is 8 days old: it counts toward the letter from 16 October."; !strings.Contains(f.Note, want) {
		t.Errorf("note %q does not say %q", f.Note, want)
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "1 finding has a fix under 14 days old") || !strings.Contains(strings.Join(r.Notes, "\n"), "16 October") {
		t.Errorf("result notes = %v", r.Notes)
	}
	if x := row(t, r, m); x.Reason == "" || strings.Contains(x.Reason, "nothing found") {
		t.Errorf("row reason %q", x.Reason)
	}
}

// f. The hugo boundary: 13 days 16 hours old is not counted; exactly 14 days old counts.
func TestV21_GraceBoundary(t *testing.T) {
	m := "github.com/gohugoio/hugo"
	fresh := aged("GO-2026-8001", m, "HIGH", "called", "v0.150.0", 13*day+16*time.Hour)
	if r := gradeDeps(dep(m, fresh)); r.Letter != LetterA || row(t, r, m).Findings[0].Counted {
		t.Errorf("13 days 16 hours: %s counted=%v", r.Letter, row(t, r, m).Findings[0].Counted)
	}
	edge := aged("GO-2026-8001", m, "HIGH", "called", "v0.150.0", 14*day)
	r := gradeDeps(dep(m, edge))
	wantRow(t, "exactly 14 days", r, m, 70, LetterD)
	if !row(t, r, m).Findings[0].Counted || strings.Contains(strings.Join(r.Notes, "\n"), "under 14 days") {
		t.Errorf("exactly 14 days must count: %+v %v", row(t, r, m).Findings[0], r.Notes)
	}
	if got := ResponseWindowDays; got != 14 {
		t.Errorf("the grace is the response window: %d", got)
	}
}

// g. A known-exploited finding gets no grace: it counts on the day the fix is out.
func TestV21_ExploitedGetsNoGrace(t *testing.T) {
	m := "golang.org/x/net"
	kev := aged("GO-2026-8002", m, "HIGH", "called", "v0.60.0", day)
	kev.Exploited = true
	r := gradeDeps(dep(m, kev))
	if r.Letter != LetterF || r.Score != 76 || !row(t, r, m).Findings[0].Counted {
		t.Errorf("%s %d counted=%v", r.Letter, r.Score, row(t, r, m).Findings[0].Counted)
	}
	if strings.Contains(strings.Join(r.Notes, "\n"), "under 14 days") {
		t.Errorf("notes = %v", r.Notes)
	}
}

// h. A called critical whose fix is 5 days old is graced, so the called_critical tree rule does not fire: not F.
func TestV21_FreshCalledCriticalIsNotF(t *testing.T) {
	m := "golang.org/x/net"
	r := gradeDeps(dep(m, aged("GO-2026-8003", m, "CRITICAL", "called", "v0.60.0", 5*day)))
	if r.Letter == LetterF || len(r.TreeRows) != 0 || r.Letter != LetterA {
		t.Errorf("%s %d %+v", r.Letter, r.Score, r.TreeRows)
	}
	// 14 days later it counts: F
	r = gradeDeps(dep(m, aged("GO-2026-8003", m, "CRITICAL", "called", "v0.60.0", 14*day)))
	if r.Letter != LetterF {
		t.Errorf("a called critical with a fix 14 days old is F: %s", r.Letter)
	}
	// a graced finding is also left out of called_findings
	a, b, c := "example.com/a", "example.com/b", "example.com/c"
	r = gradeDeps(dep(a, aged("1", a, "HIGH", "called", "v2", 3*day)), dep(b, aged("2", b, "HIGH", "called", "v2", 3*day)), dep(c, aged("3", c, "HIGH", "called", "v2", 3*day)))
	if r.Letter != LetterA || len(r.TreeRows) != 0 {
		t.Errorf("three fresh called highs: %s %+v", r.Letter, r.TreeRows)
	}
	// ... and it does not make the 2-module count: two counted plus one graced in another module is not F
	r = gradeDeps(dep(a, aged("1", a, "HIGH", "called", "v2", 30*day), aged("2", a, "HIGH", "called", "v2", 30*day)), dep(b, aged("3", b, "HIGH", "called", "v2", 3*day)))
	if r.Letter != LetterD || len(r.TreeRows) != 0 {
		t.Errorf("%s %+v", r.Letter, r.TreeRows)
	}
}

// i. An unknown fix date counts, and does not trigger the overdue +5.
func TestV21_UnknownFixDate(t *testing.T) {
	m := "golang.org/x/net"
	f := Finding{ID: "GO-2026-8004", Module: m, Severity: "HIGH", Reachability: "called", FixedVersion: "v0.60.0"} // no FixReleasedAt
	r := gradeDeps(dep(m, f))
	wantRow(t, "called", r, m, 70, LetterD)
	if strings.Contains(row(t, r, m).Reason, "+5") || !row(t, r, m).Findings[0].Counted {
		t.Errorf("%+v", row(t, r, m))
	}
	f.Reachability = "imported"
	r = gradeDeps(dep(m, f))
	wantRow(t, "imported", r, m, 49, LetterC)
}

// j. The overdue +5 fires on any counted finding of the row, not only the one that sets the score: unioffice's x/net row has an
// imported high whose fix is 23 days old and imported mediums whose fix is 181 days old.
func TestV21_OverdueFromANonScoringFinding(t *testing.T) {
	m := "golang.org/x/net"
	r := gradeDeps(dep(m,
		aged("GO-2026-6860", m, "HIGH", "imported", "v0.50.0", days(23)),
		aged("GO-2024-3333", m, "MEDIUM", "imported", "v0.33.0", days(181))))
	wantRow(t, "x/net", r, m, 54, LetterD)
	// the overdue fix is graph-only: it does not weigh
	r = gradeDeps(dep(m,
		aged("GO-2026-6860", m, "HIGH", "imported", "v0.50.0", days(23)),
		aged("GO-2024-3333", m, "MEDIUM", "required", "v0.33.0", days(181))))
	wantRow(t, "graph-only overdue", r, m, 49, LetterC)
	// and so is a graced one (a fix under 14 days old is not counted, so it cannot be overdue either: the fields are exclusive)
	r = gradeDeps(dep(m, aged("GO-2026-6860", m, "HIGH", "imported", "v0.50.0", days(23)), aged("X", m, "LOW", "imported", "v0.50.0", days(2))))
	wantRow(t, "graced low", r, m, 49, LetterC)
	// the overdue fix is on a medium that is only called: 45 + 5
	r = gradeDeps(dep(m, aged("M", m, "MEDIUM", "called", "v0.33.0", days(90))))
	wantRow(t, "called medium", r, m, 50, LetterC)
}

// k. A test-only row halves after the +5: (49 + 5) / 2 = 27.
func TestV21_TestOnlyOverdue(t *testing.T) {
	m := "golang.org/x/text"
	d := dep(m, aged("GO-2026-5970", m, "HIGH", "imported", "v0.35.0", days(128)))
	d.TestOnly = ptr(true)
	r := gradeDeps(d)
	wantRow(t, "test-only", r, m, 27, LetterC)
	if x := row(t, r, m); !strings.Contains(x.Reason, "halved to 27") {
		t.Errorf("%q", x.Reason)
	}
}

// the overdue +5 is added once, however many findings are overdue, and the total is capped at 100
func TestV21_OverdueOnce(t *testing.T) {
	m := "golang.org/x/net"
	r := gradeDeps(dep(m, aged("A", m, "MEDIUM", "called", "v2", days(100)), aged("B", m, "MEDIUM", "called", "v2", days(200)), aged("C", m, "LOW", "called", "v2", days(300))))
	wantRow(t, "once", r, m, 50, LetterC)
	crit := dep(m, aged("A", m, "CRITICAL", "called", "", 0), aged("B", m, "HIGH", "called", "", 0), aged("C", m, "HIGH", "called", "", 0), aged("D", m, "HIGH", "called", "", 0),
		aged("E", m, "HIGH", "called", "", 0), aged("F", m, "HIGH", "called", "", 0), aged("G", m, "HIGH", "called", "v2", days(100)))
	if x := row(t, gradeDeps(crit), m); x.Score != 100 {
		t.Errorf("capped at 100: %d (%s)", x.Score, x.Reason)
	}
}

// the finding keeps its place in the report while graced: shown, VEX unchanged, the response label says why
func TestV21_GracedFindingIsListed(t *testing.T) {
	m := "golang.org/x/net"
	imp := aged("GO-2026-8005", m, "HIGH", "imported", "v0.60.0", 6*day)
	r := gradeDeps(dep(m, imp, aged("GO-2026-8006", m, "LOW", "imported", "v0.60.0", day)))
	if r.Letter != LetterA {
		t.Fatalf("%s", r.Letter)
	}
	fs := row(t, r, m).Findings
	if len(fs) != 2 {
		t.Fatalf("%+v", fs)
	}
	for _, f := range fs {
		if f.Counted || f.VEX.Status != "not_affected" || f.Response.Status != "within_window" || !strings.Contains(f.Note, "counts toward the letter from") {
			t.Errorf("%+v", f)
		}
	}
	if n := strings.Join(r.Notes, "\n"); !strings.Contains(n, "2 findings have a fix under 14 days old") || !strings.Contains(n, "from 18 October") {
		t.Errorf("notes: %v", r.Notes)
	}
	// a graph-only finding is not counted anyway: no grace note, no result note
	g := gradeDeps(dep(m, aged("GO-2026-8007", m, "CRITICAL", "required", "v0.60.0", day)))
	if f := row(t, g, m).Findings[0]; f.Counted || strings.Contains(f.Note, "counts toward the letter") || len(g.Notes) != 0 {
		t.Errorf("%+v %v", f, g.Notes)
	}
}

// a graced finding is also left out when severities are estimated: Grade re-runs the rules for them
func TestV21_GraceHoldsInTheEstimateRuns(t *testing.T) {
	m := "golang.org/x/net"
	f := aged("GO-2026-8008", m, "", "called", "v0.60.0", 3*day) // no published severity
	r := gradeDeps(dep(m, f))
	if r.Letter != LetterA || r.Estimated {
		t.Errorf("%s estimated=%v", r.Letter, r.Estimated)
	}
}

// m. the rules version
func TestV21_RuleVersion(t *testing.T) {
	if r := run(Input{Self: self()}); r.RuleVersion != 3 {
		t.Errorf("rule_version = %d, want 3", r.RuleVersion)
	}
}
