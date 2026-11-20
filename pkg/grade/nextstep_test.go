package grade

import (
	"encoding/json"
	"strings"
	"testing"
)

// The next step: the one upgrade that would improve the letter most, and the letter after it. Every test pins Now (`now`).

func wantStep(t *testing.T, r Result, module, version string) *NextStep {
	t.Helper()
	n := r.NextStep
	if n == nil {
		t.Fatalf("no next step (letter %s, deciding %+v)", r.Letter, r.Deciding)
	}
	if n.Module != module || n.Version != version || n.Command != "go get "+module+"@"+version {
		t.Fatalf("next step %+v, want %s@%s", *n, module, version)
	}
	return n
}

// a. unioffice: x/image decides (75). One upgrade clears all five of its advisories, and what is left is x/net at 54: the letter
// after is D, honestly, not A.
func TestNextStep_UniofficeShape(t *testing.T) {
	img, net := "golang.org/x/image", "golang.org/x/net"
	r := gradeDeps(
		dep(img,
			aged("GO-2026-5032", img, "HIGH", "called", "v0.41.0", days(174)),
			aged("GO-2026-5062", img, "HIGH", "called", "v0.43.0", days(154)),
			aged("GO-2026-5066", img, "HIGH", "called", "v0.43.0", days(146)),
			aged("GO-2026-4815", img, "MEDIUM", "imported", "v0.38.0", days(239)),
			aged("GO-2026-4816", img, "MEDIUM", "imported", "v0.39.0", days(200))),
		dep(net,
			aged("GO-2026-6860", net, "HIGH", "imported", "v0.50.0", days(23)),
			aged("GO-2024-3333", net, "MEDIUM", "imported", "v0.33.0", days(181))))
	if r.Letter != LetterD || r.Score != 75 || r.Deciding == nil || r.Deciding.Module != img {
		t.Fatalf("%s %d %+v", r.Letter, r.Score, r.Deciding)
	}
	n := wantStep(t, r, img, "v0.43.0")
	if strings.Join(n.Clears, ",") != "GO-2026-4815,GO-2026-4816,GO-2026-5032,GO-2026-5062,GO-2026-5066" {
		t.Errorf("clears %v", n.Clears)
	}
	if n.LetterAfter != LetterD || n.ScoreAfter != 54 || n.PendingAfter != "" {
		t.Errorf("after the upgrade: %s %d (%q), want D 54", n.LetterAfter, n.ScoreAfter, n.PendingAfter)
	}
	// the grade itself is untouched by the re-grade
	if r.Score != 75 || len(r.Rows) != 3 {
		t.Errorf("%d rows, score %d", len(r.Rows), r.Score)
	}
}

// b. An upgrade that leaves nothing: A, 0.
func TestNextStep_LeavesNothing(t *testing.T) {
	m := "golang.org/x/net"
	r := gradeDeps(dep(m, aged("GO-2026-9000", m, "HIGH", "called", "v0.60.0", days(30))))
	n := wantStep(t, r, m, "v0.60.0")
	if n.LetterAfter != LetterA || n.ScoreAfter != 0 || len(n.Clears) != 1 || n.Clears[0] != "GO-2026-9000" {
		t.Errorf("%+v", *n)
	}
	// the module itself: the same command (a consumer moves to the fixed release)
	s := self(aged("GO-2026-9001", "example.com/app", "HIGH", "called", "v1.4.0", days(30)))
	r = run(Input{Self: s})
	wantStep(t, r, "example.com/app", "v1.4.0")
}

// c. A whole-tree rule decides: every row with a fixable counted finding is a candidate and the best letter wins. z has two
// highs, so its upgrade leaves two called highs in two modules (D); an upgrade of a or b leaves three (F). z is last in the
// row order, so this is not the first row. The answer does not depend on the order of the input.
func TestNextStep_TreeRulePicksTheBestUpgrade(t *testing.T) {
	a, b, z := "example.com/a", "example.com/b", "example.com/z"
	mk := func() []Row {
		return []Row{
			dep(a, aged("A1", a, "HIGH", "called", "v0.5.0", days(30))),
			dep(b, aged("B1", b, "HIGH", "called", "v0.5.0", days(30))),
			dep(z, aged("Z1", z, "HIGH", "called", "v1.2.0", days(30)), aged("Z2", z, "HIGH", "called", "v1.2.0", days(30))),
		}
	}
	for i, order := range [][]int{{0, 1, 2}, {2, 1, 0}, {1, 2, 0}, {2, 0, 1}} {
		rows := mk()
		shuffled := []Row{rows[order[0]], rows[order[1]], rows[order[2]]}
		r := gradeDeps(shuffled...)
		if r.Letter != LetterF || r.Deciding == nil || r.Deciding.Tree != "called_findings" {
			t.Fatalf("order %d: %s %+v", i, r.Letter, r.Deciding)
		}
		n := wantStep(t, r, z, "v1.2.0")
		if n.LetterAfter != LetterD || n.ScoreAfter != 70 || strings.Join(n.Clears, ",") != "Z1,Z2" {
			t.Errorf("order %d: %+v", i, *n)
		}
	}
}

// c. With the same letter and score after either upgrade, the first row in the result's order wins, whatever the input order.
func TestNextStep_TreeRuleTieGoesToTheFirstRow(t *testing.T) {
	x, y := "example.com/x", "example.com/y"
	mk := func() []Row {
		return []Row{
			dep(x, aged("X1", x, "HIGH", "called", "v1.2.0", days(30)), aged("X2", x, "HIGH", "called", "v1.2.0", days(30))),
			dep(y, aged("Y1", y, "HIGH", "called", "v0.5.0", days(30))),
		}
	}
	for _, rev := range []bool{false, true} {
		rows := mk()
		if rev {
			rows[0], rows[1] = rows[1], rows[0]
		}
		r := gradeDeps(rows...)
		if r.Deciding == nil || r.Deciding.Tree != "called_findings" || r.Rows[0].Module != x {
			t.Fatalf("%+v first row %s", r.Deciding, r.Rows[0].Module)
		}
		n := wantStep(t, r, x, "v1.2.0")
		if n.LetterAfter != LetterD || n.ScoreAfter != 70 {
			t.Errorf("%+v", *n)
		}
	}
}

// d. No next step when upkeep decides, or when the deciding finding has no fix, or when nothing decides.
func TestNextStep_NoneWhenThereIsNothingToUpgrade(t *testing.T) {
	m := "example.com/old"
	archived := dep(m)
	archived.Upkeep = Upkeep{Archived: true, LastRelease: now.AddDate(-3, 0, 0)}
	if r := gradeDeps(archived); r.Deciding == nil || r.Score != 20 || r.NextStep != nil {
		t.Errorf("upkeep decides: %+v %+v", r.Deciding, r.NextStep)
	}
	// archived 20 and a called medium WITH a fix that scores less than 20 would not decide either; a vulnerability that decides does
	noFix := aged("GO-2026-9002", m, "HIGH", "called", "", 0)
	if r := gradeDeps(dep(m, noFix)); r.Letter != LetterD || r.NextStep != nil {
		t.Errorf("no fix: %s %+v", r.Letter, r.NextStep)
	}
	// a called high whose fix is under 14 days old is not counted: nothing decides
	if r := gradeDeps(dep(m, aged("GO-2026-9003", m, "HIGH", "called", "v2", days(3)))); r.Deciding != nil || r.NextStep != nil {
		t.Errorf("graced: %+v %+v", r.Deciding, r.NextStep)
	}
	// a clean tree
	if r := gradeDeps(dep(m)); r.NextStep != nil {
		t.Errorf("%+v", r.NextStep)
	}
	// the row decides by a vulnerability that has no fix; another row with a fixable lower finding is not "the" upgrade
	other := "example.com/other"
	r := gradeDeps(dep(m, noFix), dep(other, aged("GO-2026-9004", other, "MEDIUM", "called", "v2", days(30))))
	if r.Deciding == nil || r.Deciding.Module != m || r.NextStep != nil {
		t.Errorf("%+v %+v", r.Deciding, r.NextStep)
	}
}

// e. Pending has no next step; an upgrade after which the grade would be Pending says so instead of a letter.
func TestNextStep_Pending(t *testing.T) {
	m := "golang.org/x/net"
	in := Input{Self: self(), Deps: []Row{dep(m, aged("GO-2026-9005", m, "HIGH", "called", "v0.60.0", days(30)))}, Now: now}
	in.Checks.VulnScanFailed = true
	if r := Grade(&in); r.Pending == nil || r.NextStep != nil {
		t.Errorf("a pending grade has no next step: %+v %+v", r.Pending, r.NextStep)
	}
	// a dependency whose maintenance data is missing: its possible archived 20 (B) does not matter while the letter is D, and
	// does once the upgrade leaves nothing
	missing := dep("example.com/unread")
	missing.Upkeep = Upkeep{Missing: true}
	r := gradeDeps(dep(m, aged("GO-2026-9005", m, "HIGH", "called", "v0.60.0", days(30))), missing)
	if r.Pending != nil || r.Letter != LetterD {
		t.Fatalf("%s %+v", r.Letter, r.Pending)
	}
	n := wantStep(t, r, m, "v0.60.0")
	if n.LetterAfter != "" || n.PendingAfter != "dependency_maintenance" {
		t.Errorf("%+v", *n)
	}
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"next_step":{`) || strings.Contains(string(b), `"letter_after"`) || !strings.Contains(string(b), `"pending_after":"dependency_maintenance"`) {
		t.Errorf("%s", b)
	}
}

// f. Versions are compared as semantic versions: v0.10.0 is above v0.9.0. A version without the v is read, one that is not a
// version is skipped.
func TestNextStep_TargetIsTheHighestSemver(t *testing.T) {
	m := "golang.org/x/net"
	r := gradeDeps(dep(m,
		aged("GO-2026-9006", m, "HIGH", "called", "v0.9.0", days(30)),
		aged("GO-2026-9007", m, "HIGH", "called", "v0.10.0", days(30)),
		aged("GO-2026-9008", m, "HIGH", "called", "not-a-version", days(30))))
	n := wantStep(t, r, m, "v0.10.0")
	if strings.Join(n.Clears, ",") != "GO-2026-9006,GO-2026-9007" {
		t.Errorf("clears %v (a fixed version that is not a version is not cleared)", n.Clears)
	}
	r = gradeDeps(dep(m, aged("GO-2026-9006", m, "HIGH", "called", "0.9.0", days(30)), aged("GO-2026-9007", m, "HIGH", "called", "0.10.0", days(30))))
	wantStep(t, r, m, "v0.10.0")
}

// The target is the highest fix among the COUNTED findings; a graced finding, or one in another tier, that has a higher fix does
// not set it, but is cleared when the target covers it.
func TestNextStep_GracedAndGraphOnlyDoNotSetTheTarget(t *testing.T) {
	m := "golang.org/x/net"
	r := gradeDeps(dep(m,
		aged("GO-2026-9009", m, "HIGH", "called", "v0.50.0", days(30)),
		aged("GO-2026-9010", m, "HIGH", "imported", "v0.40.0", days(30)),
		aged("GO-2026-9011", m, "CRITICAL", "called", "v0.99.0", days(2)),
		aged("GO-2026-9012", m, "CRITICAL", "required", "v0.98.0", days(30))))
	n := wantStep(t, r, m, "v0.50.0")
	if strings.Join(n.Clears, ",") != "GO-2026-9009,GO-2026-9010" {
		t.Errorf("clears %v", n.Clears)
	}
}

// The standard library: "go get toolchain@go1.X.Y".
func TestNextStep_Stdlib(t *testing.T) {
	r := gradeDeps(dep("stdlib", aged("GO-2026-9013", "stdlib", "HIGH", "called", "v1.24.4", days(30))))
	n := r.NextStep
	if n == nil || n.Module != "stdlib" || n.Version != "v1.24.4" || n.Command != "go get toolchain@go1.24.4" {
		t.Fatalf("%+v", n)
	}
}

// The overdue reason names the finding that sets the score when it is itself overdue, not the oldest one.
func TestOverdueReasonPrefersTheScoringFinding(t *testing.T) {
	m := "golang.org/x/image"
	r := gradeDeps(dep(m,
		aged("GO-2026-5032", m, "HIGH", "called", "v0.41.0", days(174)),
		aged("GO-2026-4815", m, "MEDIUM", "called", "v0.38.0", days(239))))
	if x := row(t, r, m); x.Score != 75 || !strings.Contains(x.Reason, "+5: fix for GO-2026-5032 available 174 days") {
		t.Errorf("%d %q", x.Score, x.Reason)
	}
	// when the scoring finding is not overdue, the oldest overdue one is named
	r = gradeDeps(dep(m, aged("GO-2026-5032", m, "HIGH", "called", "v0.41.0", days(30)), aged("GO-2026-4815", m, "MEDIUM", "called", "v0.38.0", days(239)), aged("GO-2026-4816", m, "LOW", "called", "v0.38.0", days(100))))
	if x := row(t, r, m); !strings.Contains(x.Reason, "+5: fix for GO-2026-4815 available 239 days") {
		t.Errorf("%q", x.Reason)
	}
}

// A candidate whose grade after the upgrade would be Pending loses to one that is not: with the known-exploited check missing, an
// upgrade that leaves D would make the grade Pending ("a finding on that list would grade F"), while one that leaves F would not.
func TestNextStep_NotPendingBeatsPending(t *testing.T) {
	a, b, z := "example.com/a", "example.com/b", "example.com/z"
	in := Input{Self: self(), Now: now, Deps: []Row{
		dep(a, aged("A1", a, "HIGH", "called", "v0.5.0", days(30))),
		dep(b, aged("B1", b, "HIGH", "called", "v0.5.0", days(30))),
		dep(z, aged("Z1", z, "HIGH", "called", "v1.2.0", days(30)), aged("Z2", z, "HIGH", "called", "v1.2.0", days(30))),
	}}
	in.Checks.KEVUnchecked = 1
	r := Grade(&in)
	if r.Pending != nil || r.Letter != LetterF {
		t.Fatalf("%s %+v", r.Letter, r.Pending)
	}
	n := wantStep(t, r, a, "v0.5.0")
	if n.LetterAfter != LetterF || n.PendingAfter != "" {
		t.Errorf("%+v", *n)
	}
}
