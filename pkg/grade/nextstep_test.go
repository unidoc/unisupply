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
		aged("GO-2026-9008", m, "LOW", "called", "not-a-version", days(30))))
	n := wantStep(t, r, m, "v0.10.0")
	if strings.Join(n.Clears, ",") != "GO-2026-9006,GO-2026-9007" {
		t.Errorf("clears %v (a fixed version that is not a version is not cleared)", n.Clears)
	}
	r = gradeDeps(dep(m, aged("GO-2026-9006", m, "HIGH", "called", "0.9.0", days(30)), aged("GO-2026-9007", m, "HIGH", "called", "0.10.0", days(30))))
	wantStep(t, r, m, "v0.10.0")
}

// The target is the highest fix among the row's counted AND graced findings (a fix that is still in the grace period counts in a
// few days, so an upgrade that skips it would be undone by it); a graph-only finding does not set it. Everything the target fixes
// is cleared, graced ones included.
func TestNextStep_GracedFixSetsTheTargetGraphOnlyDoesNot(t *testing.T) {
	m := "golang.org/x/net"
	r := gradeDeps(dep(m,
		aged("GO-2026-9009", m, "HIGH", "called", "v0.50.0", days(30)),
		aged("GO-2026-9010", m, "HIGH", "imported", "v0.40.0", days(30)),
		aged("GO-2026-9011", m, "CRITICAL", "called", "v0.99.0", days(2)),
		aged("GO-2026-9012", m, "CRITICAL", "required", "v1.20.0", days(30))))
	n := wantStep(t, r, m, "v0.99.0")
	if strings.Join(n.Clears, ",") != "GO-2026-9009,GO-2026-9010,GO-2026-9011" {
		t.Errorf("clears %v", n.Clears)
	}
	// a high in the grace period beside a counted one: the step goes to the newer fix, and the letter after is honest
	a, b := "GO-2026-9020", "GO-2026-9021"
	r = gradeDeps(dep(m, aged(a, m, "HIGH", "called", "v0.35.0", days(3)), aged(b, m, "HIGH", "called", "v0.30.0", days(100))))
	if r.Letter != LetterD || r.Score != 75 {
		t.Fatalf("%s %d", r.Letter, r.Score)
	}
	n = wantStep(t, r, m, "v0.35.0")
	if n.LetterAfter != LetterA || n.ScoreAfter != 0 || strings.Join(n.Clears, ",") != a+","+b {
		t.Errorf("%+v", *n)
	}
}

// A row is a candidate only if it has a counted finding with a fix: a fix in the grace period alone is nothing to act on yet.
func TestNextStep_RowWithOnlyAGracedFixIsNoCandidate(t *testing.T) {
	m, w := "golang.org/x/net", "example.com/w"
	in := Input{Self: self(), Now: now, Deps: []Row{
		dep(m, aged("GO-2026-9022", m, "HIGH", "called", "v0.60.0", days(30))),
		dep(w, aged("GO-2026-9023", w, "HIGH", "called", "v9.0.0", days(3))),
	}}
	merged := mergedInput(&in)
	r := Grade(&in)
	for i := range r.Rows {
		if r.Rows[i].Module == w {
			if n, _ := upgradeFor(&merged, &r.Rows[i]); n != nil {
				t.Errorf("a row with only a graced fix is no candidate: %+v", *n)
			}
		}
	}
	wantStep(t, r, m, "v0.60.0")
}

// A row-decided step is named only if it changes something: here the deciding high has no fix, so upgrading the medium that does
// leaves the grade as it is.
func TestNextStep_RowStepOnlyWhenItHelps(t *testing.T) {
	m := "golang.org/x/net"
	r := gradeDeps(dep(m, aged("GO-2026-9030", m, "HIGH", "called", "", 0), aged("GO-2026-9031", m, "MEDIUM", "called", "v0.35.0", days(30))))
	if r.Letter != LetterD || r.Score != 70 || r.Deciding == nil || r.NextStep != nil {
		t.Errorf("%s %d %+v next step %+v", r.Letter, r.Score, r.Deciding, r.NextStep)
	}
	// the same score after, but the letter is the same too, while the score falls: still named (unioffice: 75 to 54, D after)
	img := "golang.org/x/image"
	r = gradeDeps(dep(img, aged("GO-1", img, "HIGH", "called", "", 0), aged("GO-2", img, "HIGH", "called", "v0.43.0", days(30))),
		dep(m, aged("GO-3", m, "MEDIUM", "called", "v0.35.0", days(30))))
	if r.Deciding == nil || r.Deciding.Module != img {
		t.Fatalf("%+v", r.Deciding)
	}
	if n := wantStep(t, r, img, "v0.43.0"); n.ScoreAfter >= r.Score {
		t.Errorf("%+v", *n)
	}
}

// Two modules, each with one called high fixed 30 days ago: the rows tie at 70. The deciding row's upgrade leaves the other row,
// so the result stays D 70, but the deciding row falls to 0 and the upgrade is the first of the two needed: it is named.
func TestNextStep_TiedRowsKeepTheStep(t *testing.T) {
	a, b := "golang.org/x/net", "golang.org/x/text"
	r := gradeDeps(dep(a, aged("GO-1", a, "HIGH", "called", "v0.35.0", days(30))), dep(b, aged("GO-2", b, "HIGH", "called", "v0.20.0", days(30))))
	if r.Letter != LetterD || r.Score != 70 || r.Deciding == nil || r.Deciding.Module != a {
		t.Fatalf("%s %d %+v", r.Letter, r.Score, r.Deciding)
	}
	n := wantStep(t, r, a, "v0.35.0")
	if n.LetterAfter != LetterD || n.ScoreAfter != 70 || len(n.Clears) != 1 || n.Clears[0] != "GO-1" {
		t.Errorf("%+v", *n)
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

// When a whole-tree rule decides, an upgrade is named only if it improves the letter. Otherwise the reader would be told to run
// something that cannot change their grade.
func TestNextStep_TreeRuleNamesNothingThatCannotImproveTheLetter(t *testing.T) {
	// a checksum mismatch is not cleared by any upgrade
	x := "example.com/x"
	r := run(Input{Self: self(), ChecksumMismatch: true, ChecksumDetail: "example.com/x v1.0.0",
		Deps: []Row{dep(x, aged("GO-1", x, "HIGH", "called", "v1.1.0", days(30)))}})
	if r.Letter != LetterF || r.Deciding == nil || r.Deciding.Tree != "checksum_mismatch" || r.NextStep != nil {
		t.Errorf("checksum mismatch: %s %+v next step %+v", r.Letter, r.Deciding, r.NextStep)
	}
	// four called highs in four modules: any one upgrade leaves three in three modules, still F
	var rows []Row
	for _, m := range []string{"example.com/a", "example.com/b", "example.com/c", "example.com/d"} {
		rows = append(rows, dep(m, aged("H-"+m, m, "HIGH", "called", "v2", days(30))))
	}
	r = gradeDeps(rows...)
	if r.Letter != LetterF || r.Deciding == nil || r.Deciding.Tree != "called_findings" || r.NextStep != nil {
		t.Errorf("no single upgrade improves it: %s %+v next step %+v", r.Letter, r.Deciding, r.NextStep)
	}
	// a row that decides keeps its own step even when the letter after is the same (the honest "D after" case, see a)
	m, o := "golang.org/x/net", "example.com/other"
	r = gradeDeps(dep(m, aged("GO-2", m, "MEDIUM", "called", "v0.60.0", days(30))), dep(o, aged("GO-3", o, "HIGH", "called", "v2", days(30)), aged("GO-4", o, "HIGH", "called", "", 0)))
	if r.Deciding == nil || r.Deciding.Module != o || r.Score != 75 {
		t.Fatalf("%+v %d", r.Deciding, r.Score)
	}
	if n := wantStep(t, r, o, "v2"); n.LetterAfter != LetterD || n.ScoreAfter != 70 {
		t.Errorf("%+v", *n)
	}
}

// An upgrade after which the grade would be Pending is not named by a whole-tree rule either: with the known-exploited check
// missing, any upgrade that improves an F would make the grade Pending ("a finding on that list would grade F"), and one that
// leaves F improves nothing.
func TestNextStep_TreeRuleNamesNothingWhenOnlyPendingImproves(t *testing.T) {
	a, b, z := "example.com/a", "example.com/b", "example.com/z"
	in := Input{Self: self(), Now: now, Deps: []Row{
		dep(a, aged("A1", a, "HIGH", "called", "v0.5.0", days(30))),
		dep(b, aged("B1", b, "HIGH", "called", "v0.5.0", days(30))),
		dep(z, aged("Z1", z, "HIGH", "called", "v1.2.0", days(30)), aged("Z2", z, "HIGH", "called", "v1.2.0", days(30))),
	}}
	in.Checks.KEVUnchecked = 1
	r := Grade(&in)
	if r.Pending != nil || r.Letter != LetterF || r.NextStep != nil {
		t.Errorf("%s %+v next step %+v", r.Letter, r.Pending, r.NextStep)
	}
}

// The re-grade after an upgrade is the full decision: a severity that could not be looked up decides the letter after it, so the
// letter after is Pending ("severity_lookup") instead of a letter that rests on a guess. Before the upgrade the high decides the
// letter whatever the unknown severity is.
func TestNextStep_LetterAfterReadsTheSeverityLookup(t *testing.T) {
	x, y := "example.com/x", "example.com/y"
	failed := Finding{ID: "GO-2026-9040", Module: y, Severity: "", Reachability: "imported", SeverityLookupFailed: true, FixedVersion: "v2", FixReleasedAt: ptr(now.Add(-days(30))), FixDateSource: "module_proxy"}
	r := gradeDeps(dep(x, aged("GO-2026-9041", x, "HIGH", "called", "v1.1.0", days(30))), dep(y, failed))
	if r.Pending != nil || r.Letter != LetterD {
		t.Fatalf("%s %+v", r.Letter, r.Pending)
	}
	n := wantStep(t, r, x, "v1.1.0")
	if n.LetterAfter != "" || n.PendingAfter != "severity_lookup" {
		t.Errorf("%+v", *n)
	}
}

// score_after is left out when the grade after the upgrade would be Pending (there is no score then), and kept, 0 included,
// when there is a letter.
func TestNextStep_ScoreAfterJSON(t *testing.T) {
	a, _ := json.Marshal(NextStep{Module: "m", Version: "v1.0.0", Command: "go get m@v1.0.0", Clears: []string{"X"}, LetterAfter: LetterA})
	if !strings.Contains(string(a), `"letter_after":"A"`) || !strings.Contains(string(a), `"score_after":0`) {
		t.Errorf("%s", a)
	}
	p, _ := json.Marshal(NextStep{Module: "m", Version: "v1.0.0", Command: "go get m@v1.0.0", Clears: []string{"X"}, PendingAfter: "dependency_maintenance"})
	if strings.Contains(string(p), "score_after") || strings.Contains(string(p), "letter_after") || !strings.Contains(string(p), `"pending_after":"dependency_maintenance"`) {
		t.Errorf("%s", p)
	}
	var back NextStep
	if err := json.Unmarshal(p, &back); err != nil || back.PendingAfter != "dependency_maintenance" || back.ScoreAfter != 0 {
		t.Errorf("%+v %v", back, err)
	}
	// and inside a result
	m := "golang.org/x/net"
	missing := dep("example.com/unread")
	missing.Upkeep = Upkeep{Missing: true}
	r := gradeDeps(dep(m, aged("GO-2026-9005", m, "HIGH", "called", "v0.60.0", days(30))), missing)
	b, _ := json.Marshal(r)
	var top struct {
		NextStep map[string]any `json:"next_step"`
	}
	if err := json.Unmarshal(b, &top); err != nil || top.NextStep == nil {
		t.Fatalf("%s %v", b, err)
	}
	if _, ok := top.NextStep["score_after"]; ok {
		t.Errorf("%v", top.NextStep)
	}
}

// The Go spellings of a fixed version (scanner.stdlibVersionPattern): "go1.26.9", "v1.26.9", "1.26.9", "1.21", "go1.22rc1". They
// compare as versions, and the command uses the Go spelling of the chosen one.
func TestNextStep_StdlibSpellings(t *testing.T) {
	step := func(fixes ...string) *NextStep {
		var fs []Finding
		for i, v := range fixes {
			fs = append(fs, aged("GO-2026-91"+string(rune('0'+i)), "stdlib", "HIGH", "called", v, days(30)))
		}
		return gradeDeps(dep("stdlib", fs...)).NextStep
	}
	n := step("go1.26.9", "v1.26.10")
	if n == nil || n.Version != "v1.26.10" || n.Command != "go get toolchain@go1.26.10" || len(n.Clears) != 2 {
		t.Fatalf("%+v", n)
	}
	n = step("go1.26.10", "v1.26.9")
	if n == nil || n.Version != "v1.26.10" || n.Command != "go get toolchain@go1.26.10" {
		t.Fatalf("%+v", n)
	}
	if n = step("go1.24.4"); n == nil || n.Version != "v1.24.4" || n.Command != "go get toolchain@go1.24.4" {
		t.Fatalf("a go-prefixed version alone: %+v", n)
	}
	if n = step("1.26.9"); n == nil || n.Command != "go get toolchain@go1.26.9" {
		t.Fatalf("%+v", n)
	}
	// 1.21 is the release Go calls go1.21.0; a release candidate is below it, and keeps its own spelling
	if n = step("go1.22rc1", "1.22"); n == nil || n.Version != "v1.22.0" || n.Command != "go get toolchain@go1.22.0" || len(n.Clears) != 2 {
		t.Fatalf("%+v", n)
	}
	if n = step("go1.22rc1"); n == nil || n.Version != "v1.22.0-rc.1" || n.Command != "go get toolchain@go1.22rc1" {
		t.Fatalf("%+v", n)
	}
	if n = step("go1.23beta2"); n == nil || n.Version != "v1.23.0-beta.2" || n.Command != "go get toolchain@go1.23beta2" {
		t.Fatalf("%+v", n)
	}
}
