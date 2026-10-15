package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/unidoc/unipdf/v5/creator"
	"github.com/unidoc/unipdf/v5/model"

	"github.com/unidoc/unisupply/pkg/grade"
	"github.com/unidoc/unisupply/pkg/scanner"
)

func estimatedFinding(id string, tier string, counted bool) grade.FindingResult {
	return grade.FindingResult{ID: id, Severity: "MEDIUM", Estimated: true, Tier: tier, Counted: counted}
}

func TestDataQualityNote_OnlyGradedEstimated(t *testing.T) {
	g := &grade.Result{Rows: []grade.RowResult{
		{Module: "example.com/a", Findings: []grade.FindingResult{
			estimatedFinding("GO-1", grade.TierCalled, true),
			estimatedFinding("GO-2", grade.TierGraphOnly, false), // graph-only: not graded, not listed
			{ID: "GO-3", Severity: "HIGH", Tier: grade.TierCalled, Counted: true},
		}},
		{Module: "example.com/b", Findings: []grade.FindingResult{estimatedFinding("GO-4", grade.TierImported, true)}},
	}}
	intro, bullets := dataQualityNote(g, map[string]bool{"GO-4": true})
	if len(bullets) != 2 {
		t.Fatalf("bullets = %q, want GO-1 and GO-4 only", bullets)
	}
	all := strings.Join(bullets, "\n")
	for _, want := range []string{"GO-1 (example.com/a) — scored MEDIUM", "GO-4 (example.com/b) — scored MEDIUM (severity lookup failed"} {
		if !strings.Contains(all, want) {
			t.Errorf("bullets missing %q:\n%s", want, all)
		}
	}
	for _, not := range []string{"GO-2", "GO-3"} {
		if strings.Contains(all, not) {
			t.Errorf("bullets must not list %s:\n%s", not, all)
		}
	}
	for _, want := range []string{"2 graded advisory", "scored as MEDIUM, whatever its reachability", "marked * only when that estimate could change it"} {
		if !strings.Contains(intro, want) {
			t.Errorf("intro missing %q: %s", want, intro)
		}
	}
	for _, bad := range []string{"conservatively", "HIGH when called", "HIGH when the vulnerable function"} {
		if strings.Contains(intro, bad) {
			t.Errorf("intro still has v1 wording %q: %s", bad, intro)
		}
	}
}

func TestDataQualityNote_NoneWhenNothingEstimated(t *testing.T) {
	if _, b := dataQualityNote(nil, nil); len(b) != 0 {
		t.Errorf("nil grade: bullets %q", b)
	}
	g := &grade.Result{Rows: []grade.RowResult{{Module: "m", Findings: []grade.FindingResult{estimatedFinding("GO-2", grade.TierGraphOnly, false)}}}}
	if i, b := dataQualityNote(g, nil); i != "" || len(b) != 0 {
		t.Errorf("graph-only estimate must give no note, got %q %q", i, b)
	}
}

// The Estimates paragraph says what docs/grading.md says: any letter an unknown severity could change, on any row.
func TestMethodologySections_EstimatesParagraph(t *testing.T) {
	var body string
	for _, s := range methodologySections() {
		if s.title == "Estimates (*)" {
			body = s.body
		}
	}
	for _, want := range []string{
		"every such severity as low and as critical",
		"a different letter in either run marks the result, whichever row the unknown severity is on",
		"a row that does not rest on an estimate decides",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Estimates paragraph missing %q: %q", want, body)
		}
	}
	if strings.Contains(body, "no other row or rule certifies") {
		t.Errorf("Estimates paragraph still restricts the mark to a C: %q", body)
	}
}

func TestMethodologySections_MatchGradingV2(t *testing.T) {
	var sb strings.Builder
	for _, s := range methodologySections() {
		sb.WriteString(s.title + "\n" + s.body + "\n")
	}
	all := sb.String()
	for _, want := range []string{
		"the larger of its vulnerability score and its upkeep score", "worst row", "Called:", "Imported:", "Graph only:",
		"never changes the letter", "PENDING", "marked with * (for example C*) when that estimate could change it", "halved", "Whole-tree rules",
		"scores 35 when it is the module itself, 20 when it is a dependency and 10 when it is test-only or not compiled in",
		"never D or F", "policy values", "14-day",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("methodology missing %q", want)
		}
	}
	for _, bad := range []string{"highest maintenance risk", "Maintainer Analysis", "bus factor", "contributor data", "Maintenance Assessment", "takeover"} {
		if strings.Contains(all, bad) {
			t.Errorf("methodology still has v1 text %q", bad)
		}
	}
}

func TestVulnLine_V2Words(t *testing.T) {
	v := &scanner.Vulnerability{ID: "GO-9", Severity: "UNKNOWN", Reachability: "required"}
	f := &grade.FindingResult{ID: "GO-9", Severity: "MEDIUM", Estimated: true, Tier: grade.TierCalled, TierAssumed: true, VEX: grade.VEXStatus{Status: "affected"}}
	got := vulnLine(v, f)
	for _, want := range []string{"called (assumed)", "VEX affected", "severity MEDIUM (estimated)"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q missing %q", got, want)
		}
	}
	g := &grade.FindingResult{ID: "GO-9", Severity: "HIGH", Tier: grade.TierGraphOnly, VEX: grade.VEXStatus{Status: "not_affected", Justification: "vulnerable_code_not_present"}}
	got = vulnLine(v, g)
	for _, want := range []string{"graph only: shown, not graded", "not_affected (vulnerable_code_not_present)", "severity HIGH)"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q missing %q", got, want)
		}
	}
	// No grade finding: no v1 words.
	got = vulnLine(v, nil)
	if strings.Contains(got, "required") || strings.Contains(got, "UNKNOWN") || !strings.Contains(got, "graph only") {
		t.Errorf("fallback line has v1 words: %q", got)
	}
	if got := vulnLine(&scanner.Vulnerability{ID: "X", Severity: "HIGH", Reachability: "imported"}, nil); !strings.Contains(got, "imported; severity HIGH") {
		t.Errorf("imported fallback: %q", got)
	}
	if gradeFindingByID(&grade.RowResult{Findings: []grade.FindingResult{*f}}, "GO-9") == nil || gradeFindingByID(nil, "GO-9") != nil {
		t.Error("gradeFindingByID lookup wrong")
	}
}

func manyRows() *grade.Result {
	g := &grade.Result{}
	for i := 0; i < 141; i++ {
		g.Rows = append(g.Rows, grade.RowResult{Module: fmt.Sprintf("example.com/quiet%d", i), Letter: grade.LetterA, UpkeepState: grade.StateActive, Reason: "nothing found"})
	}
	g.Rows = append(g.Rows,
		grade.RowResult{Module: "example.com/b", Letter: grade.LetterB, Score: 20, UpkeepState: grade.StateActive},
		grade.RowResult{Module: "example.com/f", Letter: grade.LetterF, Score: 90, UpkeepState: grade.StateActive},
		grade.RowResult{Module: "example.com/finding", Letter: grade.LetterA, UpkeepState: grade.StateFinished, Findings: []grade.FindingResult{{ID: "GO-1", Tier: grade.TierGraphOnly}}},
		grade.RowResult{Module: "example.com/parked", Letter: grade.LetterA, UpkeepState: grade.StateParked},
		grade.RowResult{Module: "example.com/unknown", Letter: grade.LetterA, UpkeepState: grade.StateUnknown},
	)
	return g
}

func TestGradeRowsToShow(t *testing.T) {
	g := manyRows()
	shown, quiet := gradeRowsToShow(g, false)
	if quiet != 141 || len(shown) != 5 {
		t.Fatalf("shown %d quiet %d, want 5 and 141", len(shown), quiet)
	}
	if shown[0].Module != "example.com/f" || shown[1].Module != "example.com/b" {
		t.Errorf("not worst first: %s, %s", shown[0].Module, shown[1].Module)
	}
	if line := gradeQuietRowsLine(quiet); line != "141 more rows graded A with nothing found" {
		t.Errorf("line = %q", line)
	}
	if gradeQuietRowsLine(0) != "" || gradeQuietRowsLine(1) != "1 more row graded A with nothing found" {
		t.Error("singular/zero wrong")
	}
	all, q := gradeRowsToShow(g, true)
	if len(all) != 146 || q != 0 {
		t.Errorf("verbose: %d rows, %d quiet", len(all), q)
	}
}

func TestGradeText_QuietRowsCollapsed(t *testing.T) {
	g := manyRows()
	out := renderGradeText(t, g)
	requireAll(t, out, "141 more rows graded A with nothing found", "example.com/parked")
	requireNone(t, out, "example.com/quiet7 ")
	requireAll(t, renderGradeTextV(t, g, true), "example.com/quiet7 ")
}

func TestGradeWrapModulePath(t *testing.T) {
	long := "github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding"
	lines := gradeWrapModulePath(long, 28)
	if strings.Join(lines, "") != long {
		t.Errorf("lines lose text: %q", lines)
	}
	for _, l := range lines {
		if len(l) > 28 {
			t.Errorf("line %q longer than 28", l)
		}
		if !strings.HasSuffix(l, "/") && l != lines[len(lines)-1] {
			t.Errorf("line %q does not end at a slash", l)
		}
	}
	if len(lines) < 2 {
		t.Errorf("expected wrapping: %q", lines)
	}
	// A segment longer than the column is cut with an ellipsis, never wrapped mid-word.
	cut := gradeWrapModulePath("example.com/"+strings.Repeat("x", 60), 20)
	for _, l := range cut {
		if len(l) > 20 {
			t.Errorf("line %q too long", l)
		}
	}
	if last := cut[len(cut)-1]; !strings.HasSuffix(last, "...") {
		t.Errorf("long segment not cut with ellipsis: %q", cut)
	}
	if got := gradeWrapModulePath("a/b", 28); len(got) != 1 || got[0] != "a/b" {
		t.Errorf("short path: %q", got)
	}
}

func TestPDFGradeRowCells_WrapAndSelf(t *testing.T) {
	r := &grade.RowResult{Module: "github.com/some-organisation/a-quite-long-repository-name/v2", Self: true, Letter: grade.LetterC, Score: 40, UpkeepState: grade.StateArchived, Reason: "r"}
	cells := pdfGradeRowCells(r)
	if !strings.Contains(cells[0], "\n") || !strings.HasSuffix(cells[0], "(this module)") {
		t.Errorf("module cell not wrapped: %q", cells[0])
	}
	for _, l := range strings.Split(cells[0], "\n") {
		if len(l) > pdfModuleColWidth {
			t.Errorf("line %q exceeds column", l)
		}
	}
}

// TestGradePDF_DrawManyRows draws the grade page for a 146-row grade without a licence and checks only the selected rows'
// text is produced (the drawing must not fail).
func TestGradePDF_DrawManyRows(t *testing.T) {
	_ = initLicense()
	regular, _ := model.NewStandard14Font(model.HelveticaName)
	bold, _ := model.NewStandard14Font(model.HelveticaBoldName)
	c := creator.New()
	c.SetPageSize(creator.PageSizeLetter)
	c.SetPageMargins(50, 50, 50, 50)
	c.NewPage()
	writeGradeRowsPDF(c, manyRows(), regular, bold)
	if n := c.Context().Page; n > 3 {
		t.Errorf("rows table spilled over %d pages", n)
	}
}

// F34: the Pending paragraph lists every check that can make a grade Pending and says what a missing archived flag does by
// default, as docs/grading.md does.
func TestMethodologySections_PendingParagraphListsEveryCheck(t *testing.T) {
	var body string
	for _, s := range methodologySections() {
		if s.title == "Pending" {
			body = s.body
		}
	}
	for _, want := range []string{
		"scan_incomplete", "module_status", "module_advisories", "dependency_maintenance",
		"checksum", "known_exploited", "severity_lookup",
		"the letter is given with a note", "only with --strict-archived", "older than 30 days",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("Pending paragraph missing %q: %q", want, body)
		}
	}
}
