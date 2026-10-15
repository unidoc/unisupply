package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unidoc/unipdf/v5/creator"
	"github.com/unidoc/unipdf/v5/extractor"
	"github.com/unidoc/unipdf/v5/model"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/grade"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

func gradeTestFinding(id, sev, tier string, counted bool) grade.FindingResult {
	f := grade.FindingResult{
		ID: id, Module: "example.com/dep", Severity: sev, Tier: tier, Counted: counted, Score: 60,
		FixedVersion: "v1.2.4",
		VEX:          grade.VEXStatus{Status: "affected"},
		Response:     grade.Response{Status: "past_window", Text: "Fix released 40 days ago, past the 14-day window"},
		Condition:    "main.go calls dep.Parse",
		Note:         "a note about " + id,
	}
	if !counted {
		f.Score = 0
		f.VEX = grade.VEXStatus{Status: "not_affected", Justification: "vulnerable_code_not_present"}
	}
	return f
}

// gradeCases are the grades the text and PDF reports must render.
func gradeCases() map[string]*grade.Result {
	return map[string]*grade.Result{
		"A": {
			RuleVersion: 2, Letter: grade.LetterA, Score: 0,
			Rows: []grade.RowResult{
				{Module: "example.com/app", Self: true, Letter: grade.LetterA, UpkeepState: grade.StateActive, Reason: "nothing found"},
				{Module: "example.com/dep", Version: "v1.2.3", Direct: true, Letter: grade.LetterA, UpkeepState: grade.StateActive, Reason: "no findings, actively maintained"},
			},
		},
		"F": {
			RuleVersion: 2, Letter: grade.LetterF, Score: 90,
			Deciding: &grade.Deciding{Module: "example.com/dep", Reason: "called critical finding GO-2026-0001", Score: 90},
			Rows: []grade.RowResult{
				{
					Module: "example.com/dep", Version: "v1.2.3", Score: 90, VulnScore: 90, Letter: grade.LetterF,
					UpkeepState: grade.StateActive, Reason: "called critical finding GO-2026-0001",
					Findings: []grade.FindingResult{gradeTestFinding("GO-2026-0001", "CRITICAL", grade.TierCalled, true)},
				},
				{Module: "example.com/app", Self: true, Letter: grade.LetterA, UpkeepState: grade.StateActive, Reason: "nothing found"},
			},
			TreeRows: []grade.TreeRow{{Rule: "called_critical", Score: 90, Letter: grade.LetterF, Reason: "1 called critical finding across 1 module"}},
			Notes:    []string{"The module's own advisories were not looked up because no module version was given"},
		},
		"Pending": {
			RuleVersion: 2,
			Pending: &grade.Pending{
				Check: "vulnerability_scan", Reason: "the vulnerability scan did not finish",
				Known: []string{"Archived: example.com/old", "2 direct dependencies"},
			},
			Rows: []grade.RowResult{{Module: "example.com/old", Version: "v0.1.0", Letter: grade.LetterC, Score: 40, UpkeepState: grade.StateArchived, Reason: "archived"}},
		},
		"C*": {
			RuleVersion: 2, Letter: grade.LetterC, Estimated: true, Score: 40,
			Deciding: &grade.Deciding{Self: true, Reason: "imported medium finding GO-2026-0002", Score: 40},
			Rows: []grade.RowResult{
				{
					Module: "example.com/app", Self: true, Letter: grade.LetterC, Estimated: true, Score: 40, UpkeepState: grade.StateActive,
					Reason: "imported medium finding GO-2026-0002",
					Findings: []grade.FindingResult{{
						ID: "GO-2026-0002", Severity: "MEDIUM", Estimated: true, Tier: grade.TierImported, Counted: true, Score: 40,
						VEX: grade.VEXStatus{Status: "under_investigation"}, Response: grade.Response{Status: "no_fix", Text: "No fix released yet"},
					}},
				},
			},
		},
		"GraphOnly": {
			RuleVersion: 2, Letter: grade.LetterA, Score: 0,
			Rows: []grade.RowResult{{
				Module: "example.com/ghost", Version: "v0.9.0", NotBuilt: true, Letter: grade.LetterA, UpkeepState: grade.StateActive,
				Reason: "finding in code that is never compiled in",
				Findings: []grade.FindingResult{
					gradeTestFinding("GO-2026-0003", "HIGH", grade.TierGraphOnly, false),
				},
			}},
		},
	}
}

func gradeTestInput() (*scorer.ProjectScore, func() *TextOptions) {
	ps := &scorer.ProjectScore{
		Dependencies: []*scorer.DependencyScore{{
			Module: "example.com/dep", Version: "v1.2.3", Direct: true, RiskScore: 77, RiskLevel: scorer.RiskCritical,
			Vulns: []scanner.Vulnerability{{ID: "GO-2026-0001", Severity: "CRITICAL", FixedVersion: "v1.2.4"}},
		}},
	}
	return ps, func() *TextOptions { return &TextOptions{NoColor: true, Writer: &bytes.Buffer{}} }
}

func renderGradeText(t *testing.T, g *grade.Result) string {
	t.Helper()
	return renderGradeTextV(t, g, false)
}

func renderGradeTextV(t *testing.T, g *grade.Result, verbose bool) string {
	t.Helper()
	graph := testutil.MakeGraph(testutil.DepSpec{Path: "example.com/dep", Version: "v1.2.3", Direct: true, Depth: 0})
	ps, mk := gradeTestInput()
	opts := mk()
	opts.Grade = g
	opts.Verbose = verbose
	if err := WriteText(graph, ps, opts); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	return opts.Writer.(*bytes.Buffer).String()
}

func requireAll(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("output missing %q:\n%s", w, out)
		}
	}
}

func requireNone(t *testing.T, out string, nots ...string) {
	t.Helper()
	for _, n := range nots {
		if strings.Contains(out, n) {
			t.Errorf("output must not contain %q:\n%s", n, out)
		}
	}
}

func TestGradeText_A(t *testing.T) {
	out := renderGradeTextV(t, gradeCases()["A"], true)
	requireAll(t, out, "SUPPLY-CHAIN GRADE: A\n", "GRADE TABLE", "example.com/app (this module)", "no findings, actively maintained")
	// Without --verbose the two quiet A rows are one line.
	out = renderGradeText(t, gradeCases()["A"])
	requireAll(t, out, "2 more rows graded A with nothing found")
	requireNone(t, out, "no findings, actively maintained")
	requireNone(t, out, "Decided by", "A*", "Estimated:", "PENDING", "No grade")
}

func TestGradeText_FWithDecidingAndTreeRule(t *testing.T) {
	out := renderGradeText(t, gradeCases()["F"])
	requireAll(t, out,
		"SUPPLY-CHAIN GRADE: F\n",
		"Decided by: example.com/dep (score 90) — called critical finding GO-2026-0001",
		"GO-2026-0001  severity CRITICAL, tier called, counted",
		"Response: Fix released 40 days ago, past the 14-day window",
		"VEX: affected",
		"Condition: main.go calls dep.Parse",
		"Note: a note about GO-2026-0001",
		"Fixed in: v1.2.4",
		"WHOLE-TREE RULES",
		"called_critical (score 90) — 1 called critical finding across 1 module",
		"GRADE NOTES",
		"no module version was given",
		"Grade: F", // the dependency listing carries the row letter
	)
	requireNone(t, out, "Risk: 77/100", "77/100")
	// Worst row first in the table.
	out = renderGradeTextV(t, gradeCases()["F"], true)
	if strings.Index(out, "example.com/dep  v1.2.3") > strings.Index(out, "example.com/app (this module)") {
		t.Errorf("rows are not worst first:\n%s", out)
	}

	// A whole-tree rule decides: its name is the "Decided by" subject.
	g := *gradeCases()["F"]
	g.Deciding = &grade.Deciding{Tree: "called_critical", Reason: "1 called critical finding across 1 module", Score: 90}
	out = renderGradeText(t, &g)
	requireAll(t, out, "Decided by: whole-tree rule called_critical (score 90) — 1 called critical finding across 1 module")

	// The module itself decides: "this module".
	g.Deciding = &grade.Deciding{Self: true, Reason: "r", Score: 90}
	requireAll(t, renderGradeText(t, &g), "Decided by: this module (score 90) — r")
}

func TestGradeText_Pending(t *testing.T) {
	out := renderGradeText(t, gradeCases()["Pending"])
	requireAll(t, out,
		"SUPPLY-CHAIN GRADE: PENDING\n",
		"Why: the vulnerability scan did not finish",
		"Check that did not run: vulnerability_scan",
		"What we do know:",
		"- Archived: example.com/old",
		"- 2 direct dependencies",
	)
	requireNone(t, out, "Decided by", "GRADE: A", "GRADE: C", "GRADE: F")
}

func TestGradeText_EstimatedC(t *testing.T) {
	out := renderGradeText(t, gradeCases()["C*"])
	requireAll(t, out,
		"SUPPLY-CHAIN GRADE: C*\n",
		"Estimated: at least one finding had no published severity and was scored as medium",
		"Decided by: this module (score 40) — imported medium finding GO-2026-0002",
		"severity MEDIUM (estimated), tier imported, counted",
		"VEX: under_investigation",
	)
}

func TestGradeText_GraphOnlyShownNotGraded(t *testing.T) {
	out := renderGradeText(t, gradeCases()["GraphOnly"])
	requireAll(t, out,
		"SUPPLY-CHAIN GRADE: A\n",
		"GO-2026-0003  severity HIGH, tier graph_only, shown, not graded",
		"VEX: not_affected (vulnerable_code_not_present)",
	)
	requireNone(t, out, "tier graph_only, counted")
}

func TestGradeText_NoGrade(t *testing.T) {
	out := renderGradeText(t, nil)
	requireAll(t, out, "No grade: grading was not run")
	requireNone(t, out, "SUPPLY-CHAIN GRADE", "GRADE TABLE", "77/100", "Grade: A", "Grade: F")
}

// TestGradeText_RemovedWordsGone: nothing of the old score model is published any more.
func TestGradeText_RemovedWordsGone(t *testing.T) {
	graph := testutil.MakeGraph(testutil.DepSpec{Path: "example.com/dep", Version: "v1.2.3", Direct: true, Depth: 0})
	for name, g := range gradeCases() {
		ps, mk := gradeTestInput()
		ps.OverallScore, ps.OverallLevel = 77, scorer.RiskHigh
		ps.HeadlineDriver, ps.MeanDepRiskScore, ps.WorstCVEID = "severity_adjusted", 50, "GO-2026-0001"
		d := ps.Dependencies[0]
		d.MaintainerInfo = &scanner.MaintainerInfo{DataAvailable: true, Owner: "o", TakeoverCandidate: true, TakeoverReason: "abandoned"}
		d.AIGenRisk = &scanner.AIGenRisk{Score: 60, RiskLevel: "high", Indicators: []string{"x"}}
		eps := 0.9
		d.Vulns[0].EPSSScore = &eps
		d.Vulns[0].InKEV = true
		opts := mk()
		opts.Grade = g
		opts.Verbose = true
		if err := WriteText(graph, ps, opts); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out := opts.Writer.(*bytes.Buffer).String()
		requireNone(t, out,
			"Takeover", "takeover", "overall risk", "AI-generat", "SUPPLY-CHAIN RISK", "Driver:", "Worst CVE",
			"EPSS", "Score breakdown", "Mean Dep Risk", "severity_adjusted", "/100",
		)
		if !strings.Contains(out, "[KEV]") {
			t.Errorf("%s: KEV marker lost:\n%s", name, out)
		}
	}
}

func TestGradeLabels(t *testing.T) {
	cases := map[string]string{"A": "A", "F": "F", "Pending": "PENDING", "C*": "C*", "GraphOnly": "A"}
	for name, want := range cases {
		if got := gradeLetterLabel(gradeCases()[name]); got != want {
			t.Errorf("%s: label = %q, want %q", name, got, want)
		}
	}
}

// TestGradePDF_DrawSmoke draws the grade pages and cover for each case; it needs no licence because nothing is written.
func TestGradePDF_DrawSmoke(t *testing.T) {
	_ = initLicense()
	regular, _ := model.NewStandard14Font(model.HelveticaName)
	bold, _ := model.NewStandard14Font(model.HelveticaBoldName)
	ps, _ := gradeTestInput()
	cases := gradeCases()
	cases["none"] = nil
	for name, g := range cases {
		c := creator.New()
		c.SetPageSize(creator.PageSizeLetter)
		c.SetPageMargins(50, 50, 50, 50)
		c.NewPage()
		writeGradeCoverBlock(c, g, regular, bold)
		writeGradeSection(c, g, regular, bold)
		writeDependencyFindings(c, ps, g, regular, bold)
		_ = name
	}
}

// TestGradePDF_WriteAndExtract writes a full PDF per case and checks the extracted text. Needs a UniPDF licence.
func TestGradePDF_WriteAndExtract(t *testing.T) {
	requirePDFLicense(t)
	_ = initLicense()
	graph := testutil.MakeGraph(testutil.DepSpec{Path: "example.com/dep", Version: "v1.2.3", Direct: true, Depth: 0})
	ps, _ := gradeTestInput()
	ps.OverallScore, ps.OverallLevel, ps.HeadlineDriver = 77, scorer.RiskHigh, "severity_adjusted"

	cases := gradeCases()
	cases["none"] = nil
	want := map[string][]string{
		"A":         {"Supply-Chain Grade"},
		"F":         {"Decided by", "called_critical", "GO-2026-0001", "VEX: affected"},
		"Pending":   {"PENDING", "What we do know:", "Archived: example.com/old"},
		"C*":        {"C*", "Estimated: at least one finding had no published severity"},
		"GraphOnly": {"shown, not graded"},
		"none":      {"No grade: grading was not run"},
	}
	for name, g := range cases {
		path := filepath.Join(t.TempDir(), name+".pdf")
		if err := WritePDF(t.Context(), graph, ps, PDFOptions{OutputPath: path, Grade: g, GoVersion: "go1.26"}); err != nil {
			t.Fatalf("%s: WritePDF: %v", name, err)
		}
		if fi, err := os.Stat(path); err != nil || fi.Size() == 0 {
			t.Fatalf("%s: no PDF written: %v", name, err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := model.NewPdfReader(f)
		if err != nil {
			t.Fatalf("%s: read PDF: %v", name, err)
		}
		n, _ := reader.GetNumPages()
		var all strings.Builder
		for p := 1; p <= n; p++ {
			page, err := reader.GetPage(p)
			if err != nil {
				t.Fatal(err)
			}
			ex, err := extractor.New(page)
			if err != nil {
				t.Fatal(err)
			}
			txt, _ := ex.ExtractText()
			all.WriteString(txt)
		}
		f.Close()
		got := strings.Join(strings.Fields(all.String()), " ")
		for _, w := range want[name] {
			if !strings.Contains(got, w) {
				t.Errorf("%s: PDF text missing %q", name, w)
			}
		}
		for _, bad := range []string{"Takeover", "takeover", "overall risk", "AI-generat", "Mean Dep Risk", "Headline Driver", "Risk Distribution"} {
			if strings.Contains(got, bad) {
				t.Errorf("%s: PDF text contains removed %q", name, bad)
			}
		}
	}
}

func TestScanDetailsAreReported(t *testing.T) {
	info := &scanner.ScanInfo{Platform: "linux/amd64", GoVersion: "go1.26.9", GovulncheckVersion: "v1.1.4", VulnDB: "https://vuln.go.dev", VulnDBLastModified: "2026-10-14T10:00:00Z"}
	var buf bytes.Buffer
	writeScanInfoText(&buf, info)
	out := buf.String()
	for _, want := range []string{"SCAN DETAILS", "linux/amd64", "go1.26.9", "govulncheck v1.1.4", "https://vuln.go.dev", "2026-10-14T10:00:00Z"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q missing from %q", want, out)
		}
	}
	buf.Reset()
	writeScanInfoText(&buf, nil)
	writeScanInfoText(&buf, &scanner.ScanInfo{})
	if buf.Len() != 0 {
		t.Errorf("nothing to say: %q", buf.String())
	}
	var j bytes.Buffer
	graph := &resolver.Graph{Root: "example.com/app", Dependencies: map[string]*resolver.Dependency{}}
	if err := WriteJSON(graph, &scorer.ProjectScore{}, JSONOptions{Scan: info}, &j); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(j.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	scan, _ := m["scan"].(map[string]any)
	if scan["go_version"] != "go1.26.9" || scan["vuln_db_last_modified"] != "2026-10-14T10:00:00Z" || scan["platform"] != "linux/amd64" {
		t.Errorf("the scan block: %v", m["scan"])
	}
	j.Reset()
	_ = WriteJSON(graph, &scorer.ProjectScore{}, JSONOptions{}, &j)
	m = map[string]any{}
	_ = json.Unmarshal(j.Bytes(), &m)
	if _, has := m["scan"]; has {
		t.Error("no scan block when no scan ran")
	}
}
