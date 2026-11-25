package report

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/unidoc/unipdf/v5/creator"
	"github.com/unidoc/unipdf/v5/extractor"
	"github.com/unidoc/unipdf/v5/model"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/grade"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// TestWriteDependencyBlock_ReachabilitySmoke verifies that writeDependencyBlock
// does not panic when vulnerabilities carry all three reachability tiers.
// This exercises the inline tag code path added in task-07.
func TestWriteDependencyBlock_ReachabilitySmoke(t *testing.T) {
	// UniPDF creator may emit license warnings to stderr — that is expected in
	// the unlicensed demo mode and does not indicate a test failure.
	_ = initLicense()

	c := creator.New()
	c.SetPageSize(creator.PageSizeLetter)
	c.SetPageMargins(50, 50, 50, 50)
	c.NewPage()

	regular, _ := model.NewStandard14Font(model.HelveticaName)
	bold, _ := model.NewStandard14Font(model.HelveticaBoldName)

	ds := &scorer.DependencyScore{
		Module:    "github.com/example/reach-pkg",
		Version:   "v1.0.0",
		Direct:    true,
		RiskScore: 75,
		RiskLevel: scorer.RiskHigh,
		Vulns: []scanner.Vulnerability{
			{ID: "CVE-2024-0001", Severity: "CRITICAL", Reachability: "called"},
			{ID: "CVE-2024-0002", Severity: "HIGH", Reachability: "imported"},
			{ID: "CVE-2024-0003", Severity: "MEDIUM", Reachability: "required"},
			{ID: "CVE-2024-0004", Severity: "LOW", Reachability: ""}, // legacy
		},
	}

	// Must not panic.
	writeDependencyBlock(c, ds, nil, "C", regular, bold, true)
}

// TestWriteDependencyFindings_VulnDetailSmoke verifies that a low-risk dependency
// carrying a vulnerability gets its CVE detail rendered, and that the
// section as a whole does not panic when mixed with a clean dependency.
func TestWriteDependencyFindings_VulnDetailSmoke(t *testing.T) {
	_ = initLicense()

	c := creator.New()
	c.SetPageSize(creator.PageSizeLetter)
	c.SetPageMargins(50, 50, 50, 50)
	c.NewPage()

	regular, _ := model.NewStandard14Font(model.HelveticaName)
	bold, _ := model.NewStandard14Font(model.HelveticaBoldName)

	ps := &scorer.ProjectScore{
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "golang.org/x/crypto",
				Version:   "v0.48.0",
				RiskScore: 12,
				RiskLevel: scorer.RiskLow,
				Vulns: []scanner.Vulnerability{
					{ID: "GO-2026-5005", Severity: "CRITICAL", FixedVersion: "v0.49.0"},
				},
			},
			{
				Module:    "github.com/example/clean-pkg",
				Version:   "v1.0.0",
				RiskScore: 5,
				RiskLevel: scorer.RiskLow,
			},
		},
	}

	// Must not panic.
	writeDependencyFindings(c, ps, nil, regular, bold)
}

// TestPDFTimeBombRows verifies the PDF lists each time bomb with its module,
// which the cover's "Driver: archived_floor" line does not name.
func TestPDFTimeBombRows(t *testing.T) {
	rows := pdfTimeBombRows(archivedTimeBombScore())
	want := [3]string{"archived", "github.com/google/go-cmdtest", "archived 53 months"}
	if len(rows) != 1 || rows[0] != want {
		t.Errorf("pdfTimeBombRows() = %q, want [%q]", rows, want)
	}
	if got := pdfTimeBombRows(&scorer.ProjectScore{}); len(got) != 0 {
		t.Errorf("pdfTimeBombRows(no deps) = %q, want none", got)
	}
}

// TestWriteTimeBombsSection_Smoke verifies the section draws without panicking,
// and is a no-op when there are no time bombs.
func TestWriteTimeBombsSection_Smoke(t *testing.T) {
	_ = initLicense()

	c := creator.New()
	c.SetPageSize(creator.PageSizeLetter)
	c.SetPageMargins(50, 50, 50, 50)
	c.NewPage()

	regular, _ := model.NewStandard14Font(model.HelveticaName)
	bold, _ := model.NewStandard14Font(model.HelveticaBoldName)

	writeTimeBombsSection(c, archivedTimeBombScore(), regular, bold)
	writeTimeBombsSection(c, &scorer.ProjectScore{}, regular, bold)
}

// TestWriteExecutiveSummary_ScanNotesSmoke verifies the executive summary
// renders with scan notes and without them, without panicking.
func TestWriteExecutiveSummary_ScanNotesSmoke(t *testing.T) {
	_ = initLicense()

	regular, _ := model.NewStandard14Font(model.HelveticaName)
	bold, _ := model.NewStandard14Font(model.HelveticaBoldName)
	graph := testutil.MakeGraph(
		testutil.DepSpec{Path: "github.com/example/pkg", Version: "v1.0.0", Direct: true, Depth: 0},
	)

	for _, notes := range [][]string{nil, {"go list reported package errors that do not affect module classification: x"}} {
		c := creator.New()
		c.SetPageSize(creator.PageSizeLetter)
		c.SetPageMargins(50, 50, 50, 50)
		c.NewPage()
		ps := &scorer.ProjectScore{OverallLevel: scorer.RiskLow, Notes: notes}
		writeExecutiveSummary(c, graph, ps, PDFOptions{}, regular, bold)
	}
}

// TestWriteDependencyBlock_CallTraceSmoke verifies that a called vulnerability
// carrying a trace, a cut path and several symbols renders without panicking,
// including a path with no trace at all.
func TestWriteDependencyBlock_CallTraceSmoke(t *testing.T) {
	_ = initLicense()

	c := creator.New()
	c.SetPageSize(creator.PageSizeLetter)
	c.SetPageMargins(50, 50, 50, 50)
	c.NewPage()

	regular, _ := model.NewStandard14Font(model.HelveticaName)
	bold, _ := model.NewStandard14Font(model.HelveticaBoldName)

	cut := issue134Vuln()
	cut.ID = "GO-2026-5006"
	cut.CallPath = []string{"example.com/u1repro.main", "...", "golang.org/x/crypto/ssh/agent.keyring.Add"}
	cut.CallTrace = []scanner.CallFrame{cut.CallTrace[0], {Elided: true}, cut.CallTrace[1]}
	cut.CalledSymbols = []string{"golang.org/x/crypto/ssh/agent.keyring.Add", "golang.org/x/crypto/ssh/agent.keyring.Lock"}

	noTrace := issue134Vuln()
	noTrace.ID = "GO-2026-5007"
	noTrace.CallTrace = nil

	ds := &scorer.DependencyScore{
		Module: "golang.org/x/crypto", Version: "v0.48.0", Direct: true,
		RiskScore: 80, RiskLevel: scorer.RiskCritical,
		Vulns: []scanner.Vulnerability{issue134Vuln(), cut, noTrace},
	}

	// Must not panic.
	writeDependencyBlock(c, ds, nil, "C", regular, bold, true)
}

// requirePDFLicense skips a test that writes a PDF when no UniPDF license key
// is set: unipdf v5 refuses to write without one ("unipdf license code
// required"), and CI runs without the key. Tests that only draw onto the
// creator do not need it.
func requirePDFLicense(t *testing.T) {
	t.Helper()
	if os.Getenv("UNIDOC_LICENSE_API_KEY") == "" {
		t.Skip("UNIDOC_LICENSE_API_KEY is not set: unipdf cannot write a PDF without a license")
	}
}

// TestWriteDependencyBlock_ReachedViaExtraction renders a dependency block to a
// PDF, reads it back and checks the extracted page text carries the call path
// with the ASCII separator. Extracted text is whitespace-normalized because the
// extractor may break the line at a wrap point.
func TestWriteDependencyBlock_ReachedViaExtraction(t *testing.T) {
	requirePDFLicense(t)
	// initLicense returns "license key already set" on every call after the
	// first in the test binary; that is not a failure, so the error is ignored
	// like the other PDF tests do.
	_ = initLicense()

	c := creator.New()
	c.SetPageSize(creator.PageSizeLetter)
	c.SetPageMargins(50, 50, 50, 50)
	c.NewPage()

	regular, _ := model.NewStandard14Font(model.HelveticaName)
	bold, _ := model.NewStandard14Font(model.HelveticaBoldName)

	v := issue134Vuln()
	v.CalledSymbols = []string{"golang.org/x/crypto/ssh/agent.keyring.Add", "golang.org/x/crypto/ssh/agent.keyring.Lock"}
	ds := &scorer.DependencyScore{
		Module: "golang.org/x/crypto", Version: "v0.48.0", Direct: true,
		RiskScore: 80, RiskLevel: scorer.RiskCritical,
		Vulns: []scanner.Vulnerability{v},
	}
	writeDependencyBlock(c, ds, nil, "C", regular, bold, true)

	var buf bytes.Buffer
	if err := c.Write(&buf); err != nil {
		t.Fatalf("write PDF: %v", err)
	}
	reader, err := model.NewPdfReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("read PDF: %v", err)
	}
	page, err := reader.GetPage(1)
	if err != nil {
		t.Fatalf("get page 1: %v", err)
	}
	ex, err := extractor.New(page)
	if err != nil {
		t.Fatalf("extractor: %v", err)
	}
	text, err := ex.ExtractText()
	if err != nil {
		t.Fatalf("extract text: %v", err)
	}
	got := strings.Join(strings.Fields(text), " ")

	for _, want := range []string{
		"Reached via: example.com/u1repro.main (main.go:13) > golang.org/x/crypto/ssh/agent.keyring.Add",
		"Vulnerable symbols called: golang.org/x/crypto/ssh/agent.keyring.Add, golang.org/x/crypto/ssh/agent.keyring.Lock",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("extracted PDF text missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "keyring.go:149") {
		t.Errorf("dependency position must not be shown in the PDF:\n%s", got)
	}
}

// stdlibTestVulns returns two stdlib advisories: one called with a path and
// two symbols, one merely imported.
func stdlibTestVulns() []scanner.Vulnerability {
	called := scanner.Vulnerability{
		ID:           "GO-2026-4001",
		Aliases:      []string{"CVE-2026-11111"},
		Summary:      "Unbounded allocation in net/http",
		Severity:     "HIGH",
		FixedVersion: "go1.26.3",
		Reachability: "called",
		CallPath:     []string{"example.com/app.main", "net/http.ListenAndServe"},
		CallTrace: []scanner.CallFrame{
			{Name: "example.com/app.main", Module: "example.com/app", File: "main.go", Line: 21, Project: true},
			{Name: "net/http.ListenAndServe", Module: "stdlib", File: "net/http/server.go", Line: 3500},
		},
		CalledSymbols: []string{"net/http.ListenAndServe", "net/http.Serve"},
	}
	imported := scanner.Vulnerability{
		ID:           "GO-2026-4002",
		Summary:      "Parser panic in encoding/asn1",
		Severity:     "MEDIUM",
		Reachability: "imported",
	}
	return []scanner.Vulnerability{called, imported}
}

// TestWriteStdlibVulnSection_Extraction renders the stdlib section to a PDF,
// reads it back and checks the heading, advisory IDs, summaries and the call
// path are in the extracted text.
func TestWriteStdlibVulnSection_Extraction(t *testing.T) {
	requirePDFLicense(t)
	_ = initLicense()

	c := creator.New()
	c.SetPageSize(creator.PageSizeLetter)
	c.SetPageMargins(50, 50, 50, 50)

	regular, _ := model.NewStandard14Font(model.HelveticaName)
	bold, _ := model.NewStandard14Font(model.HelveticaBoldName)

	writeStdlibVulnSection(c, stdlibTestVulns(), "go1.26.11", false, regular, bold)

	var buf bytes.Buffer
	if err := c.Write(&buf); err != nil {
		t.Fatalf("write PDF: %v", err)
	}
	reader, err := model.NewPdfReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("read PDF: %v", err)
	}
	numPages, err := reader.GetNumPages()
	if err != nil {
		t.Fatalf("page count: %v", err)
	}
	var all strings.Builder
	for i := 1; i <= numPages; i++ {
		page, err := reader.GetPage(i)
		if err != nil {
			t.Fatalf("get page %d: %v", i, err)
		}
		ex, err := extractor.New(page)
		if err != nil {
			t.Fatalf("extractor: %v", err)
		}
		text, err := ex.ExtractText()
		if err != nil {
			t.Fatalf("extract text: %v", err)
		}
		all.WriteString(text)
		all.WriteString("\n")
	}
	got := strings.Join(strings.Fields(all.String()), " ")

	for _, want := range []string{
		"Standard Library Vulnerabilities",
		stdlibIntroNotGraded,
		"Vulnerability: GO-2026-4001 (called; severity HIGH)",
		"Summary: Unbounded allocation in net/http",
		"Fix available: go1.26.3",
		"Reached via: example.com/app.main (main.go:21) > net/http.ListenAndServe",
		"Vulnerable symbols called: net/http.ListenAndServe, net/http.Serve",
		"Vulnerability: GO-2026-4002 (imported; severity MEDIUM)",
		"Summary: Parser panic in encoding/asn1",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("extracted PDF text missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "server.go:3500") {
		t.Errorf("stdlib frame position must not be shown in the PDF:\n%s", got)
	}
	if i, j := strings.Index(got, "GO-2026-4001"), strings.Index(got, "GO-2026-4002"); i < 0 || j < i {
		t.Errorf("stdlib vulnerabilities not in the given order:\n%s", got)
	}
}

// TestVulnLine_StdlibWithoutFinding pins, without a PDF licence, the first line printed for the stdlib advisories
// (no grade finding): the same inputs as TestWriteStdlibVulnSection_Extraction.
func TestVulnLine_StdlibWithoutFinding(t *testing.T) {
	vs := stdlibTestVulns()
	for i, want := range []string{
		"Vulnerability: GO-2026-4001 (called; severity HIGH)",
		"Vulnerability: GO-2026-4002 (imported; severity MEDIUM)",
	} {
		if got := vulnLine(&vs[i], nil); got != want {
			t.Errorf("vulnLine(%s) = %q, want %q", vs[i].ID, got, want)
		}
	}
}

// TestCollectVulnAliases_IncludesStdlib pins that the alias table the PDF
// appendix renders covers the stdlib advisories passed to it.
func TestCollectVulnAliases_IncludesStdlib(t *testing.T) {
	entries := collectVulnAliases(&scorer.ProjectScore{}, stdlibTestVulns())
	if len(entries) != 1 || entries[0].ID != "GO-2026-4001" ||
		len(entries[0].Aliases) != 1 || entries[0].Aliases[0] != "CVE-2026-11111" {
		t.Errorf("collectVulnAliases() = %+v, want GO-2026-4001 -> CVE-2026-11111", entries)
	}
}

// TestAddVulnBullets_CalledSymbolsCut reads the paragraph's chunks instead of a written PDF, so it needs no license and
// runs in CI.
func TestAddVulnBullets_CalledSymbolsCut(t *testing.T) {
	c := creator.New()
	p := c.NewStyledParagraph()
	regular, _ := model.NewStandard14Font(model.HelveticaName)

	v := cutSymbolsVuln()
	addVulnBullets(p, &v, nil, false, regular)

	var text strings.Builder
	for _, ch := range p.GetChunks() {
		text.WriteString(ch.Text)
	}
	want := "Vulnerable symbols called (20 of 153): example.com/lib.Sym00, "
	if !strings.Contains(text.String(), want) {
		t.Errorf("bullets missing %q:\n%s", want, text.String())
	}
}

// chunkText joins the text of a paragraph's chunks.
func chunkText(p *creator.StyledParagraph) string {
	var b strings.Builder
	for _, ch := range p.GetChunks() {
		b.WriteString(ch.Text)
	}
	return b.String()
}

// TestStdlibSectionParagraphs reads the paragraphs' chunks instead of a written PDF, so it needs no licence and runs in CI.
func TestStdlibSectionParagraphs(t *testing.T) {
	c := creator.New()
	regular, _ := model.NewStandard14Font(model.HelveticaName)

	for _, tt := range []struct {
		name    string
		version string
		graded  bool
		intro   string
	}{
		{"not graded", "go1.26.11", false, stdlibIntroNotGraded},
		{"graded", "go1.26.11", true, stdlibIntroGraded},
		{"no version", "", false, "These are in the Go standard library. Upgrading Go fixes them."},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ps := stdlibSectionParagraphs(c, stdlibTestVulns(), tt.version, tt.graded, regular)
			if len(ps) != 3 {
				t.Fatalf("got %d paragraphs, want the intro and one per entry (3)", len(ps))
			}
			if got := chunkText(ps[0]); !strings.Contains(got, tt.intro) || strings.Contains(got, "These affect") {
				t.Errorf("intro = %q, want it to contain %q", got, tt.intro)
			}
			called, imported := chunkText(ps[1]), chunkText(ps[2])
			for _, want := range []string{
				"Vulnerability: GO-2026-4001 (called; severity HIGH)",
				"Reached via: example.com/app.main (main.go:21) > net/http.ListenAndServe",
				"Vulnerable symbols called: net/http.ListenAndServe, net/http.Serve",
			} {
				if !strings.Contains(called, want) {
					t.Errorf("called entry missing %q:\n%s", want, called)
				}
			}
			if !strings.Contains(imported, "Vulnerability: GO-2026-4002 (imported; severity MEDIUM)") ||
				strings.Contains(imported, "Reached via") || strings.Contains(imported, "Vulnerable symbols") {
				t.Errorf("imported entry wrong:\n%s", imported)
			}
		})
	}
}

// TestAddVulnBullets_DependencyFinding covers, without a licence, the call a dependency block makes: a called finding
// with a grade finding and withSummary false.
func TestAddVulnBullets_DependencyFinding(t *testing.T) {
	c := creator.New()
	p := c.NewStyledParagraph()
	regular, _ := model.NewStandard14Font(model.HelveticaName)

	v := issue134Vuln()
	v.Summary = "keyring.Add retains keys"
	v.FixedVersion = "v0.49.0"
	v.CalledSymbols = []string{"golang.org/x/crypto/ssh/agent.keyring.Add", "golang.org/x/crypto/ssh/agent.keyring.Lock"}
	row := &grade.RowResult{Module: "golang.org/x/crypto", Findings: []grade.FindingResult{
		{ID: v.ID, Module: "golang.org/x/crypto", Severity: "CRITICAL", Tier: grade.TierCalled, VEX: grade.VEXStatus{Status: "affected"}},
	}}
	f := gradeFindingByID(row, v.ID)
	if f == nil {
		t.Fatal("the fixture finding was not found by ID")
	}
	addVulnBullets(p, &v, f, false, regular)

	got := chunkText(p)
	for _, want := range []string{
		"Vulnerability: GO-2026-5005 (called; VEX affected; severity CRITICAL)",
		"Fix available: v0.49.0",
		"Reached via: example.com/u1repro.main (main.go:13) > golang.org/x/crypto/ssh/agent.keyring.Add",
		"Vulnerable symbols called: golang.org/x/crypto/ssh/agent.keyring.Add, golang.org/x/crypto/ssh/agent.keyring.Lock",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("bullets missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Summary:") {
		t.Errorf("a dependency block prints no summary bullet:\n%s", got)
	}
	if strings.Contains(got, "keyring.go:149") {
		t.Errorf("dependency position must not be shown in the PDF:\n%s", got)
	}
}

// TestAddVulnBullets_ImportedVia reads the paragraph's chunks, so it needs no licence: an imported finding with a chain
// gets an ASCII "Imported via" bullet, and a called finding gets none.
func TestAddVulnBullets_ImportedVia(t *testing.T) {
	regular, _ := model.NewStandard14Font(model.HelveticaName)
	bullets := func(v *scanner.Vulnerability) string {
		p := creator.New().NewStyledParagraph()
		addVulnBullets(p, v, nil, false, regular)
		return chunkText(p)
	}

	imported := scanner.Vulnerability{
		ID: "GO-2026-5025", Severity: "MEDIUM", Reachability: "imported", FixedVersion: "v0.55.0",
		ImportPath: []string{"example.com/app/cmd/app", "github.com/some/dep", "golang.org/x/net/html"},
	}
	got := bullets(&imported)
	if want := "Imported via: example.com/app/cmd/app > github.com/some/dep > golang.org/x/net/html"; !strings.Contains(got, want) {
		t.Errorf("bullets missing %q:\n%s", want, got)
	}
	if strings.Contains(got, "Reached via") {
		t.Errorf("an imported finding must not have Reached via:\n%s", got)
	}

	noChain := imported
	noChain.ImportPath = nil
	if got := bullets(&noChain); strings.Contains(got, "Imported via") {
		t.Errorf("bullets have Imported via without a chain:\n%s", got)
	}

	called := issue134Vuln()
	called.ImportPath = imported.ImportPath
	if got := bullets(&called); strings.Contains(got, "Imported via") {
		t.Errorf("a called finding has Imported via:\n%s", got)
	}
}
