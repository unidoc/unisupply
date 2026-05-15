package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// minimalPS returns a minimal ProjectScore suitable for CI finding tests.
func minimalPS() *scorer.ProjectScore {
	return &scorer.ProjectScore{
		OverallScore: 10,
		OverallLevel: scorer.RiskLow,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "github.com/example/pkg",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 10,
				RiskLevel: scorer.RiskLow,
			},
		},
		LowRiskCount: 1,
	}
}

// minimalGraph returns a minimal graph for CI finding tests.
func minimalGraph() *resolver.Graph {
	return testutil.MakeGraph(testutil.DepSpec{
		Path:    "github.com/example/pkg",
		Version: "v1.0.0",
		Direct:  true,
		Depth:   0,
	})
}

// TestJSON_BuildFileFindings_Dockerfile verifies that a Dockerfile containing
// an unpinned base image produces a build_file_findings[] entry with a non-empty
// rule_id and message.
func TestJSON_BuildFileFindings_Dockerfile(t *testing.T) {
	// Build a synthetic project directory with a Dockerfile.
	dir := t.TempDir()
	dockerfile := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(dockerfile, []byte("FROM ubuntu:latest\nRUN echo hello\n"), 0600); err != nil {
		t.Fatalf("writing Dockerfile: %v", err)
	}

	// Run the build-file scanner directly to produce findings.
	cs := scanner.NewCIScanner()
	buildFindings := cs.ScanBuildFiles(dir)
	if len(buildFindings) == 0 {
		t.Fatal("expected at least one build finding for FROM ubuntu:latest, got none")
	}

	ciReport := &scanner.CIReport{
		BuildFindings: buildFindings,
		TotalFindings: len(buildFindings),
	}
	ciReport.OverallScore = 0
	ciReport.OverallLevel = scanner.CIRiskLow

	graph := minimalGraph()
	ps := minimalPS()

	var buf bytes.Buffer
	if err := WriteJSON(graph, ps, JSONOptions{GoVersion: "1.21", CIReport: ciReport}, &buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	// Decode into a generic map to check raw JSON keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal top-level: %v", err)
	}

	rawBF, ok := raw["build_file_findings"]
	if !ok {
		t.Fatal("build_file_findings key is missing from JSON output")
	}

	var findings []JSONFlatFinding
	if err := json.Unmarshal(rawBF, &findings); err != nil {
		t.Fatalf("unmarshal build_file_findings: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("build_file_findings[] is empty; expected at least one entry")
	}

	for i, f := range findings {
		if f.RuleID == "" {
			t.Errorf("findings[%d].rule_id is empty; must be non-empty internal rule id", i)
		}
		if f.Message == "" {
			t.Errorf("findings[%d].message is empty", i)
		}
		if f.Severity == "" {
			t.Errorf("findings[%d].severity is empty", i)
		}
	}

	// Verify the top-level ci_findings[] is also present (may be empty).
	rawCI, ok := raw["ci_findings"]
	if !ok {
		t.Fatal("ci_findings key is missing from JSON output")
	}
	var ciFindings []JSONFlatFinding
	if err := json.Unmarshal(rawCI, &ciFindings); err != nil {
		t.Fatalf("unmarshal ci_findings: %v", err)
	}
	// No workflow was scanned so ci_findings must be an empty array, not omitted.
	if ciFindings == nil {
		t.Error("ci_findings should be an empty array, not null")
	}
}

// TestJSON_CIFindings_UnpinnedAction verifies that a workflow containing an
// unpinned action reference produces a ci_findings[] entry.
func TestJSON_CIFindings_UnpinnedAction(t *testing.T) {
	// Construct a synthetic CIReport with a workflow finding for an unpinned action.
	finding := scanner.CIFinding{
		Category:    "unpinned_action",
		Severity:    scanner.CIRiskMedium,
		Description: "Action 'actions/checkout@v4' uses floating tag 'v4' instead of pinned SHA",
		File:        ".github/workflows/ci.yml",
		Remediation: "Pin to a full SHA: actions/checkout@<commit-sha>",
	}

	ciReport := &scanner.CIReport{
		Workflows: []*scanner.WorkflowRisk{
			{
				Name:     "CI",
				FilePath: ".github/workflows/ci.yml",
				Score:    10,
				Level:    scanner.CIRiskLow,
				Findings: []scanner.CIFinding{finding},
			},
		},
		UnpinnedActions: 1,
		TotalFindings:   1,
		OverallScore:    10,
		OverallLevel:    scanner.CIRiskLow,
	}

	graph := minimalGraph()
	ps := minimalPS()

	var buf bytes.Buffer
	if err := WriteJSON(graph, ps, JSONOptions{GoVersion: "1.21", CIReport: ciReport}, &buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	rawCI, ok := raw["ci_findings"]
	if !ok {
		t.Fatal("ci_findings key is missing from JSON output")
	}

	var ciFindings []JSONFlatFinding
	if err := json.Unmarshal(rawCI, &ciFindings); err != nil {
		t.Fatalf("unmarshal ci_findings: %v", err)
	}

	if len(ciFindings) == 0 {
		t.Fatal("ci_findings[] is empty; expected at least one entry for the unpinned action")
	}

	f := ciFindings[0]
	if f.RuleID != "unpinned_action" {
		t.Errorf("rule_id = %q, want %q", f.RuleID, "unpinned_action")
	}
	if f.Message == "" {
		t.Error("message is empty")
	}
	if f.Severity != "MEDIUM" {
		t.Errorf("severity = %q, want %q", f.Severity, "MEDIUM")
	}
	if f.File == "" {
		t.Error("file is empty")
	}

	// build_file_findings must be present as empty array (no build-file scan ran).
	rawBF, ok := raw["build_file_findings"]
	if !ok {
		t.Fatal("build_file_findings key is missing from JSON output")
	}
	var bfFindings []JSONFlatFinding
	if err := json.Unmarshal(rawBF, &bfFindings); err != nil {
		t.Fatalf("unmarshal build_file_findings: %v", err)
	}
	if bfFindings == nil {
		t.Error("build_file_findings should be an empty array, not null")
	}
}

// TestJSON_NoWorkflowDir_EmptyArrays verifies that when the CI scanner ran on a
// project with no .github/workflows/ directory, ci_findings and
// build_file_findings are present as empty arrays (never omitted).
func TestJSON_NoWorkflowDir_EmptyArrays(t *testing.T) {
	// A CIReport with no workflows and no build findings — as produced when
	// the scanner runs on a project without .github/workflows/.
	ciReport := &scanner.CIReport{
		Workflows:     nil,
		BuildFindings: nil,
		OverallScore:  0,
		OverallLevel:  scanner.CIRiskLow,
	}

	graph := minimalGraph()
	ps := minimalPS()

	var buf bytes.Buffer
	if err := WriteJSON(graph, ps, JSONOptions{GoVersion: "1.21", CIReport: ciReport}, &buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Both keys must be present.
	for _, key := range []string{"ci_findings", "build_file_findings"} {
		rawVal, ok := raw[key]
		if !ok {
			t.Errorf("%s key is missing from JSON output", key)
			continue
		}
		var findings []JSONFlatFinding
		if err := json.Unmarshal(rawVal, &findings); err != nil {
			t.Errorf("unmarshal %s: %v", key, err)
			continue
		}
		if findings == nil {
			t.Errorf("%s should be an empty array [], not null", key)
		}
		if len(findings) != 0 {
			t.Errorf("%s should be empty, got %d entries", key, len(findings))
		}
	}
}

// TestText_NoWorkflowDir_ShowsNoFindings verifies that when the CI scanner ran
// on a project without .github/workflows/, the text output still renders both
// "## CI/CD" and "## Build files" sections with "No findings".
func TestText_NoWorkflowDir_ShowsNoFindings(t *testing.T) {
	ciReport := &scanner.CIReport{
		Workflows:     nil,
		BuildFindings: nil,
		OverallScore:  0,
		OverallLevel:  scanner.CIRiskLow,
	}

	graph := minimalGraph()
	ps := minimalPS()

	var buf bytes.Buffer
	opts := &TextOptions{
		NoColor:  true,
		Writer:   &buf,
		CIReport: ciReport,
	}

	if err := WriteText(graph, ps, opts); err != nil {
		t.Fatalf("WriteText: %v", err)
	}

	out := buf.String()

	if !strings.Contains(out, "## CI/CD") {
		t.Error("text output is missing '## CI/CD' section header")
	}
	if !strings.Contains(out, "## Build files") {
		t.Error("text output is missing '## Build files' section header")
	}

	// Both sections must say "No findings" when there are none.
	if strings.Count(out, "No findings") < 2 {
		t.Errorf("expected at least 2 'No findings' occurrences (one per section), got %d\noutput:\n%s",
			strings.Count(out, "No findings"), out)
	}
}

// TestText_CIFindings_SectionsPresent verifies that when CI findings exist, the
// "## CI/CD" and "## Build files" section headers are present in text output.
func TestText_CIFindings_SectionsPresent(t *testing.T) {
	ciReport := &scanner.CIReport{
		Workflows: []*scanner.WorkflowRisk{
			{
				Name:     "CI",
				FilePath: ".github/workflows/ci.yml",
				Score:    10,
				Level:    scanner.CIRiskLow,
				Findings: []scanner.CIFinding{
					{
						Category:    "unpinned_action",
						Severity:    scanner.CIRiskMedium,
						Description: "Action pinned to floating tag",
						File:        ".github/workflows/ci.yml",
						Remediation: "Pin to SHA",
					},
				},
			},
		},
		UnpinnedActions: 1,
		TotalFindings:   1,
		OverallScore:    10,
		OverallLevel:    scanner.CIRiskLow,
	}

	graph := minimalGraph()
	ps := minimalPS()

	var buf bytes.Buffer
	opts := &TextOptions{
		NoColor:  true,
		Writer:   &buf,
		CIReport: ciReport,
	}

	if err := WriteText(graph, ps, opts); err != nil {
		t.Fatalf("WriteText: %v", err)
	}

	out := buf.String()

	if !strings.Contains(out, "## CI/CD") {
		t.Error("text output is missing '## CI/CD' section header")
	}
	if !strings.Contains(out, "## Build files") {
		t.Error("text output is missing '## Build files' section header")
	}
}
