package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// TestWriteText_ContainsSummary tests that output contains overall risk score and level.
func TestWriteText_ContainsSummary(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/example/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 45,
		OverallLevel: scorer.RiskMedium,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "github.com/example/pkg",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 45,
				RiskLevel: scorer.RiskMedium,
			},
		},
		MediumRiskCount: 1,
	}

	opts := TextOptions{
		NoColor: true,
		Writer:  &bytes.Buffer{},
	}

	err := WriteText(graph, ps, &opts)
	if err != nil {
		t.Fatalf("WriteText() failed: %v", err)
	}

	output := opts.Writer.(*bytes.Buffer).String()

	// Check for overall score and level
	if !strings.Contains(output, "45/100") {
		t.Error("Output should contain overall score '45/100'")
	}

	if !strings.Contains(output, "MEDIUM") {
		t.Error("Output should contain overall level 'MEDIUM'")
	}

	if !strings.Contains(output, "SUPPLY-CHAIN RISK:") {
		t.Error("Output should contain 'SUPPLY-CHAIN RISK:' header")
	}
}

// TestWriteText_NoColor tests that noColor=true removes ANSI codes.
func TestWriteText_NoColor(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/example/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 20,
		OverallLevel: scorer.RiskLow,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "github.com/example/pkg",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 20,
				RiskLevel: scorer.RiskLow,
			},
		},
		LowRiskCount: 1,
	}

	opts := TextOptions{
		NoColor: true,
		Writer:  &bytes.Buffer{},
	}

	err := WriteText(graph, ps, &opts)
	if err != nil {
		t.Fatalf("WriteText() failed: %v", err)
	}

	output := opts.Writer.(*bytes.Buffer).String()

	// Check that no ANSI escape codes are present
	if strings.Contains(output, "\033[") {
		t.Error("Output should not contain ANSI escape codes when NoColor=true")
	}
}

// TestWriteText_ColorEnabled tests that noColor=false includes ANSI codes.
func TestWriteText_ColorEnabled(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/example/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 20,
		OverallLevel: scorer.RiskLow,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "github.com/example/pkg",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 20,
				RiskLevel: scorer.RiskLow,
			},
		},
		LowRiskCount: 1,
	}

	opts := TextOptions{
		NoColor: false,
		Writer:  &bytes.Buffer{},
	}

	err := WriteText(graph, ps, &opts)
	if err != nil {
		t.Fatalf("WriteText() failed: %v", err)
	}

	output := opts.Writer.(*bytes.Buffer).String()

	// Check that ANSI escape codes are present
	if !strings.Contains(output, "\033[") {
		t.Error("Output should contain ANSI escape codes when NoColor=false")
	}
}

// TestWriteText_VulnSection tests that vulnerabilities are included in output.
func TestWriteText_VulnSection(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "vulnerable-pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 60,
		OverallLevel: scorer.RiskHigh,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "vulnerable-pkg",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 60,
				RiskLevel: scorer.RiskHigh,
				Vulns: []scanner.Vulnerability{
					{
						ID:           "CVE-2023-12345",
						Aliases:      []string{"GHSA-1234-5678-9012"},
						Summary:      "SQL injection vulnerability",
						Severity:     "HIGH",
						FixedVersion: "v1.1.0",
					},
				},
			},
		},
		HighRiskCount: 1,
		TotalVulns:    1,
	}

	opts := TextOptions{
		NoColor: true,
		Writer:  &bytes.Buffer{},
	}

	err := WriteText(graph, ps, &opts)
	if err != nil {
		t.Fatalf("WriteText() failed: %v", err)
	}

	output := opts.Writer.(*bytes.Buffer).String()

	// Check for vulnerability ID in output
	if !strings.Contains(output, "CVE-2023-12345") {
		t.Error("Output should contain vulnerability ID 'CVE-2023-12345'")
	}

	if !strings.Contains(output, "HIGH") {
		t.Error("Output should contain severity 'HIGH'")
	}

	if !strings.Contains(output, "Fix available") {
		t.Error("Output should indicate fix is available")
	}
}

// TestWriteText_RiskLevelGrouping tests dependencies are grouped by risk level.
func TestWriteText_RiskLevelGrouping(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "critical-pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
		testutil.DepSpec{
			Path:    "high-pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
		testutil.DepSpec{
			Path:    "safe-pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 55,
		OverallLevel: scorer.RiskHigh,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "critical-pkg",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 85,
				RiskLevel: scorer.RiskCritical,
			},
			{
				Module:    "high-pkg",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 65,
				RiskLevel: scorer.RiskHigh,
			},
			{
				Module:    "safe-pkg",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 15,
				RiskLevel: scorer.RiskLow,
			},
		},
		HighRiskCount: 2,
		LowRiskCount:  1,
	}

	opts := TextOptions{
		NoColor: true,
		Writer:  &bytes.Buffer{},
	}

	err := WriteText(graph, ps, &opts)
	if err != nil {
		t.Fatalf("WriteText() failed: %v", err)
	}

	output := opts.Writer.(*bytes.Buffer).String()

	// Check for risk level headers
	if !strings.Contains(output, "CRITICAL RISK") {
		t.Error("Output should contain 'CRITICAL RISK' section header")
	}

	if !strings.Contains(output, "HIGH RISK") {
		t.Error("Output should contain 'HIGH RISK' section header")
	}

	if !strings.Contains(output, "LOW RISK") {
		t.Error("Output should contain 'LOW RISK' section header")
	}
}

// TestWriteText_DirectVsIndirectLabel tests that direct/indirect labels appear.
func TestWriteText_DirectVsIndirectLabel(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "direct-pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
		testutil.DepSpec{
			Path:    "transitive-pkg",
			Version: "v1.0.0",
			Direct:  false,
			Depth:   1,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 30,
		OverallLevel: scorer.RiskLow,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "direct-pkg",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 20,
				RiskLevel: scorer.RiskLow,
			},
			{
				Module:    "transitive-pkg",
				Version:   "v1.0.0",
				Direct:    false,
				RiskScore: 25,
				RiskLevel: scorer.RiskLow,
			},
		},
		LowRiskCount: 2,
	}

	opts := TextOptions{
		NoColor: true,
		Writer:  &bytes.Buffer{},
		Verbose: true, // Show all details
	}

	err := WriteText(graph, ps, &opts)
	if err != nil {
		t.Fatalf("WriteText() failed: %v", err)
	}

	output := opts.Writer.(*bytes.Buffer).String()

	// Check for direct/indirect labels
	if !strings.Contains(output, "direct") {
		t.Error("Output should contain 'direct' label")
	}

	if !strings.Contains(output, "transitive") {
		t.Error("Output should contain 'transitive' label")
	}
}

// TestWriteText_SummaryStatistics tests that summary section contains key metrics.
func TestWriteText_SummaryStatistics(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "pkg1",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
		testutil.DepSpec{
			Path:    "pkg2",
			Version: "v1.0.0",
			Direct:  false,
			Depth:   1,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore:    40,
		OverallLevel:    scorer.RiskMedium,
		HighRiskCount:   0,
		MediumRiskCount: 1,
		LowRiskCount:    1,
		TotalVulns:      2,
		Unmaintained2yr: 1,
		Unmaintained1yr: 0,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "pkg1",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 30,
				RiskLevel: scorer.RiskLow,
				Vulns: []scanner.Vulnerability{
					{ID: "CVE-2023-1", Severity: "HIGH"},
				},
			},
			{
				Module:    "pkg2",
				Version:   "v1.0.0",
				Direct:    false,
				RiskScore: 40,
				RiskLevel: scorer.RiskMedium,
				Vulns: []scanner.Vulnerability{
					{ID: "CVE-2023-2", Severity: "MEDIUM"},
				},
			},
		},
	}

	opts := TextOptions{
		NoColor: true,
		Writer:  &bytes.Buffer{},
	}

	err := WriteText(graph, ps, &opts)
	if err != nil {
		t.Fatalf("WriteText() failed: %v", err)
	}

	output := opts.Writer.(*bytes.Buffer).String()

	// Check for summary section
	if !strings.Contains(output, "SUMMARY") {
		t.Error("Output should contain 'SUMMARY' section")
	}

	if !strings.Contains(output, "Vulnerabilities found") {
		t.Error("Output should contain vulnerability count in summary")
	}

	if !strings.Contains(output, "Unmaintained") {
		t.Error("Output should contain unmaintained count in summary")
	}
}

// TestReachabilityTag confirms the helper returns the correct bracket tags and
// suppresses the tag for the common cases ("called" and "").
func TestReachabilityTag(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"called", ""},
		{"", ""},
		{"imported", " [imported]"},
		{"required", " [required]"},
	}
	for _, tc := range tests {
		got := reachabilityTag(tc.input)
		if got != tc.want {
			t.Errorf("reachabilityTag(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestVulnReachabilityCountHeader confirms the combined count phrase format.
func TestVulnReachabilityCountHeader(t *testing.T) {
	tests := []struct {
		called, imported, required int
		want                       string
	}{
		{3, 0, 0, "3 called"},
		{0, 2, 0, "2 imported"},
		{0, 0, 1, "1 required"},
		{2, 1, 1, "2 called, 1 imported, 1 required"},
		{0, 2, 3, "2 imported, 3 required"},
		{1, 0, 1, "1 called, 1 required"},
	}
	for _, tc := range tests {
		got := vulnReachabilityCountHeader(tc.called, tc.imported, tc.required)
		if got != tc.want {
			t.Errorf("vulnReachabilityCountHeader(%d,%d,%d) = %q, want %q",
				tc.called, tc.imported, tc.required, got, tc.want)
		}
	}
}

// TestWriteText_ReachabilityTags verifies the text renderer emits [imported]
// and [required] tags on the appropriate CVE lines, and the combined count
// header when reachability is mixed.
func TestWriteText_ReachabilityTags(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/example/reach-pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 70,
		OverallLevel: scorer.RiskHigh,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "github.com/example/reach-pkg",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 70,
				RiskLevel: scorer.RiskHigh,
				Vulns: []scanner.Vulnerability{
					{ID: "CVE-2024-CALLED", Severity: "CRITICAL", Reachability: "called"},
					{ID: "CVE-2024-IMPORTED", Severity: "HIGH", Reachability: "imported"},
					{ID: "CVE-2024-REQUIRED", Severity: "MEDIUM", Reachability: "required"},
				},
			},
		},
		HighRiskCount: 1,
		TotalVulns:    3,
	}

	var buf bytes.Buffer
	opts := &TextOptions{
		NoColor: true,
		Writer:  &buf,
	}
	if err := WriteText(graph, ps, opts); err != nil {
		t.Fatalf("WriteText() failed: %v", err)
	}

	out := buf.String()

	// Per-CVE reachability tags.
	// Format is: "⚠ <ID> (<SEVERITY>) [<tag>] — <aliases>"
	if strings.Contains(out, "[called]") {
		t.Error("called CVE must NOT have a [called] tag — suppress the common case")
	}
	if !strings.Contains(out, "CVE-2024-IMPORTED (HIGH) [imported]") {
		t.Errorf("expected [imported] tag on CVE-2024-IMPORTED; output:\n%s", out)
	}
	if !strings.Contains(out, "CVE-2024-REQUIRED (MEDIUM) [required]") {
		t.Errorf("expected [required] tag on CVE-2024-REQUIRED; output:\n%s", out)
	}

	// Combined count header should appear (mix of called/imported/required).
	if !strings.Contains(out, "1 called, 1 imported, 1 required") {
		t.Errorf("expected combined count phrase in output; got:\n%s", out)
	}
}

// TestWriteText_ReachabilityAllCalled verifies no combined count header is
// emitted when all CVEs are called (or have empty reachability).
func TestWriteText_ReachabilityAllCalled(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/example/called-pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 60,
		OverallLevel: scorer.RiskHigh,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "github.com/example/called-pkg",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 60,
				RiskLevel: scorer.RiskHigh,
				Vulns: []scanner.Vulnerability{
					{ID: "CVE-2024-A", Severity: "HIGH", Reachability: "called"},
					{ID: "CVE-2024-B", Severity: "MEDIUM", Reachability: ""},
				},
			},
		},
		HighRiskCount: 1,
		TotalVulns:    2,
	}

	var buf bytes.Buffer
	opts := &TextOptions{NoColor: true, Writer: &buf}
	if err := WriteText(graph, ps, opts); err != nil {
		t.Fatalf("WriteText() failed: %v", err)
	}

	out := buf.String()

	// No mixed header expected — all CVEs are called or legacy empty.
	if strings.Contains(out, "called,") || strings.Contains(out, "imported") || strings.Contains(out, "required") {
		t.Errorf("unexpected reachability header when all CVEs are called; output:\n%s", out)
	}
	// No [called] tag should appear.
	if strings.Contains(out, "[called]") {
		t.Errorf("[called] tag should be suppressed; output:\n%s", out)
	}
}
