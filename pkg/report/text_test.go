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

	if !strings.Contains(output, "OVERALL SUPPLY CHAIN RISK SCORE") {
		t.Error("Output should contain 'OVERALL SUPPLY CHAIN RISK SCORE' header")
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
