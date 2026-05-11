package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// TestWriteJSON_ValidOutput tests that WriteJSON produces valid JSON with expected top-level keys.
func TestWriteJSON_ValidOutput(t *testing.T) {
	// Build minimal graph and project score
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/example/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 30,
		OverallLevel: scorer.RiskLow,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "github.com/example/pkg",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 30,
				RiskLevel: scorer.RiskLow,
			},
		},
		HighRiskCount:   0,
		MediumRiskCount: 0,
		LowRiskCount:    1,
	}

	opts := JSONOptions{
		GoVersion: "1.21",
	}

	var buf bytes.Buffer
	err := WriteJSON(graph, ps, opts, &buf)
	if err != nil {
		t.Fatalf("WriteJSON() failed: %v", err)
	}

	// Parse the output as JSON
	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("Failed to unmarshal JSON output: %v", err)
	}

	// Verify top-level structure
	if report.Tool != "unisupply" {
		t.Errorf("Tool = %q, want %q", report.Tool, "unisupply")
	}

	if report.Project.Module != "test/module" {
		t.Errorf("Project.Module = %q, want %q", report.Project.Module, "test/module")
	}

	if report.Project.GoVersion != "1.21" {
		t.Errorf("Project.GoVersion = %q, want %q", report.Project.GoVersion, "1.21")
	}

	if report.OverallRisk != 30 {
		t.Errorf("OverallRisk = %d, want %d", report.OverallRisk, 30)
	}

	if report.OverallLevel != "LOW" {
		t.Errorf("OverallLevel = %q, want %q", report.OverallLevel, "LOW")
	}

	// Verify GeneratedAt is present and valid
	if report.GeneratedAt == "" {
		t.Error("GeneratedAt is empty")
	}

	// Parse to ensure it's valid RFC3339
	if _, err := time.Parse(time.RFC3339, report.GeneratedAt); err != nil {
		t.Errorf("GeneratedAt is not valid RFC3339: %v", err)
	}
}

// TestWriteJSON_Dependencies tests that dependencies are properly serialized.
func TestWriteJSON_Dependencies(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/pkg1",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
		testutil.DepSpec{
			Path:    "github.com/pkg2",
			Version: "v2.0.0",
			Direct:  false,
			Depth:   1,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 40,
		OverallLevel: scorer.RiskMedium,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "github.com/pkg1",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 20,
				RiskLevel: scorer.RiskLow,
				VulnScore: 0,
			},
			{
				Module:    "github.com/pkg2",
				Version:   "v2.0.0",
				Direct:    false,
				RiskScore: 50,
				RiskLevel: scorer.RiskMedium,
				VulnScore: 25,
			},
		},
		LowRiskCount:    1,
		MediumRiskCount: 1,
	}

	opts := JSONOptions{
		GoVersion: "1.21",
	}

	var buf bytes.Buffer
	err := WriteJSON(graph, ps, opts, &buf)
	if err != nil {
		t.Fatalf("WriteJSON() failed: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if len(report.Deps) != 2 {
		t.Fatalf("Deps length = %d, want 2", len(report.Deps))
	}

	// Check first dependency
	dep1 := report.Deps[0]
	if dep1.Module != "github.com/pkg1" {
		t.Errorf("Deps[0].Module = %q, want %q", dep1.Module, "github.com/pkg1")
	}
	if dep1.Version != "v1.0.0" {
		t.Errorf("Deps[0].Version = %q, want %q", dep1.Version, "v1.0.0")
	}
	if !dep1.Direct {
		t.Errorf("Deps[0].Direct = false, want true")
	}
	if dep1.RiskScore != 20 {
		t.Errorf("Deps[0].RiskScore = %d, want %d", dep1.RiskScore, 20)
	}

	// Check second dependency
	dep2 := report.Deps[1]
	if dep2.Module != "github.com/pkg2" {
		t.Errorf("Deps[1].Module = %q, want %q", dep2.Module, "github.com/pkg2")
	}
	if dep2.Version != "v2.0.0" {
		t.Errorf("Deps[1].Version = %q, want %q", dep2.Version, "v2.0.0")
	}
	if dep2.Direct {
		t.Errorf("Deps[1].Direct = true, want false")
	}
	if dep2.RiskScore != 50 {
		t.Errorf("Deps[1].RiskScore = %d, want %d", dep2.RiskScore, 50)
	}
}

// TestWriteJSON_NilOptionalFields tests that nil optional fields don't cause panics.
func TestWriteJSON_NilOptionalFields(t *testing.T) {
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
				Module:         "github.com/example/pkg",
				Version:        "v1.0.0",
				Direct:         true,
				RiskScore:      20,
				RiskLevel:      scorer.RiskLow,
				Vulns:          nil,
				Maintenance:    nil,
				MaintainerInfo: nil,
				Typosquat:      nil,
				Resilience:     nil,
				AIGenRisk:      nil,
				TrustIndex:     nil,
			},
		},
		LowRiskCount: 1,
	}

	opts := JSONOptions{
		GoVersion: "1.21",
		CIReport:  nil,
		Takeovers: nil,
	}

	var buf bytes.Buffer
	err := WriteJSON(graph, ps, opts, &buf)
	if err != nil {
		t.Fatalf("WriteJSON() with nil fields failed: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// Verify nil fields are handled properly (not in JSON or null)
	if len(report.Deps) != 1 {
		t.Fatalf("Deps length = %d, want 1", len(report.Deps))
	}

	dep := report.Deps[0]
	if dep.Maintenance != nil {
		t.Error("Maintenance field should be nil, got non-nil value")
	}
	if dep.Maintainer != nil {
		t.Error("Maintainer field should be nil, got non-nil value")
	}
	if dep.Typosquat != nil {
		t.Error("Typosquat field should be nil, got non-nil value")
	}

	// CI/CD Report should be nil in output
	if report.CI != nil {
		t.Error("CI field should be nil, got non-nil value")
	}

	// Takeovers can be nil (omitempty in JSON output)
}

// TestWriteJSON_VulnerabilitiesPopulated tests that vulnerabilities are included.
func TestWriteJSON_VulnerabilitiesPopulated(t *testing.T) {
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

	opts := JSONOptions{
		GoVersion: "1.21",
	}

	var buf bytes.Buffer
	err := WriteJSON(graph, ps, opts, &buf)
	if err != nil {
		t.Fatalf("WriteJSON() failed: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if report.Summary.TotalVulns != 1 {
		t.Errorf("Summary.TotalVulns = %d, want 1", report.Summary.TotalVulns)
	}

	if len(report.Deps) != 1 {
		t.Fatalf("Deps length = %d, want 1", len(report.Deps))
	}

	dep := report.Deps[0]
	if len(dep.Vulns) != 1 {
		t.Fatalf("Vulns length = %d, want 1", len(dep.Vulns))
	}

	vuln := dep.Vulns[0]
	if vuln.ID != "CVE-2023-12345" {
		t.Errorf("Vuln.ID = %q, want %q", vuln.ID, "CVE-2023-12345")
	}
	if vuln.Severity != "HIGH" {
		t.Errorf("Vuln.Severity = %q, want %q", vuln.Severity, "HIGH")
	}
	if vuln.FixedVersion != "v1.1.0" {
		t.Errorf("Vuln.FixedVersion = %q, want %q", vuln.FixedVersion, "v1.1.0")
	}
}
