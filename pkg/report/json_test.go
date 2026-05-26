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

// TestWriteJSON_TestOnly_ConfirmedTrue verifies that a dep with IsTestOnly=&true
// is serialised with "test_only": true in the JSON output.
func TestWriteJSON_TestOnly_ConfirmedTrue(t *testing.T) {
	trueVal := true
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:       "github.com/testfwk/containers",
			Version:    "v0.40.0",
			Direct:     false,
			Depth:      1,
			IsTestOnly: &trueVal,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 15,
		OverallLevel: scorer.RiskLow,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:     "github.com/testfwk/containers",
				Version:    "v0.40.0",
				Direct:     false,
				IsTestOnly: &trueVal,
				RiskScore:  15,
				RiskLevel:  scorer.RiskLow,
			},
		},
		LowRiskCount: 1,
	}

	var buf bytes.Buffer
	if err := WriteJSON(graph, ps, JSONOptions{GoVersion: "1.21"}, &buf); err != nil {
		t.Fatalf("WriteJSON() failed: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if len(report.Deps) != 1 {
		t.Fatalf("Deps length = %d, want 1", len(report.Deps))
	}

	dep := report.Deps[0]
	if dep.TestOnly == nil {
		t.Fatal("test_only field is nil (omitted), want &true")
	}
	if !*dep.TestOnly {
		t.Errorf("test_only = false, want true")
	}
	if dep.Direct {
		t.Errorf("direct = true for transitive dep, want false")
	}
}

// TestWriteJSON_TestOnly_ConfirmedFalse verifies that a dep with IsTestOnly=&false
// (confirmed production) is serialised with "test_only": false.
func TestWriteJSON_TestOnly_ConfirmedFalse(t *testing.T) {
	falseVal := false
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:       "github.com/example/production",
			Version:    "v1.0.0",
			Direct:     true,
			Depth:      0,
			IsTestOnly: &falseVal,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 10,
		OverallLevel: scorer.RiskLow,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:     "github.com/example/production",
				Version:    "v1.0.0",
				Direct:     true,
				IsTestOnly: &falseVal,
				RiskScore:  10,
				RiskLevel:  scorer.RiskLow,
			},
		},
		LowRiskCount: 1,
	}

	var buf bytes.Buffer
	if err := WriteJSON(graph, ps, JSONOptions{GoVersion: "1.21"}, &buf); err != nil {
		t.Fatalf("WriteJSON() failed: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	dep := report.Deps[0]
	if dep.TestOnly == nil {
		t.Fatal("test_only field is nil (omitted), want &false")
	}
	if *dep.TestOnly {
		t.Errorf("test_only = true for confirmed production dep, want false")
	}
}

// TestWriteJSON_TestOnly_NilOmitted verifies that when IsTestOnly is nil
// (classification unavailable), the "test_only" key is absent from the JSON
// output (omitempty semantics for *bool).
func TestWriteJSON_TestOnly_NilOmitted(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:       "github.com/example/unknown",
			Version:    "v1.0.0",
			Direct:     false,
			Depth:      1,
			IsTestOnly: nil, // unknown — go list was unavailable
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 20,
		OverallLevel: scorer.RiskLow,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:     "github.com/example/unknown",
				Version:    "v1.0.0",
				Direct:     false,
				IsTestOnly: nil, // unknown
				RiskScore:  20,
				RiskLevel:  scorer.RiskLow,
			},
		},
		LowRiskCount: 1,
	}

	var buf bytes.Buffer
	if err := WriteJSON(graph, ps, JSONOptions{GoVersion: "1.21"}, &buf); err != nil {
		t.Fatalf("WriteJSON() failed: %v", err)
	}

	// Unmarshal into a map to check key presence (not just value).
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("failed to unmarshal JSON to map: %v", err)
	}

	deps, _ := raw["dependencies"].([]interface{})
	if len(deps) != 1 {
		t.Fatalf("dependencies length = %d, want 1", len(deps))
	}

	depMap, _ := deps[0].(map[string]interface{})
	if _, present := depMap["test_only"]; present {
		t.Errorf("test_only key is present in JSON for nil IsTestOnly, want omitted")
	}
}

// TestWriteJSON_Transitive_Direct_RoundTrip verifies that a transitive dep's
// Direct=false field passes through WriteJSON without re-derivation.
// This is the regression guard required by Task 04's finding.
func TestWriteJSON_Transitive_Direct_RoundTrip(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/transitive/pkg",
			Version: "v1.2.3",
			Direct:  false, // transitive — must not become true in JSON
			Depth:   2,
			UsedBy:  []string{"github.com/direct/framework"},
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 15,
		OverallLevel: scorer.RiskLow,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:         "github.com/transitive/pkg",
				Version:        "v1.2.3",
				Direct:         false,
				RiskScore:      15,
				RiskLevel:      scorer.RiskLow,
				DependencyPath: []string{"github.com/direct/framework"},
			},
		},
		LowRiskCount: 1,
	}

	var buf bytes.Buffer
	if err := WriteJSON(graph, ps, JSONOptions{GoVersion: "1.21"}, &buf); err != nil {
		t.Fatalf("WriteJSON() failed: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if len(report.Deps) != 1 {
		t.Fatalf("Deps length = %d, want 1", len(report.Deps))
	}

	dep := report.Deps[0]
	if dep.Direct {
		t.Errorf("direct = true for transitive dep; regression: Direct must not be re-derived")
	}
	if len(dep.DependencyPath) != 1 || dep.DependencyPath[0] != "github.com/direct/framework" {
		t.Errorf("DependencyPath = %v, want [github.com/direct/framework]", dep.DependencyPath)
	}
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

// TestWriteJSON_CriticalRiskCount asserts that the JSON summary distinguishes
// CRITICAL (>=76) from HIGH (51-75) — the plan 39 split.
func TestWriteJSON_CriticalRiskCount(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{Path: "github.com/crit/pkg", Version: "v1.0.0", Direct: true, Depth: 0},
		testutil.DepSpec{Path: "github.com/high/pkg", Version: "v1.0.0", Direct: true, Depth: 0},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 80,
		OverallLevel: scorer.RiskCritical,
		Dependencies: []*scorer.DependencyScore{
			{Module: "github.com/crit/pkg", Version: "v1.0.0", Direct: true, RiskScore: 90, RiskLevel: scorer.RiskCritical},
			{Module: "github.com/high/pkg", Version: "v1.0.0", Direct: true, RiskScore: 60, RiskLevel: scorer.RiskHigh},
		},
		CriticalRiskCount: 1,
		HighRiskCount:     1,
	}

	var buf bytes.Buffer
	if err := WriteJSON(graph, ps, JSONOptions{GoVersion: "1.21"}, &buf); err != nil {
		t.Fatalf("WriteJSON() failed: %v", err)
	}

	// Snapshot: the raw JSON must contain the new field key.
	if !bytes.Contains(buf.Bytes(), []byte(`"critical_risk_count"`)) {
		t.Errorf("JSON output missing critical_risk_count key, got:\n%s", buf.String())
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if report.Summary.CriticalRiskCount != 1 {
		t.Errorf("Summary.CriticalRiskCount = %d, want 1", report.Summary.CriticalRiskCount)
	}
	if report.Summary.HighRiskCount != 1 {
		t.Errorf("Summary.HighRiskCount = %d, want 1 (must not be conflated with critical)", report.Summary.HighRiskCount)
	}
}

// TestWriteJSON_Reachability verifies that each reachability tier (called,
// imported, required) is preserved in JSONVuln, and that empty Reachability
// (backward-compat legacy CVE) is omitted from the JSON key (omitempty).
func TestWriteJSON_Reachability(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/example/vuln-pkg",
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
				Module:    "github.com/example/vuln-pkg",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 70,
				RiskLevel: scorer.RiskHigh,
				Vulns: []scanner.Vulnerability{
					{ID: "CVE-2024-0001", Severity: "CRITICAL", Reachability: "called"},
					{ID: "CVE-2024-0002", Severity: "HIGH", Reachability: "imported"},
					{ID: "CVE-2024-0003", Severity: "MEDIUM", Reachability: "required"},
					{ID: "CVE-2024-0004", Severity: "LOW", Reachability: ""}, // legacy: empty → omitted in JSON
				},
			},
		},
		HighRiskCount: 1,
		TotalVulns:    4,
	}

	var buf bytes.Buffer
	if err := WriteJSON(graph, ps, JSONOptions{GoVersion: "1.21"}, &buf); err != nil {
		t.Fatalf("WriteJSON() failed: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(report.Deps) != 1 {
		t.Fatalf("Deps length = %d, want 1", len(report.Deps))
	}
	vulns := report.Deps[0].Vulns
	if len(vulns) != 4 {
		t.Fatalf("Vulns length = %d, want 4", len(vulns))
	}

	if vulns[0].Reachability != "called" {
		t.Errorf("vulns[0].Reachability = %q, want %q", vulns[0].Reachability, "called")
	}
	if vulns[1].Reachability != "imported" {
		t.Errorf("vulns[1].Reachability = %q, want %q", vulns[1].Reachability, "imported")
	}
	if vulns[2].Reachability != "required" {
		t.Errorf("vulns[2].Reachability = %q, want %q", vulns[2].Reachability, "required")
	}

	// Empty Reachability must be absent from the JSON key (omitempty).
	// Unmarshal into a raw map to check key presence explicitly.
	rawAll := struct {
		Deps []map[string]interface{} `json:"dependencies"`
	}{}
	if err := json.Unmarshal(buf.Bytes(), &rawAll); err != nil {
		t.Fatalf("raw unmarshal: %v", err)
	}
	rawVulns, _ := rawAll.Deps[0]["vulnerabilities"].([]interface{})
	if len(rawVulns) != 4 {
		t.Fatalf("raw vulnerabilities length = %d, want 4", len(rawVulns))
	}
	vuln4, _ := rawVulns[3].(map[string]interface{})
	if _, present := vuln4["reachability"]; present {
		t.Errorf("empty Reachability must be omitted from JSON (omitempty), but key is present with value %v", vuln4["reachability"])
	}
}
