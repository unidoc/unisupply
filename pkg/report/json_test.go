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

// TestWriteJSON_TimeBombReachability verifies the time_bombs[].reachability contract:
//   - critical_cve with known reachability → field present
//   - critical_cve with empty reachability → field omitted (omitempty)
//   - archived entries → field omitted
func TestWriteJSON_TimeBombReachability(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{Path: "github.com/vuln/pkg", Version: "v1.0.0", Direct: true, Depth: 0},
		testutil.DepSpec{Path: "github.com/old/pkg", Version: "v1.0.0", Direct: true, Depth: 0},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 80,
		OverallLevel: scorer.RiskCritical,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:     "github.com/vuln/pkg",
				Version:    "v1.0.0",
				Direct:     true,
				RiskScore:  80,
				RiskLevel:  scorer.RiskCritical,
				IsTestOnly: testutil.BoolPtr(false),
				Vulns: []scanner.Vulnerability{
					// CRITICAL with known reachability — must emit "reachability".
					{ID: "GO-2024-0001", Severity: "CRITICAL", Reachability: "called"},
					// CRITICAL with empty reachability — must omit "reachability".
					{ID: "GO-2024-0002", Severity: "CRITICAL", Reachability: ""},
				},
			},
			{
				Module:      "github.com/old/pkg",
				Version:     "v1.0.0",
				Direct:      true,
				RiskScore:   60,
				RiskLevel:   scorer.RiskHigh,
				IsTestOnly:  testutil.BoolPtr(false),
				Maintenance: &scanner.MaintenanceInfo{Archived: true, MonthsSinceRelease: 24},
			},
		},
	}

	var buf bytes.Buffer
	if err := WriteJSON(graph, ps, JSONOptions{GoVersion: "1.21"}, &buf); err != nil {
		t.Fatalf("WriteJSON() failed: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	// Verify the bombs were actually collected (guards against vacuous passes).
	if len(report.TimeBombs) != 3 {
		t.Fatalf("time_bombs length = %d, want 3 (2 critical_cve + 1 archived)", len(report.TimeBombs))
	}

	// Find each expected bomb by Kind+Module.
	findBomb := func(kind, module string) *JSONTimeBomb {
		for i := range report.TimeBombs {
			b := &report.TimeBombs[i]
			if b.Kind == kind && b.Module == module {
				return b
			}
		}
		return nil
	}

	// critical_cve with known reachability must carry the field.
	if b := findBomb("critical_cve", "github.com/vuln/pkg"); b == nil {
		t.Fatal("missing critical_cve bomb for github.com/vuln/pkg with GO-2024-0001")
	}

	// Use raw JSON to verify presence/absence of the "reachability" key precisely.
	raw := struct {
		Bombs []map[string]interface{} `json:"time_bombs"`
	}{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("raw unmarshal failed: %v", err)
	}

	findRawBomb := func(kind, module string) map[string]interface{} {
		for _, b := range raw.Bombs {
			if b["kind"] == kind && b["module"] == module {
				return b
			}
		}
		return nil
	}

	// GO-2024-0001 is "called" — reachability key must be present.
	b1 := findRawBomb("critical_cve", "github.com/vuln/pkg")
	if b1 == nil {
		t.Fatal("raw: missing critical_cve bomb for github.com/vuln/pkg")
	}
	// The two critical_cve bombs for the same module: find the one whose detail contains GO-2024-0001.
	var rawCalled, rawEmpty map[string]interface{}
	for _, b := range raw.Bombs {
		if b["kind"] != "critical_cve" || b["module"] != "github.com/vuln/pkg" {
			continue
		}
		detail, _ := b["detail"].(string)
		if len(detail) > 0 && detail[:len("GO-2024-0001")] == "GO-2024-0001" {
			rawCalled = b
		} else {
			rawEmpty = b
		}
	}
	if rawCalled == nil {
		t.Fatal("raw: could not find bomb for GO-2024-0001")
	}
	if v, ok := rawCalled["reachability"]; !ok || v != "called" {
		t.Errorf("GO-2024-0001 time_bomb reachability = %v (present=%v), want \"called\"", v, ok)
	}

	// GO-2024-0002 has empty reachability — key must be absent (omitempty).
	if rawEmpty == nil {
		t.Fatal("raw: could not find bomb for GO-2024-0002")
	}
	if v, present := rawEmpty["reachability"]; present {
		t.Errorf("GO-2024-0002 time_bomb reachability key must be absent, got %v", v)
	}

	// archived entry must not have a reachability key.
	rawArchived := findRawBomb("archived", "github.com/old/pkg")
	if rawArchived == nil {
		t.Fatal("raw: missing archived bomb for github.com/old/pkg")
	}
	if v, present := rawArchived["reachability"]; present {
		t.Errorf("archived time_bomb reachability key must be absent, got %v", v)
	}
}

// TestWriteJSON_InBuildAndPlatforms verifies that in_build is emitted for both
// true and false, omitted for nil, and that platforms is emitted when set.
func TestWriteJSON_InBuildAndPlatforms(t *testing.T) {
	trueVal, falseVal := true, false
	graph := testutil.MakeGraph(
		testutil.DepSpec{Path: "github.com/a/outside", Version: "v1.0.0", Depth: 1, InBuild: &falseVal},
		testutil.DepSpec{Path: "github.com/b/built", Version: "v1.0.0", Depth: 1, InBuild: &trueVal},
		testutil.DepSpec{Path: "github.com/c/unknown", Version: "v1.0.0", Depth: 1},
	)
	ps := &scorer.ProjectScore{
		OverallScore: 10,
		OverallLevel: scorer.RiskLow,
		Dependencies: []*scorer.DependencyScore{
			{Module: "github.com/a/outside", Version: "v1.0.0", RiskScore: 10, RiskLevel: scorer.RiskLow, InBuild: &falseVal},
			{Module: "github.com/b/built", Version: "v1.0.0", RiskScore: 10, RiskLevel: scorer.RiskLow, InBuild: &trueVal, Platforms: []string{"windows"}},
			{Module: "github.com/c/unknown", Version: "v1.0.0", RiskScore: 10, RiskLevel: scorer.RiskLow},
		},
		LowRiskCount: 3,
	}

	var buf bytes.Buffer
	if err := WriteJSON(graph, ps, JSONOptions{GoVersion: "1.21"}, &buf); err != nil {
		t.Fatalf("WriteJSON() failed: %v", err)
	}

	// Decode into maps to check key presence, not just value.
	var raw struct {
		Deps []map[string]interface{} `json:"dependencies"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	byModule := map[string]map[string]interface{}{}
	for _, d := range raw.Deps {
		byModule[d["module"].(string)] = d
	}

	if v, ok := byModule["github.com/a/outside"]["in_build"]; !ok || v != false {
		t.Errorf("outside: in_build = %v (present=%v), want false emitted", v, ok)
	}
	if _, ok := byModule["github.com/a/outside"]["platforms"]; ok {
		t.Errorf("outside: platforms present, want omitted when empty")
	}
	if v, ok := byModule["github.com/b/built"]["in_build"]; !ok || v != true {
		t.Errorf("built: in_build = %v (present=%v), want true", v, ok)
	}
	if p, _ := byModule["github.com/b/built"]["platforms"].([]interface{}); len(p) != 1 || p[0] != "windows" {
		t.Errorf("built: platforms = %v, want [windows]", byModule["github.com/b/built"]["platforms"])
	}
	for _, key := range []string{"in_build", "platforms"} {
		if _, ok := byModule["github.com/c/unknown"][key]; ok {
			t.Errorf("unknown: %s present for nil, want omitted", key)
		}
	}
}

// TestWriteJSON_HeadlineTiedWith verifies that tied_with reaches the JSON
// headline candidate when set and is omitted otherwise, and that headline.reason
// and the candidate reason agree.
func TestWriteJSON_HeadlineTiedWith(t *testing.T) {
	render := func(tiedWith int, reason string) map[string]interface{} {
		ps := &scorer.ProjectScore{
			OverallScore:      32,
			OverallLevel:      scorer.RiskMedium,
			HeadlineDriver:    "p95_dep_risk",
			HeadlineCandidate: &scorer.HeadlineCandidate{Name: "p95_dep_risk", Score: 32, DrivingDep: "github.com/x/y", Reason: reason, TiedWith: tiedWith},
			Dependencies: []*scorer.DependencyScore{
				{Module: "github.com/x/y", Version: "v1.0.0", RiskScore: 32, RiskLevel: scorer.RiskMedium},
			},
		}
		graph := testutil.MakeGraph(testutil.DepSpec{Path: "github.com/x/y", Version: "v1.0.0"})
		var buf bytes.Buffer
		if err := WriteJSON(graph, ps, JSONOptions{GoVersion: "1.21"}, &buf); err != nil {
			t.Fatalf("WriteJSON() failed: %v", err)
		}
		var raw struct {
			Headline map[string]interface{} `json:"headline"`
		}
		if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}
		return raw.Headline
	}

	const tied = "p95 of dep risk scores (one of 4 modules at 32)"
	h := render(3, tied)
	cand := h["candidates"].([]interface{})[0].(map[string]interface{})
	if cand["tied_with"] != float64(3) {
		t.Errorf("candidate tied_with = %v, want 3", cand["tied_with"])
	}
	if h["reason"] != tied || cand["reason"] != tied {
		t.Errorf("headline.reason = %v, candidate reason = %v, want both %q", h["reason"], cand["reason"], tied)
	}

	h = render(0, "p95 of dep risk scores")
	cand = h["candidates"].([]interface{})[0].(map[string]interface{})
	if _, ok := cand["tied_with"]; ok {
		t.Errorf("candidate tied_with present for zero, want omitted")
	}
}

// TestWriteJSON_Notes verifies that notes are emitted next to warnings and the
// key is omitted when there are none.
func TestWriteJSON_Notes(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{Path: "github.com/example/pkg", Version: "v1.0.0", Direct: true, Depth: 0},
	)
	dep := &scorer.DependencyScore{Module: "github.com/example/pkg", Version: "v1.0.0", Direct: true, RiskScore: 10, RiskLevel: scorer.RiskLow}

	decode := func(t *testing.T, ps *scorer.ProjectScore) map[string]json.RawMessage {
		t.Helper()
		var buf bytes.Buffer
		if err := WriteJSON(graph, ps, JSONOptions{GoVersion: "1.21"}, &buf); err != nil {
			t.Fatalf("WriteJSON() failed: %v", err)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}
		return raw
	}

	t.Run("emitted", func(t *testing.T) {
		raw := decode(t, &scorer.ProjectScore{
			OverallLevel: scorer.RiskLow,
			Dependencies: []*scorer.DependencyScore{dep},
			Warnings:     []string{"a warning"},
			Notes:        []string{"a note"},
		})
		var notes, warnings []string
		if err := json.Unmarshal(raw["notes"], &notes); err != nil || len(notes) != 1 || notes[0] != "a note" {
			t.Errorf("notes = %s, want [\"a note\"]", raw["notes"])
		}
		if err := json.Unmarshal(raw["warnings"], &warnings); err != nil || len(warnings) != 1 || warnings[0] != "a warning" {
			t.Errorf("warnings = %s, want [\"a warning\"]", raw["warnings"])
		}
	})

	t.Run("omitted when empty", func(t *testing.T) {
		raw := decode(t, &scorer.ProjectScore{
			OverallLevel: scorer.RiskLow,
			Dependencies: []*scorer.DependencyScore{dep},
		})
		if _, ok := raw["notes"]; ok {
			t.Errorf("notes present with none set: %s", raw["notes"])
		}
	})
}

// TestWriteJSON_SeverityAliasAndUnscored verifies severity_alias is emitted
// when set, omitted when empty, and that "unscored" passes through unchanged.
func TestWriteJSON_SeverityAliasAndUnscored(t *testing.T) {
	graph := testutil.MakeGraph(testutil.DepSpec{
		Path: "github.com/example/pkg", Version: "v1.0.0", Direct: true, Depth: 0,
	})
	ps := &scorer.ProjectScore{
		OverallScore: 30,
		OverallLevel: scorer.RiskMedium,
		Dependencies: []*scorer.DependencyScore{{
			Module: "github.com/example/pkg", Version: "v1.0.0", Direct: true,
			RiskScore: 30, RiskLevel: scorer.RiskMedium,
			Vulns: []scanner.Vulnerability{
				{ID: "GO-2026-0001", Severity: "CRITICAL", SeveritySource: "osv", SeverityAlias: "GHSA-aaaa-bbbb-cccc"},
				{ID: "GO-2026-0002", Severity: "UNKNOWN", SeveritySource: "unscored"},
			},
		}},
		TotalVulns: 2,
	}

	var buf bytes.Buffer
	if err := WriteJSON(graph, ps, JSONOptions{GoVersion: "1.21"}, &buf); err != nil {
		t.Fatalf("WriteJSON() failed: %v", err)
	}
	var raw struct {
		Deps []struct {
			Vulns []map[string]interface{} `json:"vulnerabilities"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	vulns := raw.Deps[0].Vulns
	if vulns[0]["severity_alias"] != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("severity_alias = %v, want GHSA-aaaa-bbbb-cccc", vulns[0]["severity_alias"])
	}
	if _, present := vulns[1]["severity_alias"]; present {
		t.Error("empty severity_alias must be omitted")
	}
	if vulns[1]["severity_source"] != "unscored" {
		t.Errorf("severity_source = %v, want unscored", vulns[1]["severity_source"])
	}
}
