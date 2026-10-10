package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestParseGovulncheckJSON_Empty tests parsing empty govulncheck output.
func TestParseGovulncheckJSON_Empty(t *testing.T) {
	buf := &bytes.Buffer{}

	results, err := parseGovulncheckJSON(buf)
	if err != nil {
		t.Fatalf("parseGovulncheckJSON() failed: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("Results length = %d, want 0", len(results))
	}
}

// TestParseGovulncheckJSON_SingleVuln tests parsing a single vulnerability.
func TestParseGovulncheckJSON_SingleVuln(t *testing.T) {
	// Build JSON output similar to govulncheck
	osvJSON := map[string]json.RawMessage{
		"osv": []byte(`{
			"id": "GO-2023-1234",
			"aliases": ["CVE-2023-1234"],
			"summary": "SQL injection in database driver",
			"affected": [
				{
					"package": {"name": "github.com/example/pkg", "ecosystem": "Go"},
					"ranges": [
						{
							"type": "SEMVER",
							"events": [{"introduced": "v1.0.0"}, {"fixed": "v1.2.0"}]
						}
					],
					"database_specific": {"severity": "HIGH"}
				}
			]
		}`),
	}

	findingJSON := map[string]json.RawMessage{
		"finding": []byte(`{
			"osv": "GO-2023-1234",
			"trace": [
				{"module": "github.com/example/pkg", "version": "v1.1.0"},
				{"package": "github.com/example/pkg/driver"}
			],
			"fixed_version": ""
		}`),
	}

	buf := &bytes.Buffer{}

	// Write JSON objects
	enc := json.NewEncoder(buf)
	if err := enc.Encode(osvJSON); err != nil {
		t.Fatalf("Failed to write OSV: %v", err)
	}
	if err := enc.Encode(findingJSON); err != nil {
		t.Fatalf("Failed to write finding: %v", err)
	}

	// Reset buffer for reading
	results, err := parseGovulncheckJSON(buf)
	if err != nil {
		t.Fatalf("parseGovulncheckJSON() failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Results length = %d, want 1", len(results))
	}

	vulns, ok := results["github.com/example/pkg"]
	if !ok {
		t.Fatal("Module 'github.com/example/pkg' not found in results")
	}

	if len(vulns) != 1 {
		t.Fatalf("Vulns length = %d, want 1", len(vulns))
	}

	vuln := vulns[0]
	if vuln.ID != "GO-2023-1234" {
		t.Errorf("ID = %q, want %q", vuln.ID, "GO-2023-1234")
	}

	if vuln.Summary != "SQL injection in database driver" {
		t.Errorf("Summary = %q, want %q", vuln.Summary, "SQL injection in database driver")
	}

	if vuln.Severity != "HIGH" {
		t.Errorf("Severity = %q, want %q", vuln.Severity, "HIGH")
	}

	if len(vuln.Aliases) != 1 || vuln.Aliases[0] != "CVE-2023-1234" {
		t.Errorf("Aliases = %v, want [CVE-2023-1234]", vuln.Aliases)
	}

	if vuln.FixedVersion != "v1.2.0" {
		t.Errorf("FixedVersion = %q, want %q", vuln.FixedVersion, "v1.2.0")
	}
}

// TestParseGovulncheckJSON_MultipleVulns tests parsing multiple vulnerabilities.
func TestParseGovulncheckJSON_MultipleVulns(t *testing.T) {
	// OSV 1
	osv1 := map[string]json.RawMessage{
		"osv": []byte(`{
			"id": "GO-2023-1001",
			"aliases": ["CVE-2023-1001"],
			"summary": "Vulnerability 1",
			"affected": [
				{
					"package": {"name": "github.com/pkg1", "ecosystem": "Go"},
					"ranges": [
						{
							"type": "SEMVER",
							"events": [{"introduced": "v1.0.0"}, {"fixed": "v1.1.0"}]
						}
					],
					"database_specific": {"severity": "MEDIUM"}
				}
			]
		}`),
	}

	// Finding 1
	finding1 := map[string]json.RawMessage{
		"finding": []byte(`{
			"osv": "GO-2023-1001",
			"trace": [{"module": "github.com/pkg1", "version": "v1.0.5"}],
			"fixed_version": ""
		}`),
	}

	// OSV 2
	osv2 := map[string]json.RawMessage{
		"osv": []byte(`{
			"id": "GO-2023-1002",
			"aliases": ["CVE-2023-1002"],
			"summary": "Vulnerability 2",
			"affected": [
				{
					"package": {"name": "github.com/pkg2", "ecosystem": "Go"},
					"ranges": [
						{
							"type": "SEMVER",
							"events": [{"introduced": "v2.0.0"}, {"fixed": "v2.5.0"}]
						}
					],
					"database_specific": {"severity": "CRITICAL"}
				}
			]
		}`),
	}

	// Finding 2
	finding2 := map[string]json.RawMessage{
		"finding": []byte(`{
			"osv": "GO-2023-1002",
			"trace": [{"module": "github.com/pkg2", "version": "v2.3.0"}],
			"fixed_version": ""
		}`),
	}

	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)

	if err := enc.Encode(osv1); err != nil {
		t.Fatalf("Failed to write OSV1: %v", err)
	}
	if err := enc.Encode(finding1); err != nil {
		t.Fatalf("Failed to write finding1: %v", err)
	}
	if err := enc.Encode(osv2); err != nil {
		t.Fatalf("Failed to write OSV2: %v", err)
	}
	if err := enc.Encode(finding2); err != nil {
		t.Fatalf("Failed to write finding2: %v", err)
	}

	results, err := parseGovulncheckJSON(buf)
	if err != nil {
		t.Fatalf("parseGovulncheckJSON() failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("Results length = %d, want 2", len(results))
	}

	// Check pkg1
	if vulns, ok := results["github.com/pkg1"]; ok {
		if len(vulns) != 1 {
			t.Errorf("pkg1 vulns length = %d, want 1", len(vulns))
		} else if vulns[0].ID != "GO-2023-1001" {
			t.Errorf("pkg1 vuln ID = %q, want %q", vulns[0].ID, "GO-2023-1001")
		}
	} else {
		t.Error("github.com/pkg1 not found in results")
	}

	// Check pkg2
	if vulns, ok := results["github.com/pkg2"]; ok {
		if len(vulns) != 1 {
			t.Errorf("pkg2 vulns length = %d, want 1", len(vulns))
		} else if vulns[0].ID != "GO-2023-1002" {
			t.Errorf("pkg2 vuln ID = %q, want %q", vulns[0].ID, "GO-2023-1002")
		}
	} else {
		t.Error("github.com/pkg2 not found in results")
	}
}

// TestParseGovulncheckJSON_Dedup tests that duplicate OSV+module entries are deduplicated.
func TestParseGovulncheckJSON_Dedup(t *testing.T) {
	// OSV appears once
	osv := map[string]json.RawMessage{
		"osv": []byte(`{
			"id": "GO-2023-5555",
			"aliases": ["CVE-2023-5555"],
			"summary": "Test vulnerability",
			"affected": [
				{
					"package": {"name": "github.com/testpkg", "ecosystem": "Go"},
					"ranges": [
						{
							"type": "SEMVER",
							"events": [{"introduced": "v1.0.0"}, {"fixed": "v1.5.0"}]
						}
					],
					"database_specific": {"severity": "LOW"}
				}
			]
		}`),
	}

	// Same finding twice (duplicate)
	finding := map[string]json.RawMessage{
		"finding": []byte(`{
			"osv": "GO-2023-5555",
			"trace": [{"module": "github.com/testpkg", "version": "v1.2.0"}],
			"fixed_version": ""
		}`),
	}

	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)

	if err := enc.Encode(osv); err != nil {
		t.Fatalf("Failed to write OSV: %v", err)
	}
	// Write the same finding twice
	if err := enc.Encode(finding); err != nil {
		t.Fatalf("Failed to write finding 1: %v", err)
	}
	if err := enc.Encode(finding); err != nil {
		t.Fatalf("Failed to write finding 2: %v", err)
	}

	results, err := parseGovulncheckJSON(buf)
	if err != nil {
		t.Fatalf("parseGovulncheckJSON() failed: %v", err)
	}

	vulns, ok := results["github.com/testpkg"]
	if !ok {
		t.Fatal("Module not found in results")
	}

	// Should have only 1 vulnerability (dedup worked)
	if len(vulns) != 1 {
		t.Errorf("Vulns length = %d, want 1 (deduplicated)", len(vulns))
	}
}

// buildGovulncheckBuf writes a sequence of govulncheck JSON objects into a
// buffer for use in parser tests.
func buildGovulncheckBuf(t *testing.T, objects ...map[string]json.RawMessage) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	for _, obj := range objects {
		if err := enc.Encode(obj); err != nil {
			t.Fatalf("buildGovulncheckBuf: encode failed: %v", err)
		}
	}
	return buf
}

// minimalOSV returns a govulncheck "osv" JSON object for a given module and
// severity to use in classification tests.
func minimalOSV(osvID, modPath, severity string) map[string]json.RawMessage {
	body := fmt.Sprintf(`{
		"id": %q,
		"aliases": [],
		"summary": "test vulnerability",
		"affected": [
			{
				"package": {"name": %q, "ecosystem": "Go"},
				"ranges": [{"type": "SEMVER", "events": [{"introduced": "v1.0.0"}]}],
				"database_specific": {"severity": %q}
			}
		]
	}`, osvID, modPath, severity)
	return map[string]json.RawMessage{"osv": json.RawMessage(body)}
}

// TestClassifyReachability_DirectCases tests classifyReachability in isolation.
func TestClassifyReachability_DirectCases(t *testing.T) {
	tests := []struct {
		name  string
		trace []traceEntry
		want  string
	}{
		{
			name:  "empty_trace_returns_required",
			trace: nil,
			want:  "required",
		},
		{
			name: "function_set_returns_called",
			trace: []traceEntry{
				{Module: "github.com/example/pkg", Package: "github.com/example/pkg", Function: "Vulnerable"},
			},
			want: "called",
		},
		{
			name: "position_set_returns_called",
			trace: []traceEntry{
				{Module: "github.com/example/pkg", Package: "github.com/example/pkg"},
				{Module: "github.com/example/pkg", Package: "github.com/example/pkg", Position: &struct {
					Filename string `json:"filename"`
					Line     int    `json:"line"`
					Column   int    `json:"column"`
				}{Filename: "main.go", Line: 42, Column: 5}},
			},
			want: "called",
		},
		{
			name: "package_only_returns_imported",
			trace: []traceEntry{
				{Module: "github.com/example/pkg", Package: "github.com/example/pkg"},
			},
			want: "imported",
		},
		{
			name: "module_only_returns_required",
			trace: []traceEntry{
				{Module: "github.com/example/pkg"},
			},
			want: "required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyReachability(tt.trace)
			if got != tt.want {
				t.Errorf("classifyReachability() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestParseGovulncheckJSON_ClassifiesCalled asserts that a finding whose trace
// has a non-empty Function field is classified as "called".
func TestParseGovulncheckJSON_ClassifiesCalled(t *testing.T) {
	const (
		osvID   = "GO-2024-0001"
		modPath = "github.com/example/called"
	)

	finding := map[string]json.RawMessage{
		"finding": json.RawMessage(`{
			"osv": "GO-2024-0001",
			"trace": [
				{
					"module":   "github.com/example/called",
					"version":  "v1.0.0",
					"package":  "github.com/example/called",
					"function": "VulnerableFunc"
				}
			]
		}`),
	}

	buf := buildGovulncheckBuf(t, minimalOSV(osvID, modPath, "HIGH"), finding)
	results, err := parseGovulncheckJSON(buf)
	if err != nil {
		t.Fatalf("parseGovulncheckJSON() error: %v", err)
	}

	vulns := results[modPath]
	if len(vulns) != 1 {
		t.Fatalf("len(vulns) = %d, want 1", len(vulns))
	}
	if vulns[0].Reachability != "called" {
		t.Errorf("Reachability = %q, want %q", vulns[0].Reachability, "called")
	}
}

// TestParseGovulncheckJSON_ClassifiesImported asserts that a finding whose
// trace has a Package but no Function is classified as "imported".
func TestParseGovulncheckJSON_ClassifiesImported(t *testing.T) {
	const (
		osvID   = "GO-2024-0002"
		modPath = "github.com/example/imported"
	)

	finding := map[string]json.RawMessage{
		"finding": json.RawMessage(`{
			"osv": "GO-2024-0002",
			"trace": [
				{
					"module":  "github.com/example/imported",
					"version": "v1.0.0",
					"package": "github.com/example/imported"
				}
			]
		}`),
	}

	buf := buildGovulncheckBuf(t, minimalOSV(osvID, modPath, "MEDIUM"), finding)
	results, err := parseGovulncheckJSON(buf)
	if err != nil {
		t.Fatalf("parseGovulncheckJSON() error: %v", err)
	}

	vulns := results[modPath]
	if len(vulns) != 1 {
		t.Fatalf("len(vulns) = %d, want 1", len(vulns))
	}
	if vulns[0].Reachability != "imported" {
		t.Errorf("Reachability = %q, want %q", vulns[0].Reachability, "imported")
	}
}

// TestParseGovulncheckJSON_ClassifiesRequired asserts that a finding whose
// trace has only a Module (no package or function) is classified as "required".
func TestParseGovulncheckJSON_ClassifiesRequired(t *testing.T) {
	const (
		osvID   = "GO-2024-0003"
		modPath = "github.com/example/required"
	)

	finding := map[string]json.RawMessage{
		"finding": json.RawMessage(`{
			"osv": "GO-2024-0003",
			"trace": [
				{
					"module":  "github.com/example/required",
					"version": "v1.0.0"
				}
			]
		}`),
	}

	buf := buildGovulncheckBuf(t, minimalOSV(osvID, modPath, "LOW"), finding)
	results, err := parseGovulncheckJSON(buf)
	if err != nil {
		t.Fatalf("parseGovulncheckJSON() error: %v", err)
	}

	vulns := results[modPath]
	if len(vulns) != 1 {
		t.Fatalf("len(vulns) = %d, want 1", len(vulns))
	}
	if vulns[0].Reachability != "required" {
		t.Errorf("Reachability = %q, want %q", vulns[0].Reachability, "required")
	}
}

// TestParseGovulncheckJSON_DedupKeepsHighestReachability verifies that when the
// same OSV+module appears multiple times (different trace depths), the parser
// keeps the finding with the highest reachability.  The result must be
// order-independent: flipping the input order yields the same winner.
func TestParseGovulncheckJSON_DedupKeepsHighestReachability(t *testing.T) {
	const (
		osvID   = "GO-2024-0004"
		modPath = "github.com/example/dedup"
	)

	osv := minimalOSV(osvID, modPath, "HIGH")

	calledFinding := map[string]json.RawMessage{
		"finding": json.RawMessage(`{
			"osv": "GO-2024-0004",
			"trace": [
				{
					"module":   "github.com/example/dedup",
					"version":  "v1.0.0",
					"package":  "github.com/example/dedup",
					"function": "VulnerableFunc"
				}
			]
		}`),
	}

	requiredFinding := map[string]json.RawMessage{
		"finding": json.RawMessage(`{
			"osv": "GO-2024-0004",
			"trace": [
				{
					"module":  "github.com/example/dedup",
					"version": "v1.0.0"
				}
			]
		}`),
	}

	assertCalledWins := func(t *testing.T, results map[string][]Vulnerability) {
		t.Helper()
		vulns := results[modPath]
		if len(vulns) != 1 {
			t.Fatalf("len(vulns) = %d, want 1 (dedup should produce one entry)", len(vulns))
		}
		if vulns[0].Reachability != "called" {
			t.Errorf("Reachability = %q, want %q", vulns[0].Reachability, "called")
		}
	}

	t.Run("called_first", func(t *testing.T) {
		buf := buildGovulncheckBuf(t, osv, calledFinding, requiredFinding)
		results, err := parseGovulncheckJSON(buf)
		if err != nil {
			t.Fatalf("parseGovulncheckJSON() error: %v", err)
		}
		assertCalledWins(t, results)
	})

	t.Run("required_first", func(t *testing.T) {
		buf := buildGovulncheckBuf(t, osv, requiredFinding, calledFinding)
		results, err := parseGovulncheckJSON(buf)
		if err != nil {
			t.Fatalf("parseGovulncheckJSON() error: %v", err)
		}
		assertCalledWins(t, results)
	})
}

// TestSeverityFromOSV tests severity extraction from OSV data.
func TestSeverityFromOSV(t *testing.T) {
	tests := []struct {
		name     string
		osvJSON  string
		modPath  string
		expected string
	}{
		{
			name: "severity_present",
			osvJSON: `{
				"id": "GO-2023-1111",
				"affected": [
					{
						"package": {"name": "github.com/testpkg"},
						"database_specific": {"severity": "high"}
					}
				]
			}`,
			modPath:  "github.com/testpkg",
			expected: "HIGH",
		},
		{
			name: "severity_missing",
			osvJSON: `{
				"id": "GO-2023-2222",
				"affected": [
					{
						"package": {"name": "github.com/testpkg"},
						"database_specific": null
					}
				]
			}`,
			modPath:  "github.com/testpkg",
			expected: "UNKNOWN",
		},
		{
			name: "module_not_found",
			osvJSON: `{
				"id": "GO-2023-3333",
				"affected": [
					{
						"package": {"name": "github.com/otherpkg"},
						"database_specific": {"severity": "critical"}
					}
				]
			}`,
			modPath:  "github.com/testpkg",
			expected: "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var osv gvcOSV
			if err := json.Unmarshal([]byte(tt.osvJSON), &osv); err != nil {
				t.Fatalf("Failed to unmarshal OSV: %v", err)
			}

			result := severityFromOSV(&osv, tt.modPath)
			if result != tt.expected {
				t.Errorf("severityFromOSV() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestFixedVersionFromOSV tests fixed version extraction from OSV data.
func TestFixedVersionFromOSV(t *testing.T) {
	tests := []struct {
		name     string
		osvJSON  string
		modPath  string
		expected string
	}{
		{
			name: "fixed_version_present",
			osvJSON: `{
				"id": "GO-2023-4444",
				"affected": [
					{
						"package": {"name": "github.com/testpkg"},
						"ranges": [
							{
								"type": "SEMVER",
								"events": [
									{"introduced": "v1.0.0", "fixed": "v1.5.0"}
								]
							}
						]
					}
				]
			}`,
			modPath:  "github.com/testpkg",
			expected: "v1.5.0",
		},
		{
			name: "no_fixed_event",
			osvJSON: `{
				"id": "GO-2023-5555",
				"affected": [
					{
						"package": {"name": "github.com/testpkg"},
						"ranges": [
							{
								"type": "SEMVER",
								"events": [
									{"introduced": "v1.0.0"}
								]
							}
						]
					}
				]
			}`,
			modPath:  "github.com/testpkg",
			expected: "",
		},
		{
			name: "module_not_found",
			osvJSON: `{
				"id": "GO-2023-6666",
				"affected": [
					{
						"package": {"name": "github.com/otherpkg"},
						"ranges": [
							{
								"type": "SEMVER",
								"events": [
									{"introduced": "v1.0.0", "fixed": "v1.5.0"}
								]
							}
						]
					}
				]
			}`,
			modPath:  "github.com/testpkg",
			expected: "",
		},
		{
			name: "stdlib_affected",
			osvJSON: `{
				"id": "GO-2023-7777",
				"affected": [
					{
						"package": {"name": "stdlib"},
						"ranges": [
							{
								"type": "SEMVER",
								"events": [
									{"introduced": "go1.19", "fixed": "go1.20.5"}
								]
							}
						]
					}
				]
			}`,
			modPath:  "stdlib",
			expected: "go1.20.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var osv gvcOSV
			if err := json.Unmarshal([]byte(tt.osvJSON), &osv); err != nil {
				t.Fatalf("Failed to unmarshal OSV: %v", err)
			}

			result := fixedVersionFromOSV(&osv, tt.modPath)
			if result != tt.expected {
				t.Errorf("fixedVersionFromOSV() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// loadGovulncheckFixture reads a testdata fixture file from the top-level
// testdata/ directory (not the vulnenrich sub-directory) and returns its
// contents as a bytes.Buffer suitable for passing to parseGovulncheckJSON.
func loadGovulncheckFixture(t *testing.T, name string) *bytes.Buffer {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("loadGovulncheckFixture(%q): %v", name, err)
	}
	return bytes.NewBuffer(data)
}

// TestFixture_CalledReachability loads govulncheck_called.json and asserts
// that the parsed vulnerability carries Reachability == "called".
// The fixture contains a finding whose trace[0] has both Function and Position
// set, representing a directly-called vulnerable symbol.
func TestFixture_CalledReachability(t *testing.T) {
	results, err := parseGovulncheckJSON(loadGovulncheckFixture(t, "govulncheck_called.json"))
	if err != nil {
		t.Fatalf("parseGovulncheckJSON: %v", err)
	}

	const modPath = "github.com/example/vulnpkg"
	vulns, ok := results[modPath]
	if !ok {
		t.Fatalf("module %q not found in results; got keys: %v", modPath, moduleKeys(results))
	}
	if len(vulns) != 1 {
		t.Fatalf("len(vulns) = %d, want 1", len(vulns))
	}

	vuln := vulns[0]
	if vuln.ID != "GO-2024-9901" {
		t.Errorf("ID = %q, want %q", vuln.ID, "GO-2024-9901")
	}
	if vuln.Reachability != "called" {
		t.Errorf("Reachability = %q, want %q", vuln.Reachability, "called")
	}
	if vuln.FixedVersion != "v1.4.0" {
		t.Errorf("FixedVersion = %q, want %q", vuln.FixedVersion, "v1.4.0")
	}
}

// TestFixture_ImportedReachability loads govulncheck_imported.json and asserts
// that the parsed vulnerability carries Reachability == "imported".
// The fixture is derived from an actual 2026-05-25 unisupply-self govulncheck
// run: GO-2026-5025 (CVE-2026-42506, golang.org/x/net/html) appeared with
// trace[0].Package populated and no Function — the canonical imported shape.
func TestFixture_ImportedReachability(t *testing.T) {
	results, err := parseGovulncheckJSON(loadGovulncheckFixture(t, "govulncheck_imported.json"))
	if err != nil {
		t.Fatalf("parseGovulncheckJSON: %v", err)
	}

	const modPath = "golang.org/x/net"
	vulns, ok := results[modPath]
	if !ok {
		t.Fatalf("module %q not found in results; got keys: %v", modPath, moduleKeys(results))
	}
	if len(vulns) != 1 {
		t.Fatalf("len(vulns) = %d, want 1", len(vulns))
	}

	vuln := vulns[0]
	if vuln.ID != "GO-2026-5025" {
		t.Errorf("ID = %q, want %q", vuln.ID, "GO-2026-5025")
	}
	if vuln.Reachability != "imported" {
		t.Errorf("Reachability = %q, want %q", vuln.Reachability, "imported")
	}
	if vuln.FixedVersion != "v0.55.0" {
		t.Errorf("FixedVersion = %q, want %q", vuln.FixedVersion, "v0.55.0")
	}
}

// TestFixture_RequiredReachability loads govulncheck_required.json and asserts
// that the parsed vulnerability carries Reachability == "required".
//
// This fixture is the canonical false-positive regression case for the
// calibration suite (task-09): GO-2026-5005 (CVE-2026-39833,
// golang.org/x/crypto/ssh/agent) was found in an actual 2026-05-25
// unisupply-self govulncheck scan with a module-only trace, meaning the
// vulnerable package is not imported by unisupply at all.  The scorer must
// apply a reduced weight for "required"-level findings to avoid inflating the
// risk score for this class of false-positive.
func TestFixture_RequiredReachability(t *testing.T) {
	results, err := parseGovulncheckJSON(loadGovulncheckFixture(t, "govulncheck_required.json"))
	if err != nil {
		t.Fatalf("parseGovulncheckJSON: %v", err)
	}

	const modPath = "golang.org/x/crypto"
	vulns, ok := results[modPath]
	if !ok {
		t.Fatalf("module %q not found in results; got keys: %v", modPath, moduleKeys(results))
	}
	if len(vulns) != 1 {
		t.Fatalf("len(vulns) = %d, want 1", len(vulns))
	}

	vuln := vulns[0]
	if vuln.ID != "GO-2026-5005" {
		t.Errorf("ID = %q, want %q", vuln.ID, "GO-2026-5005")
	}
	if vuln.Reachability != "required" {
		t.Errorf("Reachability = %q, want %q", vuln.Reachability, "required")
	}
	if vuln.FixedVersion != "v0.52.0" {
		t.Errorf("FixedVersion = %q, want %q", vuln.FixedVersion, "v0.52.0")
	}
	// Verify the OSV alias round-trips correctly.
	found := false
	for _, alias := range vuln.Aliases {
		if alias == "CVE-2026-39833" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Aliases = %v, want to contain %q", vuln.Aliases, "CVE-2026-39833")
	}
}

// moduleKeys returns the module paths present in a results map for use in
// diagnostic messages.
func moduleKeys(m map[string][]Vulnerability) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// callPath condenses a govulncheck trace (innermost frame first, as govulncheck
// emits it) into an outermost-first path: the entry frame, the frame where each
// package run hands over, and the vulnerable function. The trace below is the shape of a real
// govulncheck result for an application that pushes over SSH through go-git.
func TestCallPath_CondensesTraceOutermostFirst(t *testing.T) {
	trace := []traceEntry{
		{Module: "golang.org/x/crypto", Package: "golang.org/x/crypto/ssh", Function: "NewClientConn"},
		{Module: "github.com/go-git/go-git/v5", Package: "github.com/go-git/go-git/v5/plumbing/transport/ssh", Function: "dial"},
		{Module: "github.com/go-git/go-git/v5", Package: "github.com/go-git/go-git/v5/plumbing/transport/ssh", Function: "command.connect"},
		{Module: "github.com/go-git/go-git/v5", Package: "github.com/go-git/go-git/v5", Function: "Push", Receiver: "*Repository"},
		{Module: "example.com/app", Package: "example.com/app/cmd/app", Function: "syncRun"},
		{Module: "example.com/app", Package: "example.com/app/cmd/app", Function: "main"},
	}
	want := []string{
		"example.com/app/cmd/app.main",
		"example.com/app/cmd/app.syncRun",
		"github.com/go-git/go-git/v5.Repository.Push",
		"github.com/go-git/go-git/v5/plumbing/transport/ssh.dial",
		"golang.org/x/crypto/ssh.NewClientConn",
	}
	got := callPath(trace)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("callPath = %v, want %v", got, want)
	}
	if got := callPath([]traceEntry{{Package: "m/p", Function: "F$1"}}); len(got) != 1 || got[0] != "m/p.F" {
		t.Errorf("a closure suffix must be cut: %v", got)
	}
	if got := callPath([]traceEntry{{Package: "m/p", Function: "Get", Receiver: "Result"}}); len(got) != 1 || got[0] != "m/p.Result.Get" {
		t.Errorf("a value receiver must be kept: %v", got)
	}
	if callPath([]traceEntry{{Module: "m", Package: "m/p"}}) != nil {
		t.Error("a trace with no function frames has no call path")
	}
}

func TestCallPath_IsBounded(t *testing.T) {
	var trace []traceEntry
	for i := 0; i < 40; i++ {
		trace = append(trace, traceEntry{Module: "m", Package: fmt.Sprintf("m/p%d", i), Function: "F"})
	}
	got := callPath(trace)
	if len(got) != maxCallPathFrames {
		t.Errorf("len(callPath) = %d, want %d", len(got), maxCallPathFrames)
	}
	// The trace is innermost first: m/p0 is the vulnerable function, m/p39 the
	// entry. Both ends survive the cut, and the cut is marked.
	if got[0] != "m/p39.F" || got[1] != callPathElision || got[len(got)-1] != "m/p0.F" {
		t.Errorf("entry, cut marker and vulnerable function must be present: %v", got)
	}
	if got := callPath(trace[:3]); len(got) != 3 || got[1] == callPathElision {
		t.Errorf("a short path must not be marked as cut: %v", got)
	}
}

// govulncheck emits one called finding per vulnerable symbol of the same OSV, in
// no stable order. The path kept must not depend on that order: the shorter one
// wins, ties break on the joined string.
func TestParseGovulncheckJSON_CallPathIndependentOfFindingOrder(t *testing.T) {
	osv := `{"osv":{"id":"GO-1","summary":"s","affected":[{"package":{"name":"example.com/lib","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"v1.2.0"}]}],"database_specific":{"severity":"HIGH"}}]}}` + "\n"
	direct := `{"finding":{"osv":"GO-1","trace":[` +
		`{"module":"example.com/lib","package":"example.com/lib","function":"Serve","receiver":"*Server"},` +
		`{"module":"example.com/app","package":"example.com/app","function":"main"}]}}` + "\n"
	viaFmt := `{"finding":{"osv":"GO-1","trace":[` +
		`{"module":"example.com/lib","package":"example.com/lib","function":"String","receiver":"Setting"},` +
		`{"module":"stdlib","package":"fmt","function":"Errorf"},` +
		`{"module":"example.com/app","package":"example.com/app","function":"main"}]}}` + "\n"
	pathOf := func(in string) string {
		res, err := parseGovulncheckJSON(bytes.NewBufferString(in))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(res["example.com/lib"][0].CallPath, " > ")
	}
	a, b := pathOf(osv+direct+viaFmt), pathOf(osv+viaFmt+direct)
	if a != b {
		t.Errorf("path depends on finding order:\n %s\n %s", a, b)
	}
	if want := "example.com/app.main > example.com/lib.Server.Serve"; a != want {
		t.Errorf("path = %q, want the direct route %q", a, want)
	}
}

func TestParseGovulncheckJSON_CallPathOnUpgradeToCalled(t *testing.T) {
	osv := func(id string) string {
		return `{"osv":{"id":"` + id + `","summary":"s","affected":[{"package":{"name":"example.com/lib","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"v1.2.0"}]}],"database_specific":{"severity":"HIGH"}}]}}` + "\n"
	}
	finding := func(id, trace string) string {
		return `{"finding":{"osv":"` + id + `","trace":` + trace + `}}` + "\n"
	}
	in := osv("GO-1") + osv("GO-2") +
		// GO-1: module, then package, then symbol level (called).
		finding("GO-1", `[{"module":"example.com/lib","version":"v1.1.0"}]`) +
		finding("GO-1", `[{"module":"example.com/lib","version":"v1.1.0","package":"example.com/lib/p"}]`) +
		finding("GO-1", `[{"module":"example.com/lib","version":"v1.1.0","package":"example.com/lib/p","function":"Get","receiver":"*Client","position":{"filename":"p.go","line":1,"column":1}},`+
			`{"module":"example.com/app","package":"example.com/app","function":"main","position":{"filename":"main.go","line":9,"column":2}}]`) +
		// GO-2: never gets past package level.
		finding("GO-2", `[{"module":"example.com/lib","version":"v1.1.0"}]`) +
		finding("GO-2", `[{"module":"example.com/lib","version":"v1.1.0","package":"example.com/lib/p"}]`)

	res, err := parseGovulncheckJSON(bytes.NewBufferString(in))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Vulnerability{}
	for _, v := range res["example.com/lib"] {
		byID[v.ID] = v
	}
	if v := byID["GO-1"]; v.Reachability != "called" || strings.Join(v.CallPath, "|") != "example.com/app.main|example.com/lib/p.Client.Get" {
		t.Errorf("GO-1 = %q %v, want called with the receiver-qualified path", v.Reachability, v.CallPath)
	}
	if v := byID["GO-2"]; v.Reachability != "imported" || v.CallPath != nil {
		t.Errorf("GO-2 = %q %v, want imported with no call path", v.Reachability, v.CallPath)
	}
}

// gvcTestOSV is a minimal OSV line for module example.com/lib.
func gvcTestOSV(id string) string {
	return `{"osv":{"id":"` + id + `","summary":"s","affected":[{"package":{"name":"example.com/lib","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"v1.2.0"}]}],"database_specific":{"severity":"HIGH"}}]}}` + "\n"
}

// gvcTestFinding renders one govulncheck finding line from pre-rendered frames,
// innermost first.
func gvcTestFinding(osv string, frames ...string) string {
	return `{"finding":{"osv":"` + osv + `","trace":[` + strings.Join(frames, ",") + `]}}` + "\n"
}

// gvcTestFrame renders one trace frame. An empty file omits the position.
func gvcTestFrame(mod, ver, pkg, fn, recv, file string, line, col int) string {
	s := fmt.Sprintf(`{"module":%q,"version":%q,"package":%q,"function":%q`, mod, ver, pkg, fn)
	if recv != "" {
		s += fmt.Sprintf(`,"receiver":%q`, recv)
	}
	if file != "" || line != 0 {
		s += fmt.Sprintf(`,"position":{"filename":%q,"line":%d,"column":%d}`, file, line, col)
	}
	return s + "}"
}

func gvcTestParse(t *testing.T, in, mod, id string) Vulnerability {
	t.Helper()
	res, err := parseGovulncheckJSON(bytes.NewBufferString(in))
	if err != nil {
		t.Fatalf("parseGovulncheckJSON: %v", err)
	}
	for _, v := range res[mod] {
		if v.ID == id {
			return v
		}
	}
	t.Fatalf("%s not found under %s", id, mod)
	return Vulnerability{}
}

// The finding from issue #134 (verbatim govulncheck v1.8.0 shape, multi-line as
// the Decoder accepts it), with its SBOM message.
const gvcIssue134OSV = `{"osv":{"id":"GO-2026-5005","summary":"Invoking key constraints not enforced in golang.org/x/crypto/ssh/agent"}}
`

const gvcIssue134SBOM = `{"SBOM":{"roots":["example.com/u1repro"]}}
`

const gvcIssue134Finding = `{"finding":{"osv":"GO-2026-5005","fixed_version":"v0.52.0","trace":[
  {"module":"golang.org/x/crypto","package":"golang.org/x/crypto/ssh/agent","function":"Add","receiver":"*keyring",
   "position":{"filename":"ssh/agent/keyring.go","line":149,"column":19}},
  {"module":"example.com/u1repro","package":"example.com/u1repro","function":"main",
   "position":{"filename":"main.go","line":13,"column":12}}
]}}
`

func TestParseGovulncheckJSON_CallTraceIssue134(t *testing.T) {
	wantPath := []string{"example.com/u1repro.main", "golang.org/x/crypto/ssh/agent.keyring.Add"}
	wantTrace := []CallFrame{
		{Name: "example.com/u1repro.main", Module: "example.com/u1repro", File: "main.go", Line: 13, Column: 12, Project: true},
		{Name: "golang.org/x/crypto/ssh/agent.keyring.Add", Module: "golang.org/x/crypto", File: "ssh/agent/keyring.go", Line: 149, Column: 19},
	}
	wantSyms := []string{"golang.org/x/crypto/ssh/agent.keyring.Add"}

	tests := []struct {
		name string
		in   string
	}{
		{"sbom before finding", gvcIssue134OSV + gvcIssue134SBOM + gvcIssue134Finding},
		{"sbom after finding", gvcIssue134OSV + gvcIssue134Finding + gvcIssue134SBOM},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := gvcTestParse(t, tt.in, "golang.org/x/crypto", "GO-2026-5005")
			if v.Reachability != "called" {
				t.Fatalf("Reachability = %q, want called", v.Reachability)
			}
			if !slices.Equal(v.CallPath, wantPath) {
				t.Errorf("CallPath = %v, want %v", v.CallPath, wantPath)
			}
			if !reflect.DeepEqual(v.CallTrace, wantTrace) {
				t.Errorf("CallTrace = %+v, want %+v", v.CallTrace, wantTrace)
			}
			if !slices.Equal(v.CalledSymbols, wantSyms) {
				t.Errorf("CalledSymbols = %v, want %v", v.CalledSymbols, wantSyms)
			}
		})
	}
}

// Two called sinks of GO-2024-2687, verbatim from govulncheck v1.8.0 output for a
// fixture module (the positions were stripped there and are added back here so
// CallTrace is exercised).
const gvcOrderSettingString = `{"finding":{"osv":"GO-2024-2687","fixed_version":"v0.23.0","trace":[
 {"module":"golang.org/x/net","version":"v0.15.0","package":"golang.org/x/net/http2","function":"String","receiver":"Setting","position":{"filename":"http2/frame.go","line":900,"column":20}},
 {"module":"stdlib","version":"v1.26.8","package":"fmt","function":"handleMethods","receiver":"*pp","position":{"filename":"src/fmt/print.go","line":600,"column":10}},
 {"module":"stdlib","version":"v1.26.8","package":"fmt","function":"printArg","receiver":"*pp","position":{"filename":"src/fmt/print.go","line":700,"column":5}},
 {"module":"stdlib","version":"v1.26.8","package":"fmt","function":"doPrintf","receiver":"*pp","position":{"filename":"src/fmt/print.go","line":1100,"column":5}},
 {"module":"stdlib","version":"v1.26.8","package":"fmt","function":"Errorf","position":{"filename":"src/fmt/errors.go","line":30,"column":9}},
 {"module":"golang.org/x/net","version":"v0.15.0","package":"golang.org/x/net/html","function":"ParseFragmentWithOptions","position":{"filename":"html/parse.go","line":2400,"column":15}},
 {"module":"golang.org/x/net","version":"v0.15.0","package":"golang.org/x/net/html","function":"ParseFragment","position":{"filename":"html/parse.go","line":2370,"column":9}},
 {"module":"example.com/fixture","package":"example.com/fixture","function":"parseDoc","position":{"filename":"parse.go","line":22,"column":14}},
 {"module":"example.com/fixture","package":"example.com/fixture","function":"main","position":{"filename":"main.go","line":10,"column":3}}]}}
`

const gvcOrderPseudoHeaderError = `{"finding":{"osv":"GO-2024-2687","fixed_version":"v0.23.0","trace":[
 {"module":"golang.org/x/net","version":"v0.15.0","package":"golang.org/x/net/http2","function":"Error","receiver":"duplicatePseudoHeaderError","position":{"filename":"http2/errors.go","line":150,"column":40}},
 {"module":"stdlib","version":"v1.26.8","package":"fmt","function":"handleMethods","receiver":"*pp","position":{"filename":"src/fmt/print.go","line":600,"column":10}},
 {"module":"stdlib","version":"v1.26.8","package":"fmt","function":"printArg","receiver":"*pp","position":{"filename":"src/fmt/print.go","line":700,"column":5}},
 {"module":"stdlib","version":"v1.26.8","package":"fmt","function":"doPrintf","receiver":"*pp","position":{"filename":"src/fmt/print.go","line":1100,"column":5}},
 {"module":"stdlib","version":"v1.26.8","package":"fmt","function":"Errorf","position":{"filename":"src/fmt/errors.go","line":30,"column":9}},
 {"module":"golang.org/x/net","version":"v0.15.0","package":"golang.org/x/net/html","function":"ParseFragmentWithOptions","position":{"filename":"html/parse.go","line":2400,"column":15}},
 {"module":"golang.org/x/net","version":"v0.15.0","package":"golang.org/x/net/html","function":"ParseFragment","position":{"filename":"html/parse.go","line":2370,"column":9}},
 {"module":"example.com/fixture","package":"example.com/fixture","function":"parseDoc","position":{"filename":"parse.go","line":22,"column":14}},
 {"module":"example.com/fixture","package":"example.com/fixture","function":"main","position":{"filename":"main.go","line":10,"column":3}}]}}
`

// gvcOrderSettingStringMovedMain has the same condensed path string as
// gvcOrderSettingString but its call sites sit on different lines, so only the
// position tie-break can order the two.
var gvcOrderSettingStringMovedMain = strings.NewReplacer(
	`"filename":"main.go","line":10,"column":3`, `"filename":"main.go","line":9,"column":3`,
).Replace(gvcOrderSettingString)

const gvcOrderOSV = `{"osv":{"id":"GO-2024-2687","summary":"HTTP/2 CONTINUATION flood in net/http"}}
`

func TestParseGovulncheckJSON_CallTraceIndependentOfFindingOrder(t *testing.T) {
	findings := []string{gvcOrderSettingString, gvcOrderPseudoHeaderError, gvcOrderSettingStringMovedMain}
	sbom := `{"SBOM":{"roots":["example.com/fixture"]}}` + "\n"

	perms := [][]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	var first Vulnerability
	for i, perm := range perms {
		var in strings.Builder
		in.WriteString(gvcOrderOSV + sbom)
		for _, idx := range perm {
			in.WriteString(findings[idx])
		}
		v := gvcTestParse(t, in.String(), "golang.org/x/net", "GO-2024-2687")
		if i == 0 {
			first = v
			continue
		}
		if !slices.Equal(v.CallPath, first.CallPath) {
			t.Errorf("perm %v: CallPath = %v, want %v", perm, v.CallPath, first.CallPath)
		}
		if !reflect.DeepEqual(v.CallTrace, first.CallTrace) {
			t.Errorf("perm %v: CallTrace differs:\n got %+v\nwant %+v", perm, v.CallTrace, first.CallTrace)
		}
		if !slices.Equal(v.CalledSymbols, first.CalledSymbols) {
			t.Errorf("perm %v: CalledSymbols = %v, want %v", perm, v.CalledSymbols, first.CalledSymbols)
		}
	}

	wantPath := "example.com/fixture.main > example.com/fixture.parseDoc > " +
		"golang.org/x/net/html.ParseFragmentWithOptions > fmt.pp.handleMethods > " +
		"golang.org/x/net/http2.Setting.String"
	if got := strings.Join(first.CallPath, " > "); got != wantPath {
		t.Errorf("CallPath = %q, want %q", got, wantPath)
	}
	if len(first.CallTrace) != len(first.CallPath) {
		t.Fatalf("len(CallTrace) = %d, want %d", len(first.CallTrace), len(first.CallPath))
	}
	// The moved-main finding has the same path string and the smaller position.
	if f := first.CallTrace[0]; f.File != "main.go" || f.Line != 9 || !f.Project {
		t.Errorf("CallTrace[0] = %+v, want main.go:9 project frame (position tie-break)", f)
	}
	wantSyms := []string{
		"golang.org/x/net/http2.Setting.String",
		"golang.org/x/net/http2.duplicatePseudoHeaderError.Error",
	}
	if !slices.Equal(first.CalledSymbols, wantSyms) {
		t.Errorf("CalledSymbols = %v, want %v", first.CalledSymbols, wantSyms)
	}
}

func TestCondense_CutPathKeepsTraceAligned(t *testing.T) {
	var trace []traceEntry
	for i := 0; i < 40; i++ {
		trace = append(trace, traceEntry{
			Module: "m", Version: "v1.0.0", Package: fmt.Sprintf("m/p%d", i), Function: "F",
			Position: &struct {
				Filename string `json:"filename"`
				Line     int    `json:"line"`
				Column   int    `json:"column"`
			}{Filename: fmt.Sprintf("p%d/f.go", i), Line: i + 1, Column: 2},
		})
	}
	roots := map[string]bool{"m/p39": true}
	path, frames := condense(trace, roots)
	if len(path) != maxCallPathFrames || len(frames) != len(path) {
		t.Fatalf("len(path) = %d, len(frames) = %d, want both %d", len(path), len(frames), maxCallPathFrames)
	}
	if path[1] != callPathElision {
		t.Fatalf("path[1] = %q, want the cut marker", path[1])
	}
	if frames[1] != (CallFrame{Elided: true}) {
		t.Errorf("frames[1] = %+v, want CallFrame{Elided: true}", frames[1])
	}
	for i, f := range frames {
		if i == 1 {
			continue
		}
		if f.Name != path[i] {
			t.Errorf("frames[%d].Name = %q, want %q", i, f.Name, path[i])
		}
	}
	if f := frames[0]; f.Name != "m/p39.F" || !f.Project || f.File != "p39/f.go" || f.Line != 40 || f.Column != 2 || f.Version != "v1.0.0" {
		t.Errorf("frames[0] = %+v", f)
	}
	if f := frames[len(frames)-1]; f.Name != "m/p0.F" || f.Project {
		t.Errorf("sink frame = %+v", f)
	}

	// callPath is the same path without positions.
	if got := callPath(trace); !slices.Equal(got, path) {
		t.Errorf("callPath = %v, want %v", got, path)
	}
	if p, fr := condense([]traceEntry{{Module: "m", Package: "m/p"}}, nil); p != nil || fr != nil {
		t.Errorf("a trace with no function frames must condense to nil, nil: %v %v", p, fr)
	}
}

func TestParseGovulncheckJSON_CallTraceFilenameHygiene(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		wantFile string
	}{
		{"relative", "pkg/x.go", "pkg/x.go"},
		{"absolute", "/home/u/x.go", ""},
		{"parent directory", "../build/cgo.go", ""},
		{"parent only", "..", ""},
		{"windows parent", `..\build\cgo.go`, ""},
		{"dotfile is not a parent", "..hidden/x.go", "..hidden/x.go"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := gvcTestOSV("GO-1") + gvcTestFinding("GO-1",
				gvcTestFrame("example.com/lib", "v1.1.0", "example.com/lib", "Serve", "", tt.filename, 42, 7),
				gvcTestFrame("example.com/app", "", "example.com/app", "main", "", "main.go", 5, 2))
			v := gvcTestParse(t, in, "example.com/lib", "GO-1")
			if len(v.CallTrace) != 2 {
				t.Fatalf("CallTrace = %+v", v.CallTrace)
			}
			sink := v.CallTrace[1]
			if sink.File != tt.wantFile {
				t.Errorf("File = %q, want %q", sink.File, tt.wantFile)
			}
			if sink.Line != 42 || sink.Column != 7 {
				t.Errorf("Line:Column = %d:%d, want 42:7 kept even when File is dropped", sink.Line, sink.Column)
			}
		})
	}
}

func TestParseGovulncheckJSON_CallTraceWithoutSBOM(t *testing.T) {
	in := gvcIssue134OSV + gvcIssue134Finding
	v := gvcTestParse(t, in, "golang.org/x/crypto", "GO-2026-5005")
	if len(v.CallTrace) != 2 {
		t.Fatalf("CallTrace = %+v", v.CallTrace)
	}
	for i, f := range v.CallTrace {
		if f.Project {
			t.Errorf("CallTrace[%d].Project = true with no SBOM message", i)
		}
	}
	if f := v.CallTrace[0]; f.File != "main.go" || f.Line != 13 || f.Column != 12 {
		t.Errorf("CallTrace[0] = %+v, want the position kept without an SBOM", f)
	}
}

func TestParseGovulncheckJSON_NoCallTraceUnlessCalled(t *testing.T) {
	tests := []struct {
		name  string
		trace string
		want  string
	}{
		{"imported", `{"module":"example.com/lib","version":"v1.1.0","package":"example.com/lib/p"}`, "imported"},
		{"required", `{"module":"example.com/lib","version":"v1.1.0"}`, "required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := gvcTestOSV("GO-1") + `{"SBOM":{"roots":["example.com/app"]}}` + "\n" +
				gvcTestFinding("GO-1", tt.trace)
			v := gvcTestParse(t, in, "example.com/lib", "GO-1")
			if v.Reachability != tt.want {
				t.Fatalf("Reachability = %q, want %q", v.Reachability, tt.want)
			}
			if v.CallTrace != nil || v.CalledSymbols != nil || v.CallPath != nil {
				t.Errorf("CallPath/CallTrace/CalledSymbols = %v %v %v, want all nil", v.CallPath, v.CallTrace, v.CalledSymbols)
			}
		})
	}
}

func TestParseGovulncheckJSON_CalledSymbolsOnUpgradeToCalled(t *testing.T) {
	in := gvcTestOSV("GO-1") +
		gvcTestFinding("GO-1", `{"module":"example.com/lib","version":"v1.1.0","package":"example.com/lib/p"}`) +
		gvcTestFinding("GO-1",
			gvcTestFrame("example.com/lib", "v1.1.0", "example.com/lib/p", "Get", "*Client", "p.go", 1, 1),
			gvcTestFrame("example.com/app", "", "example.com/app", "main", "", "main.go", 9, 2))
	v := gvcTestParse(t, in, "example.com/lib", "GO-1")
	if v.Reachability != "called" {
		t.Fatalf("Reachability = %q, want called", v.Reachability)
	}
	if len(v.CallTrace) != 2 || v.CallTrace[0].Line != 9 {
		t.Errorf("CallTrace = %+v, want the upgrade to set the trace", v.CallTrace)
	}
	if !slices.Equal(v.CalledSymbols, []string{"example.com/lib/p.Client.Get"}) {
		t.Errorf("CalledSymbols = %v", v.CalledSymbols)
	}
}

func TestParseGovulncheckJSON_CalledSymbolsAreCapped(t *testing.T) {
	// 25 distinct sinks, emitted in reverse order, plus a duplicate.
	var sb strings.Builder
	sb.WriteString(gvcTestOSV("GO-1"))
	for i := 24; i >= 0; i-- {
		sb.WriteString(gvcTestFinding("GO-1",
			gvcTestFrame("example.com/lib", "v1.1.0", "example.com/lib", fmt.Sprintf("Sym%02d", i), "", "l.go", i+1, 1),
			gvcTestFrame("example.com/app", "", "example.com/app", "main", "", "main.go", 9, 2)))
	}
	sb.WriteString(gvcTestFinding("GO-1",
		gvcTestFrame("example.com/lib", "v1.1.0", "example.com/lib", "Sym00", "", "l.go", 1, 1),
		gvcTestFrame("example.com/app", "", "example.com/app", "main", "", "main.go", 9, 2)))

	v := gvcTestParse(t, sb.String(), "example.com/lib", "GO-1")
	if len(v.CalledSymbols) != maxCalledSymbols || maxCalledSymbols != 20 {
		t.Fatalf("len(CalledSymbols) = %d, want 20", len(v.CalledSymbols))
	}
	if !slices.IsSorted(v.CalledSymbols) {
		t.Errorf("CalledSymbols not sorted: %v", v.CalledSymbols)
	}
	if v.CalledSymbols[0] != "example.com/lib.Sym00" || v.CalledSymbols[19] != "example.com/lib.Sym19" {
		t.Errorf("the cut must keep the first 20 in sorted order: %v", v.CalledSymbols)
	}
}
