package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
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
