package scanner

import (
	"bytes"
	"encoding/json"
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
