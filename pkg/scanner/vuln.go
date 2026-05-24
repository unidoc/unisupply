// Package scanner provides vulnerability and maintenance scanning.
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/vuln/scan"
)

// Vulnerability represents a known vulnerability for a module.
type Vulnerability struct {
	ID           string   `json:"id"`
	Aliases      []string `json:"aliases"`
	Summary      string   `json:"summary"`
	Severity     string   `json:"severity"`
	FixedVersion string   `json:"fixed_version,omitempty"`

	// Enrichment metadata — populated by the OSV/GHSA enrichment pass.

	// EnrichmentAttempted is true when the enricher ran for this vuln (i.e.
	// the original severity was UNKNOWN and the ID passed validation).
	EnrichmentAttempted bool `json:"enrichment_attempted,omitempty"`

	// EnrichmentFailed is true when enrichment was attempted but both OSV
	// and GHSA lookups failed. Task 08 uses this to distinguish
	// "no severity data" from "severity data unavailable due to API failure".
	EnrichmentFailed bool `json:"enrichment_failed,omitempty"`

	// PublishedAt is the date the vulnerability was first disclosed, from OSV.
	PublishedAt *time.Time `json:"published_at,omitempty"`

	// FixPublishedAt is the date a fix became available, derived from OSV's
	// published timestamp for the fixed version event.
	FixPublishedAt *time.Time `json:"fix_published_at,omitempty"`

	// DaysUnpatched is the number of days since a fix was available.
	// Zero when no fix exists or the fix date is unknown.
	DaysUnpatched int `json:"days_unpatched,omitempty"`
}

// govulncheck JSON output is a stream of objects, each with one top-level key.
// The relevant ones for us are:
//   {"osv": { ... }}       — an OSV vulnerability entry
//   {"finding": { ... }}   — a finding linking an osv to affected code
//
// We collect all OSVs, then all findings, and match them up.

type gvcOSV struct {
	SchemaVersion string   `json:"schema_version"`
	ID            string   `json:"id"`
	Aliases       []string `json:"aliases"`
	Summary       string   `json:"summary"`
	Published     string   `json:"published"` // RFC3339 timestamp from govulncheck output
	Modified      string   `json:"modified"`
	Affected      []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
		DatabaseSpecific *struct {
			Severity string `json:"severity"`
		} `json:"database_specific,omitempty"`
	} `json:"affected"`
}

type gvcFinding struct {
	OSV   string `json:"osv"`
	Trace []struct {
		Module  string `json:"module,omitempty"`
		Version string `json:"version,omitempty"`
		Package string `json:"package,omitempty"`
	} `json:"trace"`
	FixedVersion string `json:"fixed_version,omitempty"`
}

// ScanVulns runs govulncheck on the project directory, then enriches any
// UNKNOWN-severity vulnerabilities via OSV.dev and the GitHub Advisory API.
// githubToken may be empty; enrichment proceeds unauthenticated in that case
// (OSV does not require authentication; GHSA fallback works but is rate-limited).
func ScanVulns(ctx context.Context, projectDir, githubToken string) (vulns map[string][]Vulnerability, warnings []string, err error) {
	var stdout bytes.Buffer

	cmd := scan.Command(ctx, "-json", "-C", projectDir, "./...")
	cmd.Stdout = &stdout
	cmd.Stderr = &bytes.Buffer{} // suppress stderr

	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("starting govulncheck: %w", err)
	}
	// govulncheck exits non-zero when vulns are found — not an error for us.
	_ = cmd.Wait()

	if stdout.Len() == 0 {
		warnings = append(warnings, "govulncheck produced no output")
		return nil, warnings, nil
	}

	results, err := parseGovulncheckJSON(&stdout)
	if err != nil {
		return nil, append(warnings, err.Error()), nil
	}

	// Enrich UNKNOWN-severity vulnerabilities via OSV + GHSA.
	enricher := NewVulnEnricher(VulnEnricherOptions{GitHubToken: githubToken})
	for modPath, modVulns := range results {
		for i := range modVulns {
			if modVulns[i].Severity != "UNKNOWN" && modVulns[i].Severity != "" {
				continue
			}
			enrichWarnings := enricher.Enrich(ctx, &modVulns[i])
			warnings = append(warnings, enrichWarnings...)
		}
		results[modPath] = modVulns
	}

	return results, warnings, nil
}

func parseGovulncheckJSON(buf *bytes.Buffer) (map[string][]Vulnerability, error) {
	// Collect OSVs and findings.
	osvs := make(map[string]*gvcOSV) // id -> osv
	var findings []gvcFinding

	dec := json.NewDecoder(buf)
	for dec.More() {
		var raw map[string]json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			continue
		}

		if osvData, ok := raw["osv"]; ok {
			var osv gvcOSV
			if err := json.Unmarshal(osvData, &osv); err == nil && osv.ID != "" {
				osvs[osv.ID] = &osv
			}
		}

		if findingData, ok := raw["finding"]; ok {
			var f gvcFinding
			if err := json.Unmarshal(findingData, &f); err == nil && f.OSV != "" {
				findings = append(findings, f)
			}
		}
	}

	// Build results: for each finding, look up the OSV and extract module info.
	results := make(map[string][]Vulnerability)
	seen := make(map[string]bool) // "module@osvID" dedup

	for _, f := range findings {
		osv, ok := osvs[f.OSV]
		if !ok {
			continue
		}

		// The first trace entry with a module is the affected module.
		modPath := ""
		for _, t := range f.Trace {
			if t.Module != "" {
				modPath = t.Module
				break
			}
		}
		if modPath == "" {
			continue
		}

		// For stdlib vulns, key by "stdlib" so they're grouped together.
		// Include the package name in the vulnerability summary.
		if modPath == "stdlib" {
			pkg := ""
			for _, t := range f.Trace {
				if t.Package != "" {
					pkg = t.Package
					break
				}
			}
			if pkg != "" && !strings.Contains(osv.Summary, pkg) {
				osv.Summary = fmt.Sprintf("[%s] %s", pkg, osv.Summary)
			}
		}

		key := modPath + "@" + osv.ID
		if seen[key] {
			continue
		}
		seen[key] = true

		severity := severityFromOSV(osv, modPath)
		fixedVersion := f.FixedVersion
		if fixedVersion == "" {
			fixedVersion = fixedVersionFromOSV(osv, modPath)
		}

		vuln := Vulnerability{
			ID:           osv.ID,
			Aliases:      osv.Aliases,
			Summary:      osv.Summary,
			Severity:     severity,
			FixedVersion: fixedVersion,
		}

		// Capture the publication timestamp from the govulncheck OSV record.
		if osv.Published != "" {
			if t, err := time.Parse(time.RFC3339, osv.Published); err == nil {
				vuln.PublishedAt = &t
			}
		}

		results[modPath] = append(results[modPath], vuln)
	}

	return results, nil
}

func severityFromOSV(osv *gvcOSV, modPath string) string {
	for _, aff := range osv.Affected {
		if aff.Package.Name == modPath || aff.Package.Name == "stdlib" {
			if aff.DatabaseSpecific != nil && aff.DatabaseSpecific.Severity != "" {
				return strings.ToUpper(aff.DatabaseSpecific.Severity)
			}
		}
	}
	return "UNKNOWN"
}

func fixedVersionFromOSV(osv *gvcOSV, modPath string) string {
	for _, aff := range osv.Affected {
		if aff.Package.Name == modPath || aff.Package.Name == "stdlib" {
			for _, r := range aff.Ranges {
				for _, e := range r.Events {
					if e.Fixed != "" {
						return e.Fixed
					}
				}
			}
		}
	}
	return ""
}
