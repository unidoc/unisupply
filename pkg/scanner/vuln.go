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
//
// # Reachability semantics
//
// The Reachability field classifies how close the vulnerable code is to the
// call sites in the scanned project. Allowed values, in descending severity:
//
//   - "called"   — a vulnerable function is directly called somewhere in the
//     project; govulncheck resolved a full call path ending at the vulnerable
//     symbol (trace[0].Function is non-empty or a Position was recorded).
//   - "imported" — the vulnerable package is imported by the project but the
//     vulnerable function itself is not reachable in the static call graph
//     (trace[0].Package is set, Function is empty).
//   - "required" — the module is present in the module graph but no package
//     from it is imported (trace contains only a Module entry).
//   - ""         — reachability was not determined; the vulnerability was
//     sourced from a mechanism other than govulncheck (e.g. a future enrichment
//     pass or a manually injected record). The scorer treats an empty value as
//     "called" for backward compatibility, giving it the highest weight.
//
// Static-analysis caveat: "not called" does not mean "not exploitable".
// govulncheck performs whole-program analysis on the static call graph, which
// cannot account for dynamic dispatch via reflection, plugin loading,
// build-tag-gated code paths, generated code, or opaque-interface receivers
// resolved only at runtime. Any of these patterns can hide a genuine call that
// govulncheck classifies as "imported" or "required". Treat those levels as a
// lower-confidence signal, not as evidence the vulnerability is unexploitable.
// See https://go.dev/blog/govulncheck for govulncheck's stated precision limits.
type Vulnerability struct {
	ID           string   `json:"id"`
	Aliases      []string `json:"aliases"`
	Summary      string   `json:"summary"`
	Severity     string   `json:"severity"`
	FixedVersion string   `json:"fixed_version,omitempty"`

	// Reachability is one of "called", "imported", "required", or "".
	// See the type-level doc comment for full semantics and caveats.
	Reachability string `json:"reachability,omitempty"`

	// Enrichment metadata — populated by the OSV/GHSA enrichment pass.

	// EnrichmentAttempted is true when the enricher ran for this vuln (i.e.
	// the original severity was UNKNOWN and the ID passed validation).
	EnrichmentAttempted bool `json:"enrichment_attempted,omitempty"`

	// EnrichmentFailed is true when enrichment was attempted but all tiers
	// (OSV, NVD, and GitHub Advisory) failed. Distinguishes "no severity data"
	// from "severity data unavailable due to API failure".
	EnrichmentFailed bool `json:"enrichment_failed,omitempty"`

	// SeveritySource records which API resolved the severity: "osv", "nvd",
	// "ghsa", or "none" when all tiers failed. Empty when enrichment was not
	// attempted (severity was known from govulncheck).
	SeveritySource string `json:"severity_source,omitempty"`

	// EnrichmentErrors holds a brief failure summary when all enrichment tiers
	// failed (EnrichmentFailed==true). At most one entry: the consolidated
	// "severity lookup failed (OSV/NVD/GitHub)" warning message.
	EnrichmentErrors []string `json:"enrichment_errors,omitempty"`

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

// traceEntry is one frame in a govulncheck call-trace path.
type traceEntry struct {
	Module   string `json:"module,omitempty"`
	Version  string `json:"version,omitempty"`
	Package  string `json:"package,omitempty"`
	Function string `json:"function,omitempty"`
	Position *struct {
		Filename string `json:"filename"`
		Line     int    `json:"line"`
		Column   int    `json:"column"`
	} `json:"position,omitempty"`
}

type gvcFinding struct {
	OSV          string       `json:"osv"`
	Trace        []traceEntry `json:"trace"`
	FixedVersion string       `json:"fixed_version,omitempty"`
}

// reachabilityRank maps reachability levels to a numeric rank for comparison.
// Higher rank = higher severity of reachability.
var reachabilityRank = map[string]int{
	"required": 1,
	"imported": 2,
	"called":   3,
}

// classifyReachability inspects the trace from govulncheck and returns one of
// "called", "imported", or "required" to describe how close the vulnerable code
// is to the caller.
//
// Rules (trace[0] is the deepest/innermost frame):
//   - "called"   when trace[0].Function is set or any frame has Position set.
//   - "imported" when trace[0].Package is set but Function is empty.
//   - "required" when only trace[0].Module is set.
//
// The rule structure follows govulncheck's emitted JSON shape: a frame with
// `position` set means the analyzer resolved a static call site, `package`
// without `function` means import-only, `module` alone means the vulnerable
// module is required but no package from it is reached by the build. If
// govulncheck's frame schema changes in a future release, revisit this
// classifier — the current rules are coupled to that representation. See
// the `Finding.Trace[]` schema documented in the govulncheck source
// (golang.org/x/vuln/internal/govulncheck) for the authoritative shape.
func classifyReachability(trace []traceEntry) string {
	if len(trace) == 0 {
		return "required"
	}

	// Any frame with a resolved call site means the function was called.
	for _, t := range trace {
		if t.Position != nil {
			return "called"
		}
	}

	if trace[0].Function != "" {
		return "called"
	}
	if trace[0].Package != "" {
		return "imported"
	}
	return "required"
}

// ScanVulns runs govulncheck on the project directory, then enriches any
// UNKNOWN-severity vulnerabilities via OSV.dev and the GitHub Advisory API.
// githubToken may be empty; enrichment proceeds unauthenticated in that case
// (OSV does not require authentication; GHSA fallback works but is rate-limited).
//
// The default govulncheck invocation (-json ./...) already emits all three
// reachability levels (called, imported, required) in the JSON stream — no
// additional CLI flag is needed to enable reachability data.
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
	// seenIdx maps "module@osvID" to the index of its entry in results[modPath],
	// allowing dedup to upgrade reachability when a higher-rank duplicate appears
	// (called > imported > required — keep the most severe signal).
	seenIdx := make(map[string]int)

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

		reach := classifyReachability(f.Trace)
		key := modPath + "@" + osv.ID

		if idx, exists := seenIdx[key]; exists {
			// Duplicate finding: upgrade reachability if this occurrence ranks higher.
			if reachabilityRank[reach] > reachabilityRank[results[modPath][idx].Reachability] {
				results[modPath][idx].Reachability = reach
			}
			continue
		}

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
			Reachability: reach,
		}

		// Capture the publication timestamp from the govulncheck OSV record.
		if osv.Published != "" {
			if t, err := time.Parse(time.RFC3339, osv.Published); err == nil {
				vuln.PublishedAt = &t
			}
		}

		seenIdx[key] = len(results[modPath])
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
