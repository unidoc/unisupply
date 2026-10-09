// Package scanner provides vulnerability and maintenance scanning.
package scanner

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/vuln/scan"

	"github.com/unidoc/unisupply/pkg/offline"
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
//     pass or a manually injected record). The scorer applies two axes with
//     deliberately different defaults: the weight axis treats "" as "called"
//     (worst-case, highest weight), while the confirmation axis treats "" as
//     unconfirmed (UNKNOWN severity stays MEDIUM, not HIGH). See
//     isConfirmedReachable in pkg/scorer/risk.go for the confirmation axis.
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

	// CallPath is one example of how the project reaches the vulnerable
	// function, outermost frame first, e.g. "example.com/app/cmd/app.main",
	// "github.com/go-git/go-git/v5.Repository.Push", "golang.org/x/crypto/ssh.NewClientConn".
	// It is condensed to the entry frame, the frame where each run of same-package
	// frames hands over to the next package, and the vulnerable function itself
	// (at most 8 entries), so consecutive entries are not necessarily direct
	// callers. A path longer than that is cut in the middle and an entry of
	// "..." marks the cut. Set only when Reachability is "called". It is static-analysis
	// evidence that the code is on an execution path, not proof that the
	// vulnerability is exploitable in the application's deployment.
	CallPath []string `json:"call_path,omitempty"`

	// CallTrace is CallPath with a source position per entry: same selection,
	// same order, len(CallTrace) == len(CallPath). CallTrace[i].Name equals
	// CallPath[i] except for the cut marker, whose entry is CallFrame{Elided: true}.
	// Set only when Reachability is "called". The position of a non-sink frame is
	// the call that frame makes, not the frame's own declaration; the position of
	// the last entry (the vulnerable symbol) is its declaration. Because CallPath is
	// condensed, consecutive entries are not necessarily direct callers, and a
	// kept frame's position may point at a call to a dropped frame. The path need
	// not start at main. Like CallPath it is static-analysis evidence that the
	// code is on an execution path, not proof that the vulnerability is exploitable.
	CallTrace []CallFrame `json:"call_trace,omitempty"`

	// CalledSymbols lists the vulnerable symbols govulncheck found called for this
	// advisory in this module: the innermost frame of every called finding,
	// rendered like a CallPath entry, sorted and without duplicates. govulncheck
	// emits one finding per symbol but CallPath keeps only one path, so this is
	// where the other symbols survive. It is capped at maxCalledSymbols entries;
	// the cut keeps the first maxCalledSymbols in sorted order. Set only when
	// Reachability is "called".
	CalledSymbols []string `json:"called_symbols,omitempty"`

	// Enrichment metadata — populated by the OSV/GHSA enrichment pass.

	// EnrichmentAttempted is true when the enricher ran for this vuln (i.e.
	// the original severity was UNKNOWN and the ID passed validation).
	EnrichmentAttempted bool `json:"enrichment_attempted,omitempty"`

	// EnrichmentFailed is true when enrichment was attempted, no tier produced
	// a severity, and at least one lookup (OSV, NVD or GitHub) failed
	// (SeveritySource "none"). It is false for an "unscored" advisory: every
	// source consulted answered, but none has published a severity. Distinguishes "no severity data" from "severity data
	// unavailable due to API failure".
	EnrichmentFailed bool `json:"enrichment_failed,omitempty"`

	// SeveritySource records which API resolved the severity: "osv", "nvd",
	// "ghsa"; "none" when a lookup failed; or "unscored" when every source
	// consulted (OSV, NVD, GitHub) answered but none has published a severity. Empty when
	// enrichment was not attempted (severity was known from govulncheck).
	SeveritySource string `json:"severity_source,omitempty"`

	// SeverityAlias is the alias ID (GHSA-* or CVE-*) whose OSV record
	// supplied the severity, when it did not come from the advisory's own ID.
	SeverityAlias string `json:"severity_alias,omitempty"`

	// EnrichmentErrors holds a brief failure summary when all enrichment tiers
	// failed (EnrichmentFailed==true). At most one entry: the consolidated
	// "severity lookup failed (OSV/NVD/GitHub)" warning message.
	EnrichmentErrors []string `json:"enrichment_errors,omitempty"`

	// Threat-intel enrichment — populated from EPSS and CISA KEV lookups.
	// Both influence scoring (EPSS amplifier, KEV override); see
	// docs/scanners.md "Threat-intel enrichment" for the full tables.
	// Lookups are keyed by CVE ID: for GO-*/GHSA-* vulns the first CVE-*
	// alias is used; vulns without a CVE alias have no threat-intel data
	// (expected, not an error).

	// EPSSScore is FIRST.org's estimated probability (0.0–1.0) that the CVE
	// will be exploited within the next 30 days. Pointer-typed so absence
	// (lookup failed or no CVE alias) is distinguishable from a real 0.0.
	EPSSScore *float64 `json:"epss_score,omitempty"`

	// EPSSPercentile is the score's percentile rank against all scored CVEs.
	EPSSPercentile *float64 `json:"epss_percentile,omitempty"`

	// EPSSDate is the date the EPSS score was computed (YYYY-MM-DD).
	EPSSDate string `json:"epss_date,omitempty"`

	// InKEV is true when the CVE appears in CISA's Known Exploited
	// Vulnerabilities catalog. Serialized only when the KEV catalog was
	// actually consulted (see KEVChecked): absent means "not checked",
	// false means "checked and not listed".
	InKEV bool `json:"in_kev,omitempty"`

	// KEVChecked is true when the KEV catalog was loaded and this vuln had a
	// CVE alias to look up — i.e. InKEV is a real answer, not a default.
	KEVChecked bool `json:"kev_checked,omitempty"`

	// KEVDateAdded is the date CISA added the CVE to the catalog.
	KEVDateAdded string `json:"kev_date_added,omitempty"`

	// KEVRansomware is CISA's knownRansomwareCampaignUse field:
	// "Known", "Unknown", or "" when not in KEV.
	KEVRansomware string `json:"kev_known_ransomware,omitempty"`

	// PublishedAt is the date the vulnerability was first disclosed, from OSV.
	PublishedAt *time.Time `json:"published_at,omitempty"`

	// FixPublishedAt is the date a fix became available, derived from OSV's
	// published timestamp for the fixed version event.
	FixPublishedAt *time.Time `json:"fix_published_at,omitempty"`

	// DaysUnpatched is the number of days since a fix was available.
	// Zero when no fix exists or the fix date is unknown.
	DaysUnpatched int `json:"days_unpatched,omitempty"`
}

// CallFrame is one entry of Vulnerability.CallTrace, index-aligned with
// Vulnerability.CallPath.
//
// Name equals CallPath[i] except for the cut marker, which is
// CallFrame{Elided: true} with every other field empty. The position of a
// non-sink frame is the call that frame makes; the position of the sink (the
// last entry) is the vulnerable function's declaration. Consecutive frames are
// not necessarily direct callers, because the trace is condensed. A frame is
// evidence that the code is reachable, not proof that it is exploitable.
type CallFrame struct {
	// Name is the same string as CallPath[i]: package, then Receiver.Function.
	Name string `json:"name,omitempty"`

	// Module and Version identify the module that owns the frame. Version is
	// empty for the main module and for replaced local paths.
	Module  string `json:"module,omitempty"`
	Version string `json:"version,omitempty"`

	// File is relative to the root of that frame's own module (the standard
	// library's is relative to GOROOT), so it is meaningless without Module and
	// Version. It is dropped when govulncheck reports an absolute path or one
	// that leaves the module ("../..."); Line and Column are kept regardless.
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`

	// Project is true when the frame's package is one of the scan roots in
	// govulncheck's SBOM message, that is, the project's own code. It is false on
	// every frame when govulncheck emitted no SBOM message (older versions).
	Project bool `json:"project,omitempty"`

	// Elided marks the slot where condensing cut the middle of a long path.
	Elided bool `json:"elided,omitempty"`
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
	// Receiver is the method receiver type ("*Repository", "Result"), empty for
	// a plain function. govulncheck splits a method into Function and Receiver.
	Receiver string `json:"receiver,omitempty"`
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

// maxCallPathFrames bounds Vulnerability.CallPath.
const maxCallPathFrames = 8

// maxCalledSymbols bounds Vulnerability.CalledSymbols.
const maxCalledSymbols = 20

// callPathElision marks, in a path that was cut to maxCallPathFrames, where the
// middle was dropped: its neighbours are not direct callers.
const callPathElision = "..."

// preferPath reports whether candidate should replace current as a
// vulnerability's call path: the shorter path wins (the most direct route to
// the vulnerable code), and ties are broken on the joined string. govulncheck
// emits one called finding per vulnerable symbol in no stable order, so the
// choice must depend on the paths and not on arrival order.
func preferPath(candidate, current []string) bool {
	switch {
	case len(candidate) == 0:
		return false
	case len(current) == 0:
		return true
	case len(candidate) != len(current):
		return len(candidate) < len(current)
	}
	return strings.Join(candidate, "\x00") < strings.Join(current, "\x00")
}

// preferCandidate is preferPath over a (path, trace) pair. Two different
// findings can condense to the same path string yet carry different source
// positions, so when the paths are identical the frames' (File, Line, Column)
// break the tie. That keeps the selected trace independent of arrival order
// without ever changing which path is selected.
func preferCandidate(candPath []string, candFrames []CallFrame, curPath []string, curFrames []CallFrame) bool {
	if preferPath(candPath, curPath) {
		return true
	}
	if preferPath(curPath, candPath) {
		return false
	}
	return compareFramePositions(candFrames, curFrames) < 0
}

// compareFramePositions orders two frame lists frame by frame on (File, Line,
// Column). Lists of different length compare by the common prefix first; the
// caller only uses it for lists whose paths are equal, so the lengths match.
func compareFramePositions(a, b []CallFrame) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := cmp.Compare(a[i].File, b[i].File); c != 0 {
			return c
		}
		if c := cmp.Compare(a[i].Line, b[i].Line); c != 0 {
			return c
		}
		if c := cmp.Compare(a[i].Column, b[i].Column); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(a), len(b))
}

// frameName renders a trace frame the way govulncheck prints it: package, then
// "Receiver.Function" for a method (a leading * trimmed from the receiver), with
// a closure suffix ("$1") cut off the function name.
func frameName(t traceEntry) string {
	name, _, _ := strings.Cut(t.Function, "$")
	if t.Receiver != "" {
		name = strings.TrimPrefix(t.Receiver, "*") + "." + name
	}
	if t.Package != "" {
		name = t.Package + "." + name
	}
	return name
}

// moduleRelativeFile returns filename when it is a path inside the frame's
// module and "" otherwise. govulncheck makes positions relative to each frame's
// module root; an absolute path or one that climbs out of the module (a cgo file
// in the build cache, say) would leak the scanning machine's layout into a
// report that gets shared, and means nothing to the reader.
func moduleRelativeFile(filename string) string {
	switch {
	case filename == "", filename == "..":
		return ""
	case filepath.IsAbs(filename), path.IsAbs(filename):
		return ""
	case strings.HasPrefix(filename, "../"), strings.HasPrefix(filename, `..\`):
		return ""
	}
	return filename
}

// newCallFrame builds the CallFrame for one trace frame. roots is the set of
// scan-root package paths from govulncheck's SBOM message; a nil map marks no
// frame as a project frame.
func newCallFrame(t traceEntry, roots map[string]bool) CallFrame {
	f := CallFrame{
		Name:    frameName(t),
		Module:  t.Module,
		Version: t.Version,
		Project: roots[t.Package],
	}
	if t.Position != nil {
		f.File = moduleRelativeFile(t.Position.Filename)
		f.Line = t.Position.Line
		f.Column = t.Position.Column
	}
	return f
}

// condense condenses a govulncheck trace (innermost frame first) into an
// outermost-first path of "package.Function" entries and a parallel list of
// frames: the entry frame, the frame where each run of same-package frames
// hands over to the next package, and the vulnerable function itself. Both come
// from one walk, so len(frames) == len(path) and frames[i].Name == path[i]
// (except the cut marker, whose frame is CallFrame{Elided: true}). It returns
// nil, nil when the trace has no function frames.
func condense(trace []traceEntry, roots map[string]bool) (path []string, frames []CallFrame) {
	var fr []traceEntry
	for i := len(trace) - 1; i >= 0; i-- { // outermost first
		if trace[i].Function != "" {
			fr = append(fr, trace[i])
		}
	}
	for i, t := range fr {
		last := i == len(fr)-1
		if i == 0 || last || fr[i+1].Package != t.Package {
			frame := newCallFrame(t, roots)
			path = append(path, frame.Name)
			frames = append(frames, frame)
		}
	}
	if len(path) > maxCallPathFrames {
		// Keep the entry point and the tail (the last frames lead to the symbol),
		// and mark the cut.
		keep := maxCallPathFrames - 2
		path = append([]string{path[0], callPathElision}, path[len(path)-keep:]...)
		frames = append([]CallFrame{frames[0], {Elided: true}}, frames[len(frames)-keep:]...)
	}
	return path, frames
}

// callPath returns the condensed call path of a trace without positions.
func callPath(trace []traceEntry) []string {
	path, _ := condense(trace, nil)
	return path
}

// ScanVulns runs govulncheck on the project directory, then enriches any
// UNKNOWN-severity vulnerabilities via OSV.dev and the GitHub Advisory API.
// githubToken may be empty; enrichment proceeds unauthenticated in that case
// (OSV does not require authentication; GHSA fallback works but is rate-limited).
//
// The default govulncheck invocation (-json ./...) already emits all three
// reachability levels (called, imported, required) in the JSON stream — no
// additional CLI flag is needed to enable reachability data.
// The `scanned` return reports whether govulncheck actually analyzed the module
// graph. It exists because an empty vulns map is ambiguous — "scanned, nothing
// found" and "never ran" look identical — and because most failures here surface
// as a warning with a nil error, so a caller checking only err would read a
// failed scan as a clean one. The scorer excludes the 40% vulnerability weight
// when this is false; see scorer.ScoreInput.VulnScanUnavailable.
func ScanVulns(ctx context.Context, projectDir, githubToken string) (vulns map[string][]Vulnerability, warnings []string, scanned bool, err error) {
	return ScanVulnsWithOptions(ctx, projectDir, VulnScanOptions{GitHubToken: githubToken})
}

// VulnScanOptions carries the credentials ScanVulnsWithOptions forwards to the
// severity enrichment lookups.
type VulnScanOptions struct {
	// GitHubToken is sent as a Bearer token to api.github.com only.
	GitHubToken string
	// NVDAPIKey is sent as the apiKey header to services.nvd.nist.gov only.
	NVDAPIKey string
}

// ScanVulnsWithOptions is ScanVulns with explicit credentials for the
// enrichment lookups. It returns the same values as ScanVulns.
func ScanVulnsWithOptions(ctx context.Context, projectDir string, opts VulnScanOptions) (vulns map[string][]Vulnerability, warnings []string, scanned bool, err error) {
	if offline.Enabled() {
		// govulncheck runs in-process and reaches vuln.go.dev through
		// http.DefaultClient, so offline mode would refuse its requests and
		// leave a transport error dressed up as a scan failure. Skip it
		// outright and say why: an empty vulnerability set with no explanation
		// reads as "no vulnerabilities found", which is the one wrong answer.
		return nil, []string{"offline — vulnerability scan skipped (no local vuln DB mirror configured)"}, false, nil
	}

	var stdout bytes.Buffer

	var stderrBuf bytes.Buffer

	// govulncheck's -C only moves package loading; it resolves the Go version
	// and GOROOT for the standard library in this process's working directory.
	// Resolve the project's own so the result does not depend on where
	// unisupply was launched from.
	projectGoVersion, projectGoRoot, projectErr := resolveGoEnv(ctx, projectDir)
	if projectErr != nil {
		warnings = append(warnings, fmt.Sprintf("could not resolve the project's Go toolchain (%v); standard-library vulnerabilities are checked against the Go version of unisupply's working directory", projectErr))
	}
	// A failure here only costs stdlib file positions, so it is not reported.
	_, scannerGoRoot, scannerErr := resolveGoEnv(ctx, "")
	parseOpts := gvcParseOptions{}
	if projectErr == nil && scannerErr == nil {
		parseOpts = gvcParseOptions{scannerGOROOT: scannerGoRoot, projectGOROOT: projectGoRoot}
	}

	cmd := scan.Command(ctx, "-json", "-C", projectDir, "./...")
	cmd.Env = govulncheckEnv(os.Environ(), projectGoVersion)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, nil, false, fmt.Errorf("starting govulncheck: %w", err)
	}
	// govulncheck exits non-zero when vulns are found (JSON mode returns nil in that
	// case via jsonHandler.Flush), so exitErr != nil only signals a real scan failure.
	// scan.Command runs govulncheck in-process; errors come back through Wait() as Go
	// error values, not written to stderr. Prefer stderrBuf when populated (future-proof),
	// fall back to exitErr.Error() for the common in-process case.
	exitErr := cmd.Wait()

	if exitErr != nil {
		// scan.Command runs govulncheck in-process; errors surface via Wait(), not stderr.
		// The library already prefixes errors with "govulncheck:" (derrors.Wrap).
		// Prefer stderrBuf when populated (future subprocess mode), but don't double-prefix.
		msg := strings.TrimSpace(stderrBuf.String())
		if msg == "" {
			msg = exitErr.Error()
		} else if !strings.HasPrefix(msg, "govulncheck:") {
			msg = "govulncheck: " + msg
		}
		warnings = append(warnings, msg)
	}

	if stdout.Len() == 0 {
		warnings = append(warnings, "govulncheck produced no output")
		return nil, warnings, false, nil
	}

	results, err := parseGovulncheckJSONWithOptions(&stdout, parseOpts)
	if err != nil {
		return nil, append(warnings, err.Error()), false, nil
	}

	// Enrich UNKNOWN-severity vulnerabilities via OSV + GHSA.
	enricher := NewVulnEnricher(VulnEnricherOptions{GitHubToken: opts.GitHubToken, NVDAPIKey: opts.NVDAPIKey})
	var enrichWarnings []string
	// Sorted module order keeps the warning order, and the single-failure path
	// in collapseSeverityLookupWarnings, stable across runs.
	for _, modPath := range slices.Sorted(maps.Keys(results)) {
		modVulns := results[modPath]
		for i := range modVulns {
			if modVulns[i].Severity != "UNKNOWN" && modVulns[i].Severity != "" {
				continue
			}
			enrichWarnings = append(enrichWarnings, enricher.Enrich(ctx, &modVulns[i])...)
		}
		results[modPath] = modVulns
	}
	warnings = append(warnings, collapseSeverityLookupWarnings(enrichWarnings)...)

	warnings = append(warnings, enrichThreatIntel(ctx, NewThreatIntelClient(ThreatIntelOptions{}), results)...)

	// A non-nil exitErr means govulncheck failed even though it emitted parseable
	// output, so the results are partial. Report the axis as unmeasured rather
	// than scoring an incomplete scan as a complete one.
	return results, warnings, exitErr == nil, nil
}

// CVEAlias returns the CVE ID to use for threat-intel lookups on v: the ID
// itself when it is a CVE, otherwise the first valid CVE-* alias. Empty when
// the vuln has no CVE identifier — EPSS and KEV only index CVE IDs, so such
// vulns (common for fresh GO-* advisories) have no threat-intel data.
func CVEAlias(v *Vulnerability) string {
	if strings.HasPrefix(v.ID, "CVE-") && validateVulnID(v.ID) {
		return v.ID
	}
	for _, alias := range v.Aliases {
		if strings.HasPrefix(alias, "CVE-") && validateVulnID(alias) {
			return alias
		}
	}
	return ""
}

// enrichThreatIntel populates EPSS and KEV fields on every vulnerability that
// has a CVE alias. Both lookups are best-effort: failures produce warnings,
// never errors — the scan completes with the threat-intel fields absent.
func enrichThreatIntel(ctx context.Context, ti *ThreatIntelClient, results map[string][]Vulnerability) (warnings []string) {
	// Collect the distinct CVE IDs across all vulns.
	cveSet := make(map[string]bool)
	for _, modVulns := range results {
		for i := range modVulns {
			if cve := CVEAlias(&modVulns[i]); cve != "" {
				cveSet[cve] = true
			}
		}
	}
	if len(cveSet) == 0 {
		return nil
	}
	cveIDs := make([]string, 0, len(cveSet))
	for cve := range cveSet {
		cveIDs = append(cveIDs, cve)
	}
	sort.Strings(cveIDs)

	epss, epssErr := ti.LookupEPSS(ctx, cveIDs)
	if epssErr != nil {
		warnings = append(warnings, fmt.Sprintf(
			"EPSS lookup incomplete; exploitation probability may be missing for some CVEs: %v", epssErr))
	}

	kev, kevErr := ti.LoadKEV(ctx)
	if kevErr != nil {
		warnings = append(warnings, fmt.Sprintf(
			"CISA KEV catalog unavailable; known-exploited status unchecked: %v", kevErr))
	}

	for modPath, modVulns := range results {
		for i := range modVulns {
			v := &modVulns[i]
			cve := CVEAlias(v)
			if cve == "" {
				continue
			}
			if entry, ok := epss[cve]; ok {
				score, percentile := entry.Score, entry.Percentile
				v.EPSSScore = &score
				v.EPSSPercentile = &percentile
				v.EPSSDate = entry.Date
			}
			// A nil kev map means the catalog could not be loaded — leave
			// KEVChecked false so consumers see "not checked", not "not listed".
			if kev != nil {
				v.KEVChecked = true
				if entry, ok := kev[cve]; ok {
					v.InKEV = true
					v.KEVDateAdded = entry.DateAdded
					v.KEVRansomware = entry.KnownRansomwareCampaignUse
				}
			}
		}
		results[modPath] = modVulns
	}

	return warnings
}

// gvcParseOptions carries the toolchain locations needed to normalise
// standard-library frame filenames. The zero value disables the rebase.
type gvcParseOptions struct {
	// scannerGOROOT is the GOROOT of the process running govulncheck.
	scannerGOROOT string
	// projectGOROOT is the GOROOT of the scanned project's toolchain.
	projectGOROOT string
}

// parseGovulncheckJSON parses govulncheck's JSON stream without any standard
// library filename rebasing.
func parseGovulncheckJSON(buf *bytes.Buffer) (map[string][]Vulnerability, error) {
	return parseGovulncheckJSONWithOptions(buf, gvcParseOptions{})
}

// parseGovulncheckJSONWithOptions parses govulncheck's JSON stream. Filenames
// of standard-library trace frames are rebased from opts.scannerGOROOT onto
// opts.projectGOROOT before the call path is condensed; see rebaseStdlibFile.
func parseGovulncheckJSONWithOptions(buf *bytes.Buffer, opts gvcParseOptions) (map[string][]Vulnerability, error) {
	// Collect OSVs and findings.
	osvs := make(map[string]*gvcOSV) // id -> osv
	var findings []gvcFinding
	// roots is the set of scan-root package paths from govulncheck's SBOM
	// message. It stays nil when the stream has none (older govulncheck), which
	// leaves every CallFrame.Project false rather than guessing.
	var roots map[string]bool

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

		// The message key is literally "SBOM". Findings are processed after the
		// whole stream is read, so its position in the stream does not matter.
		if sbomData, ok := raw["SBOM"]; ok {
			var sbom struct {
				Roots []string `json:"roots"`
			}
			if err := json.Unmarshal(sbomData, &sbom); err == nil {
				for _, r := range sbom.Roots {
					if roots == nil {
						roots = make(map[string]bool, len(sbom.Roots))
					}
					roots[r] = true
				}
			}
		}

		if findingData, ok := raw["finding"]; ok {
			var f gvcFinding
			if err := json.Unmarshal(findingData, &f); err == nil && f.OSV != "" {
				for i := range f.Trace {
					t := &f.Trace[i]
					if t.Module == "stdlib" && t.Position != nil {
						t.Position.Filename = rebaseStdlibFile(t.Position.Filename, opts.scannerGOROOT, opts.projectGOROOT)
					}
				}
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
	// calledSinks collects, per "module@osvID", the vulnerable symbol of every
	// called finding. It is sorted, deduplicated and capped once after the loop.
	calledSinks := make(map[string][]string)

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
			if reach == "called" {
				cur := &results[modPath][idx]
				if p, frames := condense(f.Trace, roots); preferCandidate(p, frames, cur.CallPath, cur.CallTrace) {
					cur.CallPath, cur.CallTrace = p, frames
				}
				calledSinks[key] = appendCalledSink(calledSinks[key], f.Trace)
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
		if reach == "called" {
			vuln.CallPath, vuln.CallTrace = condense(f.Trace, roots)
			calledSinks[key] = appendCalledSink(calledSinks[key], f.Trace)
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

	for modPath, vulns := range results {
		for i := range vulns {
			vulns[i].CalledSymbols = capCalledSymbols(calledSinks[modPath+"@"+vulns[i].ID])
		}
	}

	return results, nil
}

// appendCalledSink adds the vulnerable symbol of a called finding's trace (its
// innermost frame) to sinks. A frame without a function name has no symbol to
// report, so it adds nothing.
func appendCalledSink(sinks []string, trace []traceEntry) []string {
	if len(trace) == 0 || trace[0].Function == "" {
		return sinks
	}
	return append(sinks, frameName(trace[0]))
}

// capCalledSymbols sorts and deduplicates sinks and keeps the first
// maxCalledSymbols. Sorting before the cut makes the kept set independent of
// the order govulncheck emitted the findings in. It returns nil for no sinks.
func capCalledSymbols(sinks []string) []string {
	if len(sinks) == 0 {
		return nil
	}
	slices.Sort(sinks)
	sinks = slices.Compact(sinks)
	if len(sinks) > maxCalledSymbols {
		sinks = sinks[:maxCalledSymbols]
	}
	return sinks
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

// severityLookupFailedPrefix opens the enricher's per-advisory failure
// message. Kept in one place so the emitter (vulnenrich.go), the matcher and
// the collapsed summary cannot drift apart silently: rewording the constant
// rewords all three at once.
const severityLookupFailedPrefix = "severity lookup failed (OSV/NVD/GitHub) for "

// severityUnscoredPrefix opens the enricher's per-advisory "no severity
// published yet" message. It is not a failure: every source consulted answered
// and none carried a severity. Kept next to severityLookupFailedPrefix for the same
// reason: emitter, matcher and collapsed summary share one constant.
const severityUnscoredPrefix = "severity not yet published (OSV/NVD/GitHub) for "

// maxListedFailedIDs caps how many advisory IDs the aggregate warning names
// before eliding the rest.
const maxListedFailedIDs = 5

// collapseSeverityLookupWarnings replaces a run of per-advisory
// "severity lookup failed" warnings, and separately a run of per-advisory
// "severity not yet published" warnings, with one summary line each naming the
// count and the first few IDs. Every other warning passes through untouched,
// in order.
//
// A scan of a vulnerability-heavy module produced 21 near-identical lines,
// which buried the warnings that were not repeats. The information is not
// lost: each affected vulnerability keeps its own EnrichmentErrors entry
// (failures) or SeveritySource (unscored), which is what the JSON report
// exposes.
func collapseSeverityLookupWarnings(warnings []string) []string {
	out := collapseWarningGroup(warnings, severityLookupFailedPrefix, "advisories; severities remain UNKNOWN")
	return collapseWarningGroup(out, severityUnscoredPrefix, "advisories; not lookup failures, scored conservatively")
}

// collapseWarningGroup collapses the warnings that start with prefix into one
// summary placed where the group started. The summary is
// prefix + count + " " + tail + " (ids)".
func collapseWarningGroup(warnings []string, prefix, tail string) []string {
	var (
		out      []string
		ids      []string
		seen     = make(map[string]struct{})
		firstMsg string
		insertAt = -1
	)

	for _, w := range warnings {
		if !strings.HasPrefix(w, prefix) {
			out = append(out, w)
			continue
		}
		if insertAt < 0 {
			// Hold the position of the first collapsed warning so the summary
			// lands where the group started rather than at the end, and keep
			// the message itself for the single-warning case below.
			insertAt = len(out)
			firstMsg = w
		}
		id := strings.TrimPrefix(w, prefix)
		if i := strings.Index(id, ";"); i >= 0 {
			id = id[:i]
		}
		// The same advisory can be reported under more than one module —
		// parsing deduplicates by module@osvID, not globally — and the second
		// enrichment hits the cache and re-emits the same warning.
		// Count and list each advisory once so repeats neither inflate the
		// count nor consume the displayed slots. The list is sorted below
		// before anything is truncated or displayed.
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}

	switch len(ids) {
	case 0:
		return out
	case 1:
		// A single warning reads better as itself than as a summary of one.
		// Passed through verbatim rather than rebuilt, so this function owns
		// no second copy of the message the enricher writes.
		return slices.Insert(out, insertAt, firstMsg)
	}

	// ids arrives in the caller's enrichment order (ScanVulns walks modules in
	// sorted path order). Sort by ID anyway before truncating, so the summary —
	// which consumers diff between runs — lists IDs in ID order whatever order
	// the caller uses. GO/CVE IDs sort by year, then number.
	sort.Strings(ids)

	listed := ids
	ellipsis := ""
	if len(listed) > maxListedFailedIDs {
		listed = listed[:maxListedFailedIDs]
		ellipsis = ", …"
	}
	// Built from the shared prefix rather than a second copy of it, so a
	// reword of the constant cannot leave the summary reading the old text
	// while the matcher above still passes.
	summary := fmt.Sprintf(
		"%s%d %s (%s%s)",
		prefix, len(ids), tail, strings.Join(listed, ", "), ellipsis,
	)
	return slices.Insert(out, insertAt, summary)
}
