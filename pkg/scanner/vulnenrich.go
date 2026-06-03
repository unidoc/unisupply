package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	osvHost           = "api.osv.dev"
	nvdHost           = "services.nvd.nist.gov"
	ghsaHost          = "api.github.com"
	enrichMaxBytes    = 512 * 1024 // 512 KB per spec
	cacheSubDir       = "unisupply/vuln"
	cacheTTL          = 24 * time.Hour
	cacheFileMode     = 0o600
	cacheDirMode      = 0o700
	cacheFallbackBase = "unisupply-vuln-cache"
)

// vulnIDPattern enforces the allowed character set for vulnerability IDs.
// Accepted prefixes: GO, CVE, GHSA. Only alphanumerics plus [._-] are allowed
// after the prefix-separator, which prevents path traversal and shell injection.
var vulnIDPattern = regexp.MustCompile(`^(GO|CVE|GHSA)-[A-Za-z0-9._-]+$`)

// VulnEnricherOptions controls construction of a VulnEnricher.
type VulnEnricherOptions struct {
	// GitHubToken is forwarded as a Bearer token to api.github.com only.
	// Empty means unauthenticated (OSV does not require auth; GHSA fallback
	// still works but is rate-limited).
	GitHubToken string

	// CacheDir overrides the on-disk cache location. Intended for tests.
	// When empty, the enricher resolves the path via os.UserCacheDir() with
	// a TempDir() fallback.
	CacheDir string

	// clockFn is the time source for TTL checks. Defaults to time.Now.
	// Tests inject a fake to advance the clock without sleeping.
	clockFn func() time.Time
}

// VulnEnricher enriches Vulnerability records whose severity is UNKNOWN by
// querying OSV.dev and, when necessary, the GitHub Advisory API.
//
// Results are cached on disk for 24 hours to avoid hammering the APIs on
// repeated scans of the same project.
type VulnEnricher struct {
	client   *Client
	opts     VulnEnricherOptions
	cacheDir string
	now      func() time.Time
}

// NewVulnEnricher creates a new VulnEnricher. The returned enricher is safe
// for concurrent use by multiple goroutines.
func NewVulnEnricher(opts VulnEnricherOptions) *VulnEnricher {
	now := opts.clockFn
	if now == nil {
		now = time.Now
	}

	e := &VulnEnricher{
		client: NewClient(ClientOptions{Timeout: 10 * time.Second}),
		opts:   opts,
		now:    now,
	}
	e.cacheDir = e.resolveCache(opts.CacheDir)
	return e
}

// resolveCache returns the effective cache directory path and, if forced to use
// the TempDir fallback, records a warning (deferred to the Enrich call site via
// the returned warnings slice). The dir is created lazily on first write.
func (e *VulnEnricher) resolveCache(override string) string {
	if override != "" {
		return override
	}
	base, err := os.UserCacheDir()
	if err == nil {
		return filepath.Join(base, cacheSubDir)
	}
	return filepath.Join(os.TempDir(), cacheFallbackBase)
}

// usingFallbackCache reports whether the enricher is using the TempDir-based
// fallback cache (i.e., os.UserCacheDir() was unavailable at construction time).
func (e *VulnEnricher) usingFallbackCache() bool {
	if e.opts.CacheDir != "" {
		return false
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return true
	}
	return e.cacheDir == filepath.Join(os.TempDir(), cacheFallbackBase) &&
		e.cacheDir != filepath.Join(base, cacheSubDir)
}

// Enrich attempts to resolve the CVSS severity for v if v.Severity is empty or
// "UNKNOWN". It returns any warnings generated (cache fallback, ID rejection,
// network failures). The Vulnerability is mutated in place.
func (e *VulnEnricher) Enrich(ctx context.Context, v *Vulnerability) []string {
	var warnings []string

	if e.usingFallbackCache() {
		warnings = append(warnings,
			fmt.Sprintf("vuln enrichment: os.UserCacheDir() unavailable; using TempDir fallback cache at %s", e.cacheDir),
		)
	}

	// Only enrich when severity is absent or UNKNOWN.
	if v.Severity != "" && v.Severity != "UNKNOWN" {
		return warnings
	}

	if !validateVulnID(v.ID) {
		warnings = append(warnings,
			fmt.Sprintf("vuln enrichment: rejected malformed ID %q; severity remains UNKNOWN", v.ID),
		)
		return warnings
	}

	v.EnrichmentAttempted = true

	// Try cache first.
	if cached, ok := e.loadCache(v.ID); ok {
		e.applyEnrichResult(v, cached)
		return warnings
	}

	// OSV lookup.
	osvResult, osvWarns := e.fetchOSV(ctx, v.ID)
	warnings = append(warnings, osvWarns...)

	if osvResult != nil && osvResult.Severity != "" {
		e.saveCache(v.ID, osvResult)
		e.applyEnrichResult(v, osvResult)
		return warnings
	}

	// Find a CVE alias for NVD and GitHub Advisory lookups.
	// The ID itself may be a CVE (govulncheck sometimes uses CVE as primary ID),
	// or a CVE alias may appear in v.Aliases (always present for Go advisories).
	cveID := ""
	if strings.HasPrefix(v.ID, "CVE-") {
		cveID = v.ID
	} else {
		for _, alias := range v.Aliases {
			if strings.HasPrefix(alias, "CVE-") && validateVulnID(alias) {
				cveID = alias
				break
			}
		}
	}

	if cveID != "" {
		// NVD lookup (canonical CVSS authority for CVEs).
		nvdResult, nvdWarns := e.fetchNVD(ctx, cveID)
		warnings = append(warnings, nvdWarns...)

		if nvdResult != nil && nvdResult.Severity != "" {
			e.saveCache(v.ID, nvdResult)
			e.applyEnrichResult(v, nvdResult)
			return warnings
		}

		// GitHub Advisory lookup by CVE ID (?cve_id= endpoint).
		// Covers advisories that have no GHSA alias yet (fresh GO-2026-xxxx).
		ghsaResult, ghsaWarns := e.fetchGHSAByCVE(ctx, cveID)
		warnings = append(warnings, ghsaWarns...)

		if ghsaResult != nil && ghsaResult.Severity != "" {
			e.saveCache(v.ID, ghsaResult)
			e.applyEnrichResult(v, ghsaResult)
			return warnings
		}
	}

	// All tiers failed.
	v.EnrichmentFailed = true
	warnings = append(warnings,
		fmt.Sprintf("severity lookup failed (OSV/NVD/GitHub) for %s; severity remains UNKNOWN", v.ID),
	)
	return warnings
}

// enrichResult holds the data extracted from OSV or GHSA responses.
type enrichResult struct {
	Severity    string     `json:"severity"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
	ModifiedAt  *time.Time `json:"modified_at,omitempty"`
}

// applyEnrichResult copies enrichResult fields into v. DaysUnpatched is
// computed from e.now() rather than time.Now so it uses the same clock as the
// cache TTL check (deterministic under injected fakes — required by the
// scan-start determinism invariant in commit a5bcce1).
func (e *VulnEnricher) applyEnrichResult(v *Vulnerability, r *enrichResult) {
	if r.Severity != "" {
		v.Severity = r.Severity
	}
	if r.PublishedAt != nil && v.PublishedAt == nil {
		v.PublishedAt = r.PublishedAt
	}
	// FixPublishedAt is approximated from the advisory's publication date
	// (OSV/GHSA `published`), NOT the actual fix release timestamp. The OSV
	// schema records the fixed version (`affected[].ranges[].events[fixed]`)
	// but not when that version shipped; deriving the real fix-publication
	// time would require a separate module-proxy `@v/<ver>.info` lookup per
	// CVE. For most CVEs the advisory is published close to the fix release,
	// so the proxy is within days — acceptable for the day-quantized
	// thresholds in lowFixAgeFloor (30/180/365). Renaming the field would
	// break downstream JSON consumers; the misnomer is preserved with this
	// docstring acting as the authoritative caveat.
	if v.FixedVersion != "" && r.PublishedAt != nil && v.FixPublishedAt == nil {
		v.FixPublishedAt = r.PublishedAt
		days := int(e.now().Sub(*r.PublishedAt).Hours() / 24)
		if days < 0 {
			days = 0
		}
		v.DaysUnpatched = days
	}
}

// validateVulnID returns true when id matches the allowed pattern AND its
// length is ≤ 100 characters. Both checks are required; the length cap
// bounds URL size even for IDs that pass the charset test.
func validateVulnID(id string) bool {
	if len(id) > 100 {
		return false
	}
	return vulnIDPattern.MatchString(id)
}

// osvResponse is a partial decode of the OSV API vulnerability object.
// Only fields needed for severity enrichment are captured.
type osvResponse struct {
	ID        string `json:"id"`
	Published string `json:"published"`
	Modified  string `json:"modified"`
	// severity is an array of CVSS entries in the OSV schema v1.3+
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	// database_specific carries severity in the Go vuln DB schema.
	DatabaseSpecific *struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// fetchOSV queries https://api.osv.dev/v1/vulns/{id} and returns an
// enrichResult. It returns (nil, warnings) on any non-2xx or parse failure
// without hard-erroring — the caller falls back to GHSA.
func (e *VulnEnricher) fetchOSV(ctx context.Context, id string) (result *enrichResult, warnings []string) {
	url := "https://api.osv.dev/v1/vulns/" + id
	body, resp, err := e.client.Get(ctx, url, GetOptions{
		Host:     osvHost,
		MaxBytes: enrichMaxBytes,
		Accept:   "application/json",
	})

	if err != nil {
		warnings = append(warnings, fmt.Sprintf("vuln enrichment: OSV fetch error for %s: %v", id, err))
		return nil, warnings
	}
	if resp.StatusCode != 200 {
		warnings = append(warnings, fmt.Sprintf("vuln enrichment: OSV returned HTTP %d for %s", resp.StatusCode, id))
		return nil, warnings
	}

	var osv osvResponse
	if err := json.Unmarshal(body, &osv); err != nil {
		warnings = append(warnings, fmt.Sprintf("vuln enrichment: OSV JSON parse error for %s: %v", id, err))
		return nil, warnings
	}

	result = &enrichResult{}

	// Prefer database_specific.severity (Go vuln DB convention).
	if osv.DatabaseSpecific != nil && osv.DatabaseSpecific.Severity != "" {
		result.Severity = cvssStringToTier(osv.DatabaseSpecific.Severity)
	}

	// Fall through to severity[].score if database_specific didn't have it.
	if result.Severity == "" {
		for _, s := range osv.Severity {
			if score, ok := parseCVSSScore(s.Score); ok {
				result.Severity = cvssScoreToTier(score)
				break
			}
		}
	}

	if osv.Published != "" {
		if t, err := time.Parse(time.RFC3339, osv.Published); err == nil {
			result.PublishedAt = &t
		}
	}
	if osv.Modified != "" {
		if t, err := time.Parse(time.RFC3339, osv.Modified); err == nil {
			result.ModifiedAt = &t
		}
	}

	return result, warnings
}

// ghsaResponse is a partial decode of a single GitHub Advisory API record.
type ghsaResponse struct {
	GHSAID string `json:"ghsa_id"`
	CVSSV3 *struct {
		Score float64 `json:"score"`
	} `json:"cvss"`
	Severity    string `json:"severity"` // low/medium/high/critical
	PublishedAt string `json:"published_at"`
	UpdatedAt   string `json:"updated_at"`
}

// nvdCVSSMetric is one entry in the NVD CVE metrics array (v3.1 or v3.0).
type nvdCVSSMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

// nvdResponse is a partial decode of the NVD CVE 2.0 API response.
type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			Published string `json:"published"`
			Metrics   struct {
				CVSSV31 []nvdCVSSMetric `json:"cvssMetricV31"`
				CVSSV30 []nvdCVSSMetric `json:"cvssMetricV30"`
			} `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// fetchNVD queries https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id>
// and returns an enrichResult. Returns (nil, warnings) on network or parse
// failure; returns (&enrichResult{}, nil) when NVD has no data for the CVE.
func (e *VulnEnricher) fetchNVD(ctx context.Context, cveID string) (result *enrichResult, warnings []string) {
	url := "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cveID
	body, resp, err := e.client.Get(ctx, url, GetOptions{
		Host:     nvdHost,
		MaxBytes: enrichMaxBytes,
		Accept:   "application/json",
	})
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("vuln enrichment: NVD fetch error for %s: %v", cveID, err))
		return nil, warnings
	}
	if resp.StatusCode != 200 {
		warnings = append(warnings, fmt.Sprintf("vuln enrichment: NVD returned HTTP %d for %s", resp.StatusCode, cveID))
		return nil, warnings
	}

	var nvd nvdResponse
	if err := json.Unmarshal(body, &nvd); err != nil {
		warnings = append(warnings, fmt.Sprintf("vuln enrichment: NVD JSON parse error for %s: %v", cveID, err))
		return nil, warnings
	}
	if nvd.TotalResults == 0 || len(nvd.Vulnerabilities) == 0 {
		return &enrichResult{}, nil
	}

	cveData := nvd.Vulnerabilities[0].CVE
	result = &enrichResult{}

	// Prefer CVSS v3.1; fall back to v3.0 when v3.1 metrics are absent.
	metrics := cveData.Metrics.CVSSV31
	if len(metrics) == 0 {
		metrics = cveData.Metrics.CVSSV30
	}
	if len(metrics) > 0 {
		m := metrics[0]
		if m.CVSSData.BaseScore > 0 {
			result.Severity = cvssScoreToTier(m.CVSSData.BaseScore)
		} else if m.CVSSData.BaseSeverity != "" {
			result.Severity = cvssStringToTier(m.CVSSData.BaseSeverity)
		}
	}

	if cveData.Published != "" {
		if t, err := time.Parse("2006-01-02T15:04:05.999", cveData.Published); err == nil {
			result.PublishedAt = &t
		}
	}

	return result, warnings
}

// fetchGHSAByCVE queries https://api.github.com/advisories?cve_id=<cveID> and
// returns an enrichResult from the first matching advisory. Returns
// (&enrichResult{}, nil) when no advisory is found (empty array response).
// The GitHub token is injected by the httpclient RoundTripper after host-pin
// validation — not passed in the URL.
func (e *VulnEnricher) fetchGHSAByCVE(ctx context.Context, cveID string) (result *enrichResult, warnings []string) {
	url := "https://api.github.com/advisories?cve_id=" + cveID

	authHeader := ""
	if e.opts.GitHubToken != "" {
		authHeader = "Bearer " + e.opts.GitHubToken
	}

	body, resp, err := e.client.Get(ctx, url, GetOptions{
		Host:       ghsaHost,
		MaxBytes:   enrichMaxBytes,
		AuthHeader: authHeader,
		Accept:     "application/vnd.github+json",
	})
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("vuln enrichment: GitHub Advisory fetch error for %s: %v", cveID, err))
		return nil, warnings
	}
	if resp.StatusCode != 200 {
		warnings = append(warnings, fmt.Sprintf("vuln enrichment: GitHub Advisory returned HTTP %d for %s", resp.StatusCode, cveID))
		return nil, warnings
	}

	var advisories []ghsaResponse
	if err := json.Unmarshal(body, &advisories); err != nil {
		warnings = append(warnings, fmt.Sprintf("vuln enrichment: GitHub Advisory JSON parse error for %s: %v", cveID, err))
		return nil, warnings
	}
	if len(advisories) == 0 {
		return &enrichResult{}, nil
	}

	ghsa := advisories[0]
	result = &enrichResult{}

	// Prefer numeric CVSS score for precision.
	if ghsa.CVSSV3 != nil && ghsa.CVSSV3.Score > 0 {
		result.Severity = cvssScoreToTier(ghsa.CVSSV3.Score)
	} else if ghsa.Severity != "" {
		result.Severity = strings.ToUpper(ghsa.Severity)
	}

	if ghsa.PublishedAt != "" {
		if t, err := time.Parse(time.RFC3339, ghsa.PublishedAt); err == nil {
			result.PublishedAt = &t
		}
	}

	return result, warnings
}

// cvssStringToTier maps the Go vuln DB text severity labels to canonical tiers.
// The Go vuln DB uses text labels (HIGH, MEDIUM, etc.) rather than numeric CVSS.
func cvssStringToTier(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM", "MODERATE":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return ""
	}
}

// cvssScoreToTier maps a numeric CVSS v3 base score to a severity tier per the
// CVSS v3.1 specification:
//
//	9.0–10.0  CRITICAL
//	7.0–8.9   HIGH
//	4.0–6.9   MEDIUM
//	0.1–3.9   LOW
func cvssScoreToTier(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// parseCVSSScore extracts a numeric CVSS base score from the string OSV
// stores under severity[].score. OSV permits two shapes:
//
//   - A bare base score ("7.5") — handled here.
//   - A full CVSS vector ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") —
//     NOT handled here. The base score is not encoded in the vector; it must
//     be computed from the impact and exploitability sub-metrics using the
//     CVSS v3.1 formula (https://www.first.org/cvss/v3.1/specification-document).
//     Implementing that formula requires either a CVSS library (none currently
//     vendored) or ~80 lines of math we have deliberately not added.
//
// When the input is a vector, parseCVSSScore returns (0, false). The caller
// falls back to OSV's database_specific.severity (text tier) or to the GHSA
// advisory's numeric CVSS score, both of which already carry the same
// information for nearly all Go-ecosystem advisories.
func parseCVSSScore(s string) (float64, bool) {
	// Direct numeric value (some OSV entries use just the score).
	if score, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
		return score, true
	}
	return 0, false
}

// --- On-disk 24h cache ---

// vulnCacheEntry is what gets written to / read from each vulnerability cache file.
type vulnCacheEntry struct {
	FetchedAt time.Time     `json:"fetched_at"`
	Result    *enrichResult `json:"result"`
}

// cacheFilePath returns the path for a given vulnerability ID.
// The ID has already been validated, so it only contains safe characters.
func (e *VulnEnricher) cacheFilePath(id string) string {
	return filepath.Join(e.cacheDir, id+".json")
}

// ensureCacheDir creates the cache directory with mode 0700 if it does not
// already exist.
func (e *VulnEnricher) ensureCacheDir() error {
	return os.MkdirAll(e.cacheDir, cacheDirMode)
}

// loadCache returns a cached enrichResult if one exists and is still within the
// 24h TTL. Returns (nil, false) on any miss or error.
func (e *VulnEnricher) loadCache(id string) (*enrichResult, bool) {
	path := e.cacheFilePath(id)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	var entry vulnCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false
	}

	if e.now().Sub(entry.FetchedAt) > cacheTTL {
		return nil, false
	}

	return entry.Result, true
}

// saveCache persists an enrichResult to disk with mode 0600.
func (e *VulnEnricher) saveCache(id string, result *enrichResult) {
	if err := e.ensureCacheDir(); err != nil {
		return
	}

	entry := vulnCacheEntry{
		FetchedAt: e.now(),
		Result:    result,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	path := e.cacheFilePath(id)
	// Write with mode 0600 — cache files may contain API response data.
	_ = os.WriteFile(path, data, cacheFileMode)
}
