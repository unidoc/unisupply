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
	ghsaHost          = "api.github.com"
	enrichMaxBytes    = 512 * 1024 // 512 KB per spec
	cacheSubDir       = "unisupply/vuln"
	cacheTTL          = 24 * time.Hour
	cacheFileMode     = 0600
	cacheDirMode      = 0700
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
		applyEnrichResult(v, cached)
		return warnings
	}

	// OSV lookup.
	osvResult, osvWarns := e.fetchOSV(ctx, v.ID)
	warnings = append(warnings, osvWarns...)

	if osvResult != nil && osvResult.Severity != "" {
		e.saveCache(v.ID, osvResult)
		applyEnrichResult(v, osvResult)
		return warnings
	}

	// GHSA fallback: find a GHSA alias in the existing alias list.
	ghsaID := ""
	for _, alias := range v.Aliases {
		if strings.HasPrefix(alias, "GHSA-") {
			ghsaID = alias
			break
		}
	}

	if ghsaID != "" && validateVulnID(ghsaID) {
		ghsaResult, ghsaWarns := e.fetchGHSA(ctx, ghsaID)
		warnings = append(warnings, ghsaWarns...)

		if ghsaResult != nil && ghsaResult.Severity != "" {
			e.saveCache(v.ID, ghsaResult)
			applyEnrichResult(v, ghsaResult)
			return warnings
		}
	}

	// Both paths failed.
	v.EnrichmentFailed = true
	warnings = append(warnings,
		fmt.Sprintf("OSV severity lookup failed for %s; severity remains UNKNOWN", v.ID),
	)
	return warnings
}

// enrichResult holds the data extracted from OSV or GHSA responses.
type enrichResult struct {
	Severity    string     `json:"severity"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
	ModifiedAt  *time.Time `json:"modified_at,omitempty"`
}

// applyEnrichResult copies enrichResult fields into v.
func applyEnrichResult(v *Vulnerability, r *enrichResult) {
	if r.Severity != "" {
		v.Severity = r.Severity
	}
	if r.PublishedAt != nil && v.PublishedAt == nil {
		v.PublishedAt = r.PublishedAt
	}
	// DaysUnpatched: if we have a published time and a FixedVersion,
	// use the published-at as proxy for when the fix shipped.
	// A more precise FixPublishedAt would require a separate API call;
	// this is a conservative approximation used by Task 08.
	if v.FixedVersion != "" && r.PublishedAt != nil && v.FixPublishedAt == nil {
		v.FixPublishedAt = r.PublishedAt
		days := int(time.Since(*r.PublishedAt).Hours() / 24)
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
func (e *VulnEnricher) fetchOSV(ctx context.Context, id string) (*enrichResult, []string) {
	url := "https://api.osv.dev/v1/vulns/" + id
	body, resp, err := e.client.Get(ctx, url, GetOptions{
		Host:     osvHost,
		MaxBytes: enrichMaxBytes,
		Accept:   "application/json",
	})

	var warnings []string
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

	result := &enrichResult{}

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

// ghsaResponse is a partial decode of the GitHub Advisory API response.
type ghsaResponse struct {
	GHSAID string `json:"ghsa_id"`
	CVSSV3 *struct {
		Score float64 `json:"score"`
	} `json:"cvss"`
	Severity    string `json:"severity"` // low/medium/high/critical
	PublishedAt string `json:"published_at"`
	UpdatedAt   string `json:"updated_at"`
}

// fetchGHSA queries https://api.github.com/advisories/{ghsa_id} and returns an
// enrichResult. The GitHub token is injected by the httpclient RoundTripper
// after host-pin validation — not passed in the URL.
func (e *VulnEnricher) fetchGHSA(ctx context.Context, ghsaID string) (*enrichResult, []string) {
	url := "https://api.github.com/advisories/" + ghsaID

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

	var warnings []string
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("vuln enrichment: GHSA fetch error for %s: %v", ghsaID, err))
		return nil, warnings
	}
	if resp.StatusCode != 200 {
		warnings = append(warnings, fmt.Sprintf("vuln enrichment: GHSA returned HTTP %d for %s", resp.StatusCode, ghsaID))
		return nil, warnings
	}

	var ghsa ghsaResponse
	if err := json.Unmarshal(body, &ghsa); err != nil {
		warnings = append(warnings, fmt.Sprintf("vuln enrichment: GHSA JSON parse error for %s: %v", ghsaID, err))
		return nil, warnings
	}

	result := &enrichResult{}

	// Prefer numeric CVSS score for precision.
	if ghsa.CVSSV3 != nil && ghsa.CVSSV3.Score > 0 {
		result.Severity = cvssScoreToTier(ghsa.CVSSV3.Score)
	} else if ghsa.Severity != "" {
		// GitHub also returns a text tier; map it directly.
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

// parseCVSSScore extracts the numeric base score from a CVSS vector string.
// OSV stores CVSS as either a plain number ("7.5") or a full vector string
// ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"). We try a direct parse
// first, then look for the /S: prefix that indicates a vector.
func parseCVSSScore(s string) (float64, bool) {
	// Direct numeric value (some OSV entries use just the score).
	if score, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
		return score, true
	}
	// CVSS vector: the base score is embedded after "CVSS:3.x/" as a
	// separate element in some serializations, but OSV stores the full
	// vector and the caller must parse the score from severity[].score.
	// The actual numeric score for a full CVSS vector requires a CVSS
	// library; since we don't have one, return false and let the caller
	// fall back to database_specific or text tier.
	return 0, false
}

// --- On-disk 24h cache ---

// cacheEntry is what gets written to / read from each cache file.
type cacheEntry struct {
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

	var entry cacheEntry
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

	entry := cacheEntry{
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
