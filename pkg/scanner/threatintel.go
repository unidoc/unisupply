package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	epssHost        = "api.first.org"
	kevHost         = "www.cisa.gov"
	epssURL         = "https://api.first.org/data/v1/epss"
	kevURL          = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	epssCacheSubDir = "unisupply/epss"
	kevCacheSubDir  = "unisupply/kev"
	epssBatchSize   = 100
	epssMaxBytes    = 512 * 1024
	// kevMaxBytes caps the KEV bulk catalog download. The catalog is ~1.5 MB
	// today and grows slowly (~1100 entries); 8 MB leaves years of headroom.
	kevMaxBytes          = 8 * 1024 * 1024
	kevCatalogFile       = "catalog.json"
	threatIntelCacheTTL  = 24 * time.Hour
	threatIntelFallback  = "unisupply-threatintel-cache"
	threatIntelCacheVers = 1
)

// EPSSEntry is the FIRST.org EPSS record for one CVE.
type EPSSEntry struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
	Date       string  `json:"date"`
}

// KEVEntry is one CISA Known Exploited Vulnerabilities catalog record.
type KEVEntry struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"` // "Known" | "Unknown"
}

// ThreatIntelOptions controls construction of a ThreatIntelClient.
type ThreatIntelOptions struct {
	// CacheDir overrides the on-disk cache base directory (epss/ and kev/
	// subdirectories are created under it). Intended for tests. When empty,
	// the client resolves via os.UserCacheDir() with a TempDir() fallback.
	CacheDir string

	// clockFn is the time source for TTL checks. Defaults to time.Now.
	clockFn func() time.Time
}

// ThreatIntelClient looks up EPSS exploitation-probability scores and CISA KEV
// (Known Exploited Vulnerabilities) status for CVE IDs. Both sources are
// best-effort: lookups return partial results plus an error rather than
// failing the scan.
//
// Results are cached on disk for 24 hours (EPSS is recomputed daily; KEV
// updates weekly at most).
type ThreatIntelClient struct {
	client       *Client
	epssCacheDir string
	kevCacheDir  string
	now          func() time.Time
}

// NewThreatIntelClient creates a new ThreatIntelClient. The client is intended
// for serial use: its on-disk cache reads and writes are not synchronized, so
// it is not safe for concurrent use by multiple goroutines.
func NewThreatIntelClient(opts ThreatIntelOptions) *ThreatIntelClient {
	now := opts.clockFn
	if now == nil {
		now = time.Now
	}

	t := &ThreatIntelClient{
		client: NewClient(ClientOptions{Timeout: 10 * time.Second}),
		now:    now,
	}

	if opts.CacheDir != "" {
		t.epssCacheDir = filepath.Join(opts.CacheDir, "epss")
		t.kevCacheDir = filepath.Join(opts.CacheDir, "kev")
		return t
	}
	base, err := os.UserCacheDir()
	if err != nil {
		base = filepath.Join(os.TempDir(), threatIntelFallback)
		t.epssCacheDir = filepath.Join(base, "epss")
		t.kevCacheDir = filepath.Join(base, "kev")
		return t
	}
	t.epssCacheDir = filepath.Join(base, epssCacheSubDir)
	t.kevCacheDir = filepath.Join(base, kevCacheSubDir)
	return t
}

// epssResponse is a partial decode of the FIRST.org EPSS API response.
// Score and percentile are string-typed in the JSON ("0.12345").
type epssResponse struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	} `json:"data"`
}

// LookupEPSS returns EPSS entries for the given CVE IDs, batching up to 100
// IDs per request. IDs that EPSS does not score are simply absent from the
// returned map — that is expected, not an error.
//
// Best-effort: on transport or parse failure the partial result (cache hits
// plus any successful batches) is returned together with a non-nil error the
// caller should surface as a warning. The scan must never fail because EPSS
// was unavailable.
func (t *ThreatIntelClient) LookupEPSS(ctx context.Context, cveIDs []string) (map[string]EPSSEntry, error) {
	result := make(map[string]EPSSEntry)

	// Resolve from cache first; collect the misses for batched fetching.
	var misses []string
	for _, id := range cveIDs {
		if !strings.HasPrefix(id, "CVE-") || !validateVulnID(id) {
			continue
		}
		if entry, ok := t.loadEPSSCache(id); ok {
			if entry != nil {
				result[id] = *entry
			}
			continue
		}
		misses = append(misses, id)
	}

	var firstErr error
	for start := 0; start < len(misses); start += epssBatchSize {
		end := start + epssBatchSize
		if end > len(misses) {
			end = len(misses)
		}
		batch := misses[start:end]

		fetched, err := t.fetchEPSSBatch(ctx, batch)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, id := range batch {
			if entry, ok := fetched[id]; ok {
				result[id] = entry
				t.saveEPSSCache(id, &entry)
			} else {
				// EPSS has no score for this CVE — cache the negative result
				// so repeat scans don't re-query it for 24h.
				t.saveEPSSCache(id, nil)
			}
		}
	}

	return result, firstErr
}

// fetchEPSSBatch queries the EPSS API for one comma-separated batch of CVE IDs.
func (t *ThreatIntelClient) fetchEPSSBatch(ctx context.Context, batch []string) (map[string]EPSSEntry, error) {
	url := epssURL + "?cve=" + strings.Join(batch, ",")
	body, resp, err := t.client.Get(ctx, url, GetOptions{
		Host:     epssHost,
		MaxBytes: epssMaxBytes,
		Accept:   "application/json",
		Purpose:  "threatintel:epss",
	})
	if err != nil {
		return nil, fmt.Errorf("EPSS fetch error: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("EPSS returned HTTP %d", resp.StatusCode)
	}

	var parsed epssResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("EPSS JSON parse error: %w", err)
	}

	entries := make(map[string]EPSSEntry, len(parsed.Data))
	for _, d := range parsed.Data {
		// Score and percentile are string-typed floats; reject malformed or
		// out-of-range values rather than crashing or recording garbage.
		score, err := strconv.ParseFloat(strings.TrimSpace(d.EPSS), 64)
		if err != nil || score < 0 || score > 1 {
			continue
		}
		percentile, err := strconv.ParseFloat(strings.TrimSpace(d.Percentile), 64)
		if err != nil || percentile < 0 || percentile > 1 {
			percentile = 0
		}
		entries[d.CVE] = EPSSEntry{Score: score, Percentile: percentile, Date: d.Date}
	}
	return entries, nil
}

// kevCatalog is a partial decode of the CISA KEV bulk catalog.
type kevCatalog struct {
	CatalogVersion  string     `json:"catalogVersion"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
}

// LoadKEV fetches the CISA Known Exploited Vulnerabilities catalog (one bulk
// JSON, cached 24h) and returns it as a map keyed by CVE ID.
//
// Best-effort: on failure it returns a nil map and a non-nil error the caller
// should surface as a warning. A nil map means "KEV status unknown" — callers
// must not interpret it as "not in KEV".
func (t *ThreatIntelClient) LoadKEV(ctx context.Context) (map[string]KEVEntry, error) {
	if cached, ok := t.loadKEVCache(); ok {
		return cached, nil
	}

	body, resp, err := t.client.Get(ctx, kevURL, GetOptions{
		Host:     kevHost,
		MaxBytes: kevMaxBytes,
		Accept:   "application/json",
		Purpose:  "threatintel:kev",
	})
	if err != nil {
		return nil, fmt.Errorf("KEV catalog fetch error: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("KEV catalog returned HTTP %d", resp.StatusCode)
	}

	var catalog kevCatalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, fmt.Errorf("KEV catalog JSON parse error: %w", err)
	}

	entries := make(map[string]KEVEntry, len(catalog.Vulnerabilities))
	for _, e := range catalog.Vulnerabilities {
		if e.CVEID == "" {
			continue
		}
		entries[e.CVEID] = e
	}

	t.saveKEVCache(entries)
	return entries, nil
}

// --- On-disk 24h caches (same pattern as vulnenrich.go) ---

// epssCacheEntry is the on-disk shape for one cached EPSS lookup. A nil Entry
// records a negative result (EPSS has no score for the CVE).
type epssCacheEntry struct {
	Version   int        `json:"version"`
	FetchedAt time.Time  `json:"fetched_at"`
	Entry     *EPSSEntry `json:"entry"`
}

// kevCacheFile is the on-disk shape for the cached KEV catalog map.
type kevCacheFile struct {
	Version   int                 `json:"version"`
	FetchedAt time.Time           `json:"fetched_at"`
	Entries   map[string]KEVEntry `json:"entries"`
}

// loadEPSSCache returns the cached entry for a CVE ID if present and within
// TTL. The second return value is false on any miss; the first is nil for a
// cached negative result.
func (t *ThreatIntelClient) loadEPSSCache(id string) (*EPSSEntry, bool) {
	data, err := os.ReadFile(filepath.Join(t.epssCacheDir, id+".json"))
	if err != nil {
		return nil, false
	}
	var entry epssCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false
	}
	if entry.Version != threatIntelCacheVers {
		return nil, false
	}
	if t.now().Sub(entry.FetchedAt) > threatIntelCacheTTL {
		return nil, false
	}
	return entry.Entry, true
}

// saveEPSSCache persists an EPSS lookup result (nil = negative) with mode 0600.
func (t *ThreatIntelClient) saveEPSSCache(id string, entry *EPSSEntry) {
	if err := os.MkdirAll(t.epssCacheDir, cacheDirMode); err != nil {
		return
	}
	data, err := json.Marshal(epssCacheEntry{
		Version:   threatIntelCacheVers,
		FetchedAt: t.now(),
		Entry:     entry,
	})
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(t.epssCacheDir, id+".json"), data, cacheFileMode)
}

// loadKEVCache returns the cached KEV catalog map if present and within TTL.
func (t *ThreatIntelClient) loadKEVCache() (map[string]KEVEntry, bool) {
	data, err := os.ReadFile(filepath.Join(t.kevCacheDir, kevCatalogFile))
	if err != nil {
		return nil, false
	}
	var f kevCacheFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, false
	}
	if f.Version != threatIntelCacheVers || f.Entries == nil {
		return nil, false
	}
	if t.now().Sub(f.FetchedAt) > threatIntelCacheTTL {
		return nil, false
	}
	return f.Entries, true
}

// saveKEVCache persists the KEV catalog map with mode 0600.
func (t *ThreatIntelClient) saveKEVCache(entries map[string]KEVEntry) {
	if err := os.MkdirAll(t.kevCacheDir, cacheDirMode); err != nil {
		return
	}
	data, err := json.Marshal(kevCacheFile{
		Version:   threatIntelCacheVers,
		FetchedAt: t.now(),
		Entries:   entries,
	})
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(t.kevCacheDir, kevCatalogFile), data, cacheFileMode)
}
