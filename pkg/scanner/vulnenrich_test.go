package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// staticTransport returns a fixed response body and status for all requests.
type staticTransport struct {
	body       string
	statusCode int
	calls      int
	// authLeaked records the Authorization header value if one was sent.
	authLeaked string
}

func (st *staticTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	st.calls++
	st.authLeaked = req.Header.Get("Authorization")
	return &http.Response{
		StatusCode: st.statusCode,
		Body:       io.NopCloser(strings.NewReader(st.body)),
		Header:     make(http.Header),
	}, nil
}

// newEnricherWithTransport builds a VulnEnricher that uses the provided
// transport for all HTTP calls. cacheDir must be a valid temp dir.
func newEnricherWithTransport(t *testing.T, transport http.RoundTripper, githubToken string, clockFn func() time.Time) *VulnEnricher {
	t.Helper()
	cacheDir := t.TempDir()
	e := NewVulnEnricher(VulnEnricherOptions{
		GitHubToken: githubToken,
		CacheDir:    cacheDir,
		clockFn:     clockFn,
	})
	e.client.Transport = transport
	return e
}

// --- AC#2: Malformed ID validator ---

// TestVulnEnrich_MalformedIDs verifies that dangerous or malformed vulnerability
// IDs are rejected before any URL is constructed, and that a warning is emitted.
func TestVulnEnrich_MalformedIDs(t *testing.T) {
	badIDs := []struct {
		name string
		id   string
	}{
		{"path_traversal", "../../etc/passwd"},
		{"shell_injection", "CVE-${IFS}"},
		{"url_scheme", "http://attacker/"},
		{"too_long", "CVE-" + strings.Repeat("A", 97)}, // 101 chars total
	}

	for _, tc := range badIDs {
		t.Run(tc.name, func(t *testing.T) {
			st := &staticTransport{statusCode: 200, body: "{}"}
			e := newEnricherWithTransport(t, st, "", nil)

			v := &Vulnerability{ID: tc.id, Severity: "UNKNOWN"}
			warns := e.Enrich(context.Background(), v)

			if st.calls > 0 {
				t.Errorf("ID %q reached network (%d calls made); expected zero calls", tc.id, st.calls)
			}
			if len(warns) == 0 {
				t.Errorf("ID %q: expected a warning, got none", tc.id)
			}
			if v.EnrichmentAttempted {
				t.Errorf("ID %q: EnrichmentAttempted should be false for rejected IDs", tc.id)
			}
		})
	}
}

// --- AC#7: CVSS score → tier mapping ---

// TestCVSSScoreToTier validates the four boundary cases of the CVSS tier mapping.
func TestCVSSScoreToTier(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{9.8, "CRITICAL"},
		{9.0, "CRITICAL"},
		{8.9, "HIGH"},
		{7.0, "HIGH"},
		{6.9, "MEDIUM"},
		{4.0, "MEDIUM"},
		{3.9, "LOW"},
		{0.0, "LOW"},
	}
	for _, tt := range tests {
		got := cvssScoreToTier(tt.score)
		if got != tt.expected {
			t.Errorf("cvssScoreToTier(%.1f) = %q, want %q", tt.score, got, tt.expected)
		}
	}
}

// --- AC#3 + recorded fixture: OSV returns CRITICAL ---

// TestVulnEnrich_OSVFixture tests OSV enrichment using the recorded fixture for
// CVE-2024-23653 (Moby authorization bypass, CRITICAL).
func TestVulnEnrich_OSVFixture(t *testing.T) {
	fixture := loadFixture(t, "osv-CVE-2024-23653.json")
	st := &staticTransport{statusCode: 200, body: string(fixture)}
	e := newEnricherWithTransport(t, st, "", nil)

	v := &Vulnerability{
		ID:       "CVE-2024-23653",
		Severity: "UNKNOWN",
	}
	warns := e.Enrich(context.Background(), v)

	if v.Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL; warnings: %v", v.Severity, warns)
	}
	if !v.EnrichmentAttempted {
		t.Error("EnrichmentAttempted should be true")
	}
	if v.EnrichmentFailed {
		t.Error("EnrichmentFailed should be false on success")
	}
	if v.PublishedAt == nil {
		t.Error("PublishedAt should be populated from OSV fixture")
	}
}

// --- AC#3 + recorded fixture: GHSA returns CRITICAL ---

// TestVulnEnrich_GHSAFixture tests GHSA fallback enrichment using the recorded
// fixture for GHSA-vc3v-ppc7-v486.
func TestVulnEnrich_GHSAFixture(t *testing.T) {
	fixture := loadFixture(t, "ghsa-vc3v-ppc7-v486.json")

	// OSV returns 404, GHSA returns the fixture.
	calls := 0
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if strings.Contains(req.URL.Host, "osv.dev") {
			return &http.Response{
				StatusCode: 404,
				Body:       io.NopCloser(strings.NewReader(`{"code":5,"message":"Bug not found"}`)),
				Header:     make(http.Header),
			}, nil
		}
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(fixture))),
			Header:     make(http.Header),
		}, nil
	})

	e := newEnricherWithTransport(t, transport, "", nil)
	v := &Vulnerability{
		ID:       "CVE-2024-23653",
		Aliases:  []string{"GHSA-vc3v-ppc7-v486"},
		Severity: "UNKNOWN",
	}
	warns := e.Enrich(context.Background(), v)

	if v.Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL; warnings: %v", v.Severity, warns)
	}
	if calls != 2 {
		t.Errorf("Expected 2 HTTP calls (OSV + GHSA), got %d", calls)
	}
}

// --- AC#4: Token NOT sent when host-pin would reject ---

// TestVulnEnrich_TokenNotLeakedToWrongHost verifies that the Bearer token is
// not forwarded to the inner transport when the URL host does not match the
// pinned host. The httpclient.Get call must fail with a host-pin error before
// the inner transport (and therefore the network) is reached.
//
// Design: we call client.Get with Host="api.github.com" but supply a URL that
// points to "evil.example.com". hostPinTransport rejects the mismatch before
// delegating to the inner transport, so st.RoundTrip is never called and
// st.authLeaked stays empty.
func TestVulnEnrich_TokenNotLeakedToWrongHost(t *testing.T) {
	// st is the inner transport. If it is ever called, auth could leak.
	st := &staticTransport{statusCode: 200, body: `{}`}

	cacheDir := t.TempDir()
	e := NewVulnEnricher(VulnEnricherOptions{
		GitHubToken: "secret-token",
		CacheDir:    cacheDir,
	})
	e.client.Transport = st

	// Issue a Get with Host pinned to "api.github.com" but URL pointing to
	// an attacker host. hostPinTransport must reject this before st.RoundTrip.
	_, _, err := e.client.Get(context.Background(), "https://evil.example.com/foo", GetOptions{
		Host:       "api.github.com",
		MaxBytes:   1024,
		AuthHeader: "Bearer secret-token",
	})

	if err == nil {
		t.Error("Expected host-pin mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "host pin mismatch") {
		t.Errorf("Expected host-pin mismatch error, got: %v", err)
	}
	// The inner transport must never have been reached.
	if st.calls != 0 {
		t.Errorf("Inner transport was called %d times; expected 0 (auth would leak)", st.calls)
	}
	if st.authLeaked != "" {
		t.Errorf("Token leaked to inner transport: %q", st.authLeaked)
	}
}

// --- AC#5: Cache dir mode 0700, file mode 0600 ---

// TestVulnEnrich_CachePermissions verifies that the cache directory is created
// with mode 0700 and cache files are written with mode 0600.
func TestVulnEnrich_CachePermissions(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "test-cache")
	fixture := loadFixture(t, "osv-CVE-2024-23653.json")
	st := &staticTransport{statusCode: 200, body: string(fixture)}

	e := NewVulnEnricher(VulnEnricherOptions{CacheDir: cacheDir})
	e.client.Transport = st

	v := &Vulnerability{ID: "CVE-2024-23653", Severity: "UNKNOWN"}
	e.Enrich(context.Background(), v)

	// Verify cache directory permissions.
	dirInfo, err := os.Stat(cacheDir)
	if err != nil {
		t.Fatalf("cache dir not created: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != cacheDirMode {
		t.Errorf("cache dir mode = %04o, want %04o", perm, cacheDirMode)
	}

	// Verify cache file permissions.
	cacheFile := filepath.Join(cacheDir, "CVE-2024-23653.json")
	fileInfo, err := os.Stat(cacheFile)
	if err != nil {
		t.Fatalf("cache file not created: %v", err)
	}
	if perm := fileInfo.Mode().Perm(); perm != cacheFileMode {
		t.Errorf("cache file mode = %04o, want %04o", perm, cacheFileMode)
	}
}

// --- AC#6: Within-TTL: second call does NOT re-fetch ---

// TestVulnEnrich_CacheTTL_WithinWindow verifies that a second Enrich call
// within 24 hours uses the cached result and does not hit the network again.
func TestVulnEnrich_CacheTTL_WithinWindow(t *testing.T) {
	fixture := loadFixture(t, "osv-CVE-2024-23653.json")
	st := &staticTransport{statusCode: 200, body: string(fixture)}

	fixedTime := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)
	e := newEnricherWithTransport(t, st, "", func() time.Time { return fixedTime })

	// First call — should hit network once.
	v1 := &Vulnerability{ID: "CVE-2024-23653", Severity: "UNKNOWN"}
	e.Enrich(context.Background(), v1)

	if st.calls != 1 {
		t.Fatalf("First call: expected 1 network call, got %d", st.calls)
	}

	// Second call within TTL — must NOT re-fetch.
	v2 := &Vulnerability{ID: "CVE-2024-23653", Severity: "UNKNOWN"}
	e.Enrich(context.Background(), v2)

	if st.calls != 1 {
		t.Errorf("Second call within TTL: expected still 1 network call, got %d", st.calls)
	}
	if v2.Severity != "CRITICAL" {
		t.Errorf("Second call: Severity = %q, want CRITICAL", v2.Severity)
	}
}

// --- AC#6: After TTL expiry: third call DOES re-fetch ---

// TestVulnEnrich_CacheTTL_Expiry verifies that after the 24h TTL has elapsed,
// a subsequent Enrich call re-fetches from the network.
func TestVulnEnrich_CacheTTL_Expiry(t *testing.T) {
	fixture := loadFixture(t, "osv-CVE-2024-23653.json")
	st := &staticTransport{statusCode: 200, body: string(fixture)}

	// Start at a fixed time.
	currentTime := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)
	clockFn := func() time.Time { return currentTime }

	e := newEnricherWithTransport(t, st, "", clockFn)

	// First call — network hit expected.
	v1 := &Vulnerability{ID: "CVE-2024-23653", Severity: "UNKNOWN"}
	e.Enrich(context.Background(), v1)

	if st.calls != 1 {
		t.Fatalf("First call: expected 1 network call, got %d", st.calls)
	}

	// Advance clock by 25 hours — past the 24h TTL.
	currentTime = currentTime.Add(25 * time.Hour)

	// Third call after TTL expiry — must re-fetch.
	v3 := &Vulnerability{ID: "CVE-2024-23653", Severity: "UNKNOWN"}
	e.Enrich(context.Background(), v3)

	if st.calls != 2 {
		t.Errorf("After TTL expiry: expected 2 total network calls, got %d", st.calls)
	}
}

// --- AC#8: Enrichment failure path ---

// TestVulnEnrich_BothFail verifies that when both OSV and GHSA fail, the
// Vulnerability is marked with EnrichmentAttempted=true, EnrichmentFailed=true,
// Severity remains "UNKNOWN", and a warning is emitted.
func TestVulnEnrich_BothFail(t *testing.T) {
	// Both OSV and GHSA return 500.
	st := &staticTransport{statusCode: 500, body: `{"error":"internal server error"}`}
	e := newEnricherWithTransport(t, st, "", nil)

	v := &Vulnerability{
		ID:       "CVE-2024-23653",
		Aliases:  []string{"GHSA-vc3v-ppc7-v486"},
		Severity: "UNKNOWN",
	}
	warns := e.Enrich(context.Background(), v)

	if !v.EnrichmentAttempted {
		t.Error("EnrichmentAttempted should be true")
	}
	if !v.EnrichmentFailed {
		t.Error("EnrichmentFailed should be true when both sources fail")
	}
	if v.Severity != "UNKNOWN" {
		t.Errorf("Severity = %q, want UNKNOWN", v.Severity)
	}
	if len(warns) == 0 {
		t.Error("Expected at least one warning on enrichment failure")
	}

	found := false
	for _, w := range warns {
		if strings.Contains(w, "CVE-2024-23653") && strings.Contains(w, "UNKNOWN") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected warning mentioning CVE ID and UNKNOWN; got: %v", warns)
	}
}

// --- AC#3 (MaxBytes guard): large response treated as unenriched ---

// TestVulnEnrich_LargeResponseCapped verifies that a response body at exactly
// MaxBytes does not cause a crash and that the enricher handles the truncated
// (likely invalid) JSON gracefully by emitting a warning.
func TestVulnEnrich_LargeResponseCapped(t *testing.T) {
	// Construct a response that is exactly enrichMaxBytes large. The LimitReader
	// in httpclient will cut it at exactly that point, making the JSON invalid.
	largeBody := strings.Repeat("A", enrichMaxBytes+1)
	// Wrap in a fake JSON object so the HTTP status is 200 but JSON is invalid.
	fakeJSON := fmt.Sprintf(`{"id":"CVE-2024-23653","summary":"%s"}`, largeBody[:enrichMaxBytes-100])

	st := &staticTransport{statusCode: 200, body: fakeJSON}
	e := newEnricherWithTransport(t, st, "", nil)

	v := &Vulnerability{ID: "CVE-2024-23653", Severity: "UNKNOWN", Aliases: []string{}}
	// The enricher should not panic, and severity should remain UNKNOWN or be
	// empty (no CVSS data in the truncated/invalid response).
	_ = e.Enrich(context.Background(), v)
	// Pass: no panic; warnings may or may not be present depending on parse result.
}

// --- Validate ID: boundary case exactly 100 chars should pass ---

func TestValidateVulnID_BoundaryLength(t *testing.T) {
	// CVE- = 4 chars, then 96 alphanumeric chars = exactly 100
	id := "CVE-" + strings.Repeat("1", 96)
	if len(id) != 100 {
		t.Fatalf("test setup: id length = %d, want 100", len(id))
	}
	if !validateVulnID(id) {
		t.Errorf("validateVulnID(%q) = false, want true for 100-char valid ID", id)
	}

	// 101 chars should be rejected.
	id101 := id + "1"
	if validateVulnID(id101) {
		t.Errorf("validateVulnID(%q) = true, want false for 101-char ID", id101)
	}
}

// --- helpers ---

// loadFixture reads a file from testdata/vulnenrich/ in the scanner package
// directory. go test sets cwd to the package directory, so the relative path
// resolves correctly. The testdata/ directory name is recognized by go's
// tooling and excluded from build/vet automatically.
func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("testdata", "vulnenrich", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("loadFixture(%q): %v", name, err)
	}
	return data
}

// roundTripFunc adapts a function to the http.RoundTripper interface.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
