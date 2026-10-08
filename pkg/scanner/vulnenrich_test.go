package scanner

import (
	"context"
	"errors"
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

// --- AC#3 + recorded fixture: GitHub Advisory returns CRITICAL via CVE lookup ---

// TestVulnEnrich_GHSAFixture tests GitHub Advisory fallback enrichment using
// the recorded fixture for CVE-2024-23653. OSV and NVD fail; GitHub Advisory
// resolves via the ?cve_id= endpoint (array response).
func TestVulnEnrich_GHSAFixture(t *testing.T) {
	arrayFixture := loadFixture(t, "ghsa-CVE-2024-23653-array.json")

	calls := 0
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		host := req.URL.Host
		switch {
		case strings.Contains(host, "osv.dev"):
			return &http.Response{
				StatusCode: 404,
				Body:       io.NopCloser(strings.NewReader(`{"code":5,"message":"Bug not found"}`)),
				Header:     make(http.Header),
			}, nil
		case strings.Contains(host, "nvd.nist.gov"):
			return &http.Response{
				StatusCode: 404,
				Body:       io.NopCloser(strings.NewReader(`{"message":"Not Found"}`)),
				Header:     make(http.Header),
			}, nil
		default: // api.github.com
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(string(arrayFixture))),
				Header:     make(http.Header),
			}, nil
		}
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
	// OSV + OSV alias record (GHSA-vc3v-ppc7-v486, 404) + NVD + GitHub: the
	// alias lookup now runs before NVD.
	if calls != 4 {
		t.Errorf("Expected 4 HTTP calls (OSV + OSV alias + NVD + GitHub), got %d", calls)
	}
}

// TestVulnEnrich_NVDFixture tests that NVD resolves severity when OSV returns
// no data, using the recorded NVD fixture for CVE-2024-23653.
func TestVulnEnrich_NVDFixture(t *testing.T) {
	nvdFixture := loadFixture(t, "nvd-CVE-2024-23653.json")

	calls := 0
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		host := req.URL.Host
		switch {
		case strings.Contains(host, "osv.dev"):
			return &http.Response{
				StatusCode: 404,
				Body:       io.NopCloser(strings.NewReader(`{"code":5,"message":"Bug not found"}`)),
				Header:     make(http.Header),
			}, nil
		case strings.Contains(host, "nvd.nist.gov"):
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(string(nvdFixture))),
				Header:     make(http.Header),
			}, nil
		default:
			t.Error("GitHub Advisory should not be called when NVD succeeds")
			return &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
		}
	})

	e := newEnricherWithTransport(t, transport, "", nil)
	v := &Vulnerability{
		ID:       "CVE-2024-23653",
		Severity: "UNKNOWN",
	}
	warns := e.Enrich(context.Background(), v)

	if v.Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL; warnings: %v", v.Severity, warns)
	}
	if calls != 2 {
		t.Errorf("Expected 2 HTTP calls (OSV + NVD), got %d", calls)
	}
}

// TestVulnEnrichment_OSVFails_NVDSucceeds_HonestSeverity is the table-driven
// regression test covering all four tier combinations: OSV-OK, OSV-fail/NVD-OK,
// OSV-fail/NVD-fail/GitHub-OK, all-fail.
func TestVulnEnrichment_OSVFails_NVDSucceeds_HonestSeverity(t *testing.T) {
	osvFixture := string(loadFixture(t, "osv-CVE-2024-23653.json"))
	nvdFixture := string(loadFixture(t, "nvd-CVE-2024-23653.json"))
	ghFixture := string(loadFixture(t, "ghsa-CVE-2024-23653-array.json"))

	cases := []struct {
		name            string
		osvStatus       int
		nvdStatus       int
		ghStatus        int
		wantSeverity    string
		wantFailed      bool
		wantCallsAtMost int // GitHub is not called if NVD succeeds
	}{
		{
			name:            "OSV_OK",
			osvStatus:       200,
			nvdStatus:       500, // should not be reached
			ghStatus:        500, // should not be reached
			wantSeverity:    "CRITICAL",
			wantFailed:      false,
			wantCallsAtMost: 1,
		},
		{
			name:            "OSV_fail_NVD_OK",
			osvStatus:       404,
			nvdStatus:       200,
			ghStatus:        500, // should not be reached
			wantSeverity:    "CRITICAL",
			wantFailed:      false,
			wantCallsAtMost: 2,
		},
		{
			name:            "OSV_fail_NVD_fail_GitHub_OK",
			osvStatus:       404,
			nvdStatus:       404,
			ghStatus:        200,
			wantSeverity:    "CRITICAL",
			wantFailed:      false,
			wantCallsAtMost: 3,
		},
		{
			name:            "all_fail",
			osvStatus:       500,
			nvdStatus:       500,
			ghStatus:        500,
			wantSeverity:    "UNKNOWN",
			wantFailed:      true,
			wantCallsAtMost: 3,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				host := req.URL.Host
				var status int
				var body string
				switch {
				case strings.Contains(host, "osv.dev"):
					status = tc.osvStatus
					if status == 200 {
						body = osvFixture
					} else {
						body = `{"code":5,"message":"not found"}`
					}
				case strings.Contains(host, "nvd.nist.gov"):
					status = tc.nvdStatus
					if status == 200 {
						body = nvdFixture
					} else {
						body = `{"message":"not found"}`
					}
				default: // github.com
					status = tc.ghStatus
					if status == 200 {
						body = ghFixture
					} else {
						body = `{"message":"internal server error"}`
					}
				}
				return &http.Response{
					StatusCode: status,
					Body:       io.NopCloser(strings.NewReader(body)),
					Header:     make(http.Header),
				}, nil
			})

			e := newEnricherWithTransport(t, transport, "", nil)
			v := &Vulnerability{
				ID:       "CVE-2024-23653",
				Severity: "UNKNOWN",
			}
			warns := e.Enrich(context.Background(), v)

			if v.Severity != tc.wantSeverity {
				t.Errorf("Severity = %q, want %q; warnings: %v", v.Severity, tc.wantSeverity, warns)
			}
			if v.EnrichmentFailed != tc.wantFailed {
				t.Errorf("EnrichmentFailed = %v, want %v", v.EnrichmentFailed, tc.wantFailed)
			}
			if calls > tc.wantCallsAtMost {
				t.Errorf("HTTP calls = %d, want ≤ %d (short-circuit broken)", calls, tc.wantCallsAtMost)
			}
		})
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

// TestVulnEnrich_DaysUnpatched_UsesInjectedClock asserts that DaysUnpatched is
// computed off the enricher's injected clockFn, not wall-clock time.Now. This
// pins the determinism fix from the PR-30 review: a bare time.Since here
// breaks the scan-start determinism invariant (commit a5bcce1).
func TestVulnEnrich_DaysUnpatched_UsesInjectedClock(t *testing.T) {
	// Fixture: published 2024-01-01. Injected "now" = 2024-04-10 → 100 days.
	fixture := loadFixture(t, "osv-CVE-2024-23653.json")
	st := &staticTransport{statusCode: 200, body: string(fixture)}

	frozen := time.Date(2024, 4, 10, 0, 0, 0, 0, time.UTC)
	clockFn := func() time.Time { return frozen }
	e := newEnricherWithTransport(t, st, "", clockFn)

	published := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	v := &Vulnerability{
		ID:           "CVE-2024-23653",
		Severity:     "UNKNOWN",
		FixedVersion: "v25.0.2",
		PublishedAt:  &published,
	}
	// Drive the enrichment path that populates DaysUnpatched via
	// applyEnrichResult. The OSV fixture supplies its own PublishedAt; we
	// pass the same date so the diff is deterministic.
	r := &enrichResult{Severity: "HIGH", PublishedAt: &published}
	e.applyEnrichResult(v, r)

	want := 100
	if v.DaysUnpatched != want {
		t.Errorf("DaysUnpatched = %d (using clockFn=%v, published=%v); want %d",
			v.DaysUnpatched, frozen, published, want)
	}
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

// --- Task 5: Cache durability ---

// TestVulnEnrich_FailureCachedFor1h verifies that a failed enrichment is cached
// for 1h: a second call within 1h makes zero HTTP calls and still reports
// EnrichmentFailed=true with severity UNKNOWN.
func TestVulnEnrich_FailureCachedFor1h(t *testing.T) {
	st := &staticTransport{statusCode: 500, body: `{"error":"internal"}`}

	fixedTime := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)
	e := newEnricherWithTransport(t, st, "", func() time.Time { return fixedTime })

	// First call — all tiers fail, failure gets cached.
	v1 := &Vulnerability{ID: "CVE-2024-23653", Severity: "UNKNOWN"}
	e.Enrich(context.Background(), v1)

	if !v1.EnrichmentFailed {
		t.Fatal("First call: expected EnrichmentFailed=true")
	}
	callsAfterFirst := st.calls

	// Second call at same time — still within 1 h TTL, must serve from failure cache, no HTTP calls.
	v2 := &Vulnerability{ID: "CVE-2024-23653", Severity: "UNKNOWN"}
	e.Enrich(context.Background(), v2)

	if st.calls != callsAfterFirst {
		t.Errorf("Second call within 1h: expected %d total HTTP calls, got %d (cache not used)", callsAfterFirst, st.calls)
	}
	if !v2.EnrichmentFailed {
		t.Error("Second call: EnrichmentFailed should still be true from cached failure")
	}
	if v2.Severity != "UNKNOWN" {
		t.Errorf("Second call: Severity = %q, want UNKNOWN", v2.Severity)
	}
}

// TestVulnEnrich_FailureCacheTTL_Expiry verifies that a cached failure expires
// after 1h (not 24h), and the enricher re-fetches on the next call.
func TestVulnEnrich_FailureCacheTTL_Expiry(t *testing.T) {
	st := &staticTransport{statusCode: 500, body: `{"error":"internal"}`}

	currentTime := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)
	clockFn := func() time.Time { return currentTime }
	e := newEnricherWithTransport(t, st, "", clockFn)

	// First call — failure cached.
	v1 := &Vulnerability{ID: "CVE-2024-23653", Severity: "UNKNOWN"}
	e.Enrich(context.Background(), v1)
	callsAfterFirst := st.calls

	// Advance 2 hours — past 1h failure TTL.
	currentTime = currentTime.Add(2 * time.Hour)

	// Second call after failure TTL expiry — must re-fetch.
	v2 := &Vulnerability{ID: "CVE-2024-23653", Severity: "UNKNOWN"}
	e.Enrich(context.Background(), v2)

	if st.calls <= callsAfterFirst {
		t.Errorf("After failure TTL expiry: expected more HTTP calls than %d, got %d", callsAfterFirst, st.calls)
	}
}

// TestVulnEnrich_CacheVersionMismatch verifies that an on-disk cache entry with
// a different version is treated as a miss and triggers a fresh network lookup.
func TestVulnEnrich_CacheVersionMismatch(t *testing.T) {
	fixture := loadFixture(t, "osv-CVE-2024-23653.json")

	fixedTime := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)

	// Write an old-version cache entry manually.
	cacheDir := t.TempDir()
	oldEntry := `{"version":0,"fetched_at":"2024-03-01T12:00:00Z","result":{"severity":"HIGH","source":"osv"}}`
	cacheFile := filepath.Join(cacheDir, "CVE-2024-23653.json")
	if err := os.WriteFile(cacheFile, []byte(oldEntry), 0o600); err != nil {
		t.Fatal(err)
	}

	st := &staticTransport{statusCode: 200, body: string(fixture)}
	e := NewVulnEnricher(VulnEnricherOptions{
		CacheDir: cacheDir,
		clockFn:  func() time.Time { return fixedTime },
	})
	e.client.Transport = st

	v := &Vulnerability{ID: "CVE-2024-23653", Severity: "UNKNOWN"}
	e.Enrich(context.Background(), v)

	// The old-version entry must have been treated as a miss → network call made.
	if st.calls == 0 {
		t.Error("Expected network call due to cache version mismatch; got 0 calls")
	}
	// And result from the live call is used.
	if v.Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL after version-mismatch re-fetch", v.Severity)
	}
}

// TestVulnEnrich_NoUNKNOWNDisplayedAsLOW verifies the golden invariant: no CVE
// with UNKNOWN severity produces "LOW" in the text report. The cached-failure
// path is exercised here (second call uses the 1h-cached failure), ensuring the
// display is correct even when enrichment results come from cache.
func TestVulnEnrich_NoUNKNOWNDisplayedAsLOW(t *testing.T) {
	st := &staticTransport{statusCode: 500, body: `{"error":"internal"}`}
	fixedTime := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)
	e := newEnricherWithTransport(t, st, "", func() time.Time { return fixedTime })

	// First call — all tiers fail; failure cached.
	v1 := &Vulnerability{ID: "CVE-2024-99999", Severity: "UNKNOWN"}
	e.Enrich(context.Background(), v1)

	// Second call — served from 1h failure cache.
	v2 := &Vulnerability{ID: "CVE-2024-99999", Severity: "UNKNOWN"}
	e.Enrich(context.Background(), v2)

	// Neither the live nor the cached path should produce "LOW".
	for _, v := range []*Vulnerability{v1, v2} {
		if strings.EqualFold(v.Severity, "LOW") {
			t.Errorf("CVE %s: Severity = %q — UNKNOWN must not be displayed as LOW", v.ID, v.Severity)
		}
		if !v.EnrichmentFailed {
			t.Errorf("CVE %s: EnrichmentFailed should be true", v.ID)
		}
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

// --- Alias cache ---

func TestAliasCache_RoundTrip(t *testing.T) {
	e := newEnricherWithTransport(t, &staticTransport{}, "", func() time.Time {
		return time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	})
	e.saveAliasCache("GHSA-aaaa-bbbb-cccc", "HIGH")
	sev, hit := e.loadAliasCache("GHSA-aaaa-bbbb-cccc")
	if !hit || sev != "HIGH" {
		t.Errorf("loadAliasCache = (%q, %v), want (HIGH, true)", sev, hit)
	}
	if _, hit := e.loadAliasCache("GHSA-other"); hit {
		t.Error("unexpected hit for an alias that was never saved")
	}
}

func TestAliasCache_Expiry(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	e := newEnricherWithTransport(t, &staticTransport{}, "", func() time.Time { return now })
	e.saveAliasCache("CVE-2026-1", "HIGH")

	now = now.Add(23 * time.Hour)
	if _, hit := e.loadAliasCache("CVE-2026-1"); !hit {
		t.Error("entry should still be fresh after 23h")
	}
	now = now.Add(2 * time.Hour)
	if _, hit := e.loadAliasCache("CVE-2026-1"); hit {
		t.Error("entry should have expired after 25h")
	}
}

func TestAliasCache_EmptySeverityIsHit(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	e := newEnricherWithTransport(t, &staticTransport{}, "", func() time.Time { return now })
	e.saveAliasCache("CVE-2026-2", "")

	// Well past the 1h failure TTL but inside 24h.
	now = now.Add(5 * time.Hour)
	sev, hit := e.loadAliasCache("CVE-2026-2")
	if !hit || sev != "" {
		t.Errorf("loadAliasCache = (%q, %v), want (empty, true)", sev, hit)
	}
}

func TestAliasCache_Permissions(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "alias-cache")
	e := NewVulnEnricher(VulnEnricherOptions{CacheDir: cacheDir})
	e.saveAliasCache("CVE-2026-3", "LOW")

	info, err := os.Stat(filepath.Join(cacheDir, "osv-CVE-2026-3.json"))
	if err != nil {
		t.Fatalf("alias cache file not created: %v", err)
	}
	if perm := info.Mode().Perm(); perm != cacheFileMode {
		t.Errorf("alias cache file mode = %04o, want %04o", perm, cacheFileMode)
	}
	dirInfo, err := os.Stat(cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != cacheDirMode {
		t.Errorf("cache dir mode = %04o, want %04o", perm, cacheDirMode)
	}
}

// --- Alias lookup and unscored state ---

// aliasTransport serves OSV records from a path-to-body map (404 when absent),
// fails NVD and GitHub with a network error, and counts requests.
type aliasTransport struct {
	osv       map[string]string
	osvStatus map[string]int // overrides for specific IDs
	osvPaths  []string
	nvdCalls  int
	ghsaCalls int
	failEvery bool
	// nvd and ghsa, when set, answer that host with the given status and
	// body; when nil the host is unreachable (transport error).
	nvd  *stubAnswer
	ghsa *stubAnswer
}

type stubAnswer struct {
	status int
	body   string
}

func (s *stubAnswer) response() (*http.Response, error) {
	if s == nil {
		return nil, errors.New("unreachable")
	}
	return &http.Response{StatusCode: s.status, Body: io.NopCloser(strings.NewReader(s.body)), Header: make(http.Header)}, nil
}

func (a *aliasTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if a.failEvery {
		return nil, errors.New("unreachable")
	}
	switch req.URL.Host {
	case osvHost:
		id := strings.TrimPrefix(req.URL.Path, "/v1/vulns/")
		a.osvPaths = append(a.osvPaths, id)
		status, body := 404, `{"code":5,"message":"not found"}`
		if b, ok := a.osv[id]; ok {
			status, body = 200, b
		}
		if st, ok := a.osvStatus[id]; ok {
			status, body = st, `{"error":"x"}`
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	case nvdHost:
		a.nvdCalls++
		return a.nvd.response()
	case ghsaHost:
		a.ghsaCalls++
		return a.ghsa.response()
	}
	return nil, errors.New("unreachable")
}

func (a *aliasTransport) countOSV(id string) int {
	n := 0
	for _, p := range a.osvPaths {
		if p == id {
			n++
		}
	}
	return n
}

func osvFixtures(t *testing.T, ids ...string) map[string]string {
	t.Helper()
	m := make(map[string]string, len(ids))
	for _, id := range ids {
		m[id] = string(loadFixture(t, "osv-"+id+".json"))
	}
	return m
}

func TestVulnEnrich_GHSAAliasResolves(t *testing.T) {
	tr := &aliasTransport{osv: osvFixtures(t, "GO-2026-5005", "GHSA-jppx-rxg9-jmrx")}
	e := newEnricherWithTransport(t, tr, "", nil)

	v := &Vulnerability{ID: "GO-2026-5005", Aliases: []string{"CVE-2026-39833", "GHSA-jppx-rxg9-jmrx"}, Severity: "UNKNOWN"}
	e.Enrich(context.Background(), v)

	if v.Severity != "CRITICAL" || v.SeveritySource != "osv" || v.SeverityAlias != "GHSA-jppx-rxg9-jmrx" {
		t.Errorf("got severity=%q source=%q alias=%q", v.Severity, v.SeveritySource, v.SeverityAlias)
	}
	if tr.nvdCalls != 0 || tr.ghsaCalls != 0 {
		t.Errorf("NVD calls=%d GitHub calls=%d, want 0 and 0", tr.nvdCalls, tr.ghsaCalls)
	}
	if n := tr.countOSV("CVE-2026-39833"); n != 0 {
		t.Errorf("OSV requests for the CVE alias = %d, want 0 (GHSA wins first)", n)
	}
}

func TestVulnEnrich_CVEAliasVectorResolves(t *testing.T) {
	tr := &aliasTransport{osv: osvFixtures(t, "GO-2026-4918", "CVE-2026-33814")}
	e := newEnricherWithTransport(t, tr, "", nil)

	v := &Vulnerability{ID: "GO-2026-4918", Aliases: []string{"CVE-2026-33814"}, Severity: "UNKNOWN"}
	e.Enrich(context.Background(), v)

	if v.Severity != "HIGH" || v.SeveritySource != "osv" || v.SeverityAlias != "CVE-2026-33814" {
		t.Errorf("got severity=%q source=%q alias=%q", v.Severity, v.SeveritySource, v.SeverityAlias)
	}
	if v.PublishedAt == nil {
		t.Error("PublishedAt should be carried over from the primary OSV record")
	}
}

func TestVulnEnrich_NoAliasesUnscored(t *testing.T) {
	tr := &aliasTransport{osv: osvFixtures(t, "GO-2026-5932")}
	e := newEnricherWithTransport(t, tr, "", nil)

	v := &Vulnerability{ID: "GO-2026-5932", Severity: "UNKNOWN"}
	warns := e.Enrich(context.Background(), v)

	assertUnscored(t, v, warns)
}

// nvdNoData and ghsaNoData are authoritative "no record" answers.
var (
	nvdNoData  = &stubAnswer{200, `{"totalResults":0,"vulnerabilities":[]}`}
	ghsaNoData = &stubAnswer{200, `[]`}
)

func TestVulnEnrich_CVEAliasNoSeverityUnscored(t *testing.T) {
	// CVE-2026-46604 is a 404 on OSV (recorded: the API answers 404 with an
	// alias hint), so it is absent from the map. NVD and GitHub both answer
	// that they have no record, so nothing is published anywhere.
	tr := &aliasTransport{osv: osvFixtures(t, "GO-2026-5066"), nvd: nvdNoData, ghsa: ghsaNoData}
	e := newEnricherWithTransport(t, tr, "", nil)

	v := &Vulnerability{ID: "GO-2026-5066", Aliases: []string{"CVE-2026-46604"}, Severity: "UNKNOWN"}
	warns := e.Enrich(context.Background(), v)

	assertUnscored(t, v, warns)
	if tr.nvdCalls != 1 || tr.ghsaCalls != 1 {
		t.Errorf("NVD calls=%d GitHub calls=%d, want 1 and 1", tr.nvdCalls, tr.ghsaCalls)
	}
}

// TestVulnEnrich_FallbackErrorStaysFailed covers the case seen live for
// GO-2026-4559: OSV has no severity, but NVD was rate limited although it
// publishes one. A tier that did not answer may have missed a published
// severity, so the advisory is a lookup failure, never "unscored".
func TestVulnEnrich_FallbackErrorStaysFailed(t *testing.T) {
	cases := []struct {
		name string
		nvd  *stubAnswer
		ghsa *stubAnswer
	}{
		{"NVD 429, GitHub no data", &stubAnswer{429, ``}, ghsaNoData},
		{"NVD no data, GitHub 403", nvdNoData, &stubAnswer{403, `{"message":"rate limited"}`}},
		{"NVD 503, GitHub no data", &stubAnswer{503, ``}, ghsaNoData},
		{"NVD malformed JSON, GitHub no data", &stubAnswer{200, `{`}, ghsaNoData},
		{"both unreachable", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &aliasTransport{osv: osvFixtures(t, "GO-2026-5066"), nvd: tc.nvd, ghsa: tc.ghsa}
			e := newEnricherWithTransport(t, tr, "", nil)

			v := &Vulnerability{ID: "GO-2026-5066", Aliases: []string{"CVE-2026-46604"}, Severity: "UNKNOWN"}
			warns := e.Enrich(context.Background(), v)

			if !v.EnrichmentFailed || v.SeveritySource != "none" {
				t.Errorf("EnrichmentFailed=%v SeveritySource=%q, want true and none", v.EnrichmentFailed, v.SeveritySource)
			}
			for _, w := range warns {
				if strings.HasPrefix(w, severityUnscoredPrefix) {
					t.Errorf("unexpected unscored warning: %q", w)
				}
			}
		})
	}
}

func assertUnscored(t *testing.T, v *Vulnerability, warns []string) {
	t.Helper()
	if v.SeveritySource != "unscored" {
		t.Errorf("SeveritySource = %q, want unscored", v.SeveritySource)
	}
	if v.EnrichmentFailed {
		t.Error("EnrichmentFailed must be false for an unscored advisory")
	}
	if v.Severity != "UNKNOWN" {
		t.Errorf("Severity = %q, want UNKNOWN", v.Severity)
	}
	if len(v.EnrichmentErrors) != 0 {
		t.Errorf("EnrichmentErrors = %v, want empty", v.EnrichmentErrors)
	}
	found := false
	for _, w := range warns {
		if strings.HasPrefix(w, severityUnscoredPrefix) {
			found = true
		}
		if strings.HasPrefix(w, severityLookupFailedPrefix) {
			t.Errorf("unexpected failure warning: %q", w)
		}
	}
	if !found {
		t.Errorf("no warning with prefix %q in %v", severityUnscoredPrefix, warns)
	}
}

func TestVulnEnrich_OSVErrorStaysFailed(t *testing.T) {
	tr := &aliasTransport{
		osv:       osvFixtures(t, "GO-2026-5066"),
		osvStatus: map[string]int{"CVE-2026-46604": 503},
	}
	e := newEnricherWithTransport(t, tr, "", nil)

	v := &Vulnerability{ID: "GO-2026-5066", Aliases: []string{"CVE-2026-46604"}, Severity: "UNKNOWN"}
	e.Enrich(context.Background(), v)

	if !v.EnrichmentFailed || v.SeveritySource != "none" {
		t.Errorf("EnrichmentFailed=%v SeveritySource=%q, want true and none", v.EnrichmentFailed, v.SeveritySource)
	}
}

func TestVulnEnrich_UnscoredCachedPath(t *testing.T) {
	tr := &aliasTransport{osv: osvFixtures(t, "GO-2026-5932")}
	e := newEnricherWithTransport(t, tr, "", func() time.Time {
		return time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	})

	v1 := &Vulnerability{ID: "GO-2026-5932", Severity: "UNKNOWN"}
	e.Enrich(context.Background(), v1)
	if v1.SeveritySource != "unscored" {
		t.Fatalf("first call: SeveritySource = %q", v1.SeveritySource)
	}

	e.client.Transport = &aliasTransport{failEvery: true}
	v2 := &Vulnerability{ID: "GO-2026-5932", Severity: "UNKNOWN"}
	warns := e.Enrich(context.Background(), v2)
	assertUnscored(t, v2, warns)
}

func TestVulnEnrich_AliasCacheShared(t *testing.T) {
	tr := &aliasTransport{osv: osvFixtures(t, "CVE-2026-33814")}
	e := newEnricherWithTransport(t, tr, "", nil)

	for _, id := range []string{"GO-2026-4918", "GO-2026-4961"} {
		v := &Vulnerability{ID: id, Aliases: []string{"CVE-2026-33814"}, Severity: "UNKNOWN"}
		e.Enrich(context.Background(), v)
		if v.Severity != "HIGH" {
			t.Errorf("%s: Severity = %q, want HIGH", id, v.Severity)
		}
	}
	if n := tr.countOSV("CVE-2026-33814"); n != 1 {
		t.Errorf("OSV requests for the shared CVE = %d, want 1", n)
	}
}

func TestVulnEnrich_AliasLookupCap(t *testing.T) {
	tr := &aliasTransport{}
	e := newEnricherWithTransport(t, tr, "", nil)

	v := &Vulnerability{
		ID: "GO-2026-9999",
		Aliases: []string{
			"GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb", "GHSA-cccc-cccc-cccc",
			"GHSA-dddd-dddd-dddd", "GHSA-eeee-eeee-eeee", "GHSA-ffff-ffff-ffff",
		},
		Severity: "UNKNOWN",
	}
	e.Enrich(context.Background(), v)

	aliasReqs := 0
	for _, p := range tr.osvPaths {
		if strings.HasPrefix(p, "GHSA-") {
			aliasReqs++
		}
	}
	if aliasReqs != maxAliasLookups {
		t.Errorf("alias requests = %d, want %d", aliasReqs, maxAliasLookups)
	}
}
