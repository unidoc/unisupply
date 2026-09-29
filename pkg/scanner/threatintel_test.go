package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// newThreatIntelWithTransport builds a ThreatIntelClient that uses the
// provided transport for all HTTP calls and a fixed clock.
func newThreatIntelWithTransport(t *testing.T, transport *staticTransport, cacheDir string, clock func() time.Time) *ThreatIntelClient {
	t.Helper()
	ti := NewThreatIntelClient(ThreatIntelOptions{
		CacheDir: cacheDir,
		clockFn:  clock,
	})
	ti.client.Transport = transport
	return ti
}

func fixedClock() time.Time {
	return time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC)
}

func TestLookupEPSS_ParsesStringTypedFloats(t *testing.T) {
	st := &staticTransport{
		statusCode: 200,
		body: `{"data":[
			{"cve":"CVE-2024-0001","epss":"0.97114","percentile":"0.99921","date":"2026-07-10"},
			{"cve":"CVE-2024-0002","epss":"0.00042","percentile":"0.05130","date":"2026-07-10"}
		]}`,
	}
	ti := newThreatIntelWithTransport(t, st, t.TempDir(), fixedClock)

	got, err := ti.LookupEPSS(context.Background(), []string{"CVE-2024-0001", "CVE-2024-0002"})
	if err != nil {
		t.Fatalf("LookupEPSS error: %v", err)
	}
	e1, ok := got["CVE-2024-0001"]
	if !ok {
		t.Fatal("CVE-2024-0001 missing from result")
	}
	if e1.Score != 0.97114 || e1.Percentile != 0.99921 || e1.Date != "2026-07-10" {
		t.Errorf("CVE-2024-0001 = %+v, want score 0.97114 percentile 0.99921", e1)
	}
	if e2 := got["CVE-2024-0002"]; e2.Score != 0.00042 {
		t.Errorf("CVE-2024-0002 score = %v, want 0.00042", e2.Score)
	}
}

func TestLookupEPSS_MalformedScoreSkipped(t *testing.T) {
	st := &staticTransport{
		statusCode: 200,
		body: `{"data":[
			{"cve":"CVE-2024-0003","epss":"not-a-number","percentile":"0.5","date":"2026-07-10"},
			{"cve":"CVE-2024-0004","epss":"1.7","percentile":"0.5","date":"2026-07-10"}
		]}`,
	}
	ti := newThreatIntelWithTransport(t, st, t.TempDir(), fixedClock)

	got, err := ti.LookupEPSS(context.Background(), []string{"CVE-2024-0003", "CVE-2024-0004"})
	if err != nil {
		t.Fatalf("LookupEPSS error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d entries, want 0 (malformed and out-of-range scores rejected)", len(got))
	}
}

func TestLookupEPSS_CacheHitSkipsNetwork(t *testing.T) {
	cacheDir := t.TempDir()
	st := &staticTransport{
		statusCode: 200,
		body:       `{"data":[{"cve":"CVE-2024-0001","epss":"0.5","percentile":"0.9","date":"2026-07-10"}]}`,
	}
	ti := newThreatIntelWithTransport(t, st, cacheDir, fixedClock)
	if _, err := ti.LookupEPSS(context.Background(), []string{"CVE-2024-0001"}); err != nil {
		t.Fatalf("first LookupEPSS error: %v", err)
	}
	if st.calls != 1 {
		t.Fatalf("first lookup made %d calls, want 1", st.calls)
	}

	// Fresh client on the same cache dir: must be served from cache.
	ti2 := newThreatIntelWithTransport(t, st, cacheDir, fixedClock)
	got, err := ti2.LookupEPSS(context.Background(), []string{"CVE-2024-0001"})
	if err != nil {
		t.Fatalf("second LookupEPSS error: %v", err)
	}
	if st.calls != 1 {
		t.Errorf("second lookup made a network call (calls=%d), want cache hit", st.calls)
	}
	if e := got["CVE-2024-0001"]; e.Score != 0.5 {
		t.Errorf("cached score = %v, want 0.5", e.Score)
	}
}

func TestLookupEPSS_CacheExpiresAfterTTL(t *testing.T) {
	cacheDir := t.TempDir()
	st := &staticTransport{
		statusCode: 200,
		body:       `{"data":[{"cve":"CVE-2024-0001","epss":"0.5","percentile":"0.9","date":"2026-07-10"}]}`,
	}
	ti := newThreatIntelWithTransport(t, st, cacheDir, fixedClock)
	if _, err := ti.LookupEPSS(context.Background(), []string{"CVE-2024-0001"}); err != nil {
		t.Fatalf("first LookupEPSS error: %v", err)
	}

	// Advance the clock past the 24h TTL: the entry must be re-fetched.
	lateClock := func() time.Time { return fixedClock().Add(25 * time.Hour) }
	ti2 := newThreatIntelWithTransport(t, st, cacheDir, lateClock)
	if _, err := ti2.LookupEPSS(context.Background(), []string{"CVE-2024-0001"}); err != nil {
		t.Fatalf("second LookupEPSS error: %v", err)
	}
	if st.calls != 2 {
		t.Errorf("calls = %d, want 2 (expired cache entry re-fetched)", st.calls)
	}
}

func TestLookupEPSS_BatchesAt100(t *testing.T) {
	st := &staticTransport{statusCode: 200, body: `{"data":[]}`}
	ti := newThreatIntelWithTransport(t, st, t.TempDir(), fixedClock)

	ids := make([]string, 150)
	for i := range ids {
		ids[i] = fmt.Sprintf("CVE-2024-%04d", i+1)
	}
	if _, err := ti.LookupEPSS(context.Background(), ids); err != nil {
		t.Fatalf("LookupEPSS error: %v", err)
	}
	if st.calls != 2 {
		t.Errorf("calls = %d, want 2 (150 IDs split into batches of 100)", st.calls)
	}
}

func TestLookupEPSS_TransportErrorReturnsError(t *testing.T) {
	st := &staticTransport{statusCode: 500, body: `oops`}
	ti := newThreatIntelWithTransport(t, st, t.TempDir(), fixedClock)

	got, err := ti.LookupEPSS(context.Background(), []string{"CVE-2024-0001"})
	if err == nil {
		t.Fatal("expected error on HTTP 500, got nil")
	}
	if len(got) != 0 {
		t.Errorf("got %d entries, want 0", len(got))
	}
}

func TestLookupEPSS_SkipsNonCVEIDs(t *testing.T) {
	st := &staticTransport{statusCode: 200, body: `{"data":[]}`}
	ti := newThreatIntelWithTransport(t, st, t.TempDir(), fixedClock)

	if _, err := ti.LookupEPSS(context.Background(), []string{"GO-2024-1234", "GHSA-xxxx-yyyy-zzzz"}); err != nil {
		t.Fatalf("LookupEPSS error: %v", err)
	}
	if st.calls != 0 {
		t.Errorf("calls = %d, want 0 (non-CVE IDs never reach the network)", st.calls)
	}
}

const kevTestCatalog = `{
	"catalogVersion": "2026.07.10",
	"vulnerabilities": [
		{"cveID":"CVE-2024-0001","vendorProject":"Example","product":"Widget","dateAdded":"2026-07-01","shortDescription":"RCE","knownRansomwareCampaignUse":"Known"},
		{"cveID":"CVE-2024-0002","vendorProject":"Other","product":"Gadget","dateAdded":"2026-06-15","shortDescription":"Auth bypass","knownRansomwareCampaignUse":"Unknown"}
	]
}`

func TestLoadKEV_ParsesCatalog(t *testing.T) {
	st := &staticTransport{statusCode: 200, body: kevTestCatalog}
	ti := newThreatIntelWithTransport(t, st, t.TempDir(), fixedClock)

	got, err := ti.LoadKEV(context.Background())
	if err != nil {
		t.Fatalf("LoadKEV error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	e := got["CVE-2024-0001"]
	if e.DateAdded != "2026-07-01" || e.KnownRansomwareCampaignUse != "Known" {
		t.Errorf("CVE-2024-0001 = %+v, want dateAdded 2026-07-01, ransomware Known", e)
	}
}

func TestLoadKEV_CacheHitSkipsNetwork(t *testing.T) {
	cacheDir := t.TempDir()
	st := &staticTransport{statusCode: 200, body: kevTestCatalog}
	ti := newThreatIntelWithTransport(t, st, cacheDir, fixedClock)
	if _, err := ti.LoadKEV(context.Background()); err != nil {
		t.Fatalf("first LoadKEV error: %v", err)
	}

	ti2 := newThreatIntelWithTransport(t, st, cacheDir, fixedClock)
	got, err := ti2.LoadKEV(context.Background())
	if err != nil {
		t.Fatalf("second LoadKEV error: %v", err)
	}
	if st.calls != 1 {
		t.Errorf("calls = %d, want 1 (second load served from cache)", st.calls)
	}
	if len(got) != 2 {
		t.Errorf("cached catalog has %d entries, want 2", len(got))
	}
}

func TestLoadKEV_FailureReturnsError(t *testing.T) {
	st := &staticTransport{statusCode: 503, body: `unavailable`}
	ti := newThreatIntelWithTransport(t, st, t.TempDir(), fixedClock)

	got, err := ti.LoadKEV(context.Background())
	if err == nil {
		t.Fatal("expected error on HTTP 503, got nil")
	}
	if got != nil {
		t.Errorf("got non-nil map on failure; callers must see nil = \"status unknown\"")
	}
}

func TestEnrichThreatIntel_PopulatesFields(t *testing.T) {
	// One transport serves both endpoints; distinguish by URL.
	st := &routingTransport{
		epssBody: `{"data":[{"cve":"CVE-2024-0001","epss":"0.85","percentile":"0.99","date":"2026-07-10"}]}`,
		kevBody:  kevTestCatalog,
	}
	ti := NewThreatIntelClient(ThreatIntelOptions{CacheDir: t.TempDir(), clockFn: fixedClock})
	ti.client.Transport = st

	results := map[string][]Vulnerability{
		"github.com/risky/pkg": {
			{ID: "GO-2024-9999", Aliases: []string{"CVE-2024-0001"}, Severity: "HIGH"},
			{ID: "GO-2024-8888", Severity: "MEDIUM"}, // no CVE alias
		},
	}
	warnings := enrichThreatIntel(context.Background(), ti, results)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}

	v := results["github.com/risky/pkg"][0]
	if v.EPSSScore == nil || *v.EPSSScore != 0.85 {
		t.Errorf("EPSSScore = %v, want 0.85", v.EPSSScore)
	}
	if !v.InKEV || !v.KEVChecked || v.KEVDateAdded != "2026-07-01" || v.KEVRansomware != "Known" {
		t.Errorf("KEV fields = InKEV %v KEVChecked %v DateAdded %q Ransomware %q, want true/true/2026-07-01/Known",
			v.InKEV, v.KEVChecked, v.KEVDateAdded, v.KEVRansomware)
	}

	noAlias := results["github.com/risky/pkg"][1]
	if noAlias.EPSSScore != nil || noAlias.KEVChecked {
		t.Errorf("vuln without CVE alias must have no threat-intel data, got EPSS %v KEVChecked %v",
			noAlias.EPSSScore, noAlias.KEVChecked)
	}
}

func TestEnrichThreatIntel_KEVFailureLeavesUnchecked(t *testing.T) {
	st := &routingTransport{
		epssBody:   `{"data":[{"cve":"CVE-2024-0001","epss":"0.85","percentile":"0.99","date":"2026-07-10"}]}`,
		kevBody:    `unavailable`,
		kevStatus:  503,
		epssStatus: 200,
	}
	ti := NewThreatIntelClient(ThreatIntelOptions{CacheDir: t.TempDir(), clockFn: fixedClock})
	ti.client.Transport = st

	results := map[string][]Vulnerability{
		"github.com/risky/pkg": {
			{ID: "CVE-2024-0001", Severity: "HIGH"},
		},
	}
	warnings := enrichThreatIntel(context.Background(), ti, results)

	v := results["github.com/risky/pkg"][0]
	if v.KEVChecked || v.InKEV {
		t.Errorf("KEV fetch failed: KEVChecked/InKEV must stay false, got %v/%v", v.KEVChecked, v.InKEV)
	}
	if v.EPSSScore == nil {
		t.Error("EPSS succeeded and must still populate despite KEV failure")
	}
	foundWarn := false
	for _, w := range warnings {
		if strings.Contains(w, "KEV catalog unavailable") {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Errorf("expected KEV unavailability warning, got %v", warnings)
	}
}

// routingTransport serves different canned responses for the EPSS and KEV
// endpoints based on the request host.
type routingTransport struct {
	epssBody   string
	kevBody    string
	epssStatus int
	kevStatus  int
}

func (rt *routingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, status := rt.epssBody, rt.epssStatus
	if req.URL.Host == kevHost {
		body, status = rt.kevBody, rt.kevStatus
	}
	if status == 0 {
		status = 200
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}, nil
}
