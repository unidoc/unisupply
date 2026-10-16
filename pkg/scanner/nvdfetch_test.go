package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeNVDServer stands in for the whole network. OSV answers 404, GitHub an
// empty list, and NVD enforces the real unauthenticated limit on the fake
// clock: more than `limit` requests in a rolling 30 s are answered 429. This
// reproduces the failure seen on a 214-module scan, where 14 advisories were
// looked up back to back and most got 429.
type fakeNVDServer struct {
	mu    sync.Mutex
	clock *fakeClock
	limit int
	// body is served with 200 when the request is within the limit.
	body string
	// status, when non-zero, answers every NVD request with it instead.
	status     int
	retryAfter string
	netErr     bool
	hits       []time.Time // fake time of every NVD request
	nvdCalls   int
}

func (f *fakeNVDServer) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mk := func(status int, body string, h http.Header) (*http.Response, error) {
		if h == nil {
			h = make(http.Header)
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: h}, nil
	}
	switch req.URL.Host {
	case osvHost:
		return mk(404, `{"code":5}`, nil)
	case ghsaHost:
		return mk(200, `[]`, nil)
	case nvdHost:
		f.nvdCalls++
		now := f.clock.now()
		if f.netErr {
			return nil, errors.New("connection reset")
		}
		recent := 0
		for _, h := range f.hits {
			if now.Sub(h) < 30*time.Second {
				recent++
			}
		}
		f.hits = append(f.hits, now)
		if f.status != 0 {
			h := make(http.Header)
			if f.retryAfter != "" {
				h.Set("Retry-After", f.retryAfter)
			}
			return mk(f.status, `{}`, h)
		}
		if f.limit > 0 && recent >= f.limit {
			return mk(429, `{}`, nil)
		}
		return mk(200, f.body, nil)
	}
	return nil, errors.New("unexpected host " + req.URL.Host)
}

func newFakeNVDEnricher(t *testing.T, srv *fakeNVDServer, key string, budget time.Duration) *VulnEnricher {
	t.Helper()
	e := NewVulnEnricher(VulnEnricherOptions{
		CacheDir:     t.TempDir(),
		NVDAPIKey:    key,
		EnrichBudget: budget,
		clockFn:      srv.clock.now,
		nvdPacer:     srv.clock.pacer(),
	})
	e.client.Transport = srv
	return e
}

func goAdvisory(i int) *Vulnerability {
	return &Vulnerability{
		ID:       fmt.Sprintf("GO-2026-%04d", 6600+i),
		Aliases:  []string{fmt.Sprintf("CVE-2026-%05d", 78650+i)},
		Severity: "UNKNOWN",
	}
}

func TestNVDPacer_Spacing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		spacing time.Duration
	}{{"keyless", nvdSpacingKeyless}, {"keyed", nvdSpacingKeyed}} {
		t.Run(tc.name, func(t *testing.T) {
			c := newFakeClock()
			p := c.pacer()
			start := c.now()
			for range 6 {
				if !p.wait(context.Background(), tc.spacing, time.Time{}) {
					t.Fatal("wait refused")
				}
			}
			// The first request starts at once, the other five are spaced.
			if got, want := c.now().Sub(start), 5*tc.spacing; got != want {
				t.Errorf("6 requests took %v of fake time, want %v", got, want)
			}
		})
	}
	if nvdSpacingKeyless < 6200*time.Millisecond || nvdSpacingKeyed < 700*time.Millisecond {
		t.Errorf("spacing below the documented minimum: %v %v", nvdSpacingKeyless, nvdSpacingKeyed)
	}
}

// TestVulnEnrich_NVDBatchStaysUnderRateLimit is the replay of the real bug: 14
// advisories with a severity only in NVD, no API key, and an NVD that answers
// 429 beyond 5 requests per 30 s. Every one must resolve to HIGH.
func TestVulnEnrich_NVDBatchStaysUnderRateLimit(t *testing.T) {
	srv := &fakeNVDServer{clock: newFakeClock(), limit: 5, body: string(loadFixture(t, "nvd-CVE-2026-78659.json"))}
	e := newFakeNVDEnricher(t, srv, "", 0)

	var all []string
	for i := range 14 {
		v := goAdvisory(i)
		all = append(all, e.Enrich(context.Background(), v)...)
		if v.Severity != "HIGH" || v.EnrichmentFailed || v.SeveritySource != "nvd" {
			t.Errorf("%s: severity=%q failed=%v source=%q, want HIGH from nvd; errors %v", v.ID, v.Severity, v.EnrichmentFailed, v.SeveritySource, v.EnrichmentErrors)
		}
	}
	if srv.nvdCalls != 14 {
		t.Errorf("NVD requests = %d, want exactly 14 (no 429 retries needed)", srv.nvdCalls)
	}
	for _, w := range collapseSeverityLookupWarnings(all) {
		if strings.Contains(w, "severity could not be looked up") || strings.HasPrefix(w, severityLookupFailedPrefix) {
			t.Errorf("unexpected failure warning: %q", w)
		}
	}
}

// TestVulnEnrich_NVDBatchRetriesThroughRateLimit: even when the pacer is too
// fast for the server (limit 2 per 30 s), retries with backoff get every
// lookup through.
func TestVulnEnrich_NVDBatchRetriesThroughRateLimit(t *testing.T) {
	srv := &fakeNVDServer{clock: newFakeClock(), limit: 2, body: string(loadFixture(t, "nvd-CVE-2026-78659.json"))}
	e := newFakeNVDEnricher(t, srv, "", 10*time.Minute)
	for i := range 4 {
		v := goAdvisory(i)
		e.Enrich(context.Background(), v)
		if v.Severity != "HIGH" {
			t.Errorf("%s: severity=%q (failed=%v %v), want HIGH after retries", v.ID, v.Severity, v.EnrichmentFailed, v.EnrichmentErrors)
		}
	}
	if srv.nvdCalls <= 4 {
		t.Errorf("NVD requests = %d, want > 4: the 429s should have been retried", srv.nvdCalls)
	}
}

func TestVulnEnrich_NVDRetryAfterHonoured(t *testing.T) {
	srv := &fakeNVDServer{clock: newFakeClock(), status: 429, retryAfter: "17"}
	e := newFakeNVDEnricher(t, srv, "", 0)
	v := goAdvisory(0)
	e.Enrich(context.Background(), v)

	if srv.nvdCalls != 1+nvdMaxRetries {
		t.Fatalf("NVD requests = %d, want %d", srv.nvdCalls, 1+nvdMaxRetries)
	}
	for i := 1; i < len(srv.hits); i++ {
		if gap := srv.hits[i].Sub(srv.hits[i-1]); gap < 17*time.Second {
			t.Errorf("gap before retry %d = %v, want >= 17s (Retry-After)", i, gap)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		in     string
		want   time.Duration
		wantOK bool
	}{
		{"", 0, false},
		{"abc", 0, false},
		{"7", 7 * time.Second, true},
		{"0", 0, true},
		{"-5", 0, true},
		{"3600", nvdRetryAfterCap, true},
		{now.Add(25 * time.Second).UTC().Format(http.TimeFormat), 25 * time.Second, true},
		{now.Add(-time.Hour).UTC().Format(http.TimeFormat), 0, true},
		{now.Add(time.Hour).UTC().Format(http.TimeFormat), nvdRetryAfterCap, true},
	} {
		got, ok := parseRetryAfter(tc.in, now)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("parseRetryAfter(%q) = %v,%v want %v,%v", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestVulnEnrich_NVDFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		name        string
		srv         func() *fakeNVDServer
		wantRate    bool
		wantReason  string
		wantPrefix  string
		wantRequest int
	}{
		{"rate limited 429", func() *fakeNVDServer { return &fakeNVDServer{clock: newFakeClock(), status: 429} }, true, "NVD rate limited (HTTP 429)", severityRateLimitedPrefix, 1 + nvdMaxRetries},
		{"forbidden 403", func() *fakeNVDServer { return &fakeNVDServer{clock: newFakeClock(), status: 403} }, true, "NVD rate limited (HTTP 403)", severityRateLimitedPrefix, 1 + nvdMaxRetries},
		{"server error 503", func() *fakeNVDServer { return &fakeNVDServer{clock: newFakeClock(), status: 503} }, false, "NVD HTTP 503", severityLookupFailedPrefix, 1 + nvdMaxRetries},
		{"network error", func() *fakeNVDServer { return &fakeNVDServer{clock: newFakeClock(), netErr: true} }, false, "NVD network error", severityLookupFailedPrefix, 1 + nvdMaxRetries},
		{"client error 400 not retried", func() *fakeNVDServer { return &fakeNVDServer{clock: newFakeClock(), status: 400} }, false, "NVD HTTP 400", severityLookupFailedPrefix, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := tc.srv()
			e := newFakeNVDEnricher(t, srv, "", 0)
			v := goAdvisory(0)
			warns := e.Enrich(context.Background(), v)

			if !v.EnrichmentFailed || v.SeveritySource != "none" || v.Severity != "UNKNOWN" {
				t.Fatalf("failed=%v source=%q severity=%q, want a failure", v.EnrichmentFailed, v.SeveritySource, v.Severity)
			}
			if srv.nvdCalls != tc.wantRequest {
				t.Errorf("NVD requests = %d, want %d", srv.nvdCalls, tc.wantRequest)
			}
			if len(v.EnrichmentErrors) != 1 || !strings.HasPrefix(v.EnrichmentErrors[0], tc.wantPrefix+v.ID) ||
				!strings.Contains(v.EnrichmentErrors[0], tc.wantReason) {
				t.Errorf("EnrichmentErrors = %q, want prefix %q and reason %q", v.EnrichmentErrors, tc.wantPrefix, tc.wantReason)
			}
			// One summary warning for the final outcome, not one per retry.
			nvdWarns := 0
			for _, w := range warns {
				if strings.Contains(w, "NVD returned") || strings.Contains(w, "NVD fetch error") {
					nvdWarns++
				}
			}
			if nvdWarns != 1 {
				t.Errorf("per-request NVD warnings = %d, want 1; %v", nvdWarns, warns)
			}
		})
	}
}

// TestVulnEnrich_NoSeverityStaysUnscored pins the distinction the grade relies
// on: when NVD answers 200 without any metric, that is "nobody published a
// severity", not a failed lookup.
func TestVulnEnrich_NoSeverityStaysUnscored(t *testing.T) {
	srv := &fakeNVDServer{clock: newFakeClock(), body: `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-78650","metrics":{}}}]}`}
	e := newFakeNVDEnricher(t, srv, "", 0)
	v := goAdvisory(0)
	e.Enrich(context.Background(), v)
	if v.EnrichmentFailed || v.SeveritySource != "unscored" || len(v.EnrichmentErrors) != 0 {
		t.Errorf("failed=%v source=%q errors=%v, want unscored and not failed", v.EnrichmentFailed, v.SeveritySource, v.EnrichmentErrors)
	}
}

func TestVulnEnrich_NVDBudgetStopsWaiting(t *testing.T) {
	srv := &fakeNVDServer{clock: newFakeClock(), limit: 1000, body: string(loadFixture(t, "nvd-CVE-2026-78659.json"))}
	budget := 20 * time.Second
	e := newFakeNVDEnricher(t, srv, "", budget)
	start := srv.clock.now()

	resolved, rateLimited := 0, 0
	for i := range 14 {
		v := goAdvisory(i)
		e.Enrich(context.Background(), v)
		switch {
		case v.Severity == "HIGH":
			resolved++
		case v.EnrichmentFailed && strings.HasPrefix(v.EnrichmentErrors[0], severityRateLimitedPrefix):
			rateLimited++
		default:
			t.Errorf("%s: unexpected state severity=%q errors=%v", v.ID, v.Severity, v.EnrichmentErrors)
		}
	}
	// Starts at 0, 6.2, 12.4, 18.6 s are within 20 s; the rest fail without waiting.
	if resolved != 4 || rateLimited != 10 {
		t.Errorf("resolved=%d rateLimited=%d, want 4 and 10", resolved, rateLimited)
	}
	if elapsed := srv.clock.now().Sub(start); elapsed > budget {
		t.Errorf("waited %v, more than the %v budget", elapsed, budget)
	}
	if srv.nvdCalls != 4 {
		t.Errorf("NVD requests = %d, want 4: lookups past the budget must not be sent", srv.nvdCalls)
	}
}

func TestVulnEnrich_DefaultBudget(t *testing.T) {
	e := NewVulnEnricher(VulnEnricherOptions{CacheDir: t.TempDir()})
	if e.budget != 3*time.Minute || DefaultEnrichBudget != 3*time.Minute {
		t.Errorf("default budget = %v, want 3m", e.budget)
	}
}

func TestVulnEnrich_NVDKeyedPacing(t *testing.T) {
	srv := &fakeNVDServer{clock: newFakeClock(), body: string(loadFixture(t, "nvd-CVE-2026-78659.json"))}
	e := newFakeNVDEnricher(t, srv, "k123", 0)
	for i := range 3 {
		e.Enrich(context.Background(), goAdvisory(i))
	}
	if gap := srv.hits[2].Sub(srv.hits[0]); gap != 2*nvdSpacingKeyed {
		t.Errorf("keyed spacing over two gaps = %v, want %v", gap, 2*nvdSpacingKeyed)
	}
}

func TestNVDPickSeverity(t *testing.T) {
	metric := func(src, typ string, score float64) nvdCVSSMetric {
		var m nvdCVSSMetric
		m.Source, m.Type = src, typ
		m.CVSSData.BaseScore = score
		return m
	}
	for _, tc := range []struct {
		name string
		m    nvdMetrics
		want string
	}{
		{"none", nvdMetrics{}, ""},
		{"secondary only", nvdMetrics{CVSSV31: []nvdCVSSMetric{metric("security@golang.org", "Secondary", 7.5)}}, "HIGH"},
		{"primary beats secondary", nvdMetrics{CVSSV31: []nvdCVSSMetric{
			metric("security@golang.org", "Secondary", 9.8), metric("nvd@nist.gov", "Primary", 5.0)}}, "MEDIUM"},
		{"primary v30 beats secondary v31", nvdMetrics{
			CVSSV31: []nvdCVSSMetric{metric("cna", "Secondary", 9.8)},
			CVSSV30: []nvdCVSSMetric{metric("nvd@nist.gov", "Primary", 3.0)}}, "LOW"},
		{"v40 only counts", nvdMetrics{CVSSV40: []nvdCVSSMetric{metric("cna", "Secondary", 8.2)}}, "HIGH"},
		{"v31 before v30 before v40 within a type", nvdMetrics{
			CVSSV40: []nvdCVSSMetric{metric("a", "Secondary", 9.9)},
			CVSSV30: []nvdCVSSMetric{metric("a", "Secondary", 5.0)},
			CVSSV31: []nvdCVSSMetric{metric("a", "Secondary", 7.1)}}, "HIGH"},
		{"unscored metric skipped", nvdMetrics{CVSSV31: []nvdCVSSMetric{
			metric("nvd@nist.gov", "Primary", 0), metric("cna", "Secondary", 7.5)}}, "HIGH"},
	} {
		if got := tc.m.pick(); got != tc.want {
			t.Errorf("%s: pick() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestVulnEnrich_NVDSecondaryMetricFixture: the live record of a fresh Go
// advisory ("Awaiting Analysis", only the CNA's Secondary metric) is HIGH.
func TestVulnEnrich_NVDSecondaryMetricFixture(t *testing.T) {
	srv := &fakeNVDServer{clock: newFakeClock(), body: string(loadFixture(t, "nvd-CVE-2026-78659.json"))}
	e := newFakeNVDEnricher(t, srv, "", 0)
	v := &Vulnerability{ID: "GO-2026-6603", Aliases: []string{"CVE-2026-78659"}, Severity: "UNKNOWN"}
	e.Enrich(context.Background(), v)
	if v.Severity != "HIGH" || v.SeveritySource != "nvd" || v.EnrichmentFailed {
		t.Errorf("severity=%q source=%q failed=%v, want HIGH from nvd", v.Severity, v.SeveritySource, v.EnrichmentFailed)
	}
}

func TestVulnEnrich_RateLimitFailureCachedTwoMinutes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		ttl         time.Duration
		wantRefetch bool
	}{
		{"429 after 3m retried", 429, 3 * time.Minute, true},
		{"429 within 1m cached", 429, time.Minute, false},
		{"503 after 3m still cached", 503, 3 * time.Minute, false},
		{"503 after 61m retried", 503, 61 * time.Minute, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := &fakeNVDServer{clock: newFakeClock(), status: tc.status}
			e := newFakeNVDEnricher(t, srv, "", 0)
			e.Enrich(context.Background(), goAdvisory(0))
			before := srv.nvdCalls

			_ = srv.clock.sleep(context.Background(), tc.ttl)
			e.deadlineMu.Lock()
			e.deadline = time.Time{} // a new scan would have a fresh budget
			e.deadlineMu.Unlock()
			v := goAdvisory(0)
			e.Enrich(context.Background(), v)

			if refetched := srv.nvdCalls > before; refetched != tc.wantRefetch {
				t.Errorf("refetched = %v, want %v", refetched, tc.wantRefetch)
			}
			if !v.EnrichmentFailed || len(v.EnrichmentErrors) != 1 {
				t.Errorf("failed=%v errors=%v", v.EnrichmentFailed, v.EnrichmentErrors)
			}
			wantRate := tc.status == 429
			if got := strings.HasPrefix(v.EnrichmentErrors[0], severityRateLimitedPrefix); got != wantRate {
				t.Errorf("rate-limited message = %v, want %v: %q", got, wantRate, v.EnrichmentErrors[0])
			}
		})
	}
}

func TestVulnEnrich_CachedRateLimitFailureKeepsMessage(t *testing.T) {
	srv := &fakeNVDServer{clock: newFakeClock(), status: 429}
	e := newFakeNVDEnricher(t, srv, "", 0)
	e.Enrich(context.Background(), goAdvisory(0))
	v := goAdvisory(0)
	warns := e.Enrich(context.Background(), v)
	if len(warns) != 1 || !strings.HasPrefix(warns[0], severityRateLimitedPrefix) || !strings.Contains(warns[0], "HTTP 429") {
		t.Errorf("cached failure warning = %q", warns)
	}
}

func TestCollapse_RateLimitText(t *testing.T) {
	var in []string
	for _, id := range []string{"GO-2026-0003", "GO-2026-0001", "GO-2026-0002"} {
		in = append(in, failureMessage(id, true, "NVD rate limited (HTTP 429)"))
	}
	in = append(in, failureMessage("GO-2026-0009", false, "NVD HTTP 503"), failureMessage("GO-2026-0010", false, ""))
	got := collapseSeverityLookupWarnings(in)
	want := []string{
		"severity could not be looked up (NVD rate limit: set NVD_API_KEY) for 3 advisories; severities remain UNKNOWN (GO-2026-0001, GO-2026-0002, GO-2026-0003)",
		"severity lookup failed (OSV/NVD/GitHub) for 2 advisories; severities remain UNKNOWN (GO-2026-0009, GO-2026-0010)",
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("got  %q\nwant %q", got, want)
	}

	one := collapseSeverityLookupWarnings(in[:1])
	if len(one) != 1 || !strings.HasPrefix(one[0], severityRateLimitedPrefix+"GO-2026-0003") {
		t.Errorf("single warning = %q", one)
	}
}
