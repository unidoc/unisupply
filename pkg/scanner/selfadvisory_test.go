package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/offline"
)

const selfTestModule = "github.com/example/Lib"

// osvFixture serves /v1/query and records each request body. pages maps a page
// token ("" for the first) to the response; it is looked up by the request's
// page_token.
type osvFixture struct {
	srv      *httptest.Server
	requests []map[string]any
	pages    map[string]string
	status   int
}

func newOSVFixture(t *testing.T, pages map[string]string) *osvFixture {
	t.Helper()
	f := &osvFixture{pages: pages, status: http.StatusOK}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/query" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var req map[string]any
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Errorf("request body is not JSON: %v", err)
		}
		f.requests = append(f.requests, req)
		if f.status != http.StatusOK {
			http.Error(w, "boom", f.status)
			return
		}
		tok, _ := req["page_token"].(string)
		body, ok := f.pages[tok]
		if !ok {
			t.Errorf("no page for token %q", tok)
		}
		io.WriteString(w, body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// quietEnrichers returns options whose severity enricher and threat-intel
// client answer from a stub, never the real network: no severity anywhere, one
// EPSS score for CVE-2026-0002, and a KEV catalog listing the given CVEs.
func quietEnrichers(t *testing.T, base string, kev []string) SelfAdvisoryOptions {
	t.Helper()
	var hosts []string
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		hosts = append(hosts, req.URL.Host)
		body, status := `{}`, 200
		switch req.URL.Host {
		case osvHost:
			status = 404
		case nvdHost:
			body = `{"vulnerabilities":[]}`
		case ghsaHost:
			body = `[]`
		case epssHost:
			body = `{"data":[{"cve":"CVE-2026-0002","epss":"0.5","percentile":"0.9","date":"2026-07-10"}]}`
		case kevHost:
			var entries []string
			for _, c := range kev {
				entries = append(entries, `{"cveID":"`+c+`","dateAdded":"2026-01-02","knownRansomwareCampaignUse":"Known"}`)
			}
			body = `{"vulnerabilities":[` + strings.Join(entries, ",") + `]}`
		default:
			t.Errorf("unexpected host %q: a test must never reach the real network", req.URL.Host)
			status = 500
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})
	enricher := newEnricherWithTransport(t, transport, "", fixedClock)
	ti := newThreatIntelWithTransport(t, &staticTransport{}, t.TempDir(), fixedClock)
	ti.client.Transport = transport
	return SelfAdvisoryOptions{BaseURL: base, Enricher: enricher, ThreatIntel: ti, Now: fixedClock}
}

const selfFullPage = `{"vulns":[
 {"id":"GO-2026-0002","aliases":["CVE-2026-0002","GHSA-aaaa-bbbb-cccc"],"summary":"second",
  "published":"2026-06-01T00:00:00Z","withdrawn":"",
  "database_specific":{"severity":"HIGH"},
  "affected":[
   {"package":{"name":"github.com/example/Lib","ecosystem":"Go"},
    "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.4.0"}]},
              {"type":"SEMVER","events":[{"introduced":"2.0.0"},{"fixed":"2.1.0"}]}],
    "ecosystem_specific":{"imports":[{"path":"github.com/example/Lib/zip"},{"path":"github.com/example/Lib/a"},{"path":"github.com/example/Lib/zip"}]}},
   {"package":{"name":"github.com/other/fork","ecosystem":"Go"},
    "ranges":[{"type":"SEMVER","events":[{"fixed":"9.9.9"}]}],
    "ecosystem_specific":{"imports":[{"path":"github.com/other/fork/x"}]}}]},
 {"id":"GO-2026-0001","summary":"first, no severity, no fix",
  "published":"2026-05-01T00:00:00Z",
  "affected":[{"package":{"name":"github.com/example/Lib","ecosystem":"Go"},
    "ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]},
 {"id":"GO-2026-0003","summary":"withdrawn","withdrawn":"2026-06-02T00:00:00Z",
  "affected":[{"package":{"name":"github.com/example/Lib","ecosystem":"Go"}}]}
]}`

func TestScanModuleAdvisories_MapsRecords(t *testing.T) {
	f := newOSVFixture(t, map[string]string{"": selfFullPage})
	opts := quietEnrichers(t, f.srv.URL, nil)

	got, err := ScanModuleAdvisories(context.Background(), opts, selfTestModule, "v1.2.0")
	if err != nil {
		t.Fatalf("ScanModuleAdvisories: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d vulns, want 2 (withdrawn skipped): %+v", len(got), got)
	}
	if got[0].ID != "GO-2026-0001" || got[1].ID != "GO-2026-0002" {
		t.Fatalf("not sorted by ID: %s, %s", got[0].ID, got[1].ID)
	}

	v := got[1]
	if v.Severity != "HIGH" || v.SeveritySource != "osv" {
		t.Errorf("severity = %q (%q), want HIGH (osv)", v.Severity, v.SeveritySource)
	}
	if v.FixedVersion != "v1.4.0" {
		t.Errorf("FixedVersion = %q, want v1.4.0 (the fix above v1.2.0, not the unrelated 2.1.0 or the fork's 9.9.9)", v.FixedVersion)
	}
	if want := []string{"github.com/example/Lib/a", "github.com/example/Lib/zip"}; !slices.Equal(v.AffectedPackages, want) {
		t.Errorf("AffectedPackages = %v, want %v (sorted, deduplicated, this module only)", v.AffectedPackages, want)
	}
	if v.Summary != "second" || !slices.Equal(v.Aliases, []string{"CVE-2026-0002", "GHSA-aaaa-bbbb-cccc"}) {
		t.Errorf("summary/aliases not copied: %+v", v)
	}
	if v.PublishedAt == nil || v.FixPublishedAt == nil || !v.FixPublishedAt.Equal(*v.PublishedAt) {
		t.Errorf("FixPublishedAt = %v, want the advisory publication date %v", v.FixPublishedAt, v.PublishedAt)
	}
	if want := int(fixedClock().Sub(*v.PublishedAt).Hours() / 24); v.DaysUnpatched != want {
		t.Errorf("DaysUnpatched = %d, want %d", v.DaysUnpatched, want)
	}
	if v.Reachability != "" {
		t.Errorf("Reachability = %q, want empty (the grade assumes the module's own advisories are called)", v.Reachability)
	}
	if v.EPSSScore == nil || *v.EPSSScore != 0.5 {
		t.Errorf("EPSSScore = %v, want 0.5 (threat-intel helper reused)", v.EPSSScore)
	}
	if !v.KEVChecked || v.InKEV {
		t.Errorf("KEVChecked=%v InKEV=%v, want checked and not listed", v.KEVChecked, v.InKEV)
	}

	// No severity published anywhere: stays UNKNOWN, the unscored state, not a failure.
	u := got[0]
	if u.Severity != "UNKNOWN" || u.SeveritySource != "unscored" || u.EnrichmentFailed {
		t.Errorf("unscored advisory = severity %q source %q failed %v, want UNKNOWN/unscored/false", u.Severity, u.SeveritySource, u.EnrichmentFailed)
	}
	if u.FixedVersion != "" || u.FixPublishedAt != nil || u.DaysUnpatched != 0 {
		t.Errorf("no-fix advisory carries fix fields: %+v", u)
	}

	if len(f.requests) != 1 {
		t.Fatalf("%d OSV requests, want 1", len(f.requests))
	}
	req := f.requests[0]
	pkg, _ := req["package"].(map[string]any)
	if req["version"] != "v1.2.0" || pkg["name"] != selfTestModule || pkg["ecosystem"] != "Go" {
		t.Errorf("request = %v, want version v1.2.0 for Go package %s", req, selfTestModule)
	}
}

func TestScanModuleAdvisories_KEVAndCVSSVector(t *testing.T) {
	page := `{"vulns":[{"id":"GHSA-aaaa-bbbb-cccc","aliases":["CVE-2026-0002"],
	 "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
	 "affected":[{"package":{"name":"github.com/example/Lib","ecosystem":"Go"}}]}]}`
	f := newOSVFixture(t, map[string]string{"": page})
	opts := quietEnrichers(t, f.srv.URL, []string{"CVE-2026-0002"})

	got, err := ScanModuleAdvisories(context.Background(), opts, selfTestModule, "v1.2.0")
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
	if got[0].Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL from the CVSS v3 vector", got[0].Severity)
	}
	if !got[0].InKEV || !got[0].KEVChecked || got[0].KEVDateAdded != "2026-01-02" {
		t.Errorf("KEV not applied: %+v", got[0])
	}
}

func TestScanModuleAdvisories_PaginatesAndDeduplicates(t *testing.T) {
	rec := func(id string) string {
		return `{"id":"` + id + `","database_specific":{"severity":"LOW"},"affected":[{"package":{"name":"github.com/example/Lib","ecosystem":"Go"}}]}`
	}
	f := newOSVFixture(t, map[string]string{
		"":   `{"vulns":[` + rec("GO-2026-0001") + `],"next_page_token":"p2"}`,
		"p2": `{"vulns":[` + rec("GO-2026-0001") + `,` + rec("GO-2026-0002") + `]}`,
	})
	got, err := ScanModuleAdvisories(context.Background(), quietEnrichers(t, f.srv.URL, nil), selfTestModule, "v1.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || len(f.requests) != 2 {
		t.Fatalf("%d vulns from %d requests, want 2 from 2", len(got), len(f.requests))
	}
	if f.requests[1]["page_token"] != "p2" || f.requests[1]["version"] != "v1.2.0" {
		t.Errorf("second request = %v, want page_token p2 and the same version", f.requests[1])
	}
}

func TestScanModuleAdvisories_PageCapIsAnError(t *testing.T) {
	// Every page promises another one.
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, `{"vulns":[],"next_page_token":"again"}`)
	}))
	defer srv.Close()

	got, err := ScanModuleAdvisories(context.Background(), quietEnrichers(t, srv.URL, nil), selfTestModule, "v1.2.0")
	if err == nil || got != nil {
		t.Fatalf("got %v, %v; want an error and no list (a truncated list is not an answer)", got, err)
	}
	if int(calls.Load()) != selfAdvisoryMaxPages {
		t.Errorf("%d requests, want the cap of %d", calls.Load(), selfAdvisoryMaxPages)
	}
}

func TestScanModuleAdvisories_EmptyAnswerIsEmptyListNotError(t *testing.T) {
	f := newOSVFixture(t, map[string]string{"": `{}`})
	got, err := ScanModuleAdvisories(context.Background(), quietEnrichers(t, f.srv.URL, nil), selfTestModule, "v1.2.0")
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v; want an empty list and no error", got, err)
	}
}

func TestScanModuleAdvisories_InvalidInputsMakeNoRequest(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer srv.Close()

	cases := []struct{ name, module, version string }{
		{"empty version", selfTestModule, ""},
		{"no v prefix", selfTestModule, "1.2.0"},
		{"not semver", selfTestModule, "latest"},
		{"query injection", selfTestModule, "v1.2.0\"}"},
		{"empty module", "", "v1.2.0"},
		{"bad module", "not a module", "v1.2.0"},
		{"path traversal", "../etc/passwd", "v1.2.0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ScanModuleAdvisories(context.Background(), SelfAdvisoryOptions{BaseURL: srv.URL}, c.module, c.version)
			if err == nil || got != nil {
				t.Errorf("got %v, %v; want an error", got, err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Errorf("%d requests were made for invalid input", calls.Load())
	}
}

func TestScanModuleAdvisories_LookupFailureIsError(t *testing.T) {
	t.Run("http 500", func(t *testing.T) {
		f := newOSVFixture(t, nil)
		f.status = http.StatusInternalServerError
		got, err := ScanModuleAdvisories(context.Background(), SelfAdvisoryOptions{BaseURL: f.srv.URL}, selfTestModule, "v1.2.0")
		if err == nil || got != nil || !strings.Contains(err.Error(), "500") {
			t.Errorf("got %v, %v; want an HTTP 500 error, never an empty list", got, err)
		}
	})
	t.Run("bad json", func(t *testing.T) {
		f := newOSVFixture(t, map[string]string{"": `not json`})
		got, err := ScanModuleAdvisories(context.Background(), SelfAdvisoryOptions{BaseURL: f.srv.URL}, selfTestModule, "v1.2.0")
		if err == nil || got != nil {
			t.Errorf("got %v, %v; want a parse error", got, err)
		}
	})
	t.Run("connection refused", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		url := srv.URL
		srv.Close()
		got, err := ScanModuleAdvisories(context.Background(), SelfAdvisoryOptions{BaseURL: url}, selfTestModule, "v1.2.0")
		if err == nil || got != nil {
			t.Errorf("got %v, %v; want a transport error", got, err)
		}
	})
	t.Run("response over the cap", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"vulns":[{"id":"GO-1","summary":"`)
			io.WriteString(w, strings.Repeat("x", selfAdvisoryMaxBytes+1024))
			io.WriteString(w, `"}]}`)
		}))
		defer srv.Close()
		got, err := ScanModuleAdvisories(context.Background(), SelfAdvisoryOptions{BaseURL: srv.URL}, selfTestModule, "v1.2.0")
		if err == nil || got != nil {
			t.Errorf("got %d vulns, %v; want an error for a truncated body", len(got), err)
		}
	})
}

func TestScanModuleAdvisories_FailedSeverityKeepsMeaning(t *testing.T) {
	page := `{"vulns":[{"id":"GO-2026-0001","aliases":["CVE-2026-0001"],"affected":[{"package":{"name":"github.com/example/Lib","ecosystem":"Go"}}]}]}`
	f := newOSVFixture(t, map[string]string{"": page})
	opts := quietEnrichers(t, f.srv.URL, nil)
	// Every enrichment source is down.
	opts.Enricher.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("down")
	})
	var warnings []string
	opts.OnWarning = func(w string) { warnings = append(warnings, w) }

	got, err := ScanModuleAdvisories(context.Background(), opts, selfTestModule, "v1.2.0")
	if err != nil || len(got) != 1 {
		t.Fatalf("got %v, %v; enrichment failure must not fail the lookup", got, err)
	}
	if got[0].Severity != "UNKNOWN" || !got[0].EnrichmentFailed || got[0].SeveritySource != "none" {
		t.Errorf("severity %q failed=%v source %q, want UNKNOWN / EnrichmentFailed / none", got[0].Severity, got[0].EnrichmentFailed, got[0].SeveritySource)
	}
	if len(warnings) == 0 {
		t.Error("no warning reported for the failed enrichment")
	}
}

func TestScanModuleAdvisories_OfflineDoesNoNetwork(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer srv.Close()

	offline.Enable()
	defer offline.Disable()

	// A client with its own transport bypasses offline's global swap, so only
	// the explicit check in ScanModuleAdvisories can keep it off the wire.
	client := NewClient(ClientOptions{})
	client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, http.ErrNotSupported
	})
	got, err := ScanModuleAdvisories(context.Background(), SelfAdvisoryOptions{BaseURL: srv.URL, Client: client}, selfTestModule, "v1.2.0")
	if !errors.Is(err, offline.ErrOffline) || got != nil {
		t.Fatalf("got %v, %v; want offline.ErrOffline", got, err)
	}
	if calls.Load() != 0 {
		t.Errorf("%d requests in offline mode", calls.Load())
	}
}

func TestScanModuleAdvisories_TimeoutBoundsTheLookup(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	start := time.Now()
	got, err := ScanModuleAdvisories(context.Background(), SelfAdvisoryOptions{BaseURL: srv.URL, Timeout: 100 * time.Millisecond}, selfTestModule, "v1.2.0")
	if err == nil || got != nil {
		t.Fatalf("got %v, %v; want a timeout error", got, err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("lookup took %v despite a 100ms timeout", time.Since(start))
	}
}

func TestFirstFixAfter(t *testing.T) {
	tests := []struct {
		name    string
		fixes   []string
		version string
		want    string
	}{
		{"single", []string{"v1.4.0"}, "v1.2.0", "v1.4.0"},
		{"lowest above", []string{"v2.1.0", "v1.4.0"}, "v1.2.0", "v1.4.0"},
		{"skips below", []string{"v1.0.1", "v2.1.0"}, "v1.2.0", "v2.1.0"},
		{"equal is not a fix", []string{"v1.2.0"}, "v1.2.0", ""},
		{"none", nil, "v1.2.0", ""},
		{"prerelease below release", []string{"v1.3.0"}, "v1.3.0-rc.1", "v1.3.0"},
	}
	for _, tt := range tests {
		if got := firstFixAfter(tt.fixes, tt.version); got != tt.want {
			t.Errorf("%s: firstFixAfter(%v, %s) = %q, want %q", tt.name, tt.fixes, tt.version, got, tt.want)
		}
	}
}
