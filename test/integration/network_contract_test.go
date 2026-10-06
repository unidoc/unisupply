package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/scanner"
)

// The network contract in README.md is a promise to anyone who has to approve
// this tool inside an enterprise: these hosts, this data, nothing else. The
// tests in this file are its enforcement arm. They install a recording
// round-tripper at the same choke point --network-log uses
// (http.DefaultTransport, which every scanner Client delegates to), drive
// every scanner that talks to the network, and compare what was actually
// contacted against the table parsed out of the README.
//
// Hermetic: no request leaves the machine. The recorder notes the intended
// host and then rewrites the request to a local httptest server that serves
// canned responses.

// upstreamHeader carries the originally-intended host from the recorder to the
// stub server, which serves a per-host canned response.
const upstreamHeader = "X-Contract-Upstream-Host"

// undrivenRows lists contract rows this in-process harness cannot exercise,
// each with the reason. Keeping the exemptions here — rather than omitting
// them silently — means a new README row is a test failure until someone
// either drives it or writes down why it cannot be driven.
var undrivenRows = map[string]string{
	"vuln.go.dev": "golang.org/x/vuln resolves the vulnerability database in-process during a " +
		"full govulncheck run, which needs a real buildable module and its module cache. " +
		"Driving it here would test the toolchain, not the contract. Covered instead by " +
		"TestOffline_NoScannerDials (the scan is skipped, not silently attempted) and by " +
		"netlog's host-derived purpose label.",
	"cloud.unidoc.io": "UniPDF's license check, reached only with UNIDOC_LICENSE_API_KEY set and " +
		"--format pdf. Contacting it from a test would require a real license key.",
	"<trust-index-url>": "user-supplied host, opt-in via --trust-index-url. Exercised by " +
		"TestNetworkContract_TrustIndexContactsOnlyConfiguredHost, which asserts the client " +
		"contacts that host and no other.",
}

// rowMatcher identifies one contract row by the request it produces. A host
// with several README rows has several matchers, each of which must fire.
type rowMatcher struct {
	// name is the README row this matcher stands for, short enough to read in
	// a failure message.
	name string

	// match reports whether a recorded request path belongs to this row.
	match func(path string) bool
}

// rowMatchers declares, per documented host, one matcher per README table row.
// Matching on the host alone would let two of the three api.github.com rows
// stop running while a single GitHub request from the third kept the coverage
// assertion green — the paths are what tell the rows apart.
//
// The declared count must equal the number of rows the README carries for that
// host, so adding a row to the table fails here until a matcher is written for
// it. Hosts listed in undrivenRows are exempt and must not appear here.
var rowMatchers = map[string][]rowMatcher{
	"proxy.golang.org": {
		{name: "maintenance and resilience version lookups", match: anyPath},
	},
	"api.github.com": {
		{name: "maintainer scanner (contributor list)", match: hasSuffix("/contributors")},
		{name: "resilience scanner (governance file checks)", match: contains("/contents/")},
		{name: "GHSA severity enrichment", match: hasPrefix("/advisories")},
	},
	"api.osv.dev": {
		{name: "OSV severity enrichment", match: anyPath},
	},
	"services.nvd.nist.gov": {
		{name: "NVD severity enrichment", match: anyPath},
	},
	"api.first.org": {
		{name: "EPSS lookup", match: anyPath},
	},
	"www.cisa.gov": {
		{name: "CISA KEV catalog download", match: anyPath},
	},
}

func anyPath(string) bool { return true }

func hasPrefix(p string) func(string) bool {
	return func(path string) bool { return strings.HasPrefix(path, p) }
}

func hasSuffix(p string) func(string) bool {
	return func(path string) bool { return strings.HasSuffix(path, p) }
}

func contains(p string) func(string) bool {
	return func(path string) bool { return strings.Contains(path, p) }
}

// hostRecorder records the host of every outbound request and then serves it
// from a local stub, so the scan is both observable and hermetic.
type hostRecorder struct {
	mu    sync.Mutex
	hosts map[string]int

	// paths holds every request path seen per host. The host alone cannot
	// distinguish the three api.github.com contract rows from one another;
	// the path can, and TestNetworkContract_NoDeadRows matches on it.
	pathsByHost map[string][]string

	stub     *url.URL
	upstream http.RoundTripper
}

func (r *hostRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()

	r.mu.Lock()
	r.hosts[host]++
	if r.pathsByHost == nil {
		r.pathsByHost = map[string][]string{}
	}
	r.pathsByHost[host] = append(r.pathsByHost[host], req.URL.Path)
	r.mu.Unlock()

	// Rewrite to the stub. The host-pin check in pkg/scanner/httpclient.go has
	// already run against the real host by the time a request reaches
	// http.DefaultTransport, so rewriting here cannot mask a pin failure.
	clone := req.Clone(req.Context())
	clone.Header.Set(upstreamHeader, host)
	clone.URL.Scheme = r.stub.Scheme
	clone.URL.Host = r.stub.Host
	clone.Host = ""

	return r.upstream.RoundTrip(clone)
}

// recorded returns the set of hosts contacted, sorted.
func (r *hostRecorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	hosts := make([]string, 0, len(r.hosts))
	for h := range r.hosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return hosts
}

// paths returns the request paths recorded for host, in the order seen.
func (r *hostRecorder) paths(host string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string(nil), r.pathsByHost[host]...)
}

// stubServer serves canned responses keyed by the intended upstream host. The
// bodies are only as real as they need to be to keep each scanner walking its
// request chain — this suite asserts on hosts contacted, not on scan results.
func stubServer(t *testing.T) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get(upstreamHeader)
		w.Header().Set("Content-Type", "application/json")

		switch host {
		case "proxy.golang.org":
			switch {
			case strings.HasSuffix(r.URL.Path, "/@v/list"):
				w.Header().Set("Content-Type", "text/plain")
				fmt.Fprint(w, "v1.0.0\nv1.0.1\n")
			default: // /@latest and /@v/<version>.info share a shape
				writeJSON(w, map[string]any{
					"Version": "v1.0.1",
					"Time":    "2025-01-02T03:04:05Z",
				})
			}

		case "api.github.com":
			switch {
			case strings.HasPrefix(r.URL.Path, "/advisories"):
				// No advisory for the fixture CVE: the honest empty answer,
				// and the last tier of the enrichment chain.
				writeJSON(w, []any{})
			case strings.HasSuffix(r.URL.Path, "/contributors"):
				writeJSON(w, []map[string]any{
					{"login": "alice", "contributions": 120},
					{"login": "bob", "contributions": 40},
				})
			case strings.Contains(r.URL.Path, "/contents/"):
				// Governance file absent — a 404 here is a normal answer, and
				// the request is what this suite is recording.
				http.NotFound(w, r)
			case strings.HasPrefix(r.URL.Path, "/users/"):
				writeJSON(w, map[string]any{
					"login": "example", "name": "Example Org", "type": "Organization",
				})
			default: // /repos/{owner}/{repo}
				writeJSON(w, map[string]any{
					"full_name":        "example/example",
					"archived":         false,
					"fork":             false,
					"stargazers_count": 1234,
					"pushed_at":        "2025-06-01T00:00:00Z",
					"created_at":       "2015-06-01T00:00:00Z",
					"owner":            map[string]any{"login": "example", "type": "Organization"},
				})
			}

		case "api.osv.dev":
			// Unknown to OSV, so enrichment falls through to NVD and then GHSA
			// — which is how all three enrichment hosts get exercised.
			http.NotFound(w, r)

		case "services.nvd.nist.gov":
			writeJSON(w, map[string]any{"vulnerabilities": []any{}})

		case "api.first.org":
			writeJSON(w, map[string]any{"status": "OK", "data": []any{}})

		case "www.cisa.gov":
			writeJSON(w, map[string]any{"vulnerabilities": []any{}})

		default:
			// A host with no canned response means the harness cannot actually
			// exercise this request chain. Answering with a 500 alone would be
			// silent — scanners treat a non-200 as a warning and move on — and
			// a documented-but-unstubbed host would still satisfy the coverage
			// assertion. Fail the test instead. t.Errorf is safe from the
			// server goroutine.
			t.Errorf("stub has no canned response for upstream host %q (path %s); "+
				"add one, or the coverage assertion passes without exercising the request chain",
				host, r.URL.Path)
			http.Error(w, "stub: unexpected upstream host "+host, http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeJSON(w http.ResponseWriter, v any) {
	_ = json.NewEncoder(w).Encode(v)
}

// enterRecordedNetwork installs the recorder over http.DefaultTransport and
// redirects the on-disk caches to a temp dir. Not parallel-safe: it swaps a
// process global, so no test using it may call t.Parallel.
//
// The cache redirection is load-bearing for the same reason it is in the
// offline suite: the maintainer, vulnenrich, and threatintel caches resolve
// through os.UserCacheDir, so a developer with a warm cache would see a scan
// that contacts nothing and a coverage assertion that fails for the wrong
// reason.
func enterRecordedNetwork(t *testing.T) *hostRecorder {
	t.Helper()

	cacheDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheDir)
	t.Setenv("HOME", cacheDir)

	srv := stubServer(t)
	stubURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parsing stub URL: %v", err)
	}

	rec := &hostRecorder{
		hosts:    map[string]int{},
		stub:     stubURL,
		upstream: srv.Client().Transport,
	}

	original := http.DefaultTransport
	http.DefaultTransport = rec
	t.Cleanup(func() { http.DefaultTransport = original })

	return rec
}

// driveNetworkScanners runs every scanner that issues in-process HTTP requests
// and returns the hosts they contacted. Results are deliberately ignored: the
// contract under test is which hosts are reached, not what is concluded.
func driveNetworkScanners(t *testing.T) *hostRecorder {
	t.Helper()

	rec := enterRecordedNetwork(t)
	graph := fixtureGraph(t)
	ctx := context.Background()
	const timeout = 5 * time.Second

	// proxy.golang.org
	if _, err := scanner.NewMaintenanceScanner(timeout).ScanAll(ctx, graph); err != nil {
		t.Logf("maintenance scan reported %v (stub responses are minimal; hosts contacted is what matters)", err)
	}

	// api.github.com (repo, owner profile, contributors)
	maintainers := scanner.NewMaintainerScanner(timeout, "").ScanAll(ctx, graph)

	// proxy.golang.org + api.github.com (governance files)
	scanner.NewResilienceScanner(timeout).ScanAll(ctx, graph, maintainers)

	// api.osv.dev → services.nvd.nist.gov → api.github.com, in that order:
	// the fixture vuln is unknown to every tier, so the whole chain runs.
	v := &scanner.Vulnerability{
		ID:       "GO-2026-0001",
		Severity: "UNKNOWN",
		Aliases:  []string{"CVE-2026-0001"},
	}
	scanner.NewVulnEnricher(scanner.VulnEnricherOptions{CacheDir: t.TempDir()}).Enrich(ctx, v)

	// api.first.org + www.cisa.gov
	ti := scanner.NewThreatIntelClient(scanner.ThreatIntelOptions{CacheDir: t.TempDir()})
	if _, err := ti.LookupEPSS(ctx, []string{"CVE-2026-0001"}); err != nil {
		t.Logf("EPSS lookup reported %v", err)
	}
	if _, err := ti.LoadKEV(ctx); err != nil {
		t.Logf("KEV load reported %v", err)
	}

	if len(rec.recorded()) == 0 {
		t.Fatal("no hosts recorded; the harness contacted nothing, so every assertion below would pass vacuously")
	}
	return rec
}

// TestNetworkContract_NoUndocumentedHosts is the allowlist direction: every
// host a scanner actually contacts must have a row in the README table.
func TestNetworkContract_NoUndocumentedHosts(t *testing.T) {
	contract := parseNetworkContract(t, readmePath)
	rec := driveNetworkScanners(t)

	for _, host := range rec.recorded() {
		if !contract.has(host) {
			t.Errorf("scanner contacted %q, which has no row in the %q table in README.md.\n"+
				"Either the request is unintended, or the contract needs a row for it — "+
				"the table is what users are asked to trust.", host, contractSection)
		}
	}
}

// TestNetworkContract_NoDeadRows is the coverage direction: every documented
// row must either be exercised by a scanner or carry a written reason it
// cannot be driven here. Coverage is asserted per row, not per host: a host
// with three README rows needs three matchers and all three must fire, so two
// of the three api.github.com request chains cannot quietly stop running
// behind the third. It also fails on stale exemptions and stale matchers, so a
// row removed from the README leaves no orphan entry behind.
func TestNetworkContract_NoDeadRows(t *testing.T) {
	contract := parseNetworkContract(t, readmePath)
	rec := driveNetworkScanners(t)

	for _, host := range contract.Hosts {
		if reason, ok := undrivenRows[host]; ok {
			// undrivenRows is host-keyed, which is sound only while every
			// exempt host has exactly one row. A host that gains a second row
			// while staying undriven needs per-row exemptions instead.
			if n := contract.RowCount[host]; n != 1 {
				t.Errorf("undrivenRows exempts %q by host, but the README carries %d rows for it; "+
					"the exemption must become per-row before the extra rows can be trusted", host, n)
			}
			t.Logf("%s: documented but not driven in-process — %s", host, reason)
			continue
		}

		matchers, ok := rowMatchers[host]
		if !ok {
			t.Errorf("README documents %q but no scanner in this harness contacts it.\n"+
				"Either drive it in driveNetworkScanners and declare its rows in rowMatchers, "+
				"remove the row, or add it to undrivenRows with the reason it cannot be driven.", host)
			continue
		}

		if len(matchers) != contract.RowCount[host] {
			t.Errorf("README carries %d rows for %q but rowMatchers declares %d.\n"+
				"Each row is a distinct operation and needs its own matcher, or the "+
				"coverage assertion passes without exercising it.",
				contract.RowCount[host], host, len(matchers))
			continue
		}

		paths := rec.paths(host)
		for _, m := range matchers {
			hit := false
			for _, path := range paths {
				if m.match(path) {
					hit = true
					break
				}
			}
			if !hit {
				t.Errorf("README row %q (%s) was never exercised; paths recorded for that host: %v.\n"+
					"The request chain for this row is not running — a sibling row on the same "+
					"host firing is not coverage for it.", m.name, host, paths)
			}
		}
	}

	for host := range undrivenRows {
		if !contract.has(host) {
			t.Errorf("undrivenRows exempts %q, which the README no longer documents; remove the exemption", host)
		}
	}

	for host := range rowMatchers {
		if !contract.has(host) {
			t.Errorf("rowMatchers declares rows for %q, which the README no longer documents; remove them", host)
		}
		if _, exempt := undrivenRows[host]; exempt {
			t.Errorf("%q is in both rowMatchers and undrivenRows; a host is either driven or exempt, not both", host)
		}
	}
}

// TestNetworkContract_NeverContactedHostsStayUncontacted guards the other half
// of the promise: the hosts the README says unisupply never calls itself.
func TestNetworkContract_NeverContactedHostsStayUncontacted(t *testing.T) {
	contract := parseNetworkContract(t, readmePath)
	rec := driveNetworkScanners(t)

	contacted := map[string]bool{}
	for _, h := range rec.recorded() {
		contacted[h] = true
	}

	for _, host := range contract.NeverContacted {
		if contacted[host] {
			t.Errorf("README states %q is never contacted directly, but a scanner contacted it", host)
		}
	}
}

// nopTransport answers any request with an empty 204 without dialing. Used by
// the rogue-host test, which deliberately targets a host the stub server has
// no canned response for.
type nopTransport struct{}

func (nopTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

// TestNetworkContract_DetectsRogueHost is the red test kept permanently: it
// proves the allowlist check has teeth, so the assertions above are not
// passing because the comparison is broken.
func TestNetworkContract_DetectsRogueHost(t *testing.T) {
	contract := parseNetworkContract(t, readmePath)

	if contract.has("telemetry.example.com") {
		t.Fatal("fixture host is documented in the README; pick another")
	}

	rec := &hostRecorder{
		hosts:    map[string]int{},
		stub:     &url.URL{Scheme: "http", Host: "stub.invalid"},
		upstream: nopTransport{},
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://telemetry.example.com/beacon", http.NoBody)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	resp, err := rec.RoundTrip(req)
	if err != nil {
		t.Fatalf("rogue request failed before it could be recorded: %v", err)
	}
	_ = resp.Body.Close()

	var flagged []string
	for _, host := range rec.recorded() {
		if !contract.has(host) {
			flagged = append(flagged, host)
		}
	}
	if len(flagged) != 1 || flagged[0] != "telemetry.example.com" {
		t.Errorf("undocumented hosts = %v, want exactly [telemetry.example.com]; "+
			"the allowlist assertion does not detect an undocumented host", flagged)
	}
}

// TestNetworkContract_TrustIndexContactsOnlyConfiguredHost covers the
// `<trust-index-url>` row, which the recorder cannot: the Trust Index client
// pins dial IPs by cloning http.DefaultTransport and uses that clone directly,
// so its traffic never reaches the default transport. The httptest server
// records for itself instead, and the assertion is the one that matters for a
// user-supplied endpoint — the configured host is contacted, and nothing else.
func TestNetworkContract_TrustIndexContactsOnlyConfiguredHost(t *testing.T) {
	var (
		mu    sync.Mutex
		hosts = map[string]int{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hosts[r.Host]++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		writeJSON(w, map[string]any{"results": map[string]any{}})
	}))
	defer srv.Close()

	// allowPrivate: the httptest server is on loopback, which the SSRF guard
	// otherwise rejects.
	client, err := scanner.NewTrustIndexClient(srv.URL, 5*time.Second, true)
	if err != nil {
		t.Fatalf("NewTrustIndexClient: %v", err)
	}
	if client == nil {
		t.Fatal("NewTrustIndexClient returned nil for a non-empty URL")
	}

	if _, err := client.LookupAll(context.Background(), fixtureGraph(t)); err != nil {
		t.Logf("LookupAll reported %v (the stub returns an empty result set)", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(hosts) != 1 {
		t.Fatalf("Trust Index lookup contacted %d hosts (%v), want exactly the configured one", len(hosts), hosts)
	}
	wantHost := strings.TrimPrefix(srv.URL, "http://")
	if hosts[wantHost] == 0 {
		t.Errorf("contacted hosts = %v, want %q", hosts, wantHost)
	}
}
