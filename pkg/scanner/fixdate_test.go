package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/offline"
)

func ptrTime(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return &t
}

// proxyFixture serves <path>/@v/<version>.info from a map keyed by the
// requested URL path (escaped form), and counts requests per path.
type proxyFixture struct {
	srv   *httptest.Server
	mu    sync.Mutex
	hits  map[string]int
	times map[string]string // path -> Time; absent = 404, "410" = Gone, "bad" = junk body
	live  atomic.Int32
	peak  atomic.Int32
	delay time.Duration
}

func newProxyFixture(t *testing.T, times map[string]string) *proxyFixture {
	t.Helper()
	f := &proxyFixture{hits: map[string]int{}, times: times}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := f.live.Add(1)
		defer f.live.Add(-1)
		for {
			p := f.peak.Load()
			if n <= p || f.peak.CompareAndSwap(p, n) {
				break
			}
		}
		if f.delay > 0 {
			select {
			case <-time.After(f.delay):
			case <-r.Context().Done():
			}
		}
		f.mu.Lock()
		f.hits[r.URL.Path]++
		f.mu.Unlock()
		ts, ok := f.times[r.URL.Path]
		switch {
		case !ok:
			http.NotFound(w, r)
		case ts == "410":
			http.Error(w, "gone", http.StatusGone)
		case ts == "bad":
			w.Write([]byte("<html>"))
		case ts == "notime":
			w.Write([]byte(`{"Version":"v1.4.0"}`))
		default:
			w.Write([]byte(`{"Version":"v1.4.0","Time":"` + ts + `"}`))
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *proxyFixture) opts() FixDateOptions {
	return FixDateOptions{ProxyURL: f.srv.URL, clockFn: fixedClock}
}

// Module path with an upper-case letter: the proxy wants it escaped.
const fixTestPath = "/github.com/!example/!lib/@v/"

func TestResolveFixDates_LaterOfAdvisoryAndProxy(t *testing.T) {
	f := newProxyFixture(t, map[string]string{
		fixTestPath + "v1.4.0.info": "2026-06-10T00:00:00Z", // after the advisory
		fixTestPath + "v1.5.0.info": "2026-05-01T00:00:00Z", // before the advisory
		fixTestPath + "v1.6.0.info": "2026-06-01T12:00:00Z", // equal
	})
	vulns := []Vulnerability{
		{ID: "A", FixedVersion: "v1.4.0", FixPublishedAt: ptrTime("2026-06-01T12:00:00Z")},
		{ID: "B", FixedVersion: "1.5.0", FixPublishedAt: ptrTime("2026-06-01T12:00:00Z")}, // OSV spelling, no v
		{ID: "C", FixedVersion: "v1.6.0", FixPublishedAt: ptrTime("2026-06-01T12:00:00Z")},
	}
	ResolveFixDates(context.Background(), f.opts(), "github.com/Example/Lib", vulns)

	want := []struct{ at, src string }{
		{"2026-06-10T00:00:00Z", "module_proxy"},
		{"2026-06-01T12:00:00Z", "advisory"},
		{"2026-06-01T12:00:00Z", "module_proxy"}, // proxy later or equal
	}
	for i, w := range want {
		v := vulns[i]
		if v.FixReleasedAt == nil || !v.FixReleasedAt.Equal(*ptrTime(w.at)) || v.FixDateSource != w.src {
			t.Errorf("%s: FixReleasedAt=%v source=%q, want %s %q", v.ID, v.FixReleasedAt, v.FixDateSource, w.at, w.src)
		}
	}
	// DaysUnpatched counts from the release, not the advisory.
	if want := int(fixedClock().Sub(*ptrTime("2026-06-10T00:00:00Z")).Hours() / 24); vulns[0].DaysUnpatched != want {
		t.Errorf("DaysUnpatched = %d, want %d (from FixReleasedAt)", vulns[0].DaysUnpatched, want)
	}
}

func TestResolveFixDates_FailuresFallBackNeverInvent(t *testing.T) {
	f := newProxyFixture(t, map[string]string{
		fixTestPath + "v1.1.0.info": "410",
		fixTestPath + "v1.2.0.info": "bad",
		fixTestPath + "v1.3.0.info": "notime",
		fixTestPath + "v1.4.0.info": "0001-01-01T00:00:00Z",
		// v1.9.0 absent: 404
	})
	adv := ptrTime("2026-06-01T00:00:00Z")
	var vulns []Vulnerability
	for _, ver := range []string{"v1.1.0", "v1.2.0", "v1.3.0", "v1.4.0", "v1.9.0"} {
		vulns = append(vulns,
			Vulnerability{ID: "with-adv-" + ver, FixedVersion: ver, FixPublishedAt: adv},
			Vulnerability{ID: "no-adv-" + ver, FixedVersion: ver})
	}
	ResolveFixDates(context.Background(), f.opts(), "github.com/Example/Lib", vulns)

	for _, v := range vulns {
		if strings.HasPrefix(v.ID, "with-adv-") {
			if v.FixReleasedAt == nil || !v.FixReleasedAt.Equal(*adv) || v.FixDateSource != "advisory" {
				t.Errorf("%s: %v %q, want the advisory date with source advisory", v.ID, v.FixReleasedAt, v.FixDateSource)
			}
		} else if v.FixReleasedAt != nil || v.FixDateSource != "" {
			t.Errorf("%s: %v %q, want unknown (no date was ever given)", v.ID, v.FixReleasedAt, v.FixDateSource)
		}
	}
}

func TestResolveFixDates_NoFixGetsNothing(t *testing.T) {
	f := newProxyFixture(t, nil)
	vulns := []Vulnerability{{ID: "A", FixPublishedAt: ptrTime("2026-06-01T00:00:00Z")}}
	ResolveFixDates(context.Background(), f.opts(), "github.com/Example/Lib", vulns)
	if vulns[0].FixReleasedAt != nil || vulns[0].FixDateSource != "" {
		t.Errorf("a vuln with no fix got %v %q", vulns[0].FixReleasedAt, vulns[0].FixDateSource)
	}
	if len(f.hits) != 0 {
		t.Errorf("lookups made for a vuln with no fix: %v", f.hits)
	}
}

func TestResolveFixDates_DeduplicatesAndBoundsConcurrency(t *testing.T) {
	times := map[string]string{}
	var vulns []Vulnerability
	// 40 distinct fixed versions, 3 vulns each.
	for i := 0; i < 40; i++ {
		ver := "v1." + strconv.Itoa(i) + ".0"
		times[fixTestPath+ver+".info"] = "2026-06-10T00:00:00Z"
		for j := 0; j < 3; j++ {
			vulns = append(vulns, Vulnerability{ID: "x", FixedVersion: ver})
		}
	}
	f := newProxyFixture(t, times)
	f.delay = 20 * time.Millisecond
	ResolveFixDates(context.Background(), f.opts(), "github.com/Example/Lib", vulns)

	for path, n := range f.hits {
		if n != 1 {
			t.Errorf("%s requested %d times, want 1", path, n)
		}
	}
	if len(f.hits) != len(times) {
		t.Errorf("%d distinct lookups, want %d", len(f.hits), len(times))
	}
	if p := f.peak.Load(); p > 8 || p < 2 {
		t.Errorf("peak concurrency %d, want between 2 and 8", p)
	}
	for _, v := range vulns {
		if v.FixDateSource != "module_proxy" {
			t.Fatalf("vuln %+v not resolved", v)
		}
	}
}

func TestResolveFixDates_TotalTimeBounded(t *testing.T) {
	f := newProxyFixture(t, map[string]string{fixTestPath + "v1.4.0.info": "2026-06-10T00:00:00Z"})
	f.delay = 3 * time.Second
	opts := f.opts()
	opts.Timeout = 100 * time.Millisecond
	vulns := []Vulnerability{{ID: "A", FixedVersion: "v1.4.0", FixPublishedAt: ptrTime("2026-06-01T00:00:00Z")}}

	start := time.Now()
	ResolveFixDates(context.Background(), opts, "github.com/Example/Lib", vulns)
	if time.Since(start) > 2*time.Second {
		t.Errorf("took %v despite a 100ms budget", time.Since(start))
	}
	if vulns[0].FixDateSource != "advisory" {
		t.Errorf("source = %q, want advisory (the lookup never finished)", vulns[0].FixDateSource)
	}
}

func TestResolveFixDates_OfflineDoesNoNetwork(t *testing.T) {
	f := newProxyFixture(t, map[string]string{fixTestPath + "v1.4.0.info": "2026-06-10T00:00:00Z"})
	offline.Enable()
	defer offline.Disable()

	// A client with its own transport bypasses offline's global swap, so only
	// the explicit check in the resolver can keep it off the wire.
	var attempts atomic.Int32
	opts := f.opts()
	opts.Client = NewClient(ClientOptions{})
	opts.Client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts.Add(1)
		return nil, http.ErrNotSupported
	})
	vulns := []Vulnerability{{ID: "A", FixedVersion: "v1.4.0", FixPublishedAt: ptrTime("2026-06-01T00:00:00Z")}}
	ResolveFixDates(context.Background(), opts, "github.com/Example/Lib", vulns)
	if len(f.hits) != 0 || attempts.Load() != 0 {
		t.Errorf("requests in offline mode: %v, %d attempts", f.hits, attempts.Load())
	}
	if vulns[0].FixDateSource != "advisory" {
		t.Errorf("source = %q, want advisory", vulns[0].FixDateSource)
	}
}

func TestResolveFixDates_InvalidFixedVersionIsNotQueried(t *testing.T) {
	f := newProxyFixture(t, nil)
	vulns := []Vulnerability{
		{ID: "A", FixedVersion: "../../etc/passwd", FixPublishedAt: ptrTime("2026-06-01T00:00:00Z")},
		{ID: "B", FixedVersion: "not-a-version"},
	}
	ResolveFixDates(context.Background(), f.opts(), "github.com/Example/Lib", vulns)
	if len(f.hits) != 0 {
		t.Errorf("lookups for unparseable versions: %v", f.hits)
	}
	if vulns[0].FixDateSource != "advisory" || vulns[1].FixDateSource != "" {
		t.Errorf("sources %q, %q; want advisory, unknown", vulns[0].FixDateSource, vulns[1].FixDateSource)
	}
}

func TestResolveFixDates_IsIdempotent(t *testing.T) {
	f := newProxyFixture(t, map[string]string{fixTestPath + "v1.4.0.info": "2026-06-10T00:00:00Z"})
	vulns := []Vulnerability{{ID: "A", FixedVersion: "v1.4.0", FixPublishedAt: ptrTime("2026-06-01T00:00:00Z")}}
	ResolveFixDates(context.Background(), f.opts(), "github.com/Example/Lib", vulns)
	first := *vulns[0].FixReleasedAt
	ResolveFixDates(context.Background(), f.opts(), "github.com/Example/Lib", vulns)
	if !vulns[0].FixReleasedAt.Equal(first) || vulns[0].FixDateSource != "module_proxy" {
		t.Errorf("second run changed the result: %v %q", vulns[0].FixReleasedAt, vulns[0].FixDateSource)
	}
}

const stdlibToolchainPath = "/golang.org/toolchain/@v/"

func TestResolveStdlibFixDates(t *testing.T) {
	f := newProxyFixture(t, map[string]string{
		stdlibToolchainPath + "v0.0.1-go1.26.9.linux-amd64.info":  "2026-06-10T00:00:00Z",
		stdlibToolchainPath + "v0.0.1-go1.21.0.linux-amd64.info":  "2023-08-08T00:00:00Z",
		stdlibToolchainPath + "v0.0.1-go1.22rc1.linux-amd64.info": "2024-01-01T00:00:00Z",
	})
	adv := ptrTime("2026-06-01T00:00:00Z")
	vulns := []Vulnerability{
		{ID: "go-form", FixedVersion: "go1.26.9", FixPublishedAt: adv},
		{ID: "v-form", FixedVersion: "v1.26.9", FixPublishedAt: adv},
		{ID: "bare-form", FixedVersion: "1.26.9", FixPublishedAt: adv},
		{ID: "first-release", FixedVersion: "go1.21", FixPublishedAt: ptrTime("2023-01-01T00:00:00Z")},
		{ID: "rc", FixedVersion: "go1.22rc1"},
		{ID: "unknown-version", FixedVersion: "go1.99.9", FixPublishedAt: adv},
		{ID: "junk", FixedVersion: "tip", FixPublishedAt: adv},
		{ID: "nofix", FixPublishedAt: adv},
	}
	ResolveStdlibFixDates(context.Background(), f.opts(), vulns)

	check := func(i int, at, src string) {
		t.Helper()
		v := vulns[i]
		if src == "" {
			if v.FixReleasedAt != nil || v.FixDateSource != "" {
				t.Errorf("%s: %v %q, want unknown", v.ID, v.FixReleasedAt, v.FixDateSource)
			}
			return
		}
		if v.FixReleasedAt == nil || !v.FixReleasedAt.Equal(*ptrTime(at)) || v.FixDateSource != src {
			t.Errorf("%s: %v %q, want %s %q", v.ID, v.FixReleasedAt, v.FixDateSource, at, src)
		}
	}
	check(0, "2026-06-10T00:00:00Z", "module_proxy")
	check(1, "2026-06-10T00:00:00Z", "module_proxy")
	check(2, "2026-06-10T00:00:00Z", "module_proxy")
	check(3, "2023-08-08T00:00:00Z", "module_proxy")
	check(4, "2024-01-01T00:00:00Z", "module_proxy")
	check(5, "2026-06-01T00:00:00Z", "advisory") // proxy 404
	check(6, "2026-06-01T00:00:00Z", "advisory") // not a Go release: never queried
	check(7, "", "")
	if f.hits[stdlibToolchainPath+"v0.0.1-go1.26.9.linux-amd64.info"] != 1 {
		t.Errorf("go1.26.9 looked up %d times, want 1 for the three spellings", f.hits[stdlibToolchainPath+"v0.0.1-go1.26.9.linux-amd64.info"])
	}
}

func TestFixDate_Network(t *testing.T) {
	if testing.Short() {
		t.Skip("real-network test")
	}
	// A real, long-published release: the proxy must give it a time.
	vulns := []Vulnerability{{ID: "x", FixedVersion: "go1.21.0"}}
	ResolveStdlibFixDates(context.Background(), FixDateOptions{}, vulns)
	if vulns[0].FixReleasedAt == nil || vulns[0].FixDateSource != "module_proxy" {
		t.Errorf("go1.21.0: %v %q, want a module_proxy date", vulns[0].FixReleasedAt, vulns[0].FixDateSource)
	}
}
