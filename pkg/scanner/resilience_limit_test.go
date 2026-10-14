package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// hugeProxy serves modules with a given number of versions, v1.N.0 released
// N days after 2020-01-01, and counts the requests it receives per kind.
type hugeProxy struct {
	*httptest.Server
	versions map[string]int // module path -> version count
	lists    atomic.Int64
	infos    atomic.Int64
	mu       sync.Mutex
	maxLive  int
	live     int
}

func newHugeProxy(t *testing.T, versions map[string]int) *hugeProxy {
	t.Helper()
	hp := &hugeProxy{versions: versions}
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	hp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hp.mu.Lock()
		hp.live++
		hp.maxLive = max(hp.maxLive, hp.live)
		hp.mu.Unlock()
		defer func() { hp.mu.Lock(); hp.live--; hp.mu.Unlock() }()

		mod, rest, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/@v/")
		n, known := hp.versions["example.com/"+strings.TrimPrefix(mod, "example.com/")]
		if !ok || !known {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch {
		case rest == "list":
			hp.lists.Add(1)
			var b strings.Builder
			for i := 0; i < n; i++ {
				fmt.Fprintf(&b, "v1.%d.0\n", i)
			}
			fmt.Fprint(w, b.String())
		case strings.HasSuffix(rest, ".info"):
			hp.infos.Add(1)
			var i int
			if _, err := fmt.Sscanf(rest, "v1.%d.0.info", &i); err != nil || i >= n {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"Version": fmt.Sprintf("v1.%d.0", i), "Time": base.AddDate(0, 0, i)})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(hp.Close)
	return hp
}

// A module with 5,000 versions costs the version list plus at most
// maxResilienceVersionSamples dates, and the result says it is a sample. The
// old code made 1 + 5,000 requests here.
func TestResilience_HugeModuleIsBounded(t *testing.T) {
	hp := newHugeProxy(t, map[string]int{"example.com/huge": 5000})
	rs := NewResilienceScanner(10 * time.Second)
	rs.proxyURL = hp.URL

	info := rs.analyzeModule(context.Background(), "example.com/huge")

	t.Logf("requests: %d list, %d info", hp.lists.Load(), hp.infos.Load())
	if got := hp.lists.Load(); got != 1 {
		t.Errorf("version list requests = %d, want 1", got)
	}
	if got := hp.infos.Load(); got > maxResilienceVersionSamples {
		t.Errorf("version info requests = %d, want at most %d", got, maxResilienceVersionSamples)
	}
	if !info.DataAvailable || !info.Limited {
		t.Errorf("DataAvailable = %v, Limited = %v, want both true", info.DataAvailable, info.Limited)
	}
	if info.TotalReleases != 5000 || info.SampledVersions != maxResilienceVersionSamples {
		t.Errorf("TotalReleases = %d, SampledVersions = %d, want 5000 and %d", info.TotalReleases, info.SampledVersions, maxResilienceVersionSamples)
	}
	// The sample is the newest versions plus the oldest, so the age and the
	// cadence are not understated by the cut.
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if !info.FirstReleaseDate.Equal(base) || !info.LastReleaseDate.Equal(base.AddDate(0, 0, 4999)) {
		t.Errorf("first/last = %v / %v, want the oldest and the newest release", info.FirstReleaseDate, info.LastReleaseDate)
	}
	if info.AvgDaysBetween < 0.99 || info.AvgDaysBetween > 1.01 {
		t.Errorf("AvgDaysBetween = %v, want about 1 from the full release count", info.AvgDaysBetween)
	}
}

// A module at or under the cap is fetched in full and is not marked limited.
func TestResilience_SmallModuleIsNotLimited(t *testing.T) {
	hp := newHugeProxy(t, map[string]int{"example.com/small": maxResilienceVersionSamples})
	rs := NewResilienceScanner(10 * time.Second)
	rs.proxyURL = hp.URL

	info := rs.analyzeModule(context.Background(), "example.com/small")

	if info.Limited || info.SampledVersions != 0 {
		t.Errorf("Limited = %v, SampledVersions = %d, want a complete result", info.Limited, info.SampledVersions)
	}
	if got := hp.infos.Load(); got != maxResilienceVersionSamples {
		t.Errorf("version info requests = %d, want %d", got, maxResilienceVersionSamples)
	}
}

// The per-scan budget stops one huge module from starving the rest: with a
// budget smaller than the modules need, every module still gets some dates or
// is marked limited, the total stays within the budget, and the concurrency
// stays bounded.
func TestResilience_ScanBudgetBoundsTotalRequests(t *testing.T) {
	versions := map[string]int{}
	deps := []resDepSpec{}
	for i := 0; i < 10; i++ {
		p := fmt.Sprintf("example.com/m%d", i)
		versions[p] = 5000
		deps = append(deps, resDepSpec{path: p, ver: "v1.0.0", direct: true})
	}
	hp := newHugeProxy(t, versions)
	rs := NewResilienceScanner(10 * time.Second)
	rs.proxyURL = hp.URL
	rs.scanBudget = 100

	res := rs.ScanAll(context.Background(), makeResGraph(deps...), nil)

	if got := hp.infos.Load(); got > 100 {
		t.Errorf("version info requests = %d, want at most the budget of 100", got)
	}
	if got := hp.maxLive; got > resilienceInfoConcurrency+resilienceModuleConcurrency {
		t.Errorf("peak concurrent requests = %d, want bounded", got)
	}
	for p, info := range res {
		if !info.Limited {
			t.Errorf("%s: Limited = false, want true under a spent budget", p)
		}
		if info.DataAvailable && info.SampledVersions == 0 {
			t.Errorf("%s: DataAvailable with no sampled dates", p)
		}
	}
}

// A module whose dates the budget could not fetch at all reports no data
// rather than a stale cadence computed from nothing.
func TestResilience_SpentBudgetYieldsNoData(t *testing.T) {
	hp := newHugeProxy(t, map[string]int{"example.com/huge": 100})
	rs := NewResilienceScanner(10 * time.Second)
	rs.proxyURL = hp.URL
	rs.infoBudget = 0

	info := rs.analyzeModule(context.Background(), "example.com/huge")

	if info.DataAvailable || !info.Limited {
		t.Errorf("DataAvailable = %v, Limited = %v, want false and true", info.DataAvailable, info.Limited)
	}
	if got := hp.infos.Load(); got != 0 {
		t.Errorf("version info requests = %d, want 0", got)
	}
}
