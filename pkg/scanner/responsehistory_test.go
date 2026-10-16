package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/offline"
)

const rhModule = "example.com/app"

var rhDay0 = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

func rhAt(days int) time.Time { return rhDay0.AddDate(0, 0, days) }

// rhRelease is one release of the graded module in the fake proxy.
type rhRelease struct {
	version  string
	day      int               // days after rhDay0
	requires map[string]string // dependency -> required version; nil means an empty go.mod
}

// rhFake fakes the module proxy and OSV in one server.
type rhFake struct {
	srv      *httptest.Server
	mu       sync.Mutex
	requests []string
	list     []string
	times    map[string]time.Time // "module@version" -> release time
	mods     map[string]string    // "module@version" -> go.mod text
	failMod  map[string]bool
	advis    map[string][]string // dependency -> fixed versions, one advisory each (no "v" prefix, as OSV writes)
	osvExtra map[string][]map[string]any
	listCode int
}

func newRHFake(t *testing.T, releases []rhRelease) *rhFake {
	t.Helper()
	f := &rhFake{
		times:   map[string]time.Time{},
		mods:    map[string]string{},
		failMod: map[string]bool{},
		advis:   map[string][]string{},
	}
	for _, r := range releases {
		f.list = append(f.list, r.version)
		key := rhModule + "@" + r.version
		f.times[key] = rhAt(r.day)
		var b strings.Builder
		b.WriteString("module " + rhModule + "\n\ngo 1.21\n")
		for dep, v := range r.requires {
			fmt.Fprintf(&b, "\nrequire %s %s\n", dep, v)
		}
		f.mods[key] = b.String()
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// release registers a dependency version released at day.
func (f *rhFake) release(dep, version string, day int) { f.times[dep+"@"+version] = rhAt(day) }

func (f *rhFake) count(substr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if strings.Contains(r, substr) {
			n++
		}
	}
	return n
}

func (f *rhFake) opts() ResponseHistoryOptions {
	return ResponseHistoryOptions{ProxyURL: f.srv.URL, OSVURL: f.srv.URL, Timeout: 5 * time.Second}
}

func (f *rhFake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	f.mu.Unlock()

	if r.Method == http.MethodPost && r.URL.Path == "/v1/query" {
		f.serveOSV(w, r)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	i := strings.Index(path, "/@v/")
	if i < 0 {
		http.NotFound(w, r)
		return
	}
	mod, rest := path[:i], path[i+len("/@v/"):]
	switch {
	case rest == "list":
		if f.listCode != 0 {
			http.Error(w, "gone", f.listCode)
			return
		}
		fmt.Fprint(w, strings.Join(f.list, "\n"))
	case strings.HasSuffix(rest, ".info"):
		key := mod + "@" + strings.TrimSuffix(rest, ".info")
		t, ok := f.times[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Version": strings.TrimSuffix(rest, ".info"), "Time": t})
	case strings.HasSuffix(rest, ".mod"):
		key := mod + "@" + strings.TrimSuffix(rest, ".mod")
		if f.failMod[key] {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		body, ok := f.mods[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, body)
	default:
		http.NotFound(w, r)
	}
}

func (f *rhFake) serveOSV(w http.ResponseWriter, r *http.Request) {
	var q osvQuery
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil || q.Package.Ecosystem != "Go" {
		http.Error(w, "bad query", http.StatusBadRequest)
		return
	}
	var vulns []map[string]any
	for i, fv := range f.advis[q.Package.Name] {
		vulns = append(vulns, map[string]any{
			"id": fmt.Sprintf("GO-2024-%04d", i),
			"affected": []any{map[string]any{
				"package": map[string]any{"name": q.Package.Name, "ecosystem": "Go"},
				"ranges":  []any{map[string]any{"type": "SEMVER", "events": []any{map[string]any{"introduced": "0"}, map[string]any{"fixed": fv}}}},
			}},
		})
	}
	vulns = append(vulns, f.osvExtra[q.Package.Name]...)
	// Two pages: the first carries every advisory but the last, to exercise the token.
	if q.PageToken == "" && len(vulns) > 1 {
		_ = json.NewEncoder(w).Encode(map[string]any{"vulns": vulns[:len(vulns)-1], "next_page_token": "p2"})
		return
	}
	if q.PageToken == "p2" {
		vulns = vulns[len(vulns)-1:]
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"vulns": vulns})
}

// rhThreeAdopters builds a module with releases every 10 days from day 0 and a dependency whose three fixes (days 10,
// 20 and 30) were adopted after 5, 30 and 61 days. The module requires the dependency at the fixed version in the
// release at the matching day.
func rhThreeAdopters(t *testing.T) (*rhFake, string) {
	const dep = "example.org/dep"
	releases := []rhRelease{
		{"v1.0.0", 0, map[string]string{dep: "v1.0.0"}},
		{"v1.1.0", 15, map[string]string{dep: "v1.1.0"}}, // fix 1.1.0 released day 10 -> 5 days
		{"v1.2.0", 50, map[string]string{dep: "v1.2.0"}}, // fix 1.2.0 released day 20 -> 30 days
		{"v1.3.0", 91, map[string]string{dep: "v1.3.0"}}, // fix 1.3.0 released day 30 -> 61 days
	}
	f := newRHFake(t, releases)
	f.release(dep, "v1.1.0", 10)
	f.release(dep, "v1.2.0", 20)
	f.release(dep, "v1.3.0", 30)
	f.advis[dep] = []string{"1.1.0", "1.2.0", "1.3.0"}
	return f, dep
}

func TestResponseHistoryMedianOfThree(t *testing.T) {
	f, dep := rhThreeAdopters(t)
	got, err := ScanResponseHistory(context.Background(), f.opts(), rhModule, []string{dep})
	if err != nil {
		t.Fatal(err)
	}
	h := got[dep]
	if h == nil {
		t.Fatalf("no history for %s: %v", dep, got)
	}
	if h.Dependency != dep || h.MedianDays != 30 || h.Samples != 3 {
		t.Errorf("history = %+v, want median 30 over 3 samples", h)
	}
	if !h.From.Equal(rhAt(10)) || !h.To.Equal(rhAt(30)) {
		t.Errorf("span = %v..%v, want %v..%v", h.From, h.To, rhAt(10), rhAt(30))
	}
}

// Negative control for the median: the same data must not give 30 if the middle sample moves.
func TestResponseHistoryMedianFollowsSamples(t *testing.T) {
	f, dep := rhThreeAdopters(t)
	f.times["example.com/app@v1.2.0"] = rhAt(90) // second fix adopted after 70 days instead of 30
	got, err := ScanResponseHistory(context.Background(), f.opts(), rhModule, []string{dep})
	if err != nil {
		t.Fatal(err)
	}
	if h := got[dep]; h == nil || h.MedianDays != 61 {
		t.Errorf("history = %+v, want median 61 (days 5, 70, 61)", h)
	}
}

func TestResponseHistoryTwoSamplesOmitted(t *testing.T) {
	f, dep := rhThreeAdopters(t)
	f.advis[dep] = []string{"1.1.0", "1.2.0"}
	got, err := ScanResponseHistory(context.Background(), f.opts(), rhModule, []string{dep})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[dep]; ok || len(got) != 0 {
		t.Errorf("got %v, want the dependency omitted with 2 samples (< %d)", got, MinResponseSamples)
	}
}

func TestResponseHistoryFixBeforeSampledRangeSkipped(t *testing.T) {
	f, dep := rhThreeAdopters(t)
	// A fourth advisory fixed before the module's oldest sampled release (day 0).
	f.release(dep, "v0.9.0", -40)
	f.advis[dep] = append(f.advis[dep], "0.9.0")
	got, err := ScanResponseHistory(context.Background(), f.opts(), rhModule, []string{dep})
	if err != nil {
		t.Fatal(err)
	}
	if h := got[dep]; h == nil || h.Samples != 3 {
		t.Errorf("history = %+v, want the pre-range fix skipped (3 samples)", h)
	}
	// Negative control: shrinking the sample window to the newest two releases turns the day-10 fix into a pre-range one.
	o := f.opts()
	o.MaxVersions = 2
	got, err = ScanResponseHistory(context.Background(), o, rhModule, []string{dep})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("with MaxVersions=2 got %v, want the dependency omitted", got)
	}
}

func TestResponseHistoryAlreadyRequiredIsZeroDays(t *testing.T) {
	const dep = "example.org/dep"
	// Every release requires the fixed version before it is released (pre-release tag of the fix, say).
	releases := []rhRelease{
		{"v1.0.0", 0, map[string]string{dep: "v1.1.0"}},
		{"v1.1.0", 40, map[string]string{dep: "v1.2.0"}},
		{"v1.2.0", 80, map[string]string{dep: "v1.3.0"}},
	}
	f := newRHFake(t, releases)
	f.release(dep, "v1.1.0", 10)
	f.release(dep, "v1.2.0", 20)
	f.release(dep, "v1.3.0", 30)
	f.advis[dep] = []string{"1.1.0", "1.2.0", "1.3.0"}
	got, err := ScanResponseHistory(context.Background(), f.opts(), rhModule, []string{dep})
	if err != nil {
		t.Fatal(err)
	}
	// Fix v1.1.0 was already required by v1.0.0 (0 days); v1.2.0 by v1.1.0 (20 days); v1.3.0 by v1.2.0 (50 days).
	if h := got[dep]; h == nil || h.MedianDays != 20 || h.Samples != 3 {
		t.Errorf("history = %+v, want median 20 over 3 samples", h)
	}
	// Negative control: the 0-day sample is clamped, not negative: one more advisory fixed at a version the first release already required.
	f.release(dep, "v1.0.5", 5)
	f.advis[dep] = append(f.advis[dep], "1.0.5")
	got, err = ScanResponseHistory(context.Background(), f.opts(), rhModule, []string{dep})
	if err != nil {
		t.Fatal(err)
	}
	if h := got[dep]; h == nil || h.Samples != 4 || h.MedianDays != 10 { // 0, 0, 20, 50 -> (0+20+1)/2 = 10
		t.Errorf("history = %+v, want 4 samples, median 10 (days 0, 0, 20, 50)", h)
	}
}

func TestResponseHistoryNeverRequiredDependency(t *testing.T) {
	f, _ := rhThreeAdopters(t)
	const other = "example.org/other"
	f.advis[other] = []string{"1.1.0", "1.2.0", "1.3.0"}
	f.release(other, "v1.1.0", 10)
	f.release(other, "v1.2.0", 20)
	f.release(other, "v1.3.0", 30)
	got, err := ScanResponseHistory(context.Background(), f.opts(), rhModule, []string{other})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want no history for a dependency the module never required", got)
	}
}

func TestResponseHistoryUnadoptedFixIsNotASample(t *testing.T) {
	f, dep := rhThreeAdopters(t)
	// A fourth fix newer than anything the module requires: not a sample, and not a long adoption either.
	f.release(dep, "v1.9.0", 85)
	f.advis[dep] = append(f.advis[dep], "1.9.0")
	got, err := ScanResponseHistory(context.Background(), f.opts(), rhModule, []string{dep})
	if err != nil {
		t.Fatal(err)
	}
	if h := got[dep]; h == nil || h.Samples != 3 || h.MedianDays != 30 {
		t.Errorf("history = %+v, want the unadopted fix ignored (3 samples, median 30)", h)
	}
}

func TestResponseHistoryFailedModSkipsOnlyThatVersion(t *testing.T) {
	const dep = "example.org/dep"
	// Four fixes; the fourth is adopted only by a release whose go.mod fails, so the others still count.
	releases := []rhRelease{
		{"v1.0.0", 0, map[string]string{dep: "v1.0.0"}},
		{"v1.1.0", 15, map[string]string{dep: "v1.1.0"}},
		{"v1.2.0", 50, map[string]string{dep: "v1.2.0"}},
		{"v1.3.0", 91, map[string]string{dep: "v1.3.0"}},
		{"v1.4.0", 120, map[string]string{dep: "v1.4.0"}},
	}
	f := newRHFake(t, releases)
	f.release(dep, "v1.1.0", 10)
	f.release(dep, "v1.2.0", 20)
	f.release(dep, "v1.3.0", 30)
	f.release(dep, "v1.4.0", 100)
	f.advis[dep] = []string{"1.1.0", "1.2.0", "1.3.0", "1.4.0"}
	f.failMod[rhModule+"@v1.4.0"] = true
	got, err := ScanResponseHistory(context.Background(), f.opts(), rhModule, []string{dep})
	if err != nil {
		t.Fatalf("one failed .mod must not fail the call: %v", err)
	}
	if h := got[dep]; h == nil || h.Samples != 3 || h.MedianDays != 30 {
		t.Errorf("history = %+v, want 3 samples, median 30 with v1.4.0 skipped", h)
	}
	// Negative control: with the .mod readable the fourth fix (20 days) is a sample too.
	f.failMod[rhModule+"@v1.4.0"] = false
	got, _ = ScanResponseHistory(context.Background(), f.opts(), rhModule, []string{dep})
	if h := got[dep]; h == nil || h.Samples != 4 {
		t.Errorf("history = %+v, want 4 samples when no .mod fails", h)
	}
}

func TestResponseHistoryFailedAdvisoryLookupSkipsDependency(t *testing.T) {
	f, dep := rhThreeAdopters(t)
	// A dependency whose OSV query is rejected is skipped; another one still answers.
	other := "example.org/ok"
	got, err := ScanResponseHistory(context.Background(), ResponseHistoryOptions{ProxyURL: f.srv.URL, OSVURL: f.srv.URL + "/nowhere"}, rhModule, []string{dep, other})
	if err != nil {
		t.Fatalf("failed OSV lookups must not fail the call: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %v, want nothing when OSV fails", got)
	}
}

func TestResponseHistoryVersionListFailureIsAnError(t *testing.T) {
	f, dep := rhThreeAdopters(t)
	f.listCode = http.StatusGone
	got, err := ScanResponseHistory(context.Background(), f.opts(), rhModule, []string{dep})
	if err == nil || got != nil {
		t.Errorf("got %v, %v, want an error when the module's own version list fails", got, err)
	}
}

func TestResponseHistoryRequestBounds(t *testing.T) {
	const dep = "example.org/dep"
	var releases []rhRelease
	for i := 0; i < 30; i++ {
		releases = append(releases, rhRelease{fmt.Sprintf("v1.%d.0", i), i * 10, map[string]string{dep: "v1.0.0"}})
	}
	// A pre-release must neither be sampled nor read.
	releases = append(releases, rhRelease{"v1.30.0-rc.1", 400, nil})
	f := newRHFake(t, releases)
	f.advis[dep] = []string{"1.1.0"}
	f.release(dep, "v1.1.0", 15)

	o := f.opts()
	o.MaxVersions = 7
	if _, err := ScanResponseHistory(context.Background(), o, rhModule, []string{dep}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(".mod"); n != 7 {
		t.Errorf(".mod reads = %d, want exactly MaxVersions (7)", n)
	}
	if n := f.count("rc.1"); n != 0 {
		t.Errorf("pre-release was requested %d times, want 0", n)
	}
	// Negative control: the default cap is 40, so all 30 releases are read.
	f.mu.Lock()
	f.requests = nil
	f.mu.Unlock()
	if _, err := ScanResponseHistory(context.Background(), f.opts(), rhModule, []string{dep}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(".mod"); n != 30 {
		t.Errorf("default .mod reads = %d, want 30", n)
	}
}

func TestResponseHistoryDependencyCapAndDedup(t *testing.T) {
	const dep = "example.org/dep"
	f := newRHFake(t, []rhRelease{{"v1.0.0", 0, map[string]string{dep: "v1.0.0", "example.org/b": "v1.0.0", "example.org/c": "v1.0.0"}}})
	o := f.opts()
	o.MaxDependencies = 2
	if _, err := ScanResponseHistory(context.Background(), o, rhModule, []string{dep, dep, rhModule, "", "example.org/b", "example.org/c"}); err != nil {
		t.Fatal(err)
	}
	// Two distinct dependencies were examined: one OSV query each, none for the repeat, the module itself or the third.
	if n := f.count("POST /v1/query"); n != 2 {
		t.Errorf("OSV queries = %d, want 2", n)
	}
}

func TestResponseHistoryOSVDetails(t *testing.T) {
	f, dep := rhThreeAdopters(t)
	// Withdrawn, no-fix and other-module advisories add no samples; a second range's later fix does not replace the first.
	f.osvExtra = map[string][]map[string]any{dep: {
		{"id": "GO-W", "withdrawn": "2024-02-01T00:00:00Z", "affected": []any{map[string]any{
			"package": map[string]any{"name": dep, "ecosystem": "Go"},
			"ranges":  []any{map[string]any{"events": []any{map[string]any{"fixed": "1.9.0"}}}}}}},
		{"id": "GO-NOFIX", "affected": []any{map[string]any{
			"package": map[string]any{"name": dep, "ecosystem": "Go"},
			"ranges":  []any{map[string]any{"events": []any{map[string]any{"introduced": "0"}}}}}}},
		{"id": "GO-OTHER", "affected": []any{map[string]any{
			"package": map[string]any{"name": "example.org/else", "ecosystem": "Go"},
			"ranges":  []any{map[string]any{"events": []any{map[string]any{"fixed": "1.8.0"}}}}}}},
	}}
	f.release(dep, "v1.9.0", 25)
	f.release(dep, "v1.8.0", 25)
	got, err := ScanResponseHistory(context.Background(), f.opts(), rhModule, []string{dep})
	if err != nil {
		t.Fatal(err)
	}
	if h := got[dep]; h == nil || h.Samples != 3 {
		t.Errorf("history = %+v, want 3 samples (withdrawn, unfixed and foreign advisories ignored)", h)
	}
}

func TestResponseHistoryDeterministic(t *testing.T) {
	f, dep := rhThreeAdopters(t)
	var first string
	for i := 0; i < 5; i++ {
		got, err := ScanResponseHistory(context.Background(), f.opts(), rhModule, []string{dep})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(got)
		if i == 0 {
			first = string(b)
		} else if string(b) != first {
			t.Fatalf("run %d differs: %s vs %s", i, b, first)
		}
	}
}

func TestResponseHistoryOffline(t *testing.T) {
	f, dep := rhThreeAdopters(t)
	offline.Enable()
	t.Cleanup(offline.Disable)
	got, err := ScanResponseHistory(context.Background(), f.opts(), rhModule, []string{dep})
	if !errors.Is(err, offline.ErrOffline) || got != nil {
		t.Errorf("got %v, %v, want offline.ErrOffline", got, err)
	}
	if n := len(f.requests); n != 0 {
		t.Errorf("offline made %d requests: %v", n, f.requests)
	}
}

func TestMedianDays(t *testing.T) {
	for _, tc := range []struct {
		in   []int
		want int
	}{
		{[]int{61, 5, 30}, 30},
		{[]int{4, 5}, 5}, // 4.5 rounds up
		{[]int{4, 6}, 5},
		{[]int{0, 0, 1, 5}, 1}, // 0.5 rounds up
		{[]int{7}, 7},
	} {
		if got := medianDays(tc.in); got != tc.want {
			t.Errorf("medianDays(%v) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
