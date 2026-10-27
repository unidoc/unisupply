package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/facts"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
)

func fixProxy(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch {
		case strings.HasSuffix(r.URL.Path, ".info"):
			_, _ = w.Write([]byte(`{"Version":"v1.2.0","Time":"2025-12-05T00:00:00Z"}`))
		case strings.HasSuffix(r.URL.Path, ".mod"):
			_, _ = w.Write([]byte("module github.com/example/dep\n\ngo 1.21\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestResolveFixes_ReadsThroughTheStore(t *testing.T) {
	ctx := context.Background()
	var hits atomic.Int32
	srv := fixProxy(t, &hits)
	date := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	opts := scanner.FixDateOptions{ProxyURL: srv.URL, Timeout: 5 * time.Second, Now: func() time.Time { return date }}
	store := facts.NewMemory()
	fr := &factReader{store: store, date: date, analysed: date}
	mk := func() map[string][]scanner.Vulnerability {
		return map[string][]scanner.Vulnerability{"github.com/example/dep": {{ID: "GO-1", FixedVersion: "v1.2.0"}, {ID: "GO-2"}}}
	}

	// first grade: the proxy is asked, and the answer is stored
	v1 := mk()
	resolveFixes(ctx, fr, opts, v1)
	f := v1["github.com/example/dep"][0]
	if f.FixReleasedAt == nil || !f.FixReleasedAt.Equal(time.Date(2025, 12, 5, 0, 0, 0, 0, time.UTC)) || f.FixDateSource != scanner.FixDateModuleProxy || f.FixRequiresGo != "1.21" || f.DaysUnpatched != 27 {
		t.Fatalf("resolved finding = %+v", f)
	}
	if v1["github.com/example/dep"][1].FixReleasedAt != nil {
		t.Error("a finding with no fix has no fix date")
	}
	asked := hits.Load()
	if asked == 0 {
		t.Fatal("the proxy was never asked")
	}
	fx, ok, _ := store.GetFix(ctx, "github.com/example/dep", "v1.2.0")
	if !ok || fx.RequiresGo != "1.21" || fx.Source != scanner.FixDateModuleProxy {
		t.Fatalf("stored fix = %+v %v", fx, ok)
	}

	// a later grade, a month on: no request, the same fix, the days counted to the new date
	later := date.AddDate(0, 0, 20)
	fr2 := &factReader{store: store, date: later, analysed: date}
	v2 := mk()
	resolveFixes(ctx, fr2, scanner.FixDateOptions{ProxyURL: srv.URL, Now: func() time.Time { return later }}, v2)
	g := v2["github.com/example/dep"][0]
	if hits.Load() != asked || g.FixReleasedAt == nil || g.FixRequiresGo != "1.21" || g.DaysUnpatched != 47 {
		t.Errorf("second grade: %d more requests, finding %+v", hits.Load()-asked, g)
	}

	// a fix fact older than the policy allows is looked up again
	old := facts.NewMemory()
	_ = old.PutFix(ctx, &facts.Fix{Module: "github.com/example/dep", Version: "v1.2.0", ReleasedAt: date.AddDate(-1, 0, 0), Source: "advisory", RequiresGo: "1.1", FetchedAt: date.AddDate(0, -3, 0)})
	hits.Store(0)
	v3 := mk()
	resolveFixes(ctx, &factReader{store: old, date: date, analysed: date}, opts, v3)
	if hits.Load() == 0 || v3["github.com/example/dep"][0].FixRequiresGo != "1.21" {
		t.Errorf("a stale fact must be looked up again: %d requests, %+v", hits.Load(), v3["github.com/example/dep"][0])
	}
}

func TestResolveFixes_NoStoreIsTheOldBehaviour(t *testing.T) {
	var hits atomic.Int32
	srv := fixProxy(t, &hits)
	date := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	vulns := map[string][]scanner.Vulnerability{"github.com/example/dep": {{ID: "GO-1", FixedVersion: "v1.2.0"}}}
	resolveFixes(context.Background(), nil, scanner.FixDateOptions{ProxyURL: srv.URL, Now: func() time.Time { return date }}, vulns)
	if vulns["github.com/example/dep"][0].FixReleasedAt == nil || hits.Load() == 0 {
		t.Errorf("%+v, %d requests", vulns, hits.Load())
	}
}

func TestPutModule_OnlyWholeAnswers(t *testing.T) {
	ctx := context.Background()
	date := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := facts.NewMemory()
	fr := &factReader{store: store, date: date}
	cases := map[string]struct {
		info   scanner.MaintenanceInfo
		stored bool
	}{
		"checked":           {scanner.MaintenanceInfo{ArchivedCheck: scanner.ArchivedChecked}, true},
		"unsupported host":  {scanner.MaintenanceInfo{ArchivedCheck: scanner.ArchivedUnsupported}, true},
		"repository gone":   {scanner.MaintenanceInfo{ArchivedCheck: scanner.ArchivedCheckFailed, RepositoryNotFound: true}, true},
		"rate limited":      {scanner.MaintenanceInfo{ArchivedCheck: scanner.ArchivedCheckFailed}, false},
		"not attempted":     {scanner.MaintenanceInfo{}, false},
		"go.mod unreadable": {scanner.MaintenanceInfo{ArchivedCheck: scanner.ArchivedChecked, ModCheckFailed: true}, false},
	}
	for name, c := range cases {
		info := c.info
		fr.putModule(ctx, "m/"+name, "v1.0.0", &info)
		_, ok, _ := store.GetModule(ctx, "m/"+name, "v1.0.0")
		if ok != c.stored {
			t.Errorf("%s: stored = %v, want %v", name, ok, c.stored)
		}
	}
	fr.putModule(ctx, "m/nil", "v1", nil) // must not panic
}

func TestSplitModules_UsesFreshStatusOnly(t *testing.T) {
	ctx := context.Background()
	date := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := facts.NewMemory()
	g := &resolver.Graph{Root: "r", Dependencies: map[string]*resolver.Dependency{
		"a": {}, "b": {}, "c": {},
	}}
	g.Dependencies["a"].Module.Version, g.Dependencies["b"].Module.Version, g.Dependencies["c"].Module.Version = "v1", "v1", "v1"
	_ = store.PutModule(ctx, &facts.Module{Path: "a", Version: "v1", FetchedAt: date.Add(-time.Hour), Info: scanner.MaintenanceInfo{Archived: true, LastRelease: date.AddDate(-1, 0, 0)}})
	_ = store.PutModule(ctx, &facts.Module{Path: "b", Version: "v1", FetchedAt: date.AddDate(0, 0, -3)}) // stale
	// c is unknown

	scan, cached := (&factReader{store: store, date: date}).splitModules(ctx, g)
	if len(cached) != 1 || !cached["a"].Archived || cached["a"].MonthsSinceRelease != 12 {
		t.Errorf("cached = %+v (the counts are aged to the grade's date)", cached)
	}
	if len(scan.Dependencies) != 2 || scan.Dependencies["b"] == nil || scan.Dependencies["c"] == nil || scan.Root != "r" {
		t.Errorf("to scan = %+v", scan.Dependencies)
	}
	// without a store the graph is returned itself
	if s, c := (*factReader)(nil).splitModules(ctx, g); s != g || c != nil {
		t.Error("no store: the graph must be scanned as it is")
	}
	// with nothing cached too
	if s, c := (&factReader{store: facts.NewMemory(), date: date}).splitModules(ctx, g); s != g || c != nil {
		t.Error("empty store: the graph must be scanned as it is")
	}
}

// TestStaleCalledPass: an analysis made in auto mode that skipped the called pass cannot be graded as it stands once the
// facts of the day (a known-exploited entry, a higher severity) mean the called pass could change the letter.
func TestStaleCalledPass(t *testing.T) {
	skippedAuto := &Analysis{Scan: &scanner.ScanInfo{CalledPass: scanner.CalledPassSkipped, CalledPassMode: string(scanner.CalledPassAuto)}}
	imported := func(sev string, kev bool) map[string][]scanner.Vulnerability {
		return map[string][]scanner.Vulnerability{"github.com/example/dep": {{ID: "GO-1", Severity: sev, Reachability: "imported", InKEV: kev}}}
	}
	cases := []struct {
		name  string
		an    *Analysis
		vulns map[string][]scanner.Vulnerability
		stale bool
	}{
		{"still medium", skippedAuto, imported("MEDIUM", false), false},
		{"now known exploited", skippedAuto, imported("MEDIUM", true), true},
		{"now critical", skippedAuto, imported("CRITICAL", false), true},
		{"the called pass ran", &Analysis{Scan: &scanner.ScanInfo{CalledPass: scanner.CalledPassRan, CalledPassMode: string(scanner.CalledPassAuto)}}, imported("CRITICAL", true), false},
		{"always mode", &Analysis{Scan: &scanner.ScanInfo{CalledPass: scanner.CalledPassSkipped, CalledPassMode: string(scanner.CalledPassAlways)}}, imported("CRITICAL", true), false},
		{"no scan info", &Analysis{}, imported("CRITICAL", true), false},
	}
	for _, c := range cases {
		got := staleCalledPass(c.an, c.vulns, false)
		if (got != "") != c.stale || (c.stale && !strings.Contains(got, "analyse again")) {
			t.Errorf("%s: staleCalledPass = %q, want stale %v", c.name, got, c.stale)
		}
	}
}
