package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Item 1: a version must be full and canonical, and OSV gets it without +incompatible.
func TestCheckModuleVersion(t *testing.T) {
	good := []string{"v1.4.0", "v0.0.1", "v1.4.0-rc.1", "v2.0.0+incompatible", "v0.0.0-20200101000000-abcdef123456"}
	bad := []string{"", "v1", "v1.4", "1.4.0", "latest", "v1.4.0+build.5", "v1.4.0+incompatible+incompatible", "v1.4.0 ", "v01.4.0", "v1.4.0\"}"}
	for _, v := range good {
		if err := CheckModuleVersion(v); err != nil {
			t.Errorf("CheckModuleVersion(%q) = %v, want nil", v, err)
		}
	}
	for _, v := range bad {
		err := CheckModuleVersion(v)
		if err == nil {
			t.Errorf("CheckModuleVersion(%q) = nil, want an error", v)
			continue
		}
		if !strings.Contains(err.Error(), "full version") {
			t.Errorf("CheckModuleVersion(%q) error %q does not say a full version is needed", v, err)
		}
	}
}

func TestScanModuleAdvisories_ShorthandVersionMakesNoRequest(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer srv.Close()
	for _, v := range []string{"v1", "v1.4"} {
		if _, err := ScanModuleAdvisories(context.Background(), SelfAdvisoryOptions{BaseURL: srv.URL}, selfTestModule, v); err == nil {
			t.Errorf("version %q: want an error", v)
		}
	}
	if calls.Load() != 0 {
		t.Errorf("%d requests for shorthand versions", calls.Load())
	}
}

func TestScanModuleAdvisories_IncompatibleIsStrippedForOSV(t *testing.T) {
	f := newOSVFixture(t, map[string]string{"": `{"vulns":[]}`})
	opts := quietEnrichers(t, f.srv.URL, nil)
	if _, err := ScanModuleAdvisories(context.Background(), opts, selfTestModule, "v2.3.0+incompatible"); err != nil {
		t.Fatal(err)
	}
	if len(f.requests) != 1 || f.requests[0]["version"] != "v2.3.0" {
		t.Errorf("OSV request version = %v, want the bare v2.3.0", f.requests)
	}
}

// The maintenance scanner is never handed a non-canonical pinned version.
func TestMaintenanceScanner_NonCanonicalPinnedVersionMakesNoInfoRequest(t *testing.T) {
	var infoReqs atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/@latest"):
			fmt.Fprint(w, `{"Version":"v1.2.0","Time":"2026-01-01T00:00:00Z"}`)
		case strings.HasSuffix(r.URL.Path, ".mod"):
			fmt.Fprint(w, "module example.com/m\n")
		case strings.HasSuffix(r.URL.Path, "/@v/list"):
			fmt.Fprint(w, "v1.2.0\n")
		default:
			infoReqs.Add(1)
			fmt.Fprint(w, `{"Version":"v1","Time":"2026-01-01T00:00:00Z"}`)
		}
	}))
	defer proxy.Close()
	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = proxy.URL
	ms.diskCache = nil
	if _, err := ms.checkModule(context.Background(), "example.com/m", "v1.1"); err != nil {
		t.Fatal(err)
	}
	if infoReqs.Load() != 0 {
		t.Errorf("%d .info requests for a shorthand pinned version, want 0", infoReqs.Load())
	}
}

// Item 2: every date fetch failing is "no data", whatever the budget.
func TestResilience_AllDateFetchesFailedYieldsNoData(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/@v/list") {
			fmt.Fprint(w, "v1.0.0\nv1.1.0\nv1.2.0\n")
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer proxy.Close()
	rs := NewResilienceScanner(5 * time.Second)
	rs.proxyURL = proxy.URL

	info := rs.analyzeModule(context.Background(), "example.com/m")

	if info.DataAvailable || !info.Limited {
		t.Errorf("DataAvailable = %v, Limited = %v, want false and true", info.DataAvailable, info.Limited)
	}
	if info.ReleaseCadence != "" {
		t.Errorf("ReleaseCadence = %q, want none: nothing was measured", info.ReleaseCadence)
	}
}

// Item 3: under a spent budget the modules that get dates are the first ones in
// sorted order, every time.
func TestResilience_BudgetAllocationIsDeterministic(t *testing.T) {
	versions := map[string]int{}
	var deps []resDepSpec
	for i := 0; i < 10; i++ {
		p := fmt.Sprintf("example.com/m%d", i)
		versions[p] = 5000
		deps = append(deps, resDepSpec{path: p, ver: "v1.0.0", direct: true})
	}
	// 100 requests: m0..m3 get 24 each (96), m4 gets the last 4, m5..m9 get none.
	for run := 0; run < 8; run++ {
		hp := newHugeProxy(t, versions)
		rs := NewResilienceScanner(10 * time.Second)
		rs.proxyURL = hp.URL
		rs.scanBudget = 100
		res := rs.ScanAll(context.Background(), makeResGraph(deps...), nil)
		for i := 0; i < 10; i++ {
			p := fmt.Sprintf("example.com/m%d", i)
			wantData := i <= 4
			if got := res[p].DataAvailable && res[p].SampledVersions > 0; got != wantData {
				t.Fatalf("run %d: %s has dates = %v, want %v", run, p, got, wantData)
			}
		}
		if got := res["example.com/m4"].SampledVersions; got != 4 {
			t.Fatalf("run %d: m4 sampled %d, want 4", run, got)
		}
	}
}

// Item 5: a failed or missing go.mod check is flagged, not read as clean.
func TestMaintenanceScanner_ModCheckFailed(t *testing.T) {
	cases := []struct {
		name       string
		modStatus  int
		noLatest   bool
		wantFailed bool
	}{
		{"mod fetch ok", http.StatusOK, false, false},
		{"mod fetch non-200", http.StatusInternalServerError, false, true},
		{"no latest version", http.StatusOK, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/@latest"):
					if c.noLatest {
						http.NotFound(w, r)
						return
					}
					fmt.Fprint(w, `{"Version":"v1.2.0","Time":"2026-01-01T00:00:00Z"}`)
				case strings.HasSuffix(r.URL.Path, ".mod"):
					if c.modStatus != http.StatusOK {
						http.Error(w, "boom", c.modStatus)
						return
					}
					fmt.Fprint(w, "module example.com/m\n")
				case strings.HasSuffix(r.URL.Path, ".info"):
					fmt.Fprint(w, `{"Version":"v1.1.0","Time":"2025-01-01T00:00:00Z"}`)
				default:
					fmt.Fprint(w, "v1.2.0\n")
				}
			}))
			defer proxy.Close()
			ms := NewMaintenanceScanner(5 * time.Second)
			ms.proxyURL = proxy.URL
			ms.diskCache = nil
			info, err := ms.checkModule(context.Background(), "example.com/m", "v1.1.0")
			if err != nil {
				t.Fatal(err)
			}
			if info.ModCheckFailed != c.wantFailed {
				t.Errorf("ModCheckFailed = %v, want %v", info.ModCheckFailed, c.wantFailed)
			}
		})
	}
}

// Item 8a.
func TestNormalizeRepositoryURL_PortAndControlCharacters(t *testing.T) {
	tests := map[string]string{
		"https://github.com:443/o/r":             "https://github.com/o/r",
		"https://go.googlesource.com:443/crypto": "https://go.googlesource.com/crypto",
		"https://git.example.com:8443/o/r":       "https://git.example.com:8443/o/r",
		"https://gitlab.com/g/some%20thing":      "",
		"https://gitlab.com/g/so%0Ame":           "",
		"https://gitlab.com/g/so%09me":           "",
		"https://gitlab.com/g/so%C2%A0me":        "",
		"https://gitlab.com/g/r%00":              "",
		"https://gitlab.com/g/r":                 "https://gitlab.com/g/r",
	}
	for in, want := range tests {
		if got := normalizeRepositoryURL(in); got != want {
			t.Errorf("normalizeRepositoryURL(%q) = %q, want %q", in, got, want)
		}
	}
}
