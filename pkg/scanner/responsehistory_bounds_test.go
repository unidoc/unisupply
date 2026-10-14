package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestResponseHistoryNoDependenciesMakesNoRequest(t *testing.T) {
	f, _ := rhThreeAdopters(t)
	for name, deps := range map[string][]string{"nil": nil, "only the module and blanks": {rhModule, ""}} {
		got, err := ScanResponseHistory(context.Background(), f.opts(), rhModule, deps)
		if err != nil || len(got) != 0 {
			t.Errorf("%s: got %v, %v; want an empty result", name, got, err)
		}
	}
	if n := len(f.requests); n != 0 {
		t.Errorf("%d requests for a call with no dependencies, want 0: %v", n, f.requests)
	}
}

// A dependency with many advisories costs at most responseHistoryMaxFixes release-time requests.
func TestResponseHistoryFixesPerDependencyCapped(t *testing.T) {
	const dep = "example.org/dep"
	f := newRHFake(t, []rhRelease{
		{"v1.0.0", 0, map[string]string{dep: "v1.0.0"}},
		{"v1.1.0", 100, map[string]string{dep: "v1.30.0"}},
	})
	for i := 1; i <= 30; i++ {
		v := fmt.Sprintf("v1.%d.0", i)
		f.release(dep, v, 10+i)
		f.advis[dep] = append(f.advis[dep], fmt.Sprintf("1.%d.0", i))
	}
	got, err := ScanResponseHistory(context.Background(), f.opts(), rhModule, []string{dep})
	if err != nil {
		t.Fatal(err)
	}
	if n := f.count(dep + "/@v/"); n != responseHistoryMaxFixes {
		t.Errorf("%d release-time requests for %s, want the cap of %d", n, dep, responseHistoryMaxFixes)
	}
	if h := got[dep]; h == nil || h.Samples != responseHistoryMaxFixes {
		t.Errorf("history = %+v, want %d samples (the newest fixes)", h, responseHistoryMaxFixes)
	}
}

// The release time of a fix no sampled release adopted is not requested.
func TestResponseHistoryUnadoptedFixTimeNotFetched(t *testing.T) {
	const dep = "example.org/dep"
	f := newRHFake(t, []rhRelease{
		{"v1.0.0", 0, map[string]string{dep: "v1.0.0"}},
		{"v1.1.0", 50, map[string]string{dep: "v1.1.0"}},
	})
	f.release(dep, "v1.1.0", 10)
	f.advis[dep] = []string{"1.1.0"}
	for i := 2; i <= 6; i++ { // fixed later than any release requires
		f.release(dep, fmt.Sprintf("v1.%d.0", i), 20+i)
		f.advis[dep] = append(f.advis[dep], fmt.Sprintf("1.%d.0", i))
	}
	if _, err := ScanResponseHistory(context.Background(), f.opts(), rhModule, []string{dep}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(dep + "/@v/"); n != 1 {
		t.Errorf("%d release-time requests for %s, want 1 (only the adopted fix)", n, dep)
	}
}

func TestResponseHistoryRequestBudget(t *testing.T) {
	f, dep := rhThreeAdopters(t)
	opts := f.opts()
	opts.MaxRequests = 5
	if _, err := ScanResponseHistory(context.Background(), opts, rhModule, []string{dep}); err != nil {
		// A spent budget may leave nothing to read; either way no more than 5 requests may be made.
		t.Logf("error under a small budget: %v", err)
	}
	if n := len(f.requests); n > 5 {
		t.Errorf("%d requests, want at most the budget of 5", n)
	}
}

func TestResponseHistoryOverallDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
		http.Error(w, "late", http.StatusGatewayTimeout)
	}))
	defer srv.Close()
	opts := ResponseHistoryOptions{ProxyURL: srv.URL, OSVURL: srv.URL, Timeout: 8 * time.Second, Deadline: 300 * time.Millisecond}

	start := time.Now()
	_, err := ScanResponseHistory(context.Background(), opts, rhModule, []string{"example.org/dep"})
	if err == nil {
		t.Error("want an error when the version list cannot be read in time")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("took %v with an overall deadline of 300ms", d)
	}
}
