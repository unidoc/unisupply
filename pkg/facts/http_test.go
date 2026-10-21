package facts

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/scanner"
)

const testKey = "gk_secret_key_123"

type seen struct {
	mu   sync.Mutex
	reqs []*http.Request
}

func (s *seen) add(r *http.Request) {
	s.mu.Lock()
	s.reqs = append(s.reqs, r.Clone(r.Context()))
	s.mu.Unlock()
}
func (s *seen) n() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.reqs) }

func apiServer(t *testing.T, rec *seen) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r)
		if r.Header.Get("Authorization") != "Bearer "+testKey {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/facts/modules":
			if r.URL.Query().Get("path") == "example.com/hit" {
				_ = json.NewEncoder(w).Encode(Module{Path: "example.com/hit", Version: r.URL.Query().Get("version"), Info: scanner.MaintenanceInfo{Archived: true}, FetchedAt: time.Now()})
				return
			}
		case "/api/v1/facts/advisories/GO-2026-0001":
			_ = json.NewEncoder(w).Encode(Advisory{ID: "GO-2026-0001", Severity: "HIGH", FetchedAt: time.Now()})
			return
		case "/api/v1/facts/fixes":
			_ = json.NewEncoder(w).Encode(Fix{Module: "m", Version: "v1.2.0", ReleasedAt: time.Now(), FetchedAt: time.Now()})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestHTTPStore_HitsMissesAndCache(t *testing.T) {
	var rec seen
	srv := apiServer(t, &rec)
	s, err := NewHTTPStore(srv.URL+"/", testKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	m, ok, err := s.GetModule(ctx, "example.com/hit", "v1.0.0")
	if err != nil || !ok || !m.Info.Archived || m.Version != "v1.0.0" {
		t.Fatalf("module = %+v %v %v", m, ok, err)
	}
	if _, ok, err := s.GetModule(ctx, "example.com/miss", "v1.0.0"); ok || err != nil {
		t.Errorf("a 404 is a miss without an error: %v %v", ok, err)
	}
	if a, ok, err := s.GetAdvisory(ctx, "GO-2026-0001"); err != nil || !ok || a.Severity != "HIGH" {
		t.Errorf("advisory = %+v %v %v", a, ok, err)
	}
	if f, ok, err := s.GetFix(ctx, "m", "v1.2.0"); err != nil || !ok || f.Version != "v1.2.0" {
		t.Errorf("fix = %+v %v %v", f, ok, err)
	}
	n := rec.n()
	// the same facts again, hits and misses: no request
	_, _, _ = s.GetModule(ctx, "example.com/hit", "v1.0.0")
	_, _, _ = s.GetModule(ctx, "example.com/miss", "v1.0.0")
	_, _, _ = s.GetAdvisory(ctx, "GO-2026-0001")
	if rec.n() != n {
		t.Errorf("%d requests for facts already asked", rec.n()-n)
	}

	for _, r := range rec.reqs {
		if strings.Contains(r.URL.String(), testKey) || strings.Contains(r.URL.RawQuery, "gk_") {
			t.Errorf("the key is in a URL: %s", r.URL)
		}
		if r.Header.Get("Authorization") != "Bearer "+testKey || !strings.HasPrefix(r.Header.Get("User-Agent"), "unisupply/") {
			t.Errorf("headers = %v", r.Header)
		}
	}
	// writes do nothing
	if err := s.PutModule(ctx, &Module{Path: "private/mod"}); err != nil {
		t.Error(err)
	}
	if rec.n() != n {
		t.Error("a Put made a request")
	}
}

func TestHTTPStore_BadKeyIsAMissWithAnErrorAndStopsAsking(t *testing.T) {
	var rec seen
	srv := apiServer(t, &rec)
	s, _ := NewHTTPStore(srv.URL, "gk_wrong")
	_, ok, err := s.GetModule(context.Background(), "example.com/hit", "v1.0.0")
	if ok || err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if strings.Contains(err.Error(), "gk_wrong") {
		t.Error("the key is in the error")
	}
	_, _, err = s.GetAdvisory(context.Background(), "GO-2026-0001")
	if err == nil || rec.n() != 1 {
		t.Errorf("err=%v requests=%d: a refused key must not be sent again", err, rec.n())
	}
}

func TestHTTPStore_RetryAfter(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("path") == "slow" {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "limit", http.StatusTooManyRequests)
			return
		}
		if calls == 1 {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "limit", http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(Module{Path: "p", Version: "v1"})
	}))
	defer srv.Close()
	s, _ := NewHTTPStore(srv.URL, testKey)
	s.maxRetryWait = 2 * time.Second

	start := time.Now()
	m, ok, err := s.GetModule(context.Background(), "p", "v1")
	if err != nil || !ok || m.Path != "p" || calls != 2 || time.Since(start) < time.Second {
		t.Errorf("a short Retry-After is waited once and retried: %+v %v %v, %d calls", m, ok, err, calls)
	}
	calls = 0
	start = time.Now()
	_, ok, err = s.GetModule(context.Background(), "slow", "v1")
	if ok || err == nil || calls != 1 || time.Since(start) > time.Second {
		t.Errorf("a long Retry-After is a miss at once: %v %v, %d calls", ok, err, calls)
	}
}

func TestHTTPStore_OtherFailuresAreMissesWithErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/facts/fixes" {
			_, _ = w.Write([]byte("not json"))
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	s, _ := NewHTTPStore(srv.URL, testKey)
	if _, ok, err := s.GetModule(context.Background(), "a", "v1"); ok || err == nil {
		t.Errorf("500: %v %v", ok, err)
	}
	if _, ok, err := s.GetFix(context.Background(), "a", "v1"); ok || err == nil {
		t.Errorf("bad JSON: %v %v", ok, err)
	}
	srv.Close()
	if _, ok, err := s.GetAdvisory(context.Background(), "GO-1"); ok || err == nil {
		t.Errorf("unreachable: %v %v", ok, err)
	}
}

func TestNewHTTPStore_Validation(t *testing.T) {
	for _, base := range []string{"https://gorisk.dev", "http://127.0.0.1:8080", "http://localhost:1", "http://[::1]:9"} {
		if _, err := NewHTTPStore(base, "k"); err != nil {
			t.Errorf("%s: %v", base, err)
		}
	}
	for _, base := range []string{"http://gorisk.dev", "http://10.0.0.1", "ftp://x", "gorisk.dev", "", "https://x/?key=1", "https://u:p@x"} {
		if _, err := NewHTTPStore(base, "k"); err == nil {
			t.Errorf("%q must be refused", base)
		}
	}
	if _, err := NewHTTPStore("https://gorisk.dev", " "); err == nil {
		t.Error("an empty key must be refused")
	}
}

// A redirect is not followed: it would carry the key to another host.
func TestHTTPStore_DoesNotFollowRedirects(t *testing.T) {
	var other int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { other++ }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer srv.Close()
	s, _ := NewHTTPStore(srv.URL, testKey)
	_, ok, err := s.GetModule(context.Background(), "a", "v1")
	if ok || err == nil || other != 0 {
		t.Errorf("ok=%v err=%v, %d requests to the other host", ok, err, other)
	}
}
