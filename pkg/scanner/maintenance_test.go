package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// Utility function tests
// ============================================================================

// TestEncodeModulePath verifies module path encoding for Go module proxy spec.
func TestEncodeModulePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		// Lowercase-only paths (no escaping needed)
		{name: "lowercase_only", path: "github.com/gin-gonic/gin", expected: "github.com/gin-gonic/gin"},
		{name: "single_lowercase", path: "redis", expected: "redis"},

		// Single uppercase letters
		{name: "single_uppercase_A", path: "A", expected: "!a"},
		{name: "single_uppercase_Z", path: "Z", expected: "!z"},

		// All uppercase
		{name: "all_uppercase", path: "ABC", expected: "!a!b!c"},

		// Mixed case - Go module proxy spec escapes uppercase as !lowercase
		{name: "github_capitalized", path: "github.com/Foo/Bar", expected: "github.com/!foo/!bar"},
		{name: "mixed_case_path", path: "golang.org/x/Text", expected: "golang.org/x/!text"},

		// Multiple uppercase letters in sequence
		{name: "consecutive_uppercase", path: "HTTPClient", expected: "!h!t!t!p!client"},

		// Uppercase at different positions
		{name: "uppercase_start", path: "MyModule", expected: "!my!module"},
		{name: "uppercase_middle", path: "myModulePath", expected: "my!module!path"},
		{name: "uppercase_end", path: "moduleName", expected: "module!name"},

		// Real-world examples
		{name: "github_protobuf", path: "github.com/golang/protobuf", expected: "github.com/golang/protobuf"},
		{name: "gorm_io", path: "gorm.io/gorm", expected: "gorm.io/gorm"},

		// Empty string
		{name: "empty_string", path: "", expected: ""},

		// Numbers (should not be escaped)
		{name: "with_numbers", path: "github.com/v2/package", expected: "github.com/v2/package"},
		{name: "uppercase_with_numbers", path: "V2Package", expected: "!v2!package"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeModulePath(tt.path)
			if got != tt.expected {
				t.Errorf("encodeModulePath(%q) = %q, want %q", tt.path, got, tt.expected)
			}
		})
	}
}

// TestMonthsSince verifies calculation of months since a given time.
// A fixed reference date (15th of the month) is used for both "now" and the
// base for all offsets so that AddDate never rolls into the wrong month due to
// end-of-month day differences.
func TestMonthsSince(t *testing.T) {
	// Day 15 is safe: subtracting any number of months from the 15th always
	// lands on the 15th of the target month, regardless of month length.
	ref := time.Date(2024, time.June, 15, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		time     time.Time
		expected int
	}{
		// Zero time (not set)
		{name: "zero_time", time: time.Time{}, expected: 0},

		// Exactly the reference instant (0 months)
		{name: "today", time: ref, expected: 0},

		// Yesterday (< 1 month, so 0)
		{name: "yesterday", time: ref.AddDate(0, 0, -1), expected: 0},

		// 1 month ago
		{name: "one_month_ago", time: ref.AddDate(0, -1, 0), expected: 1},

		// 6 months ago
		{name: "six_months_ago", time: ref.AddDate(0, -6, 0), expected: 6},

		// 12 months ago (1 year)
		{name: "twelve_months_ago", time: ref.AddDate(0, -12, 0), expected: 12},

		// 18 months ago (1 year 6 months)
		{name: "eighteen_months_ago", time: ref.AddDate(0, -18, 0), expected: 18},

		// 24 months ago (2 years)
		{name: "twenty_four_months_ago", time: ref.AddDate(-2, 0, 0), expected: 24},

		// Multiple years
		{name: "three_years_ago", time: ref.AddDate(-3, 0, 0), expected: 36},

		// Future time (should return 0, clamped)
		{name: "future_one_month", time: ref.AddDate(0, 1, 0), expected: 0},
		{name: "future_one_year", time: ref.AddDate(1, 0, 0), expected: 0},

		// Within the same month (< 1 month) — use 5 days so it stays in June
		{name: "five_days_ago", time: ref.AddDate(0, 0, -5), expected: 0},

		// One month and a few days ago (still counts as 1 month)
		{name: "month_boundary_test", time: ref.AddDate(0, -1, -5), expected: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := monthsSince(ref, tt.time)
			if got != tt.expected {
				t.Errorf("monthsSince(%v) = %d, want %d (ref=%v)", tt.time, got, tt.expected, ref)
			}
		})
	}
}

// ============================================================================
// Mock proxy server helper
// ============================================================================

// mockProxyServer creates a test HTTP server that mimics the Go module proxy API.
// Returns the server and a request counter for testing caching.
func newMockProxy(t *testing.T) (*httptest.Server, *requestCounter) {
	counter := &requestCounter{counts: make(map[string]int)}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		counter.mu.Lock()
		counter.counts[path]++
		counter.mu.Unlock()

		// Parse path: /{module}/@v/{version}.info or /{module}/@latest or /{module}/@v/list
		// Example: /github.com/!foo/!bar/@latest

		switch {
		case isSuffix(path, "/@latest"):
			// Return latest version info
			info := proxyVersionInfo{
				Version: "v1.0.0",
				Time:    time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(info)

		case isSuffix(path, "/@v/list"):
			// Return version list or 410 for deprecated modules
			if contains(path, "deprecated") {
				w.WriteHeader(http.StatusGone)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "v1.0.0\nv0.9.0\nv0.8.0\n")

		case isSuffix(path, "/@v/v0.error.info"):
			// Simulate a proxy error
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Internal server error")

		case isSuffix(path, ".info"):
			// Return version info for specific version
			info := proxyVersionInfo{
				Version: "v1.0.0",
				Time:    time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(info)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	return server, counter
}

// requestCounter tracks HTTP requests to the mock proxy.
type requestCounter struct {
	counts map[string]int
	mu     sync.RWMutex
}

func (rc *requestCounter) count(path string) int {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.counts[path]
}

// Helper functions for mock server
func isSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && findSubstring(s, sub))
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ============================================================================
// MaintenanceScanner tests
// ============================================================================

// TestNewMaintenanceScanner verifies scanner initialization.
func TestNewMaintenanceScanner(t *testing.T) {
	ms := NewMaintenanceScanner(10 * time.Second)

	if ms == nil {
		t.Fatal("NewMaintenanceScanner returned nil")
	}

	if ms.client == nil {
		t.Error("client is nil")
	}

	if ms.client.Timeout() != 10*time.Second {
		t.Errorf("client timeout = %v, want 10s", ms.client.Timeout())
	}

	if ms.proxyURL != "https://proxy.golang.org" {
		t.Errorf("proxyURL = %q, want https://proxy.golang.org", ms.proxyURL)
	}

	if ms.cache == nil {
		t.Error("cache is nil")
	}

	if len(ms.cache) != 0 {
		t.Errorf("cache should be empty on init, got %d items", len(ms.cache))
	}
}

// TestMaintenanceScanner_CheckModule verifies basic module checking with proxy.
func TestMaintenanceScanner_CheckModule(t *testing.T) {
	server, _ := newMockProxy(t)
	defer server.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = server.URL

	info, err := ms.checkModule("github.com/foo/bar", "v1.0.0")
	if err != nil {
		t.Fatalf("checkModule failed: %v", err)
	}

	if info == nil {
		t.Fatalf("checkModule returned nil info")
	}

	if info.LatestVersion != "v1.0.0" {
		t.Errorf("LatestVersion = %q, want %q", info.LatestVersion, "v1.0.0")
	}

	if info.LastRelease != time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC) {
		t.Errorf("LastRelease = %v, want %v", info.LastRelease, time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC))
	}

	if info.MonthsSinceRelease < 0 {
		t.Errorf("MonthsSinceRelease = %d, want >= 0", info.MonthsSinceRelease)
	}

	if info.Deprecated {
		t.Error("Deprecated = true, want false")
	}

	if info.Archived {
		t.Error("Archived = true, want false")
	}
}

// TestMaintenanceScanner_CheckModule_Deprecated verifies deprecation detection via 410 status.
func TestMaintenanceScanner_CheckModule_Deprecated(t *testing.T) {
	server, _ := newMockProxy(t)
	defer server.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = server.URL

	// Use a module path that contains "deprecated"
	info, err := ms.checkModule("github.com/foo/deprecated-lib", "v1.0.0")
	if err != nil {
		t.Fatalf("checkModule failed: %v", err)
	}

	if !info.Deprecated {
		t.Error("Deprecated = false, want true (410 Gone)")
	}
}

// TestMaintenanceScanner_CheckModule_ProxyError verifies handling of proxy errors.
func TestMaintenanceScanner_CheckModule_ProxyError(t *testing.T) {
	server, _ := newMockProxy(t)
	defer server.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = server.URL

	// Fetch a version that will trigger a 500 error
	info, _ := ms.checkModule("github.com/foo/bar", "v0.error")

	// Error handling: the scanner's fetchVersionInfo may return an error,
	// but checkModule continues and returns a MaintenanceInfo with zero values.
	if info == nil {
		t.Fatalf("checkModule returned nil (should not panic, but returned MaintenanceInfo)")
	}

	// The info should have safe zero values
	if info.MonthsSinceRelease < 0 {
		t.Errorf("MonthsSinceRelease should be >= 0, got %d", info.MonthsSinceRelease)
	}
}

// TestMaintenanceScanner_Cache verifies caching prevents duplicate proxy requests.
func TestMaintenanceScanner_Cache(t *testing.T) {
	server, counter := newMockProxy(t)
	defer server.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = server.URL

	modPath := "github.com/foo/bar"

	// First call
	_, err := ms.checkModule(modPath, "v1.0.0")
	if err != nil {
		t.Fatalf("first checkModule failed: %v", err)
	}

	// Count requests to @latest endpoint
	firstCallCount := counter.count(fmt.Sprintf("/%s/@latest", encodeModulePath(modPath)))

	// Second call (should use cache)
	_, err = ms.checkModule(modPath, "v1.0.0")
	if err != nil {
		t.Fatalf("second checkModule failed: %v", err)
	}

	// Count requests again
	secondCallCount := counter.count(fmt.Sprintf("/%s/@latest", encodeModulePath(modPath)))

	// The count should be the same (cache hit on second call)
	if firstCallCount != secondCallCount {
		t.Errorf("requests to @latest: first=%d, second=%d; expected same count (cache hit)", firstCallCount, secondCallCount)
	}
}

// TestMaintenanceScanner_FetchVersionInfo_Success verifies fetching specific version info.
func TestMaintenanceScanner_FetchVersionInfo_Success(t *testing.T) {
	server, _ := newMockProxy(t)
	defer server.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = server.URL

	versionInfo, err := ms.fetchVersionInfo("github.com/foo/bar", "v1.0.0")
	if err != nil {
		t.Fatalf("fetchVersionInfo failed: %v", err)
	}

	if versionInfo == nil {
		t.Fatalf("fetchVersionInfo returned nil")
	}

	if versionInfo.Version != "v1.0.0" {
		t.Errorf("Version = %q, want %q", versionInfo.Version, "v1.0.0")
	}

	if versionInfo.Time != time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC) {
		t.Errorf("Time = %v, want %v", versionInfo.Time, time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC))
	}
}

// TestMaintenanceScanner_FetchVersionInfo_ProxyError verifies error handling in fetchVersionInfo.
func TestMaintenanceScanner_FetchVersionInfo_ProxyError(t *testing.T) {
	server, _ := newMockProxy(t)
	defer server.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = server.URL

	// Use a version that triggers a 500 error
	versionInfo, err := ms.fetchVersionInfo("github.com/foo/bar", "v0.error")
	if err == nil {
		t.Fatalf("fetchVersionInfo should return error for proxy error, got nil")
	}

	if versionInfo != nil {
		t.Errorf("fetchVersionInfo should return nil info on error")
	}
}

// TestMaintenanceScanner_FetchLatestVersion_Success verifies fetching latest version.
func TestMaintenanceScanner_FetchLatestVersion_Success(t *testing.T) {
	server, _ := newMockProxy(t)
	defer server.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = server.URL

	version, timestamp := ms.fetchLatestVersion("github.com/foo/bar")

	if version != "v1.0.0" {
		t.Errorf("version = %q, want %q", version, "v1.0.0")
	}

	if timestamp != time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC) {
		t.Errorf("timestamp = %v, want %v", timestamp, time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC))
	}
}

// TestMaintenanceScanner_FetchLatestVersion_ProxyError verifies error handling in fetchLatestVersion.
func TestMaintenanceScanner_FetchLatestVersion_ProxyError(t *testing.T) {
	server, _ := newMockProxy(t)
	server.Close() // Close server to cause connection error

	ms := NewMaintenanceScanner(1 * time.Millisecond) // Very short timeout
	ms.proxyURL = server.URL

	version, timestamp := ms.fetchLatestVersion("github.com/foo/bar")

	if version != "" {
		t.Errorf("version should be empty on error, got %q", version)
	}

	if !timestamp.IsZero() {
		t.Errorf("timestamp should be zero on error, got %v", timestamp)
	}
}

// TestMaintenanceScanner_CheckDeprecation_Deprecated verifies deprecation detection.
func TestMaintenanceScanner_CheckDeprecation_Deprecated(t *testing.T) {
	server, _ := newMockProxy(t)
	defer server.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = server.URL

	info := &MaintenanceInfo{}

	// Check a deprecated module path
	ms.checkDeprecation("github.com/foo/deprecated-lib", info)

	if !info.Deprecated {
		t.Error("Deprecated = false, want true")
	}
}

// TestMaintenanceScanner_CheckDeprecation_NotDeprecated verifies non-deprecated modules.
func TestMaintenanceScanner_CheckDeprecation_NotDeprecated(t *testing.T) {
	server, _ := newMockProxy(t)
	defer server.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = server.URL

	info := &MaintenanceInfo{}

	// Check a normal module path
	ms.checkDeprecation("github.com/foo/bar", info)

	if info.Deprecated {
		t.Error("Deprecated = true, want false")
	}
}

// TestMaintenanceScanner_CheckDeprecation_ProxyError verifies no panic on error.
func TestMaintenanceScanner_CheckDeprecation_ProxyError(t *testing.T) {
	server, _ := newMockProxy(t)
	server.Close() // Close to cause error

	ms := NewMaintenanceScanner(1 * time.Millisecond)
	ms.proxyURL = server.URL

	info := &MaintenanceInfo{}

	// Should not panic
	ms.checkDeprecation("github.com/foo/bar", info)

	// info should remain unchanged (not deprecated)
	if info.Deprecated {
		t.Error("Deprecated should remain false on proxy error")
	}
}

// TestMaintenanceScanner_ConcurrentChecks verifies thread-safe concurrent checking.
func TestMaintenanceScanner_ConcurrentChecks(t *testing.T) {
	server, _ := newMockProxy(t)
	defer server.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = server.URL

	// Spawn multiple goroutines checking different modules
	var wg sync.WaitGroup
	results := make(map[string]*MaintenanceInfo)
	var mu sync.Mutex

	modules := []string{
		"github.com/foo/bar",
		"github.com/baz/qux",
		"golang.org/x/crypto",
	}

	for _, modPath := range modules {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			info, err := ms.checkModule(path, "v1.0.0")
			if err != nil {
				t.Logf("checkModule(%q) error: %v", path, err)
				return
			}
			mu.Lock()
			results[path] = info
			mu.Unlock()
		}(modPath)
	}

	wg.Wait()

	if len(results) != len(modules) {
		t.Errorf("got %d results, want %d", len(results), len(modules))
	}

	// Verify all modules have valid MaintenanceInfo
	for _, modPath := range modules {
		if info, ok := results[modPath]; ok {
			if info == nil {
				t.Errorf("result for %q is nil", modPath)
			}
		}
	}
}

// TestMaintenanceScanner_MultipleInstances verifies independent scanner instances.
func TestMaintenanceScanner_MultipleInstances(t *testing.T) {
	server, _ := newMockProxy(t)
	defer server.Close()

	ms1 := NewMaintenanceScanner(5 * time.Second)
	ms1.proxyURL = server.URL

	ms2 := NewMaintenanceScanner(5 * time.Second)
	ms2.proxyURL = server.URL

	// Each should have independent caches
	info1, _ := ms1.checkModule("github.com/foo/bar", "v1.0.0")
	info2, _ := ms2.checkModule("github.com/foo/bar", "v1.0.0")

	if info1 == nil || info2 == nil {
		t.Fatalf("checkModule returned nil")
	}

	// Both should have same data from proxy but different cache instances
	if info1.LatestVersion != info2.LatestVersion {
		t.Errorf("LatestVersion mismatch: %q vs %q", info1.LatestVersion, info2.LatestVersion)
	}

	// Verify they have independent caches (calling again should hit cache in each)
	_, _ = ms1.checkModule("github.com/foo/bar", "v1.0.0")
	_, _ = ms2.checkModule("github.com/foo/bar", "v1.0.0")

	// Both should still work correctly
	if len(ms1.cache) == 0 || len(ms2.cache) == 0 {
		t.Error("caches should be populated")
	}
}

// TestMaintenanceScanner_CacheSize verifies cache only stores one entry per module.
func TestMaintenanceScanner_CacheSize(t *testing.T) {
	server, _ := newMockProxy(t)
	defer server.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = server.URL

	modPath := "github.com/foo/bar"

	// Call checkModule 5 times
	for i := 0; i < 5; i++ {
		_, _ = ms.checkModule(modPath, "v1.0.0")
	}

	// Cache should only have 1 entry
	if len(ms.cache) != 1 {
		t.Errorf("cache size = %d, want 1", len(ms.cache))
	}

	if _, ok := ms.cache[modPath]; !ok {
		t.Errorf("expected %q in cache", modPath)
	}
}
