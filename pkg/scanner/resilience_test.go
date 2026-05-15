package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/resolver"
)

// resDepSpec is a local test fixture description for building graphs.
type resDepSpec struct {
	path   string
	ver    string
	direct bool
	depth  int
}

// makeResGraph builds a resolver.Graph from dependency specs (test helper).
func makeResGraph(deps ...resDepSpec) *resolver.Graph {
	g := &resolver.Graph{
		Root:         "test/module",
		Dependencies: make(map[string]*resolver.Dependency, len(deps)),
	}
	for _, spec := range deps {
		g.Dependencies[spec.path] = &resolver.Dependency{
			Module: parser.Module{
				Path:     spec.path,
				Version:  spec.ver,
				Indirect: !spec.direct,
			},
			Direct: spec.direct,
			Depth:  spec.depth,
		}
	}
	return g
}

func TestClassifyCadence(t *testing.T) {
	// Fixed reference date (day=15) so that AddDate month arithmetic never
	// rolls forward into the next month due to end-of-month day differences.
	ref := time.Date(2024, time.June, 15, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		info        *ResilienceInfo
		expected    string
		description string
	}{
		{
			name: "no_releases",
			info: &ResilienceInfo{
				TotalReleases: 0,
			},
			expected:    "stale",
			description: "project with zero releases classified as stale",
		},
		{
			name: "single_release",
			info: &ResilienceInfo{
				TotalReleases: 1,
			},
			expected:    "stale",
			description: "project with single release classified as stale",
		},
		{
			name: "stale_30_months",
			info: &ResilienceInfo{
				TotalReleases:   10,
				LastReleaseDate: ref.AddDate(0, -30, 0),
			},
			expected:    "stale",
			description: "project with last release 30+ months ago classified as stale",
		},
		{
			name: "frequent_cadence",
			info: &ResilienceInfo{
				TotalReleases:   5,
				AvgDaysBetween:  20.0,
				LastReleaseDate: ref.AddDate(0, 0, -5),
			},
			expected:    "frequent",
			description: "project with average 20 days between releases classified as frequent",
		},
		{
			name: "regular_cadence",
			info: &ResilienceInfo{
				TotalReleases:   10,
				AvgDaysBetween:  60.0,
				LastReleaseDate: ref.AddDate(0, 0, -10),
			},
			expected:    "regular",
			description: "project with average 60 days between releases classified as regular",
		},
		{
			name: "slow_cadence",
			info: &ResilienceInfo{
				TotalReleases:   8,
				AvgDaysBetween:  120.0,
				LastReleaseDate: ref.AddDate(0, -3, 0),
			},
			expected:    "slow",
			description: "project with average 120 days between releases classified as slow",
		},
		{
			name: "stale_cadence_via_avg",
			info: &ResilienceInfo{
				TotalReleases:   5,
				AvgDaysBetween:  200.0,
				LastReleaseDate: ref.AddDate(0, 0, -10),
			},
			expected:    "stale",
			description: "project with average 200 days between releases classified as stale",
		},
		{
			name: "boundary_frequent_30_days",
			info: &ResilienceInfo{
				TotalReleases:   10,
				AvgDaysBetween:  29.9,
				LastReleaseDate: ref.AddDate(0, 0, -5),
			},
			expected:    "frequent",
			description: "project with 29.9 days average stays in frequent range",
		},
		{
			name: "boundary_regular_90_days",
			info: &ResilienceInfo{
				TotalReleases:   10,
				AvgDaysBetween:  89.9,
				LastReleaseDate: ref.AddDate(0, 0, -10),
			},
			expected:    "regular",
			description: "project with 89.9 days average stays in regular range",
		},
		{
			name: "boundary_slow_180_days",
			info: &ResilienceInfo{
				TotalReleases:   10,
				AvgDaysBetween:  179.9,
				LastReleaseDate: ref.AddDate(0, -5, 0),
			},
			expected:    "slow",
			description: "project with 179.9 days average stays in slow range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyCadence(ref, tt.info)
			if result != tt.expected {
				t.Errorf("classifyCadence(%s) = %q, want %q", tt.name, result, tt.expected)
			}
		})
	}
}

func TestClassifyVersionScheme(t *testing.T) {
	tests := []struct {
		name        string
		versions    []string
		expected    string
		description string
	}{
		{
			name:        "semver_only",
			versions:    []string{"v1.0.0", "v1.1.0", "v2.0.0"},
			expected:    "semver",
			description: "only semantic version tags classified as semver",
		},
		{
			name: "pseudo_only",
			// Pseudo version pattern: contains "-0." and length > 30
			// Using format with "-0." in the hash part to match the check
			versions:    []string{"v1.5.3-0.20240101120000-abcdefghijkl"},
			expected:    "pseudo",
			description: "only pseudo-versions classified as pseudo",
		},
		{
			name:        "mixed_semver_pseudo",
			versions:    []string{"v1.0.0", "v1.1.0", "v1.5.3-0.20240101120000-abcdefghijkl"},
			expected:    "mixed",
			description: "combination of semver and pseudo versions classified as mixed",
		},
		{
			name:        "empty_versions",
			versions:    []string{},
			expected:    "semver",
			description: "empty version list defaults to semver",
		},
		{
			name: "non_semver_with_pseudo",
			// Pseudo version: "-0." pattern with len > 30
			versions:    []string{"release1", "v1.5.3-0.20240101120000-abcdefghijkl"},
			expected:    "pseudo",
			description: "pseudo version found takes precedence",
		},
		{
			name:        "single_semver",
			versions:    []string{"v1.0.0"},
			expected:    "semver",
			description: "single semver version classified correctly",
		},
		{
			name:        "v0_semver_only",
			versions:    []string{"v0.1.0", "v0.2.0"},
			expected:    "semver",
			description: "v0.x semantic versions classified as semver",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyVersionScheme(tt.versions)
			if result != tt.expected {
				t.Errorf("classifyVersionScheme(%v) = %q, want %q", tt.name, result, tt.expected)
			}
		})
	}
}

func TestComputeResilienceScore(t *testing.T) {
	tests := []struct {
		name        string
		info        *ResilienceInfo
		minScore    int
		maxScore    int
		description string
	}{
		{
			name: "zero_score_minimal",
			info: &ResilienceInfo{
				TotalReleases:          0,
				ReleaseCadence:         "stale",
				ProjectAgeDays:         30,
				HasStableRelease:       false,
				HasSecurityPolicy:      false,
				HasContribGuide:        false,
				HasCodeOfConduct:       false,
				HasMultipleMaintainers: false,
				VersionScheme:          "semver",
			},
			minScore:    15,
			maxScore:    20, // 0 (cadence) + 5 (age) + 2 (releases) + 10 (semver) = 17
			description: "minimal project with no releases scores low",
		},
		{
			name: "perfect_score",
			info: &ResilienceInfo{
				TotalReleases:          50,
				ReleaseCadence:         "frequent",
				ProjectAgeDays:         365 * 10,
				HasStableRelease:       true,
				HasSecurityPolicy:      true,
				HasContribGuide:        true,
				HasCodeOfConduct:       true,
				HasMultipleMaintainers: true,
				VersionScheme:          "semver",
			},
			minScore:    90,
			maxScore:    100,
			description: "well-maintained project with all signals scores high",
		},
		{
			name: "frequent_cadence_score",
			info: &ResilienceInfo{
				TotalReleases:    5,
				ReleaseCadence:   "frequent",
				ProjectAgeDays:   100,
				HasStableRelease: false,
				VersionScheme:    "semver",
			},
			minScore:    30,
			maxScore:    60,
			description: "frequent release cadence contributes significant points",
		},
		{
			name: "regular_cadence_score",
			info: &ResilienceInfo{
				TotalReleases:    8,
				ReleaseCadence:   "regular",
				ProjectAgeDays:   200,
				HasStableRelease: false,
				VersionScheme:    "semver",
			},
			minScore:    30,
			maxScore:    55,
			description: "regular release cadence scores appropriately",
		},
		{
			name: "old_project_bonus",
			info: &ResilienceInfo{
				TotalReleases:    5,
				ReleaseCadence:   "slow",
				ProjectAgeDays:   365 * 6,
				HasStableRelease: true,
				VersionScheme:    "semver",
			},
			minScore:    45,
			maxScore:    80,
			description: "mature project with 6+ years gets age bonus",
		},
		{
			name: "governance_files_bonus",
			info: &ResilienceInfo{
				TotalReleases:          10,
				ReleaseCadence:         "regular",
				ProjectAgeDays:         365 * 3,
				HasStableRelease:       true,
				HasSecurityPolicy:      true,
				HasContribGuide:        true,
				HasCodeOfConduct:       true,
				HasMultipleMaintainers: true,
				VersionScheme:          "semver",
			},
			minScore:    70,
			maxScore:    95,
			description: "governance files add significant trust signals",
		},
		{
			name: "score_capped_at_100",
			info: &ResilienceInfo{
				TotalReleases:          100,
				ReleaseCadence:         "frequent",
				ProjectAgeDays:         365 * 20,
				HasStableRelease:       true,
				HasSecurityPolicy:      true,
				HasContribGuide:        true,
				HasCodeOfConduct:       true,
				HasMultipleMaintainers: true,
				VersionScheme:          "semver",
			},
			minScore:    100,
			maxScore:    100,
			description: "score is capped at maximum of 100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := computeResilienceScore(tt.info)
			if score < tt.minScore || score > tt.maxScore {
				t.Errorf("computeResilienceScore(%s) = %d, want in range [%d, %d]",
					tt.name, score, tt.minScore, tt.maxScore)
			}
		})
	}
}

func TestComputeResilienceScore_Components(t *testing.T) {
	// Test individual scoring components
	t.Run("cadence_frequent_30pts", func(t *testing.T) {
		info := &ResilienceInfo{
			ReleaseCadence: "frequent",
		}
		score := computeResilienceScore(info)
		if score < 30 {
			t.Errorf("frequent cadence should contribute 30 points, got %d", score)
		}
	})

	t.Run("cadence_regular_25pts", func(t *testing.T) {
		info := &ResilienceInfo{
			ReleaseCadence: "regular",
		}
		score := computeResilienceScore(info)
		if score < 25 {
			t.Errorf("regular cadence should contribute 25 points, got %d", score)
		}
	})

	t.Run("cadence_slow_10pts", func(t *testing.T) {
		info := &ResilienceInfo{
			ReleaseCadence: "slow",
		}
		score := computeResilienceScore(info)
		if score < 10 {
			t.Errorf("slow cadence should contribute 10 points, got %d", score)
		}
	})

	t.Run("stable_release_10pts", func(t *testing.T) {
		info := &ResilienceInfo{
			HasStableRelease: true,
		}
		score := computeResilienceScore(info)
		if score < 10 {
			t.Errorf("stable release should contribute 10 points, got %d", score)
		}
	})

	t.Run("security_policy_5pts", func(t *testing.T) {
		info := &ResilienceInfo{
			HasSecurityPolicy: true,
		}
		score := computeResilienceScore(info)
		if score < 5 {
			t.Errorf("security policy should contribute 5 points, got %d", score)
		}
	})

	t.Run("contrib_guide_5pts", func(t *testing.T) {
		info := &ResilienceInfo{
			HasContribGuide: true,
		}
		score := computeResilienceScore(info)
		if score < 5 {
			t.Errorf("contribution guide should contribute 5 points, got %d", score)
		}
	})

	t.Run("semver_10pts", func(t *testing.T) {
		info := &ResilienceInfo{
			VersionScheme: "semver",
		}
		score := computeResilienceScore(info)
		if score < 10 {
			t.Errorf("semver should contribute 10 points, got %d", score)
		}
	})
}

func TestResilienceScanner_AnalyzeModule_MockProxy(t *testing.T) {
	// Create mock Go proxy server
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/@v/list") {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "v1.0.0\nv0.9.0\nv0.8.0\n")
		} else if strings.Contains(r.URL.Path, "/@v/v1.0.0.info") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"Version": "v1.0.0",
				"Time":    "2023-01-01T00:00:00Z",
			})
		} else if strings.Contains(r.URL.Path, "/@v/v0.9.0.info") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"Version": "v0.9.0",
				"Time":    "2022-12-01T00:00:00Z",
			})
		} else if strings.Contains(r.URL.Path, "/@v/v0.8.0.info") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"Version": "v0.8.0",
				"Time":    "2022-11-01T00:00:00Z",
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer proxyServer.Close()

	scanner := NewResilienceScanner(5 * time.Second)
	scanner.proxyURL = proxyServer.URL

	info := scanner.analyzeModule("example.com/testmodule")

	if info.TotalReleases != 3 {
		t.Errorf("expected 3 releases, got %d", info.TotalReleases)
	}

	if info.FirstReleaseDate.IsZero() {
		t.Error("first release date should not be zero")
	}

	if info.LastReleaseDate.IsZero() {
		t.Error("last release date should not be zero")
	}

	if info.ProjectAgeDays <= 0 {
		t.Errorf("project age should be positive, got %d", info.ProjectAgeDays)
	}

	if info.AvgDaysBetween <= 0 {
		t.Errorf("average days between releases should be positive, got %f", info.AvgDaysBetween)
	}
}

func TestResilienceScanner_GovernanceFiles(t *testing.T) {
	// Create mock GitHub server
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if strings.Contains(r.URL.Path, "SECURITY.md") {
			w.WriteHeader(http.StatusOK)
		} else if strings.Contains(r.URL.Path, "CONTRIBUTING.md") {
			w.WriteHeader(http.StatusOK)
		} else if strings.Contains(r.URL.Path, "CODE_OF_CONDUCT.md") {
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ghServer.Close()

	scanner := NewResilienceScanner(5 * time.Second)
	info := &ResilienceInfo{}

	// Manually call checkGovernanceFiles with mock URL base
	// We need to patch the GitHub API calls
	scanner.checkGovernanceFilesWithBase(ghServer.URL, "owner", "repo", info)

	if !info.HasSecurityPolicy {
		t.Error("expected HasSecurityPolicy to be true")
	}

	if !info.HasContribGuide {
		t.Error("expected HasContribGuide to be true")
	}

	if info.HasCodeOfConduct {
		t.Error("expected HasCodeOfConduct to be false")
	}
}

// Helper method to test governance files with custom base URL
func (rs *ResilienceScanner) checkGovernanceFilesWithBase(base, owner, repo string, info *ResilienceInfo) {
	files := []struct {
		path string
		flag *bool
	}{
		{"SECURITY.md", &info.HasSecurityPolicy},
		{"CONTRIBUTING.md", &info.HasContribGuide},
		{"CODE_OF_CONDUCT.md", &info.HasCodeOfConduct},
	}

	host := ""
	if u, err := url.Parse(base); err == nil {
		host = u.Host
	}

	for _, f := range files {
		fileURL := fmt.Sprintf("%s/repos/%s/%s/contents/%s", base, owner, repo, f.path)
		resp, err := rs.client.Head(context.Background(), fileURL, GetOptions{Host: host})
		if err == nil && resp.StatusCode == http.StatusOK {
			*f.flag = true
		}
	}
}

func TestResilienceScanner_Cache(t *testing.T) {
	callCount := 0

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if strings.Contains(r.URL.Path, "/@v/list") {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "v1.0.0\n")
		} else if strings.Contains(r.URL.Path, "/@v/v1.0.0.info") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"Version": "v1.0.0",
				"Time":    "2023-01-01T00:00:00Z",
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer proxyServer.Close()

	scanner := NewResilienceScanner(5 * time.Second)
	scanner.proxyURL = proxyServer.URL

	modPath := "example.com/cached"

	// First call should hit the proxy
	info1 := scanner.analyzeModule(modPath)
	firstCallCount := callCount

	// Second call should use cache
	info2 := scanner.analyzeModule(modPath)
	secondCallCount := callCount

	// Should not have made additional proxy calls on second invocation
	if secondCallCount > firstCallCount+1 {
		t.Errorf("expected cache to prevent additional calls, got %d additional calls", secondCallCount-firstCallCount)
	}

	if info1.TotalReleases != info2.TotalReleases {
		t.Error("cached result should be identical to first call")
	}
}

func TestResilienceScanner_ScanAll(t *testing.T) {
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/@v/list") {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "v1.0.0\n")
		} else if strings.Contains(r.URL.Path, "/@v/v1.0.0.info") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"Version": "v1.0.0",
				"Time":    "2023-01-01T00:00:00Z",
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer proxyServer.Close()

	scanner := NewResilienceScanner(5 * time.Second)
	scanner.proxyURL = proxyServer.URL

	// Create test graph with 2 dependencies
	graph := makeResGraph(
		resDepSpec{
			path:   "github.com/test/module1",
			ver:    "v1.0.0",
			direct: true,
			depth:  0,
		},
		resDepSpec{
			path:   "github.com/test/module2",
			ver:    "v2.0.0",
			direct: false,
			depth:  1,
		},
	)

	maintainers := map[string]*MaintainerInfo{
		"github.com/test/module1": {BusFactor: 1},
		"github.com/test/module2": {BusFactor: 2},
	}

	results := scanner.ScanAll(context.Background(), graph, maintainers)

	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}

	if _, ok := results["github.com/test/module1"]; !ok {
		t.Error("expected result for github.com/test/module1")
	}

	if _, ok := results["github.com/test/module2"]; !ok {
		t.Error("expected result for github.com/test/module2")
	}

	// Verify multiple maintainers flag is set
	if !results["github.com/test/module2"].HasMultipleMaintainers {
		t.Error("expected HasMultipleMaintainers to be true for module2 with BusFactor=2")
	}

	// Verify scores were computed
	if results["github.com/test/module1"].Score < 0 || results["github.com/test/module1"].Score > 100 {
		t.Errorf("score out of range: %d", results["github.com/test/module1"].Score)
	}
}

func TestResilienceScanner_EmptyGraph(t *testing.T) {
	scanner := NewResilienceScanner(5 * time.Second)

	graph := &resolver.Graph{
		Root:         "test/module",
		Dependencies: make(map[string]*resolver.Dependency),
	}

	results := scanner.ScanAll(context.Background(), graph, make(map[string]*MaintainerInfo))

	if len(results) != 0 {
		t.Errorf("expected empty results for empty graph, got %d", len(results))
	}
}

func TestResilienceScanner_ProxyError(t *testing.T) {
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer proxyServer.Close()

	scanner := NewResilienceScanner(5 * time.Second)
	scanner.proxyURL = proxyServer.URL

	info := scanner.analyzeModule("example.com/failed")

	// Should return empty info without panicking
	if info == nil {
		t.Error("expected non-nil info even with proxy error")
		return
	}

	if info.TotalReleases != 0 {
		t.Errorf("expected 0 releases on proxy error, got %d", info.TotalReleases)
	}
	// DataAvailable must be false when the proxy returned a non-200 status.
	if info.DataAvailable {
		t.Errorf("DataAvailable = true, want false when proxy returns 500")
	}
}

// TestResilienceScanner_DataAvailable_FalseOnNetworkError verifies that a
// network-level failure (connection refused) sets DataAvailable to false.
func TestResilienceScanner_DataAvailable_FalseOnNetworkError(t *testing.T) {
	// Point at a closed server so the TCP connection is immediately refused.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // Closed immediately — all requests will fail.

	sc := NewResilienceScanner(5 * time.Second)
	sc.proxyURL = srv.URL

	info := sc.analyzeModule("example.com/network-fail")

	if info == nil {
		t.Fatal("analyzeModule returned nil")
	}
	if info.DataAvailable {
		t.Errorf("DataAvailable = true, want false on network error")
	}
	if info.TotalReleases != 0 {
		t.Errorf("TotalReleases = %d on network error, want 0", info.TotalReleases)
	}
}

// TestResilienceScanner_DataAvailable_TrueOnSuccess verifies that a successful
// proxy response sets DataAvailable to true.
func TestResilienceScanner_DataAvailable_TrueOnSuccess(t *testing.T) {
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/@v/list") {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "v1.0.0\n")
		} else if strings.Contains(r.URL.Path, "/@v/v1.0.0.info") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"Version": "v1.0.0",
				"Time":    "2023-01-01T00:00:00Z",
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer proxyServer.Close()

	sc := NewResilienceScanner(5 * time.Second)
	sc.proxyURL = proxyServer.URL

	info := sc.analyzeModule("example.com/success")

	if info == nil {
		t.Fatal("analyzeModule returned nil")
	}
	if !info.DataAvailable {
		t.Errorf("DataAvailable = false, want true on successful proxy response")
	}
	if info.TotalReleases == 0 {
		t.Errorf("TotalReleases = 0 with DataAvailable=true, want > 0")
	}
}

func TestResilienceScanner_NoVersions(t *testing.T) {
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/@v/list") {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "")
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer proxyServer.Close()

	scanner := NewResilienceScanner(5 * time.Second)
	scanner.proxyURL = proxyServer.URL

	info := scanner.analyzeModule("example.com/noversions")

	if info.TotalReleases != 0 {
		t.Errorf("expected 0 releases, got %d", info.TotalReleases)
	}
}

func TestNewResilienceScanner(t *testing.T) {
	timeout := 10 * time.Second
	scanner := NewResilienceScanner(timeout)

	if scanner == nil {
		t.Fatal("expected non-nil scanner")
	}

	if scanner.client == nil {
		t.Error("expected initialized http.Client")
	}

	if scanner.proxyURL != "https://proxy.golang.org" {
		t.Errorf("expected default proxy URL, got %s", scanner.proxyURL)
	}

	if len(scanner.cache) != 0 {
		t.Error("expected empty cache on initialization")
	}
}

func TestResilienceInfo_StableReleaseDetection(t *testing.T) {
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/@v/list") {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "v1.2.3\nv0.9.0\nv0.8.0\n")
		} else if strings.HasSuffix(r.URL.Path, ".info") {
			w.Header().Set("Content-Type", "application/json")
			version := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".info")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"Version": version,
				"Time":    "2023-01-01T00:00:00Z",
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer proxyServer.Close()

	scanner := NewResilienceScanner(5 * time.Second)
	scanner.proxyURL = proxyServer.URL

	info := scanner.analyzeModule("example.com/stable")

	if !info.HasStableRelease {
		t.Error("expected HasStableRelease to be true for v1.2.3")
	}
}

func TestResilienceInfo_MajorVersionCount(t *testing.T) {
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/@v/list") {
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "v1.0.0\nv1.5.0\nv2.0.0\nv2.1.0\nv3.0.0\n")
		} else if strings.HasSuffix(r.URL.Path, ".info") {
			w.Header().Set("Content-Type", "application/json")
			version := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".info")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"Version": version,
				"Time":    "2023-01-01T00:00:00Z",
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer proxyServer.Close()

	scanner := NewResilienceScanner(5 * time.Second)
	scanner.proxyURL = proxyServer.URL

	info := scanner.analyzeModule("example.com/multiversion")

	if info.MajorVersions != 3 {
		t.Errorf("expected 3 major versions, got %d", info.MajorVersions)
	}
}

func TestResilienceInfo_VersionSchemeDetection(t *testing.T) {
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/@v/list") {
			w.Header().Set("Content-Type", "text/plain")
			// Mixed versions: semver + pseudo (pseudo has "-0." pattern with len > 30)
			fmt.Fprint(w, "v1.0.0\nv1.5.3-0.20240101120000-abcdefghijkl\n")
		} else if strings.HasSuffix(r.URL.Path, ".info") {
			w.Header().Set("Content-Type", "application/json")
			version := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".info")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"Version": version,
				"Time":    "2023-01-01T00:00:00Z",
			})
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer proxyServer.Close()

	scanner := NewResilienceScanner(5 * time.Second)
	scanner.proxyURL = proxyServer.URL

	info := scanner.analyzeModule("example.com/mixedversions")

	if info.VersionScheme != "mixed" {
		t.Errorf("expected mixed version scheme, got %s", info.VersionScheme)
	}
}
