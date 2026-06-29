package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/resolver"
)

// TestMaintenanceScanner_ScanAll verifies scanning multiple modules.
func TestMaintenanceScanner_ScanAll(t *testing.T) {
	server, _ := newMockProxy(t)
	defer server.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = server.URL

	graph := &resolver.Graph{
		Root: "test/module",
		Dependencies: map[string]*resolver.Dependency{
			"github.com/foo/bar": {
				Module: parser.Module{
					Path:     "github.com/foo/bar",
					Version:  "v1.0.0",
					Indirect: false,
				},
				Direct: true,
				Depth:  0,
			},
			"github.com/baz/qux": {
				Module: parser.Module{
					Path:     "github.com/baz/qux",
					Version:  "v0.9.0",
					Indirect: true,
				},
				Direct: false,
				Depth:  1,
			},
			"golang.org/x/crypto": {
				Module: parser.Module{
					Path:     "golang.org/x/crypto",
					Version:  "v0.1.0",
					Indirect: false,
				},
				Direct: true,
				Depth:  0,
			},
		},
	}

	results, err := ms.ScanAll(context.Background(), graph)
	if err != nil {
		t.Fatalf("ScanAll failed: %v", err)
	}

	if len(results) != 3 {
		t.Fatalf("ScanAll returned %d results, want 3", len(results))
	}

	// Verify all modules are in results
	expectedModules := []string{"github.com/foo/bar", "github.com/baz/qux", "golang.org/x/crypto"}
	for _, modPath := range expectedModules {
		if _, ok := results[modPath]; !ok {
			t.Errorf("expected result for %q, not found", modPath)
		}
	}

	// Verify each result has valid data
	for modPath, info := range results {
		if info == nil {
			t.Errorf("result for %q is nil", modPath)
			continue
		}
		if info.LatestVersion == "" {
			t.Errorf("LatestVersion for %q is empty", modPath)
		}
	}
}

// TestMaintenanceScanner_ScanAll_Empty verifies scanning an empty graph.
func TestMaintenanceScanner_ScanAll_Empty(t *testing.T) {
	server, _ := newMockProxy(t)
	defer server.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = server.URL

	graph := &resolver.Graph{
		Root:         "test/module",
		Dependencies: make(map[string]*resolver.Dependency),
	}

	results, err := ms.ScanAll(context.Background(), graph)
	if err != nil {
		t.Fatalf("ScanAll failed: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("ScanAll on empty graph returned %d results, want 0", len(results))
	}
}

// TestMaintenanceScanner_ScanAll_ErrorHandling verifies error handling in ScanAll.
func TestMaintenanceScanner_ScanAll_ErrorHandling(t *testing.T) {
	server, _ := newMockProxy(t)
	defer server.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = server.URL

	// Create a graph with a module that will cause an error
	graph := &resolver.Graph{
		Root: "test/module",
		Dependencies: map[string]*resolver.Dependency{
			"github.com/foo/bar": {
				Module: parser.Module{
					Path:     "github.com/foo/bar",
					Version:  "v1.0.0",
					Indirect: false,
				},
				Direct: true,
				Depth:  0,
			},
			"github.com/error/module": {
				Module: parser.Module{
					Path:     "github.com/error/module",
					Version:  "v0.error", // This version triggers a 500 error
					Indirect: false,
				},
				Direct: true,
				Depth:  0,
			},
		},
	}

	results, err := ms.ScanAll(context.Background(), graph)

	// fetchVersionInfo fails for v0.error but fetchLatestVersion succeeds, so no error.
	if err != nil {
		t.Fatalf("ScanAll() unexpected error: %v", err)
	}

	if len(results) != len(graph.Dependencies) {
		t.Fatalf("ScanAll() returned %d results, want %d", len(results), len(graph.Dependencies))
	}
}

// TestMaintenanceScanner_ScanAll_Concurrency verifies thread-safe concurrent scanning.
func TestMaintenanceScanner_ScanAll_Concurrency(t *testing.T) {
	server, _ := newMockProxy(t)
	defer server.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = server.URL

	// Create a graph with many dependencies to exercise concurrency
	graph := &resolver.Graph{
		Root: "test/module",
		Dependencies: map[string]*resolver.Dependency{
			"github.com/foo/bar": {
				Module: parser.Module{
					Path:     "github.com/foo/bar",
					Version:  "v1.0.0",
					Indirect: false,
				},
				Direct: true,
				Depth:  0,
			},
			"github.com/baz/qux": {
				Module: parser.Module{
					Path:     "github.com/baz/qux",
					Version:  "v0.9.0",
					Indirect: true,
				},
				Direct: false,
				Depth:  1,
			},
			"golang.org/x/crypto": {
				Module: parser.Module{
					Path:     "golang.org/x/crypto",
					Version:  "v0.1.0",
					Indirect: false,
				},
				Direct: true,
				Depth:  0,
			},
			"github.com/pkg/errors": {
				Module: parser.Module{
					Path:     "github.com/pkg/errors",
					Version:  "v0.8.0",
					Indirect: true,
				},
				Direct: false,
				Depth:  1,
			},
			"github.com/sirupsen/logrus": {
				Module: parser.Module{
					Path:     "github.com/sirupsen/logrus",
					Version:  "v1.2.0",
					Indirect: false,
				},
				Direct: true,
				Depth:  0,
			},
		},
	}

	// ScanAll uses a semaphore with 10 concurrent workers
	results, err := ms.ScanAll(context.Background(), graph)
	if err != nil {
		t.Logf("ScanAll returned error (first error captured): %v", err)
	}

	if len(results) != 5 {
		t.Errorf("ScanAll returned %d results, want 5", len(results))
	}

	// Verify all modules have valid MaintenanceInfo
	expectedModules := []string{
		"github.com/foo/bar",
		"github.com/baz/qux",
		"golang.org/x/crypto",
		"github.com/pkg/errors",
		"github.com/sirupsen/logrus",
	}
	for _, modPath := range expectedModules {
		if info, ok := results[modPath]; ok {
			if info == nil {
				t.Errorf("result for %q is nil", modPath)
			}
		}
	}
}

// TestMaintenanceScanner_ScanAll_ErrorAggregation verifies that the "N of M" error
// count is reported when multiple modules fail all proxy lookups.
func TestMaintenanceScanner_ScanAll_ErrorAggregation(t *testing.T) {
	// Server returns 500 for every request to a "fail-module" path, 200 otherwise.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "fail-module") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		info := proxyVersionInfo{
			Version: "v1.0.0",
			Time:    time.Date(2025, 1, 15, 0, 0, 0, 0, time.UTC),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info) //nolint:errcheck
	}))
	defer server.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = server.URL

	graph := &resolver.Graph{
		Root: "test/module",
		Dependencies: map[string]*resolver.Dependency{
			"github.com/fail-module/one":   {Module: parser.Module{Path: "github.com/fail-module/one", Version: "v1.0.0"}},
			"github.com/fail-module/two":   {Module: parser.Module{Path: "github.com/fail-module/two", Version: "v1.0.0"}},
			"github.com/fail-module/three": {Module: parser.Module{Path: "github.com/fail-module/three", Version: "v1.0.0"}},
			"github.com/good/alpha":        {Module: parser.Module{Path: "github.com/good/alpha", Version: "v1.0.0"}},
			"github.com/good/beta":         {Module: parser.Module{Path: "github.com/good/beta", Version: "v1.0.0"}},
		},
	}

	results, err := ms.ScanAll(context.Background(), graph)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "3 of 5") {
		t.Errorf("error = %q, want it to contain '3 of 5'", err.Error())
	}

	// Good modules still appear in results.
	if len(results) != 2 {
		t.Errorf("results count = %d, want 2 (good modules only)", len(results))
	}
	for _, path := range []string{"github.com/good/alpha", "github.com/good/beta"} {
		if _, ok := results[path]; !ok {
			t.Errorf("expected result for %q, not found", path)
		}
	}
}
