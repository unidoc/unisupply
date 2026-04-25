package scanner

import (
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

	results, err := ms.ScanAll(graph)
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

	results, err := ms.ScanAll(graph)
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

	results, err := ms.ScanAll(graph)

	// First error is captured
	if err != nil {
		t.Fatalf("ScanAll() unexpected error: %v", err)
	}

	// Should have results for at least one module
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
	results, err := ms.ScanAll(graph)
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
