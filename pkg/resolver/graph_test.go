package resolver

import (
	"context"
	"os"
	"testing"

	"github.com/unidoc/unisupply/pkg/parser"
)

// ============================================================================
// Utility Function Tests
// ============================================================================

// TestModulePath tests the modulePath function.
func TestModulePath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "module_with_version",
			input:    "mod@v1.0.0",
			expected: "mod",
		},
		{
			name:     "module_without_version",
			input:    "mod",
			expected: "mod",
		},
		{
			name:     "at_sign_in_version",
			input:    "@v1",
			expected: "",
		},
		{
			name:     "complex_path_with_version",
			input:    "github.com/user/repo@v1.2.3",
			expected: "github.com/user/repo",
		},
		{
			name:     "empty_string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := modulePath(tt.input)
			if result != tt.expected {
				t.Errorf("modulePath(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestModuleVersion tests the moduleVersion function.
func TestModuleVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "module_with_version",
			input:    "mod@v1.0.0",
			expected: "v1.0.0",
		},
		{
			name:     "module_without_version",
			input:    "mod",
			expected: "",
		},
		{
			name:     "version_only",
			input:    "@v1",
			expected: "v1",
		},
		{
			name:     "complex_path_with_version",
			input:    "github.com/user/repo@v1.2.3",
			expected: "v1.2.3",
		},
		{
			name:     "empty_string",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := moduleVersion(tt.input)
			if result != tt.expected {
				t.Errorf("moduleVersion(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestCompareVersions tests the compareVersions function.
func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name     string
		a        string
		b        string
		expected int
	}{
		{
			name:     "equal_versions",
			a:        "v1.0.0",
			b:        "v1.0.0",
			expected: 0,
		},
		{
			name:     "a_greater_than_b",
			a:        "v1.2.3",
			b:        "v1.2.0",
			expected: 1,
		},
		{
			name:     "a_less_than_b",
			a:        "v1.0.0",
			b:        "v1.2.3",
			expected: -1,
		},
		{
			name:     "major_version_difference",
			a:        "v2.0.0",
			b:        "v1.9.9",
			expected: 1,
		},
		{
			name:     "minor_version_difference",
			a:        "v1.1.0",
			b:        "v1.0.0",
			expected: 1,
		},
		{
			name:     "patch_version_difference",
			a:        "v1.0.1",
			b:        "v1.0.0",
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := compareVersions(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// TestContainsStr tests the containsStr function.
func TestContainsStr(t *testing.T) {
	tests := []struct {
		name     string
		ss       []string
		s        string
		expected bool
	}{
		{
			name:     "string_found_in_slice",
			ss:       []string{"a", "b", "c"},
			s:        "b",
			expected: true,
		},
		{
			name:     "string_not_found_in_slice",
			ss:       []string{"a", "b", "c"},
			s:        "d",
			expected: false,
		},
		{
			name:     "empty_slice",
			ss:       []string{},
			s:        "a",
			expected: false,
		},
		{
			name:     "nil_slice",
			ss:       nil,
			s:        "a",
			expected: false,
		},
		{
			name:     "string_in_first_position",
			ss:       []string{"first", "second"},
			s:        "first",
			expected: true,
		},
		{
			name:     "string_in_last_position",
			ss:       []string{"first", "second"},
			s:        "second",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsStr(tt.ss, tt.s)
			if result != tt.expected {
				t.Errorf("containsStr(%v, %q) = %v, want %v", tt.ss, tt.s, result, tt.expected)
			}
		})
	}
}

// TestDepthFromIndirect tests the depthFromIndirect function.
func TestDepthFromIndirect(t *testing.T) {
	tests := []struct {
		name     string
		indirect bool
		expected int
	}{
		{
			name:     "indirect_true",
			indirect: true,
			expected: 1,
		},
		{
			name:     "indirect_false",
			indirect: false,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := depthFromIndirect(tt.indirect)
			if result != tt.expected {
				t.Errorf("depthFromIndirect(%v) = %d, want %d", tt.indirect, result, tt.expected)
			}
		})
	}
}

// ============================================================================
// Graph Method Tests
// ============================================================================

// TestGraph_DirectCount tests the DirectCount method.
func TestGraph_DirectCount(t *testing.T) {
	tests := []struct {
		name     string
		direct   int
		indirect int
		expected int
	}{
		{
			name:     "two_direct_one_indirect",
			direct:   2,
			indirect: 1,
			expected: 2,
		},
		{
			name:     "all_direct",
			direct:   2,
			indirect: 0,
			expected: 2,
		},
		{
			name:     "all_indirect",
			direct:   0,
			indirect: 2,
			expected: 0,
		},
		{
			name:     "empty_graph",
			direct:   0,
			indirect: 0,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			graph := &Graph{
				Root:         "test/module",
				Dependencies: make(map[string]*Dependency),
			}

			for i := 0; i < tt.direct; i++ {
				graph.Dependencies[string(rune('a'+i))] = &Dependency{
					Direct: true,
					Module: parser.Module{Path: string(rune('a' + i))},
				}
			}

			for i := 0; i < tt.indirect; i++ {
				graph.Dependencies[string(rune('z'-i))] = &Dependency{
					Direct: false,
					Module: parser.Module{Path: string(rune('z' - i))},
				}
			}

			result := graph.DirectCount()
			if result != tt.expected {
				t.Errorf("DirectCount() = %d, want %d", result, tt.expected)
			}
		})
	}
}

// TestGraph_TransitiveCount tests the TransitiveCount method.
func TestGraph_TransitiveCount(t *testing.T) {
	tests := []struct {
		name     string
		direct   int
		indirect int
		expected int
	}{
		{
			name:     "two_direct_one_indirect",
			direct:   2,
			indirect: 1,
			expected: 1,
		},
		{
			name:     "all_direct",
			direct:   2,
			indirect: 0,
			expected: 0,
		},
		{
			name:     "all_indirect",
			direct:   0,
			indirect: 2,
			expected: 2,
		},
		{
			name:     "empty_graph",
			direct:   0,
			indirect: 0,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			graph := &Graph{
				Root:         "test/module",
				Dependencies: make(map[string]*Dependency),
			}

			for i := 0; i < tt.direct; i++ {
				graph.Dependencies[string(rune('a'+i))] = &Dependency{
					Direct: true,
					Module: parser.Module{Path: string(rune('a' + i))},
				}
			}

			for i := 0; i < tt.indirect; i++ {
				graph.Dependencies[string(rune('z'-i))] = &Dependency{
					Direct: false,
					Module: parser.Module{Path: string(rune('z' - i))},
				}
			}

			result := graph.TransitiveCount()
			if result != tt.expected {
				t.Errorf("TransitiveCount() = %d, want %d", result, tt.expected)
			}
		})
	}
}

// TestGraph_TotalEdges tests the TotalEdges method.
func TestGraph_TotalEdges(t *testing.T) {
	tests := []struct {
		name      string
		edgeCount int
		expected  int
	}{
		{
			name:      "zero_edges",
			edgeCount: 0,
			expected:  0,
		},
		{
			name:      "multiple_edges",
			edgeCount: 10,
			expected:  10,
		},
		{
			name:      "single_edge",
			edgeCount: 1,
			expected:  1,
		},
		{
			name:      "large_edge_count",
			edgeCount: 1000,
			expected:  1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			graph := &Graph{
				Root:         "test/module",
				Dependencies: make(map[string]*Dependency),
				EdgeCount:    tt.edgeCount,
			}
			result := graph.TotalEdges()
			if result != tt.expected {
				t.Errorf("TotalEdges() = %d, want %d", result, tt.expected)
			}
		})
	}
}

// ============================================================================
// Resolve Error Tests
// ============================================================================

// TestResolve_FileNotFound tests Resolve with a non-existent go.mod file.
func TestResolve_FileNotFound(t *testing.T) {
	gomodPath := "/nonexistent/path/go.mod"
	graph, warnings, err := Resolve(context.Background(), gomodPath, false)

	if err == nil {
		t.Error("Resolve() expected error for non-existent file, got nil")
	}

	if graph != nil {
		t.Errorf("Resolve() expected nil graph, got %v", graph)
	}

	if warnings != nil {
		t.Logf("warnings: %v", warnings)
	}
}

// TestResolve_DirectOnly tests Resolve with directOnly=true.
func TestResolve_DirectOnly(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := tmpDir + "/go.mod"

	// Create a minimal go.mod file
	content := `module github.com/test/pkg

go 1.21

require (
	github.com/direct/pkg v1.0.0
	github.com/another/direct v2.0.0
)

require (
	github.com/indirect/pkg v1.5.0 // indirect
)
`

	err := writeFile(gomodPath, content)
	if err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	graph, warnings, err := Resolve(context.Background(), gomodPath, true)
	if err != nil {
		t.Fatalf("Resolve(directOnly=true) failed: %v", err)
	}

	if graph == nil {
		t.Fatal("Expected non-nil graph")
	}

	if graph.Root != "github.com/test/pkg" {
		t.Errorf("Root = %q, want %q", graph.Root, "github.com/test/pkg")
	}

	directCount := graph.DirectCount()
	if directCount != 2 {
		t.Errorf("DirectCount() = %d, want 2", directCount)
	}

	transitiveCount := graph.TransitiveCount()
	if transitiveCount != 0 {
		t.Errorf("TransitiveCount() = %d, want 0 (directOnly=true)", transitiveCount)
	}

	if len(warnings) > 0 {
		t.Logf("Warnings: %v", warnings)
	}
}

// TestResolve_ParseGoModFallback tests Resolve falls back when go mod graph is unavailable.
// This tests the fallback to go.mod/go.sum parsing.
func TestResolve_ParseGoModFallback(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := tmpDir + "/go.mod"

	content := `module github.com/test/pkg

go 1.21

require (
	github.com/direct/pkg v1.0.0
	github.com/indirect/pkg v1.5.0 // indirect
)
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	// Create empty go.sum (so it won't error, just return nothing from go.sum)
	gosum := tmpDir + "/go.sum"
	if err := writeFile(gosum, ""); err != nil {
		t.Fatalf("Failed to write go.sum: %v", err)
	}

	// Call with directOnly=false to attempt go mod graph
	// Since we're in tests, go mod graph likely won't work, triggering fallback
	graph, warnings, err := Resolve(context.Background(), gomodPath, false)

	// We accept either success (if go mod graph works) or fallback success
	if err != nil {
		t.Fatalf("Resolve() failed: %v", err)
	}

	if graph == nil {
		t.Fatal("Expected non-nil graph")
	}

	if graph.Root != "github.com/test/pkg" {
		t.Errorf("Root = %q, want %q", graph.Root, "github.com/test/pkg")
	}

	// Should have at least 1 dependency (direct)
	if graph.DirectCount() < 1 {
		t.Errorf("DirectCount() = %d, want at least 1", graph.DirectCount())
	}

	if len(warnings) > 0 {
		t.Logf("Fallback warnings (expected): %v", warnings)
	}
}

// TestResolve_WithGoSum tests addFromGoSum by creating a realistic go.sum
func TestResolve_WithGoSum(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := tmpDir + "/go.mod"
	gosum := tmpDir + "/go.sum"

	gomodContent := `module github.com/test/pkg

go 1.21

require (
	github.com/direct/pkg v1.0.0
)
`

	goSumContent := `github.com/direct/pkg v1.0.0 h1:abcdef1234567890abcdef1234567890abcdef12=
github.com/direct/pkg v1.0.0/go.mod h1:abcdef1234567890abcdef1234567890abcdef12=
github.com/transitive/dep v1.2.3 h1:abcdef1234567890abcdef1234567890abcdef12=
github.com/transitive/dep v1.2.3/go.mod h1:abcdef1234567890abcdef1234567890abcdef12=
`

	if err := writeFile(gomodPath, gomodContent); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	if err := writeFile(gosum, goSumContent); err != nil {
		t.Fatalf("Failed to write go.sum: %v", err)
	}

	graph, _, err := Resolve(context.Background(), gomodPath, false)
	if err != nil {
		t.Fatalf("Resolve() failed: %v", err)
	}

	if graph == nil {
		t.Fatal("Expected non-nil graph")
	}

	// Should have both direct and potentially transitive dependencies
	if graph.DirectCount() < 1 {
		t.Errorf("DirectCount() = %d, want at least 1", graph.DirectCount())
	}

	// Check that we got the direct dependency
	if _, ok := graph.Dependencies["github.com/direct/pkg"]; !ok {
		t.Error("Expected to find github.com/direct/pkg in dependencies")
	}
}

// TestResolve_WithReplaces tests handling of replace directives
func TestResolve_WithReplaces(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := tmpDir + "/go.mod"

	content := `module github.com/test/pkg

go 1.21

require (
	github.com/original/pkg v1.0.0
)

replace github.com/original/pkg => ./local/replacement
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	gosum := tmpDir + "/go.sum"
	if err := writeFile(gosum, ""); err != nil {
		t.Fatalf("Failed to write go.sum: %v", err)
	}

	graph, _, err := Resolve(context.Background(), gomodPath, true)
	if err != nil {
		t.Fatalf("Resolve() failed: %v", err)
	}

	if graph == nil {
		t.Fatal("Expected non-nil graph")
	}

	// Check that the replaced module has the Replaced flag set
	if dep, ok := graph.Dependencies["github.com/original/pkg"]; ok {
		if !dep.Replaced {
			t.Errorf("Expected github.com/original/pkg to be marked as replaced, but Replaced=%v", dep.Replaced)
		}
	} else {
		t.Error("Expected to find github.com/original/pkg in dependencies")
	}
}

// TestResolve_MultipleIndirectDependencies tests handling multiple indirect dependencies
func TestResolve_MultipleIndirectDependencies(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := tmpDir + "/go.mod"

	content := `module github.com/test/pkg

go 1.21

require (
	github.com/direct/a v1.0.0
	github.com/direct/b v2.0.0
)

require (
	github.com/indirect/c v1.5.0 // indirect
	github.com/indirect/d v2.5.0 // indirect
	github.com/indirect/e v3.5.0 // indirect
)
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	gosum := tmpDir + "/go.sum"
	if err := writeFile(gosum, ""); err != nil {
		t.Fatalf("Failed to write go.sum: %v", err)
	}

	graph, _, err := Resolve(context.Background(), gomodPath, true)
	if err != nil {
		t.Fatalf("Resolve() failed: %v", err)
	}

	if graph == nil {
		t.Fatal("Expected non-nil graph")
	}

	directCount := graph.DirectCount()
	if directCount != 2 {
		t.Errorf("DirectCount() = %d, want 2", directCount)
	}

	transitiveCount := graph.TransitiveCount()
	if transitiveCount != 0 {
		t.Errorf("TransitiveCount() = %d, want 0 (directOnly=true)", transitiveCount)
	}

	// Verify all dependencies are in the graph
	expectedDeps := []string{
		"github.com/direct/a",
		"github.com/direct/b",
	}
	for _, dep := range expectedDeps {
		if _, ok := graph.Dependencies[dep]; !ok {
			t.Errorf("Expected to find %q in dependencies", dep)
		}
	}
}

// TestResolve_EmptyGoMod tests handling of minimal go.mod with no requirements
func TestResolve_EmptyGoMod(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := tmpDir + "/go.mod"

	content := `module github.com/test/pkg

go 1.21
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	gosum := tmpDir + "/go.sum"
	if err := writeFile(gosum, ""); err != nil {
		t.Fatalf("Failed to write go.sum: %v", err)
	}

	graph, _, err := Resolve(context.Background(), gomodPath, true)
	if err != nil {
		t.Fatalf("Resolve() failed: %v", err)
	}

	if graph == nil {
		t.Fatal("Expected non-nil graph")
	}

	if graph.Root != "github.com/test/pkg" {
		t.Errorf("Root = %q, want %q", graph.Root, "github.com/test/pkg")
	}

	directCount := graph.DirectCount()
	if directCount != 0 {
		t.Errorf("DirectCount() = %d, want 0", directCount)
	}
}

// TestResolve_TransitiveResolutionAttempt tests the Resolve function with
// directOnly=false, which attempts to use go mod graph but falls back gracefully.
// This exercises the error handling path in resolveWithGoModGraph.
func TestResolve_TransitiveResolutionAttempt(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := tmpDir + "/go.mod"

	// Create a go.mod with complex structure to encourage go mod graph attempt
	content := `module github.com/test/complex

go 1.21

require (
	github.com/primary/dep v1.0.0
	github.com/secondary/dep v2.0.0
)

require (
	github.com/transitive/a v1.5.0 // indirect
	github.com/transitive/b v2.5.0 // indirect
)
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	gosum := tmpDir + "/go.sum"
	goSumContent := `github.com/primary/dep v1.0.0 h1:abcdef=
github.com/primary/dep v1.0.0/go.mod h1:abcdef=
github.com/secondary/dep v2.0.0 h1:abcdef=
github.com/secondary/dep v2.0.0/go.mod h1:abcdef=
github.com/transitive/a v1.5.0 h1:abcdef=
github.com/transitive/a v1.5.0/go.mod h1:abcdef=
github.com/transitive/b v2.5.0 h1:abcdef=
github.com/transitive/b v2.5.0/go.mod h1:abcdef=
`
	if err := writeFile(gosum, goSumContent); err != nil {
		t.Fatalf("Failed to write go.sum: %v", err)
	}

	// Call with directOnly=false to trigger full resolution attempt
	graph, warnings, err := Resolve(context.Background(), gomodPath, false)
	if err != nil {
		t.Fatalf("Resolve(directOnly=false) failed: %v", err)
	}

	if graph == nil {
		t.Fatal("Expected non-nil graph")
	}

	if graph.Root != "github.com/test/complex" {
		t.Errorf("Root = %q, want %q", graph.Root, "github.com/test/complex")
	}

	// Should have at least the direct dependencies
	directCount := graph.DirectCount()
	if directCount < 2 {
		t.Errorf("DirectCount() = %d, want at least 2", directCount)
	}

	// If fallback was triggered, verify warnings indicate this
	if len(warnings) > 0 {
		t.Logf("Fallback triggered with warnings: %v", warnings)
	}
}

// TestResolve_MixedDirectIndirect tests a realistic go.mod with mixed direct/indirect
func TestResolve_MixedDirectIndirect(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := tmpDir + "/go.mod"

	content := `module github.com/myapp

go 1.21

require github.com/lib/pkg v1.0.0

require (
	github.com/lib/pkg v1.0.0 // indirect in original, now explicit
	github.com/other/lib v2.1.0 // indirect
)
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	gosum := tmpDir + "/go.sum"
	if err := writeFile(gosum, ""); err != nil {
		t.Fatalf("Failed to write go.sum: %v", err)
	}

	graph, _, err := Resolve(context.Background(), gomodPath, false)
	if err != nil {
		t.Fatalf("Resolve() failed: %v", err)
	}

	if graph == nil {
		t.Fatal("Expected non-nil graph")
	}

	if graph.Root != "github.com/myapp" {
		t.Errorf("Root = %q, want %q", graph.Root, "github.com/myapp")
	}

	// Check that dependencies are properly classified
	if _, ok := graph.Dependencies["github.com/lib/pkg"]; !ok {
		t.Error("Expected github.com/lib/pkg in dependencies")
	}

	if _, ok := graph.Dependencies["github.com/other/lib"]; !ok {
		t.Error("Expected github.com/other/lib in dependencies")
	}
}

// Helper function to write test files
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
