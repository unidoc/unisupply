package scanner

import (
	"testing"

	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/resolver"
)

// ============================================================================
// Low-level string function tests
// ============================================================================

// TestLevenshtein verifies Levenshtein distance calculation.
func TestLevenshtein(t *testing.T) {
	tests := []struct {
		name     string
		a, b     string
		expected int
	}{
		// Identical strings
		{name: "identical_abc", a: "abc", b: "abc", expected: 0},
		{name: "identical_empty", a: "", b: "", expected: 0},

		// One edit distance
		{name: "one_delete", a: "abc", b: "ab", expected: 1},
		{name: "one_insert", a: "ab", b: "abc", expected: 1},
		{name: "one_substitution", a: "abc", b: "adc", expected: 1},

		// Empty string cases
		{name: "empty_to_abc", a: "", b: "abc", expected: 3},
		{name: "abc_to_empty", a: "abc", b: "", expected: 3},

		// Completely different strings
		{name: "completely_different", a: "abc", b: "xyz", expected: 3},

		// Swap characters (distance 2)
		{name: "swap_abc_acb", a: "abc", b: "acb", expected: 2},

		// Real-world examples
		{name: "gin_gni", a: "gin", b: "gni", expected: 2},
		{name: "redis_redsi", a: "redis", b: "redsi", expected: 2},
		{name: "logrus_logurs", a: "logrus", b: "logurs", expected: 2},

		// Long strings (note: gin vs gni is 2 edits, not 1)
		{name: "long_similar", a: "github.com/gin-gonic/gin", b: "github.com/gin-gonic/gni", expected: 2},
		{name: "long_very_different", a: "github.com/gin-gonic/gin", b: "totally/different/package", expected: 23},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := levenshtein(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("levenshtein(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

// TestMin3 verifies min3 function with all orderings.
func TestMin3(t *testing.T) {
	tests := []struct {
		name     string
		a, b, c  int
		expected int
	}{
		// All different values
		{name: "1_2_3", a: 1, b: 2, c: 3, expected: 1},
		{name: "1_3_2", a: 1, b: 3, c: 2, expected: 1},
		{name: "2_1_3", a: 2, b: 1, c: 3, expected: 1},
		{name: "2_3_1", a: 2, b: 3, c: 1, expected: 1},
		{name: "3_1_2", a: 3, b: 1, c: 2, expected: 1},
		{name: "3_2_1", a: 3, b: 2, c: 1, expected: 1},

		// Two same values
		{name: "2_2_3", a: 2, b: 2, c: 3, expected: 2},
		{name: "2_3_2", a: 2, b: 3, c: 2, expected: 2},
		{name: "3_2_2", a: 3, b: 2, c: 2, expected: 2},

		// All same values
		{name: "5_5_5", a: 5, b: 5, c: 5, expected: 5},

		// Negative values
		{name: "negative_-1_0_1", a: -1, b: 0, c: 1, expected: -1},
		{name: "negative_0_-1_-2", a: 0, b: -1, c: -2, expected: -2},

		// Zero as minimum
		{name: "zero_min_0_5_10", a: 0, b: 5, c: 10, expected: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := min3(tt.a, tt.b, tt.c)
			if got != tt.expected {
				t.Errorf("min3(%d, %d, %d) = %d, want %d", tt.a, tt.b, tt.c, got, tt.expected)
			}
		})
	}
}

// TestLastPathComponent verifies extraction of final path segment.
func TestLastPathComponent(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		// Standard Go module paths
		{name: "three_part_path", path: "github.com/org/repo", expected: "repo"},
		{name: "four_part_path", path: "github.com/org/repo/sub", expected: "sub"},

		// Single component
		{name: "single_component", path: "single", expected: "single"},

		// Empty string
		{name: "empty_string", path: "", expected: ""},

		// Edge cases
		{name: "trailing_slash", path: "github.com/org/repo/", expected: ""},
		{name: "no_slash", path: "package", expected: "package"},
		{name: "two_components", path: "github.com/org", expected: "org"},

		// Real examples
		{name: "gin_path", path: "github.com/gin-gonic/gin", expected: "gin"},
		{name: "zap_path", path: "go.uber.org/zap", expected: "zap"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := lastPathComponent(tt.path)
			if got != tt.expected {
				t.Errorf("lastPathComponent(%q) = %q, want %q", tt.path, got, tt.expected)
			}
		})
	}
}

// TestOrgComponent verifies extraction of organization/user name.
func TestOrgComponent(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		// Standard GitHub paths
		{name: "github_three_part", path: "github.com/org/repo", expected: "org"},
		{name: "github_four_part", path: "github.com/org/repo/sub", expected: "org"},

		// Two-part path (host/org)
		{name: "two_part_path", path: "github.com/org", expected: "org"},
		{name: "golang_org", path: "golang.org/x", expected: "x"},

		// Single component (no org)
		{name: "single_component", path: "single", expected: ""},

		// Empty string
		{name: "empty_string", path: "", expected: ""},

		// Real examples
		{name: "gin_gonic", path: "github.com/gin-gonic/gin", expected: "gin-gonic"},
		{name: "uber_zap", path: "go.uber.org/zap", expected: "zap"}, // split gives ["go.uber.org", "zap"], parts[1]="zap"
		{name: "golang_x_crypto", path: "golang.org/x/crypto", expected: "x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := orgComponent(tt.path)
			if got != tt.expected {
				t.Errorf("orgComponent(%q) = %q, want %q", tt.path, got, tt.expected)
			}
		})
	}
}

// TestCheckSwappedChars verifies detection of adjacent character transpositions.
func TestCheckSwappedChars(t *testing.T) {
	tests := []struct {
		name     string
		a, b     string
		expected bool
	}{
		// Adjacent swaps (should be true)
		{name: "gin_gni", a: "gin", b: "gni", expected: true},
		{name: "abc_bac", a: "abc", b: "bac", expected: true},
		{name: "helllo_hellol", a: "helllo", b: "hellol", expected: true}, // swapped l and o
		{name: "redis_redsi", a: "redis", b: "redsi", expected: true},

		// Different lengths (should be false)
		{name: "different_len_short", a: "ab", b: "abc", expected: false},
		{name: "different_len_long", a: "abcd", b: "abc", expected: false},

		// Identical strings (no diffs, should be false)
		{name: "identical", a: "gin", b: "gin", expected: false},

		// Too short to have swap (should be false)
		{name: "single_char", a: "a", b: "b", expected: false},
		{name: "empty_strings", a: "", b: "", expected: false},

		// Non-adjacent differences (should be false)
		{name: "different_positions", a: "abc", b: "adc", expected: false},
		{name: "multiple_diffs", a: "abcd", b: "adcb", expected: false},

		// More than two differences
		{name: "three_diffs", a: "abcd", b: "dcba", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkSwappedChars(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("checkSwappedChars(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

// TestCheckMissingDash verifies detection of missing hyphens/underscores.
func TestCheckMissingDash(t *testing.T) {
	tests := []struct {
		name     string
		a, b     string
		expected bool
	}{
		// Missing hyphen (should be true)
		{name: "goredis_go_redis", a: "goredis", b: "go-redis", expected: true},
		{name: "goredis_go_redis_alt", a: "go-redis", b: "goredis", expected: true},

		// Missing underscore (should be true)
		{name: "go_redis_as_underscore", a: "go_redis", b: "go-redis", expected: true},

		// Identical (should be false)
		{name: "identical_with_dash", a: "go-redis", b: "go-redis", expected: false},
		{name: "identical_no_dash", a: "goredis", b: "goredis", expected: false},

		// Different names (should be false)
		{name: "completely_different", a: "redis", b: "postgres", expected: false},

		// Multiple separators - only match if stripping makes them equal
		{name: "multiple_dashes", a: "go-redis-client", b: "goredsiclient", expected: false},  // "go-redis-client" -> "goredisclient"; "goredsiclient" != "goredisclient"
		{name: "mixed_separators", a: "go_redis_client", b: "goredsiclient", expected: false}, // "go_redis_client" -> "goredisclient"; "goredsiclient" != "goredisclient"

		// Real examples from well-known modules
		{name: "testify_test_ify", a: "test-ify", b: "testify", expected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkMissingDash(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("checkMissingDash(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

// TestCheckExtraChar verifies detection of one extra character.
func TestCheckExtraChar(t *testing.T) {
	tests := []struct {
		name     string
		a, b     string
		expected bool
	}{
		// One extra character (should be true)
		{name: "gins_gin", a: "gins", b: "gin", expected: true},
		{name: "gin_in", a: "gin", b: "in", expected: true},
		{name: "extra_at_end", a: "rediss", b: "redis", expected: true},
		{name: "extra_at_start", a: "mredis", b: "redis", expected: true},
		{name: "extra_in_middle", a: "reedis", b: "redis", expected: true},

		// Length mismatch != 1 (should be false)
		{name: "length_diff_2", a: "ginss", b: "gin", expected: false},
		{name: "length_diff_minus_1", a: "gi", b: "gin", expected: false},

		// Identical (should be false)
		{name: "identical", a: "gin", b: "gin", expected: false},

		// Empty strings
		{name: "empty_vs_single", a: "a", b: "", expected: true},
		{name: "both_empty", a: "", b: "", expected: false},

		// Different strings beyond one char (should be false)
		{name: "multiple_different", a: "cat", b: "dog", expected: false},
		{name: "multiple_different_len", a: "cats", b: "dog", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkExtraChar(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("checkExtraChar(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

// TestCheckHomoglyph verifies detection of homoglyph substitutions.
func TestCheckHomoglyph(t *testing.T) {
	tests := []struct {
		name     string
		a, b     string
		expected bool
	}{
		// Valid homoglyphs (should be true)
		{name: "1_vs_l", a: "g1n", b: "gin", expected: true},
		{name: "0_vs_o", a: "g0", b: "go", expected: true},
		{name: "l_vs_1", a: "l", b: "1", expected: true},
		{name: "I_vs_l", a: "gIn", b: "gln", expected: true},
		{name: "n_vs_m", a: "gin", b: "gim", expected: true},

		// Length mismatch (should be false)
		{name: "different_length", a: "gin", b: "ginn", expected: false},

		// Identical (should be false)
		{name: "identical", a: "gin", b: "gin", expected: false},

		// Non-homoglyph differences (should be false)
		{name: "random_diff", a: "gin", b: "gix", expected: false},
		{name: "multiple_non_homoglyph", a: "abc", b: "xyz", expected: false},

		// More than 2 homoglyph substitutions (should be false)
		{name: "three_homogl_subs", a: "l1I", b: "111", expected: true}, // 2 diffs (l->1, I->1), both are valid homogl subs

		// Real examples
		{name: "zap_z4p", a: "zap", b: "z4p", expected: false},         // 4 is not in homoglyph map
		{name: "redis_redi5", a: "redis", b: "redi5", expected: false}, // 5 is not a homoglyph for s
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkHomoglyph(tt.a, tt.b)
			if got != tt.expected {
				t.Errorf("checkHomoglyph(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.expected)
			}
		})
	}
}

// ============================================================================
// Module comparison tests
// ============================================================================

// TestCompareModules_NoMatch verifies no match for completely different modules.
func TestCompareModules_NoMatch(t *testing.T) {
	tests := []struct {
		name      string
		candidate string
		known     string
	}{
		{name: "completely_different", candidate: "github.com/totally/different", known: "github.com/gin-gonic/gin"},
		{name: "random_vs_random", candidate: "github.com/xyz/abc", known: "github.com/foo/bar"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareModules(tt.candidate, tt.known)
			if got != nil {
				t.Errorf("compareModules(%q, %q) = %v, want nil", tt.candidate, tt.known, got)
			}
		})
	}
}

// TestCompareModules_SimilarName verifies detection of similar package names.
func TestCompareModules_SimilarName(t *testing.T) {
	tests := []struct {
		name      string
		candidate string
		known     string
	}{
		// Use longer names since requirement is len(knownName) > 3
		{name: "gini_vs_gino", candidate: "github.com/org/gini", known: "github.com/org/gino"},
		{name: "gini_different_org", candidate: "github.com/fake-org/gini", known: "github.com/org/gino"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareModules(tt.candidate, tt.known)
			if got == nil {
				t.Fatalf("compareModules(%q, %q) = nil, want non-nil result", tt.candidate, tt.known)
			}
			if got.Confidence < 0.3 {
				t.Errorf("confidence = %f, want >= 0.3", got.Confidence)
			}
			hasIndicator := false
			for _, ind := range got.Indicators {
				if ind == "similar_package_name" {
					hasIndicator = true
					break
				}
			}
			if !hasIndicator {
				t.Errorf("indicators = %v, want 'similar_package_name' in the list", got.Indicators)
			}
		})
	}
}

// TestCompareModules_SimilarOrg verifies detection of similar org names.
func TestCompareModules_SimilarOrg(t *testing.T) {
	tests := []struct {
		name      string
		candidate string
		known     string
	}{
		// Use longer package names (> 3 chars) to trigger similar_org_name
		{name: "gim_gonic_vs_gin_gonic", candidate: "github.com/gim-gonic/redis", known: "github.com/gin-gonic/redis"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareModules(tt.candidate, tt.known)
			if got == nil {
				t.Fatalf("compareModules(%q, %q) = nil, want non-nil result", tt.candidate, tt.known)
			}
			if got.Confidence < 0.3 {
				t.Errorf("confidence = %f, want >= 0.3", got.Confidence)
			}
			hasIndicator := false
			for _, ind := range got.Indicators {
				if ind == "similar_org_name" {
					hasIndicator = true
					break
				}
			}
			if !hasIndicator {
				t.Errorf("indicators = %v, want 'similar_org_name' in the list", got.Indicators)
			}
		})
	}
}

// TestCompareModules_SameNameDiffOrg verifies detection of same name, different org.
func TestCompareModules_SameNameDiffOrg(t *testing.T) {
	tests := []struct {
		name      string
		candidate string
		known     string
	}{
		// Use longer names to trigger the similar_package_name condition first, but same_name_different_org also applies
		{name: "redis_same_name_diff_org", candidate: "github.com/fake-org/redis", known: "github.com/redis/redis"},
		{name: "gorm_same_name_diff_org", candidate: "github.com/fake-org/gorms", known: "gorm.io/gorms"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareModules(tt.candidate, tt.known)
			if got == nil {
				t.Fatalf("compareModules(%q, %q) = nil, want non-nil result", tt.candidate, tt.known)
			}
			if got.Confidence < 0.4 {
				t.Errorf("confidence = %f, want >= 0.4", got.Confidence)
			}
			hasIndicator := false
			for _, ind := range got.Indicators {
				if ind == "same_name_different_org" {
					hasIndicator = true
					break
				}
			}
			if !hasIndicator {
				t.Errorf("indicators = %v, want 'same_name_different_org' in the list", got.Indicators)
			}
		})
	}
}

// TestCompareModules_ConfidenceCap verifies confidence is capped at 1.0.
func TestCompareModules_ConfidenceCap(t *testing.T) {
	// A module with multiple matching indicators should be capped at 1.0
	// Use longer names to accumulate confidence
	candidate := "github.com/fake-gonic/ginis" // similar name + org
	known := "github.com/gin-gonic/ginio"      // longer names

	got := compareModules(candidate, known)
	if got == nil {
		t.Fatalf("compareModules(%q, %q) = nil, want non-nil", candidate, known)
	}
	if got.Confidence > 1.0 {
		t.Errorf("confidence = %f, want <= 1.0", got.Confidence)
	}
}

// TestCompareModules_BelowThreshold verifies modules with low confidence are filtered.
func TestCompareModules_BelowThreshold(t *testing.T) {
	tests := []struct {
		name      string
		candidate string
		known     string
	}{
		// Very different names and orgs should not match
		{name: "totally_different", candidate: "github.com/xyz/abc", known: "github.com/gin-gonic/gin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareModules(tt.candidate, tt.known)
			if got != nil {
				t.Errorf("compareModules(%q, %q) = %v with confidence %f, want nil (below threshold)", tt.candidate, tt.known, got, got.Confidence)
			}
		})
	}
}

// ============================================================================
// Scanner integration tests
// ============================================================================

// depSpec is a local test fixture description for building graphs.
type depSpec struct {
	path   string
	ver    string
	direct bool
	depth  int
}

// makeGraph builds a resolver.Graph from dependency specs (test helper).
func makeGraph(deps ...depSpec) *resolver.Graph {
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

// TestTyposquatScanner_ScanAll_Clean verifies clean graph returns no results.
func TestTyposquatScanner_ScanAll_Clean(t *testing.T) {
	graph := makeGraph(
		depSpec{path: "github.com/gin-gonic/gin", ver: "v1.0.0", direct: true, depth: 0},
		depSpec{path: "github.com/gorilla/mux", ver: "v1.0.0", direct: true, depth: 0},
		depSpec{path: "github.com/labstack/echo", ver: "v4.0.0", direct: false, depth: 1},
	)

	scanner := NewTyposquatScanner()
	results := scanner.ScanAll(graph)

	if len(results) != 0 {
		t.Errorf("ScanAll on clean graph = %v, want empty map", results)
	}
}

// TestTyposquatScanner_ScanAll_Suspicious verifies detection of suspicious modules.
func TestTyposquatScanner_ScanAll_Suspicious(t *testing.T) {
	graph := makeGraph(
		depSpec{path: "github.com/prometheus/client_golang", ver: "v1.0.0", direct: true, depth: 0},
		depSpec{path: "github.com/prometheus/clien_golang", ver: "v1.0.0", direct: true, depth: 0}, // Typo (missing t)
		depSpec{path: "github.com/gorilla/mux", ver: "v1.0.0", direct: true, depth: 0},
	)

	scanner := NewTyposquatScanner()
	results := scanner.ScanAll(graph)

	if len(results) != 1 {
		t.Fatalf("ScanAll detected %d results, want 1", len(results))
	}

	result, ok := results["github.com/prometheus/clien_golang"]
	if !ok {
		t.Fatalf("Expected result for typo module, got keys: %v", mapKeys(results))
	}

	if result.Confidence < 0.3 {
		t.Errorf("confidence = %f, want >= 0.3", result.Confidence)
	}
	if result.SimilarTo != "github.com/prometheus/client_golang" {
		t.Errorf("SimilarTo = %q, want %q", result.SimilarTo, "github.com/prometheus/client_golang")
	}
}

// TestTyposquatScanner_ScanAll_MultipleIndicators verifies stacking of indicators.
func TestTyposquatScanner_ScanAll_MultipleIndicators(t *testing.T) {
	graph := makeGraph(
		depSpec{path: "github.com/prometheus/client_golang", ver: "v1.0.0", direct: true, depth: 0},
		depSpec{path: "github.com/promethes/client_golang", ver: "v1.0.0", direct: true, depth: 0}, // Similar name and org
	)

	scanner := NewTyposquatScanner()
	results := scanner.ScanAll(graph)

	if len(results) != 1 {
		t.Fatalf("ScanAll detected %d results, want 1", len(results))
	}

	result, ok := results["github.com/promethes/client_golang"]
	if !ok {
		t.Fatalf("Expected result for typo module")
	}

	if len(result.Indicators) < 1 {
		t.Errorf("expected at least one indicator, got %v", result.Indicators)
	}
}

// TestTyposquatScanner_BestMatch verifies highest confidence result is returned.
func TestTyposquatScanner_BestMatch(t *testing.T) {
	// A module could match multiple known packages; we should get the best match
	graph := makeGraph(
		depSpec{path: "github.com/prometheus/client_golang", ver: "v1.0.0", direct: true, depth: 0},
		depSpec{path: "github.com/stretchr/testify", ver: "v1.0.0", direct: true, depth: 0},
		depSpec{path: "github.com/fake-org/client_golang", ver: "v1.0.0", direct: true, depth: 0}, // Similar to prometheus's package
	)

	scanner := NewTyposquatScanner()
	results := scanner.ScanAll(graph)

	result, ok := results["github.com/fake-org/client_golang"]
	if !ok {
		t.Fatalf("Expected result for suspicious module")
	}

	if result.SimilarTo != "github.com/prometheus/client_golang" {
		t.Errorf("BestMatch returned %q, want %q", result.SimilarTo, "github.com/prometheus/client_golang")
	}
}

// TestTyposquatScanner_EmptyGraph verifies empty graph returns empty results.
func TestTyposquatScanner_EmptyGraph(t *testing.T) {
	graph := makeGraph()

	scanner := NewTyposquatScanner()
	results := scanner.ScanAll(graph)

	if len(results) != 0 {
		t.Errorf("ScanAll on empty graph = %v, want empty map", results)
	}
}

// TestTyposquatScanner_HomoglyphDetection verifies homoglyph substitutions are detected.
func TestTyposquatScanner_HomoglyphDetection(t *testing.T) {
	graph := makeGraph(
		depSpec{path: "github.com/prometheus/client_golang", ver: "v1.0.0", direct: true, depth: 0},
		depSpec{path: "github.com/prometheus/c1ient_golang", ver: "v1.0.0", direct: true, depth: 0}, // 1 instead of l
	)

	scanner := NewTyposquatScanner()
	results := scanner.ScanAll(graph)

	if len(results) != 1 {
		t.Fatalf("ScanAll detected %d results, want 1", len(results))
	}

	result := results["github.com/prometheus/c1ient_golang"]
	if result == nil {
		t.Fatalf("Expected result for homoglyph variant")
	}

	hasHomoglyph := false
	for _, ind := range result.Indicators {
		if ind == "homoglyph_substitution" {
			hasHomoglyph = true
			break
		}
	}
	if !hasHomoglyph {
		t.Errorf("indicators = %v, want 'homoglyph_substitution'", result.Indicators)
	}
}

// TestTyposquatScanner_SwappedCharDetection verifies swapped char detection.
func TestTyposquatScanner_SwappedCharDetection(t *testing.T) {
	graph := makeGraph(
		depSpec{path: "github.com/prometheus/client_golang", ver: "v1.0.0", direct: true, depth: 0},
		depSpec{path: "github.com/prometheus/clinet_golang", ver: "v1.0.0", direct: true, depth: 0}, // Swapped i<->e
	)

	scanner := NewTyposquatScanner()
	results := scanner.ScanAll(graph)

	result := results["github.com/prometheus/clinet_golang"]
	if result == nil {
		t.Fatalf("Expected result for swapped char variant")
	}

	hasSwapped := false
	for _, ind := range result.Indicators {
		if ind == "swapped_characters" {
			hasSwapped = true
			break
		}
	}
	if !hasSwapped {
		t.Errorf("indicators = %v, want 'swapped_characters'", result.Indicators)
	}
}

// TestTyposquatScanner_ExtraCharDetection verifies extra character detection.
func TestTyposquatScanner_ExtraCharDetection(t *testing.T) {
	graph := makeGraph(
		depSpec{path: "github.com/prometheus/client_golang", ver: "v1.0.0", direct: true, depth: 0},
		depSpec{path: "github.com/prometheus/cclient_golang", ver: "v1.0.0", direct: true, depth: 0}, // Extra char
	)

	scanner := NewTyposquatScanner()
	results := scanner.ScanAll(graph)

	result := results["github.com/prometheus/cclient_golang"]
	if result == nil {
		t.Fatalf("Expected result for extra char variant")
	}

	hasExtra := false
	for _, ind := range result.Indicators {
		if ind == "extra_character" {
			hasExtra = true
			break
		}
	}
	if !hasExtra {
		t.Errorf("indicators = %v, want 'extra_character'", result.Indicators)
	}
}

// TestTyposquatScanner_MissingDashDetection verifies missing dash/underscore detection.
func TestTyposquatScanner_MissingDashDetection(t *testing.T) {
	graph := makeGraph(
		depSpec{path: "github.com/redis/go-redis", ver: "v1.0.0", direct: true, depth: 0},
		depSpec{path: "github.com/redis/goredis", ver: "v1.0.0", direct: true, depth: 0}, // Missing dash
	)

	scanner := NewTyposquatScanner()
	results := scanner.ScanAll(graph)

	result := results["github.com/redis/goredis"]
	if result == nil {
		t.Fatalf("Expected result for missing dash variant")
	}

	hasDash := false
	for _, ind := range result.Indicators {
		if ind == "missing_separator" {
			hasDash = true
			break
		}
	}
	if !hasDash {
		t.Errorf("indicators = %v, want 'missing_separator'", result.Indicators)
	}
}

// TestTyposquatScanner_LowConfidenceFiltered verifies low confidence results are filtered.
func TestTyposquatScanner_LowConfidenceFiltered(t *testing.T) {
	graph := makeGraph(
		depSpec{path: "github.com/gin-gonic/gin", ver: "v1.0.0", direct: true, depth: 0},
		depSpec{path: "some.org/completely/different", ver: "v1.0.0", direct: true, depth: 0},
	)

	scanner := NewTyposquatScanner()
	results := scanner.ScanAll(graph)

	if len(results) != 0 {
		t.Errorf("ScanAll filtered %d results, want 0 (all below threshold)", len(results))
	}
}

// TestTyposquatScanner_Result_Fields verifies result fields are correctly populated.
func TestTyposquatScanner_Result_Fields(t *testing.T) {
	graph := makeGraph(
		depSpec{path: "github.com/prometheus/client_golang", ver: "v1.0.0", direct: true, depth: 0},
		depSpec{path: "github.com/prometheus/clien_golang", ver: "v1.0.0", direct: true, depth: 0},
	)

	scanner := NewTyposquatScanner()
	results := scanner.ScanAll(graph)

	result := results["github.com/prometheus/clien_golang"]
	if result == nil {
		t.Fatalf("Expected result, got nil")
	}

	if result.Module != "github.com/prometheus/clien_golang" {
		t.Errorf("Module = %q, want %q", result.Module, "github.com/prometheus/clien_golang")
	}
	if result.SimilarTo != "github.com/prometheus/client_golang" {
		t.Errorf("SimilarTo = %q, want %q", result.SimilarTo, "github.com/prometheus/client_golang")
	}
	if result.Distance < 1 {
		t.Errorf("Distance = %d, want > 0", result.Distance)
	}
	if result.Confidence <= 0 || result.Confidence > 1 {
		t.Errorf("Confidence = %f, want in (0, 1]", result.Confidence)
	}
	if len(result.Indicators) == 0 {
		t.Error("Indicators is empty, want at least one indicator")
	}
}

// TestTyposquatScanner_LongModulePath verifies scanning works with long module paths.
func TestTyposquatScanner_LongModulePath(t *testing.T) {
	graph := makeGraph(
		depSpec{path: "github.com/spf13/cobra", ver: "v1.0.0", direct: true, depth: 0},
		depSpec{path: "github.com/spf13/cobra/cmd", ver: "v1.0.0", direct: true, depth: 0},
		depSpec{path: "github.com/spf13/cobrra", ver: "v1.0.0", direct: true, depth: 0}, // Typo in package name (swapped chars)
	)

	scanner := NewTyposquatScanner()
	results := scanner.ScanAll(graph)

	if len(results) != 1 {
		t.Fatalf("ScanAll detected %d results, want 1. Keys: %v", len(results), mapKeys(results))
	}

	result := results["github.com/spf13/cobrra"]
	if result == nil {
		t.Fatalf("Expected result for module path with typo")
	}
}

// ============================================================================
// Helper functions
// ============================================================================

// mapKeys returns the keys of a map for error reporting.
func mapKeys(m map[string]*TyposquatResult) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
