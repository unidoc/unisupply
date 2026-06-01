package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/resolver"
)

// tiDepSpec is a local test fixture description for building graphs.
type tiDepSpec struct {
	path   string
	ver    string
	direct bool
	depth  int
}

// makeTiGraph builds a resolver.Graph from dependency specs (test helper).
func makeTiGraph(deps ...tiDepSpec) *resolver.Graph {
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

func TestNewTrustIndexClient_EmptyURL(t *testing.T) {
	client, err := NewTrustIndexClient("", 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error for empty URL: %v", err)
	}
	if client != nil {
		t.Error("expected nil client for empty URL")
	}
}

func TestNewTrustIndexClient_ValidURL_Localhost(t *testing.T) {
	client, err := NewTrustIndexClient("http://localhost:8080", 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error for localhost URL: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client for localhost URL")
	}
	if client.baseURL != "http://localhost:8080" {
		t.Errorf("expected baseURL to be set, got %s", client.baseURL)
	}
	if client.client == nil {
		t.Error("expected initialized http.Client")
	}
}

func TestNewTrustIndexClient_SSRF_LinkLocal(t *testing.T) {
	_, err := NewTrustIndexClient("http://169.254.169.254/foo", 5*time.Second, false)
	if err == nil {
		t.Fatal("expected error for link-local address")
	}
}

func TestNewTrustIndexClient_SSRF_RFC1918_NoFlag(t *testing.T) {
	_, err := NewTrustIndexClient("https://10.0.0.5/", 5*time.Second, false)
	if err == nil {
		t.Fatal("expected error for RFC1918 address without --trust-index-allow-private")
	}
}

func TestNewTrustIndexClient_SSRF_RFC1918_WithFlag(t *testing.T) {
	// With allowPrivate=true the RFC1918 address is accepted at construction
	// time. Connection will fail (no server), but NewTrustIndexClient must not
	// error on the address itself.
	client, err := NewTrustIndexClient("https://10.0.0.5/", 5*time.Second, true)
	if err != nil {
		t.Fatalf("unexpected error with allowPrivate=true: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client with allowPrivate=true")
	}
}

func TestNewTrustIndexClient_SSRF_HttpRequiresLoopback(t *testing.T) {
	// A non-loopback host with http scheme must be rejected even without a
	// private IP (it would send credentials over plaintext to an arbitrary host).
	// Use a hostname that resolves to a public IP — here we synthesise that
	// with a literal non-loopback IP.
	_, err := NewTrustIndexClient("http://8.8.8.8/", 5*time.Second, false)
	if err == nil {
		t.Fatal("expected error for http with non-loopback host")
	}
}

func TestNewTrustIndexClient_SSRF_CGNAT(t *testing.T) {
	// 100.64.0.0/10 is CGNAT (RFC 6598) — commonly used for cloud-internal
	// infrastructure. Must be rejected without --trust-index-allow-private.
	_, err := NewTrustIndexClient("https://100.64.0.1/", 5*time.Second, false)
	if err == nil {
		t.Fatal("expected error for CGNAT address without --trust-index-allow-private")
	}
}

func TestNewTrustIndexClient_IPv6Loopback(t *testing.T) {
	// ::1 is IPv6 loopback — must be allowed on http without --trust-index-allow-private.
	client, err := NewTrustIndexClient("http://[::1]:8080", 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error for IPv6 loopback: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client for IPv6 loopback")
	}
}

func TestNewTrustIndexClient_UnsupportedScheme(t *testing.T) {
	// Non-http(s) schemes (e.g. ftp) must be rejected for non-loopback hosts.
	_, err := NewTrustIndexClient("ftp://example.com/", 5*time.Second, false)
	if err == nil {
		t.Fatal("expected error for non-https scheme on non-loopback host")
	}
}

func TestTrustIndexClient_LookupAll_NilClient(t *testing.T) {
	var client *TrustIndexClient

	graph := &resolver.Graph{
		Root:         "test/module",
		Dependencies: make(map[string]*resolver.Dependency),
	}

	results, err := client.LookupAll(context.Background(), graph)

	if results != nil {
		t.Error("expected nil results for nil client")
	}

	if err != nil {
		t.Error("expected nil error for nil client")
	}
}

func TestTrustIndexClient_LookupAll_EmptyGraph(t *testing.T) {
	client, err := NewTrustIndexClient("http://localhost:8080", 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	graph := &resolver.Graph{
		Root:         "test/module",
		Dependencies: make(map[string]*resolver.Dependency),
	}

	results, err := client.LookupAll(context.Background(), graph)

	if results != nil {
		t.Error("expected nil results for empty graph")
	}

	if err != nil {
		t.Error("expected nil error for empty graph")
	}
}

func TestTrustIndexClient_LookupAll_Success(t *testing.T) {
	// Create mock trust index server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if r.URL.Path != "/api/v1/lookup" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Parse request body
		var req struct {
			Modules []string `json:"modules"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Build response with results for requested modules
		response := map[string]interface{}{
			"results": map[string]interface{}{
				"github.com/foo/bar": map[string]interface{}{
					"module":               "github.com/foo/bar",
					"trust_score":          85,
					"maintainer_trust":     90,
					"resilience_score":     80,
					"security_score":       75,
					"community_score":      70,
					"maintainer_name":      "John Doe",
					"maintainer_org":       "FooOrg",
					"maintainer_country":   "US",
					"maintainer_verified":  true,
					"stewardship_status":   "active",
					"safer_alternative":    "",
					"is_unidoc_maintained": false,
				},
				"github.com/baz/qux": map[string]interface{}{
					"module":               "github.com/baz/qux",
					"trust_score":          45,
					"maintainer_trust":     40,
					"resilience_score":     50,
					"security_score":       45,
					"community_score":      40,
					"maintainer_name":      "Jane Smith",
					"maintainer_org":       "BazCorp",
					"maintainer_country":   "UK",
					"maintainer_verified":  false,
					"stewardship_status":   "unmaintained",
					"safer_alternative":    "github.com/better/alternative",
					"is_unidoc_maintained": false,
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := NewTrustIndexClient(server.URL, 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	// Create test graph with 2 dependencies
	graph := makeTiGraph(
		tiDepSpec{
			path:   "github.com/foo/bar",
			ver:    "v1.0.0",
			direct: true,
			depth:  0,
		},
		tiDepSpec{
			path:   "github.com/baz/qux",
			ver:    "v2.0.0",
			direct: true,
			depth:  0,
		},
	)

	results, err := client.LookupAll(context.Background(), graph)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if results == nil {
		t.Fatal("expected non-nil results")
	}

	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}

	// Verify first module
	entry1, ok := results["github.com/foo/bar"]
	if !ok {
		t.Fatal("expected result for github.com/foo/bar")
	}

	if entry1.TrustScore != 85 {
		t.Errorf("expected trust score 85, got %d", entry1.TrustScore)
	}

	if entry1.MaintainerName != "John Doe" {
		t.Errorf("expected maintainer name 'John Doe', got %s", entry1.MaintainerName)
	}

	if !entry1.MaintainerVerified {
		t.Error("expected maintainer verified to be true")
	}

	// Verify second module
	entry2, ok := results["github.com/baz/qux"]
	if !ok {
		t.Fatal("expected result for github.com/baz/qux")
	}

	if entry2.TrustScore != 45 {
		t.Errorf("expected trust score 45, got %d", entry2.TrustScore)
	}

	if entry2.MaintainerVerified {
		t.Error("expected maintainer verified to be false")
	}

	if entry2.SaferAlternative != "github.com/better/alternative" {
		t.Errorf("expected safer alternative suggestion, got %s", entry2.SaferAlternative)
	}
}

func TestTrustIndexClient_LookupAll_ServerError_500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := NewTrustIndexClient(server.URL, 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	graph := makeTiGraph(
		tiDepSpec{
			path:   "github.com/foo/bar",
			ver:    "v1.0.0",
			direct: true,
			depth:  0,
		},
	)

	results, err := client.LookupAll(context.Background(), graph)

	if err == nil {
		t.Fatal("expected non-nil error for server error")
	}

	if results != nil {
		t.Error("expected nil results on error")
	}

	if err.Error() != "trust index API returned 500" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestTrustIndexClient_LookupAll_ServerError_503(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client, err := NewTrustIndexClient(server.URL, 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	graph := makeTiGraph(
		tiDepSpec{
			path:   "github.com/foo/bar",
			ver:    "v1.0.0",
			direct: true,
			depth:  0,
		},
	)

	results, err := client.LookupAll(context.Background(), graph)

	if err == nil {
		t.Fatal("expected non-nil error for server error")
	}

	if results != nil {
		t.Error("expected nil results on error")
	}
}

func TestTrustIndexClient_LookupAll_BadJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "{invalid json")
	}))
	defer server.Close()

	client, err := NewTrustIndexClient(server.URL, 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	graph := makeTiGraph(
		tiDepSpec{
			path:   "github.com/foo/bar",
			ver:    "v1.0.0",
			direct: true,
			depth:  0,
		},
	)

	results, err := client.LookupAll(context.Background(), graph)

	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}

	if results != nil {
		t.Error("expected nil results on parse error")
	}
}

func TestTrustIndexClient_LookupAll_ConnectionError(t *testing.T) {
	// Use a non-existent server address
	client, err := NewTrustIndexClient("http://localhost:54321", 100*time.Millisecond, false)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	graph := makeTiGraph(
		tiDepSpec{
			path:   "github.com/foo/bar",
			ver:    "v1.0.0",
			direct: true,
			depth:  0,
		},
	)

	results, err := client.LookupAll(context.Background(), graph)

	if err == nil {
		t.Fatal("expected error for connection failure")
	}

	if results != nil {
		t.Error("expected nil results on connection error")
	}
}

func TestTrustIndexClient_LookupAll_MultipleModules(t *testing.T) {
	requestModules := []string{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		// Capture requested modules
		var req struct {
			Modules []string `json:"modules"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requestModules = req.Modules

		// Return empty results
		response := map[string]interface{}{
			"results": map[string]interface{}{},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := NewTrustIndexClient(server.URL, 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	// Create graph with 5 dependencies
	graph := makeTiGraph(
		tiDepSpec{path: "github.com/foo/a", ver: "v1.0.0", direct: true, depth: 0},
		tiDepSpec{path: "github.com/foo/b", ver: "v1.0.0", direct: true, depth: 0},
		tiDepSpec{path: "github.com/foo/c", ver: "v1.0.0", direct: false, depth: 1},
		tiDepSpec{path: "github.com/foo/d", ver: "v1.0.0", direct: false, depth: 1},
		tiDepSpec{path: "github.com/foo/e", ver: "v1.0.0", direct: false, depth: 2},
	)

	results, err := client.LookupAll(context.Background(), graph)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify all modules were sent in request
	if len(requestModules) != 5 {
		t.Errorf("expected 5 modules in request, got %d: %v", len(requestModules), requestModules)
	}

	if results == nil {
		t.Error("expected non-nil results map")
	}
}

func TestTrustIndexClient_LookupAll_PartialResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return results for only one of two requested modules
		response := map[string]interface{}{
			"results": map[string]interface{}{
				"github.com/foo/bar": map[string]interface{}{
					"module":      "github.com/foo/bar",
					"trust_score": 80,
				},
				// Intentionally omit github.com/baz/qux
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := NewTrustIndexClient(server.URL, 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	graph := makeTiGraph(
		tiDepSpec{path: "github.com/foo/bar", ver: "v1.0.0", direct: true, depth: 0},
		tiDepSpec{path: "github.com/baz/qux", ver: "v1.0.0", direct: true, depth: 0},
	)

	results, err := client.LookupAll(context.Background(), graph)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}

	if _, ok := results["github.com/foo/bar"]; !ok {
		t.Error("expected result for github.com/foo/bar")
	}

	if _, ok := results["github.com/baz/qux"]; ok {
		t.Error("did not expect result for github.com/baz/qux")
	}
}

func TestTrustIndexClient_LookupAll_EmptyResults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return empty results
		response := map[string]interface{}{
			"results": map[string]interface{}{},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := NewTrustIndexClient(server.URL, 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	graph := makeTiGraph(
		tiDepSpec{path: "github.com/foo/bar", ver: "v1.0.0", direct: true, depth: 0},
	)

	results, err := client.LookupAll(context.Background(), graph)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if results == nil {
		t.Fatal("expected non-nil results map")
	}

	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestTrustIndexClient_LookupAll_AllFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"results": map[string]interface{}{
				"github.com/test/full": map[string]interface{}{
					"module":               "github.com/test/full",
					"trust_score":          75,
					"maintainer_trust":     80,
					"resilience_score":     85,
					"security_score":       70,
					"community_score":      65,
					"maintainer_name":      "Alice",
					"maintainer_org":       "TechCorp",
					"maintainer_country":   "CA",
					"maintainer_verified":  true,
					"stewardship_status":   "active",
					"safer_alternative":    "github.com/alt/module",
					"is_unidoc_maintained": true,
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, err := NewTrustIndexClient(server.URL, 5*time.Second, false)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	graph := makeTiGraph(
		tiDepSpec{path: "github.com/test/full", ver: "v1.0.0", direct: true, depth: 0},
	)

	results, err := client.LookupAll(context.Background(), graph)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	entry := results["github.com/test/full"]

	// Verify all fields are populated
	if entry.Module != "github.com/test/full" {
		t.Errorf("module mismatch")
	}
	if entry.TrustScore != 75 {
		t.Errorf("trust_score mismatch")
	}
	if entry.MaintainerTrust != 80 {
		t.Errorf("maintainer_trust mismatch")
	}
	if entry.ResilienceScore != 85 {
		t.Errorf("resilience_score mismatch")
	}
	if entry.SecurityScore != 70 {
		t.Errorf("security_score mismatch")
	}
	if entry.CommunityScore != 65 {
		t.Errorf("community_score mismatch")
	}
	if entry.MaintainerName != "Alice" {
		t.Errorf("maintainer_name mismatch")
	}
	if entry.MaintainerOrg != "TechCorp" {
		t.Errorf("maintainer_org mismatch")
	}
	if entry.MaintainerCountry != "CA" {
		t.Errorf("maintainer_country mismatch")
	}
	if !entry.MaintainerVerified {
		t.Errorf("maintainer_verified mismatch")
	}
	if entry.StewardshipStatus != "active" {
		t.Errorf("stewardship_status mismatch")
	}
	if entry.SaferAlternative != "github.com/alt/module" {
		t.Errorf("safer_alternative mismatch")
	}
	if !entry.IsUnidocMaintained {
		t.Errorf("is_unidoc_maintained mismatch")
	}
}

func TestTrustIndexEntry_Struct(t *testing.T) {
	// Verify TrustIndexEntry structure and JSON marshaling
	entry := &TrustIndexEntry{
		Module:             "github.com/example/pkg",
		TrustScore:         90,
		MaintainerTrust:    85,
		ResilienceScore:    80,
		SecurityScore:      75,
		CommunityScore:     70,
		MaintainerName:     "Developer",
		MaintainerOrg:      "OrgName",
		MaintainerCountry:  "US",
		MaintainerVerified: true,
		StewardshipStatus:  "active",
		SaferAlternative:   "",
		IsUnidocMaintained: false,
	}

	// Test JSON marshaling
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaled TrustIndexEntry
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if unmarshaled.Module != entry.Module {
		t.Error("module mismatch after marshal/unmarshal")
	}

	if unmarshaled.TrustScore != entry.TrustScore {
		t.Error("trust score mismatch after marshal/unmarshal")
	}
}
