package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/offline"
)

// goYamlInfo is the recorded module proxy response for go.yaml.in/yaml/v3 at
// v3.0.4 (observed 2026-10-07).
const goYamlInfo = `{"Version":"v3.0.4","Time":"2025-06-29T14:09:51Z","Origin":{"VCS":"git","URL":"https://github.com/yaml/go-yaml","Hash":"c3552c15f996075a7634df5159d9161c67bf3d76","Ref":"refs/tags/v3.0.4"}}`

func TestResolveSourceRepo(t *testing.T) {
	tests := []struct {
		name      string
		modPath   string
		origin    string
		wantOwner string
		wantRepo  string
		wantVia   string
	}{
		{"github module path", "github.com/spf13/cobra", "", "spf13", "cobra", SourceViaModulePath},
		{"github module path with major suffix", "github.com/foo/bar/v2", "", "foo", "bar", SourceViaModulePath},
		{"github module path beats origin", "github.com/foo/bar", "https://github.com/other/repo", "foo", "bar", SourceViaModulePath},
		{"github module path beats gopkg rule", "github.com/foo/bar", "https://go.googlesource.com/x", "foo", "bar", SourceViaModulePath},

		{"origin https", "go.yaml.in/yaml/v3", "https://github.com/yaml/go-yaml", "yaml", "go-yaml", SourceViaProxyOrigin},
		{"origin dot git suffix", "k8s.io/api", "https://github.com/kubernetes/api.git", "kubernetes", "api", SourceViaProxyOrigin},
		{"origin trailing slash", "k8s.io/api", "https://github.com/kubernetes/api/", "kubernetes", "api", SourceViaProxyOrigin},
		{"origin mixed-case host", "k8s.io/api", "https://GitHub.com/kubernetes/api", "kubernetes", "api", SourceViaProxyOrigin},
		{"origin beats gopkg rule", "gopkg.in/yaml.v3", "https://github.com/yaml/go-yaml", "yaml", "go-yaml", SourceViaProxyOrigin},
		{"origin non-github host", "golang.org/x/crypto", "https://go.googlesource.com/crypto", "", "", ""},
		{"origin look-alike host", "example.org/x", "https://github.com.evil.example/a/b", "", "", ""},
		{"origin look-alike userinfo", "example.org/x", "https://github.com@evil.example/a/b", "", "", ""},
		{"origin gitlab", "example.org/x", "https://gitlab.com/a/b", "", "", ""},
		{"origin missing owner", "example.org/x", "https://github.com/onlyowner", "", "", ""},
		{"origin extra path", "example.org/x", "https://github.com/a/b/tree/main", "", "", ""},
		{"origin ssh scheme", "example.org/x", "ssh://git@github.com/a/b", "", "", ""},
		{"origin scp-like", "example.org/x", "git@github.com:a/b.git", "", "", ""},
		{"origin bad characters", "example.org/x", "https://github.com/a/b%3Fx=1", "", "", ""},
		{"origin dotdot repo", "example.org/x", "https://github.com/a/..", "", "", ""},
		{"origin malformed", "example.org/x", "://", "", "", ""},
		{"origin empty", "example.org/x", "", "", "", ""},

		{"gopkg one segment", "gopkg.in/yaml.v3", "", "go-yaml", "yaml", SourceViaGopkgIn},
		{"gopkg one segment v0", "gopkg.in/warnings.v0", "", "go-warnings", "warnings", SourceViaGopkgIn},
		{"gopkg one segment v1", "gopkg.in/check.v1", "", "go-check", "check", SourceViaGopkgIn},
		{"gopkg two segments", "gopkg.in/natefinch/lumberjack.v2", "", "natefinch", "lumberjack", SourceViaGopkgIn},
		{"gopkg unstable", "gopkg.in/yaml.v2-unstable", "", "go-yaml", "yaml", SourceViaGopkgIn},
		{"gopkg dotted name", "gopkg.in/ini.v1", "", "go-ini", "ini", SourceViaGopkgIn},
		{"gopkg origin non-github falls to rule", "gopkg.in/yaml.v3", "https://go.googlesource.com/x", "go-yaml", "yaml", SourceViaGopkgIn},
		{"gopkg no version", "gopkg.in/yaml", "", "", "", ""},
		{"gopkg leading-zero version", "gopkg.in/yaml.v03", "", "", "", ""},
		{"gopkg sub-package", "gopkg.in/yaml.v3/internal", "", "", "", ""},
		{"gopkg three segments", "gopkg.in/a/b/c.v1", "", "", "", ""},
		{"gopkg empty name", "gopkg.in/.v1", "", "", "", ""},
		{"gopkg bare host", "gopkg.in/", "", "", "", ""},
		{"gopkg look-alike host", "gopkg.in.evil.example/yaml.v3", "", "", "", ""},

		{"unmatched vanity", "golang.org/x/text", "", "", "", ""},
		{"empty", "", "", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repo, via := ResolveSourceRepo(tt.modPath, tt.origin)
			if owner != tt.wantOwner || repo != tt.wantRepo || via != tt.wantVia {
				t.Errorf("ResolveSourceRepo(%q, %q) = (%q, %q, %q), want (%q, %q, %q)",
					tt.modPath, tt.origin, owner, repo, via, tt.wantOwner, tt.wantRepo, tt.wantVia)
			}
		})
	}
}

// TestMaintenanceScanner_CapturesOrigin verifies the proxy Origin is read from
// the .info-shaped responses the scanner already fetches, and survives the
// scanner's cache.
func TestMaintenanceScanner_CapturesOrigin(t *testing.T) {
	const googlesource = `{"Version":"v0.30.0","Time":"2025-01-01T00:00:00Z","Origin":{"VCS":"git","URL":"https://go.googlesource.com/crypto"}}`
	const noOrigin = `{"Version":"v3.0.1","Time":"2022-05-27T08:35:30Z"}`

	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		p := r.URL.Path
		switch {
		case strings.HasSuffix(p, "/@v/list"):
			fmt.Fprint(w, "")
		case strings.HasPrefix(p, "/go.yaml.in/yaml/v3/"):
			fmt.Fprint(w, goYamlInfo)
		case strings.HasPrefix(p, "/golang.org/x/crypto/"):
			fmt.Fprint(w, googlesource)
		case strings.HasPrefix(p, "/gopkg.in/yaml.v3/"):
			fmt.Fprint(w, noOrigin)
		// Only the pinned version carries an Origin; @latest does not.
		case p == "/example.org/pinned/@v/v1.0.0.info":
			fmt.Fprint(w, `{"Version":"v1.0.0","Time":"2024-01-01T00:00:00Z","Origin":{"URL":"https://github.com/pinned/repo"}}`)
		case p == "/example.org/pinned/@latest":
			fmt.Fprint(w, `{"Version":"v1.1.0","Time":"2024-06-01T00:00:00Z"}`)
		// Both carry one; the latest wins.
		case p == "/example.org/moved/@v/v1.0.0.info":
			fmt.Fprint(w, `{"Version":"v1.0.0","Time":"2024-01-01T00:00:00Z","Origin":{"URL":"https://github.com/old/home"}}`)
		case p == "/example.org/moved/@latest":
			fmt.Fprint(w, `{"Version":"v1.1.0","Time":"2024-06-01T00:00:00Z","Origin":{"URL":"https://github.com/new/home"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = srv.URL

	tests := []struct {
		modPath, version, want string
	}{
		{"go.yaml.in/yaml/v3", "v3.0.4", "https://github.com/yaml/go-yaml"},
		{"golang.org/x/crypto", "v0.30.0", "https://go.googlesource.com/crypto"},
		{"gopkg.in/yaml.v3", "v3.0.1", ""},
		{"example.org/pinned", "v1.0.0", "https://github.com/pinned/repo"},
		{"example.org/moved", "v1.0.0", "https://github.com/new/home"},
	}
	for _, tt := range tests {
		t.Run(tt.modPath, func(t *testing.T) {
			info, err := ms.checkModule(context.Background(), tt.modPath, tt.version)
			if err != nil {
				t.Fatalf("checkModule: %v", err)
			}
			if info.OriginURL != tt.want {
				t.Errorf("OriginURL = %q, want %q", info.OriginURL, tt.want)
			}

			// A cache hit must return the same Origin without a new request.
			before := requests.Load()
			again, err := ms.checkModule(context.Background(), tt.modPath, tt.version)
			if err != nil {
				t.Fatalf("checkModule (cached): %v", err)
			}
			if again.OriginURL != tt.want || requests.Load() != before {
				t.Errorf("cached OriginURL = %q (requests +%d), want %q with no new requests",
					again.OriginURL, requests.Load()-before, tt.want)
			}
		})
	}

	t.Run("OriginURLs helper keeps only modules with an origin", func(t *testing.T) {
		all := make(map[string]*MaintenanceInfo)
		for _, tt := range tests {
			info, _ := ms.checkModule(context.Background(), tt.modPath, tt.version)
			all[tt.modPath] = info
		}
		all["nil.example/mod"] = nil
		got := OriginURLs(all)
		if len(got) != 4 {
			t.Errorf("OriginURLs returned %d entries, want 4: %v", len(got), got)
		}
		if _, ok := got["gopkg.in/yaml.v3"]; ok {
			t.Error("module without Origin must be absent")
		}
	})

	t.Run("origin is not serialized", func(t *testing.T) {
		b, err := json.Marshal(&MaintenanceInfo{OriginURL: "https://github.com/a/b"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "github.com/a/b") || strings.Contains(string(b), "origin") {
			t.Errorf("OriginURL leaked into JSON: %s", b)
		}
	})
}

// vanityGitHub is a fake GitHub API for the vanity-path tests. Repositories
// are keyed "owner/repo"; an unlisted one answers 404. It counts requests per
// path.
type vanityGitHub struct {
	*httptest.Server
	mu       sync.Mutex
	requests map[string]int
}

func newVanityGitHub(t *testing.T, repos map[string]githubRepo) *vanityGitHub {
	t.Helper()
	g := &vanityGitHub{requests: make(map[string]int)}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.requests[r.URL.Path]++
		g.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		rest := strings.TrimPrefix(r.URL.Path, "/repos/")
		switch {
		case strings.HasPrefix(r.URL.Path, "/users/"):
			fmt.Fprintf(w, `{"login":%q,"name":"Owner"}`, strings.TrimPrefix(r.URL.Path, "/users/"))
		case strings.HasSuffix(r.URL.Path, "/contributors"):
			fmt.Fprint(w, `[{"login":"a","contributions":50},{"login":"b","contributions":30}]`)
		case strings.HasPrefix(r.URL.Path, "/repos/"):
			repo, ok := repos[rest]
			if !ok {
				http.NotFound(w, r)
				return
			}
			// A slow repo response makes concurrent lookups of one repository
			// overlap, so duplicate fetches would show up in the count.
			time.Sleep(60 * time.Millisecond)
			_ = json.NewEncoder(w).Encode(repo)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(g.Close)
	return g
}

func (g *vanityGitHub) count(path string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.requests[path]
}

// newVanityScanner returns a maintainer scanner that talks to g and ignores
// the on-disk response cache, so the test neither reads nor writes the user's
// cache directory.
func newVanityScanner(g *vanityGitHub) *MaintainerScanner {
	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.diskCache = nil
	ms.client.Transport = &testTransport{baseURL: g.URL}
	return ms
}

func TestMaintainerScanner_ScanAll_VanityPaths(t *testing.T) {
	recent := time.Now().Add(-10 * 24 * time.Hour).Format(time.RFC3339)
	gh := newVanityGitHub(t, map[string]githubRepo{
		"go-yaml/yaml":         {Name: "yaml", Archived: true, Stars: 6000, PushedAt: "2025-04-01T00:00:00Z"},
		"yaml/go-yaml":         {Name: "go-yaml", Stars: 500, PushedAt: recent},
		"go-warnings/warnings": {Name: "warnings", Archived: true, PushedAt: "2019-01-01T00:00:00Z"},
		"natefinch/lumberjack": {Name: "lumberjack", PushedAt: recent},
		"spf13/cobra":          {Name: "cobra", PushedAt: recent},
	})

	graph := makeGraphWithDeps(
		struct{ path, ver string }{"gopkg.in/yaml.v3", "v3.0.1"},
		struct{ path, ver string }{"gopkg.in/yaml.v2", "v2.4.0"},
		struct{ path, ver string }{"go.yaml.in/yaml/v3", "v3.0.4"},
		struct{ path, ver string }{"gopkg.in/warnings.v0", "v0.1.2"},
		struct{ path, ver string }{"gopkg.in/natefinch/lumberjack.v2", "v2.2.1"},
		struct{ path, ver string }{"github.com/spf13/cobra", "v1.8.0"},
		struct{ path, ver string }{"golang.org/x/crypto", "v0.30.0"},
		struct{ path, ver string }{"example.org/unrelated", "v1.0.0"},
	)

	ms := newVanityScanner(gh)
	ms.OriginURLs = map[string]string{
		"go.yaml.in/yaml/v3":  "https://github.com/yaml/go-yaml",
		"golang.org/x/crypto": "https://go.googlesource.com/crypto",
	}
	results := ms.ScanAll(context.Background(), graph)

	tests := []struct {
		module       string
		wantRepo     string
		wantVia      string
		wantArchived bool
		wantSource   string
	}{
		{"gopkg.in/yaml.v3", "go-yaml/yaml", SourceViaGopkgIn, true, "github.com/go-yaml/yaml"},
		{"gopkg.in/yaml.v2", "go-yaml/yaml", SourceViaGopkgIn, true, "github.com/go-yaml/yaml"},
		{"go.yaml.in/yaml/v3", "yaml/go-yaml", SourceViaProxyOrigin, false, "github.com/yaml/go-yaml"},
		{"gopkg.in/warnings.v0", "go-warnings/warnings", SourceViaGopkgIn, true, "github.com/go-warnings/warnings"},
		{"gopkg.in/natefinch/lumberjack.v2", "natefinch/lumberjack", SourceViaGopkgIn, false, "github.com/natefinch/lumberjack"},
		{"github.com/spf13/cobra", "spf13/cobra", SourceViaModulePath, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.module, func(t *testing.T) {
			mi := results[tt.module]
			if mi == nil {
				t.Fatalf("no maintainer info for %s", tt.module)
			}
			if !mi.DataAvailable {
				t.Fatalf("DataAvailable = false (reason %q)", mi.UnavailableReason)
			}
			if got := mi.Owner + "/" + mi.Repo; got != tt.wantRepo {
				t.Errorf("repo = %s, want %s", got, tt.wantRepo)
			}
			if mi.IsArchived != tt.wantArchived {
				t.Errorf("IsArchived = %v, want %v", mi.IsArchived, tt.wantArchived)
			}
			if mi.SourceRepo != tt.wantSource {
				t.Errorf("SourceRepo = %q, want %q", mi.SourceRepo, tt.wantSource)
			}
			wantVia := tt.wantVia
			if wantVia == SourceViaModulePath {
				wantVia = "" // not recorded for github.com paths
			}
			if mi.SourceRepoVia != wantVia {
				t.Errorf("SourceRepoVia = %q, want %q", mi.SourceRepoVia, wantVia)
			}
		})
	}

	t.Run("unresolvable modules are not scanned", func(t *testing.T) {
		for _, mod := range []string{"golang.org/x/crypto", "example.org/unrelated"} {
			if _, ok := results[mod]; ok {
				t.Errorf("%s was scanned, want no result", mod)
			}
		}
		for _, p := range []string{"/repos/golang/crypto", "/repos/unrelated/unrelated"} {
			if n := gh.count(p); n != 0 {
				t.Errorf("GET %s issued %d times, want 0", p, n)
			}
		}
	})

	t.Run("modules sharing a repository share one fetch", func(t *testing.T) {
		// gopkg.in/yaml.v2 and gopkg.in/yaml.v3 both map to go-yaml/yaml.
		for _, p := range []string{"/repos/go-yaml/yaml", "/repos/go-yaml/yaml/contributors", "/users/go-yaml"} {
			if n := gh.count(p); n != 1 {
				t.Errorf("GET %s issued %d times, want 1", p, n)
			}
		}
	})

	t.Run("per-module copies do not share provenance", func(t *testing.T) {
		if results["gopkg.in/yaml.v2"] == results["gopkg.in/yaml.v3"] {
			t.Error("modules share one *MaintainerInfo")
		}
	})
}

// TestMaintainerScanner_ScanAll_NoOriginsNeeded verifies the gopkg.in rule
// works without any proxy data, and github.com paths resolve exactly as before.
func TestMaintainerScanner_ScanAll_NoOriginsNeeded(t *testing.T) {
	gh := newVanityGitHub(t, map[string]githubRepo{
		"go-yaml/yaml": {Name: "yaml", Archived: true, PushedAt: "2025-04-01T00:00:00Z"},
	})
	graph := makeGraphWithDeps(
		struct{ path, ver string }{"gopkg.in/yaml.v3", "v3.0.1"},
		struct{ path, ver string }{"go.yaml.in/yaml/v3", "v3.0.4"},
	)
	results := newVanityScanner(gh).ScanAll(context.Background(), graph)

	if mi := results["gopkg.in/yaml.v3"]; mi == nil || !mi.IsArchived {
		t.Errorf("gopkg.in/yaml.v3 = %+v, want archived", mi)
	}
	if _, ok := results["go.yaml.in/yaml/v3"]; ok {
		t.Error("go.yaml.in/yaml/v3 resolved without an Origin")
	}
}

// TestMaintainerScanner_ScanAll_OfflineMakesNoGitHubCall verifies that
// resolving a repository from the gopkg.in rule does not bypass --offline: the
// request is refused, and the module reports its data as unavailable.
func TestMaintainerScanner_ScanAll_OfflineMakesNoGitHubCall(t *testing.T) {
	offline.Enable()
	t.Cleanup(offline.Disable)

	ms := NewMaintainerScanner(5*time.Second, "")
	ms.diskCache = nil
	ms.OriginURLs = map[string]string{"go.yaml.in/yaml/v3": "https://github.com/yaml/go-yaml"}

	graph := makeGraphWithDeps(
		struct{ path, ver string }{"gopkg.in/yaml.v3", "v3.0.1"},
		struct{ path, ver string }{"go.yaml.in/yaml/v3", "v3.0.4"},
	)
	results := ms.ScanAll(context.Background(), graph)

	for _, mod := range []string{"gopkg.in/yaml.v3", "go.yaml.in/yaml/v3"} {
		mi := results[mod]
		if mi == nil {
			t.Fatalf("no maintainer info for %s", mod)
		}
		if mi.DataAvailable || mi.IsArchived {
			t.Errorf("%s: DataAvailable=%v IsArchived=%v, want an unmeasured record", mod, mi.DataAvailable, mi.IsArchived)
		}
		if mi.UnavailableReason != "github_api_error" {
			t.Errorf("%s: UnavailableReason = %q, want github_api_error", mod, mi.UnavailableReason)
		}
	}
}

func TestCountGitHubDeps_Vanity(t *testing.T) {
	graph := makeGraphWithDeps(
		struct{ path, ver string }{"github.com/spf13/cobra", "v1.8.0"},
		struct{ path, ver string }{"gopkg.in/yaml.v3", "v3.0.1"},
		struct{ path, ver string }{"go.yaml.in/yaml/v3", "v3.0.4"},
		struct{ path, ver string }{"golang.org/x/crypto", "v0.30.0"},
		struct{ path, ver string }{"example.org/unrelated", "v1.0.0"},
	)
	origins := map[string]string{
		"go.yaml.in/yaml/v3":  "https://github.com/yaml/go-yaml",
		"golang.org/x/crypto": "https://go.googlesource.com/crypto",
	}

	if got := CountGitHubDeps(graph); got != 2 {
		t.Errorf("CountGitHubDeps = %d, want 2 (github.com path + gopkg.in rule)", got)
	}
	if got := CountGitHubDepsWithOrigins(graph, origins); got != 3 {
		t.Errorf("CountGitHubDepsWithOrigins = %d, want 3 (adds the proxy-origin module)", got)
	}
	if got := CountGitHubDepsWithOrigins(graph, nil); got != 2 {
		t.Errorf("CountGitHubDepsWithOrigins(nil) = %d, want 2", got)
	}
}

func TestMaintainerInfo_JSONSourceRepo(t *testing.T) {
	plain, err := json.Marshal(MaintainerInfo{Owner: "spf13", Repo: "cobra"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "source_repo") {
		t.Errorf("source_repo present for a github.com module: %s", plain)
	}
	mapped, err := json.Marshal(MaintainerInfo{SourceRepo: "github.com/go-yaml/yaml", SourceRepoVia: SourceViaGopkgIn})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"source_repo":"github.com/go-yaml/yaml"`, `"source_repo_via":"gopkg_in_rule"`} {
		if !strings.Contains(string(mapped), want) {
			t.Errorf("missing %s in %s", want, mapped)
		}
	}
}
