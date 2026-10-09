package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// noRedirectTransport sends requests for api.github.com to a test server
// without following redirects, which testTransport does. The scanner's own
// client blocks redirects, so the transport under it must not hide them.
type noRedirectTransport struct{ serverHost string }

func (t noRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.URL.Scheme = "http"
	r.URL.Host = t.serverHost
	return http.DefaultTransport.RoundTrip(r)
}

// redirectGitHub fakes the GitHub API for a repository renamed from
// imdario/mergo to darccio/mergo: the old-name endpoints answer 301 to the
// canonical /repositories/{id} URL, as the real API does.
type redirectGitHub struct {
	*httptest.Server
	mu       sync.Mutex
	requests map[string]int

	// repoLocation overrides the Location header of the old-name repo
	// endpoint, and idLocation that of /repositories/1.
	repoLocation string
	idLocation   string
}

func newRedirectGitHub(t *testing.T) *redirectGitHub {
	t.Helper()
	g := &redirectGitHub{
		requests:     make(map[string]int),
		repoLocation: "https://api.github.com/repositories/1",
	}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.requests[r.URL.Path]++
		g.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/imdario/mergo":
			w.Header().Set("Location", g.repoLocation)
			w.WriteHeader(http.StatusMovedPermanently)
		case "/repositories/1":
			if g.idLocation != "" {
				w.Header().Set("Location", g.idLocation)
				w.WriteHeader(http.StatusMovedPermanently)
				return
			}
			fmt.Fprint(w, `{"name":"mergo","full_name":"darccio/mergo","archived":false,"pushed_at":"2026-09-01T00:00:00Z","owner":{"login":"darccio","type":"User"}}`)
		case "/repos/darccio/mergo/contributors":
			fmt.Fprint(w, `[{"login":"darccio","contributions":90},{"login":"x","contributions":10}]`)
		case "/users/darccio":
			fmt.Fprint(w, `{"login":"darccio","name":"Dario Castane"}`)
		default:
			// Old-name sub-resources would redirect too; the scanner must not ask.
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(g.Close)
	return g
}

func (g *redirectGitHub) count(path string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.requests[path]
}

func (g *redirectGitHub) scanner() *MaintainerScanner {
	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.diskCache = nil
	ms.client.Transport = noRedirectTransport{serverHost: strings.TrimPrefix(g.URL, "http://")}
	return ms
}

func TestMaintainerScanner_FollowsRenameRedirect(t *testing.T) {
	gh := newRedirectGitHub(t)
	graph := makeGraphWithDeps(
		struct{ path, ver string }{"github.com/imdario/mergo", "v0.3.16"},
	)
	ms := gh.scanner()

	mi := ms.ScanAll(context.Background(), graph)["github.com/imdario/mergo"]
	if mi == nil {
		t.Fatal("no maintainer info")
	}
	if !mi.DataAvailable {
		t.Fatalf("DataAvailable = false (reason %q), want the redirect followed", mi.UnavailableReason)
	}
	if mi.Owner != "darccio" || mi.Repo != "mergo" {
		t.Errorf("Owner/Repo = %s/%s, want the canonical darccio/mergo", mi.Owner, mi.Repo)
	}
	if mi.OwnerName != "Dario Castane" || mi.ContributorCount != 2 {
		t.Errorf("OwnerName = %q, ContributorCount = %d: follow-up calls must use the canonical name", mi.OwnerName, mi.ContributorCount)
	}
	for _, p := range []string{"/users/imdario", "/repos/imdario/mergo/contributors"} {
		if n := gh.count(p); n != 0 {
			t.Errorf("GET %s issued %d times, want 0 (old-name endpoint)", p, n)
		}
	}
}

func TestMaintainerScanner_GitHubGet_Redirects(t *testing.T) {
	const repoURL = "https://api.github.com/repos/imdario/mergo"

	tests := []struct {
		name         string
		repoLocation string
		idLocation   string
		wantErr      bool
		wantIDHits   int
	}{
		{name: "same host, one hop", repoLocation: "https://api.github.com/repositories/1", wantIDHits: 1},
		{name: "other host", repoLocation: "https://evil.example/repositories/1", wantErr: true},
		{name: "http scheme", repoLocation: "http://api.github.com/repositories/1", wantErr: true},
		{name: "relative", repoLocation: "/repositories/1", wantErr: true},
		{name: "userinfo", repoLocation: "https://api.github.com@evil.example/repositories/1", wantErr: true},
		{name: "empty location", repoLocation: "", wantErr: true},
		{name: "second redirect", repoLocation: "https://api.github.com/repositories/1", idLocation: "https://api.github.com/repositories/2", wantErr: true, wantIDHits: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gh := newRedirectGitHub(t)
			gh.repoLocation, gh.idLocation = tt.repoLocation, tt.idLocation
			ms := gh.scanner()

			body, err := ms.githubGet(context.Background(), repoURL, "test")
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !strings.Contains(string(body), "darccio/mergo") {
				t.Errorf("body = %s, want the canonical repository", body)
			}
			if n := gh.count("/repositories/1"); n != tt.wantIDHits {
				t.Errorf("GET /repositories/1 issued %d times, want %d", n, tt.wantIDHits)
			}
			if n := gh.count("/repositories/2"); n != 0 {
				t.Errorf("GET /repositories/2 issued %d times, want 0 (no redirect chains)", n)
			}
		})
	}
}

// TestMaintainerScanner_GitHubGet_RedirectCachedUnderOriginalURL verifies the
// final body is cached under the requested URL, so the next run is served from
// disk without repeating the redirect.
func TestMaintainerScanner_GitHubGet_RedirectCachedUnderOriginalURL(t *testing.T) {
	gh := newRedirectGitHub(t)
	ms := gh.scanner()
	ms.diskCache = newMaintainerCache(t.TempDir(), time.Hour)

	const repoURL = "https://api.github.com/repos/imdario/mergo"
	first, err := ms.githubGet(context.Background(), repoURL, "test")
	if err != nil {
		t.Fatalf("first githubGet: %v", err)
	}
	second, err := ms.githubGet(context.Background(), repoURL, "test")
	if err != nil {
		t.Fatalf("second githubGet: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("cached body differs: %s vs %s", first, second)
	}
	if a, b := gh.count("/repos/imdario/mergo"), gh.count("/repositories/1"); a != 1 || b != 1 {
		t.Errorf("requests = %d to the old name, %d to the canonical URL, want 1 each", a, b)
	}
}

func TestGitHubAPIRedirectTarget(t *testing.T) {
	tests := []struct {
		location string
		want     bool
	}{
		{"https://api.github.com/repositories/8715072", true},
		{"https://API.GITHUB.COM/repositories/8715072", true},
		{"https://api.github.com/repositories/8715072?per_page=100", true},
		{"https://github.com/repositories/1", false},
		{"https://api.github.com.evil.example/repositories/1", false},
		{"https://api.github.com:8443/repositories/1", false},
		{"https://user:pw@api.github.com/repositories/1", false},
		{"http://api.github.com/repositories/1", false},
		{"//api.github.com/repositories/1", false},
		{"/repositories/1", false},
		{"", false},
		{"https://api.github.com", false},
		{"://bad", false},
	}
	for _, tt := range tests {
		t.Run(tt.location, func(t *testing.T) {
			got, ok := githubAPIRedirectTarget(tt.location)
			if ok != tt.want {
				t.Fatalf("githubAPIRedirectTarget(%q) ok = %v, want %v", tt.location, ok, tt.want)
			}
			if ok && got != tt.location {
				t.Errorf("githubAPIRedirectTarget(%q) = %q, want the location unchanged", tt.location, got)
			}
		})
	}
}
