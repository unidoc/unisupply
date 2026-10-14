package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// budgetGitHub is a fake GitHub API that counts every request by path. The
// repositories are listed in live; anything else under /repos/ is a 404.
type budgetGitHub struct {
	*httptest.Server
	mu       sync.Mutex
	requests map[string]int
	archived map[string]bool // owner/repo -> archived flag
}

func newBudgetGitHub(t *testing.T, live ...string) *budgetGitHub {
	t.Helper()
	g := &budgetGitHub{requests: make(map[string]int), archived: make(map[string]bool)}
	liveSet := make(map[string]bool)
	for _, l := range live {
		liveSet[strings.ToLower(l)] = true
	}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.requests[r.URL.Path]++
		archived := g.archived
		g.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		p := strings.Trim(r.URL.Path, "/")
		switch parts := strings.Split(p, "/"); {
		case len(parts) == 2 && parts[0] == "users":
			fmt.Fprintf(w, `{"login":%q,"name":"N"}`, parts[1])
		case len(parts) >= 3 && parts[0] == "repos":
			if !liveSet[strings.ToLower(parts[1]+"/"+parts[2])] {
				http.NotFound(w, r)
				return
			}
			switch {
			case len(parts) == 3:
				fmt.Fprintf(w, `{"name":%q,"full_name":"%s/%s","archived":%v,"default_branch":"main","pushed_at":"2026-09-01T00:00:00Z","owner":{"login":%q,"type":"Organization"}}`,
					parts[2], parts[1], parts[2], archived[parts[1]+"/"+parts[2]], parts[1])
			case parts[3] == "contributors":
				fmt.Fprint(w, `[{"login":"a","contributions":90},{"login":"b","contributions":10}]`)
			case parts[3] == "commits":
				fmt.Fprint(w, `[{"commit":{"committer":{"date":"2026-09-01T00:00:00Z"}}}]`)
			default:
				http.NotFound(w, r)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(g.Close)
	return g
}

func (g *budgetGitHub) total() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, c := range g.requests {
		n += c
	}
	return n
}

func (g *budgetGitHub) count(path string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.requests[path]
}

func (g *budgetGitHub) dump() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var lines []string
	for p, c := range g.requests {
		lines = append(lines, fmt.Sprintf("%3d %s", c, p))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func (g *budgetGitHub) scanner(token string) *MaintainerScanner {
	ms := NewMaintainerScanner(5*time.Second, token)
	ms.diskCache = nil
	ms.client.Transport = &testTransport{baseURL: g.URL}
	return ms
}

// originProxy fakes the module proxy for a set of modules. origins maps a
// module path to the repository URL its version records name; a module not in
// the map has no Origin, and one mapped to "" answers 404 everywhere.
func originProxy(t *testing.T, origins map[string]string, gomods map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		mod, rest, ok := strings.Cut(p, "/@")
		if !ok {
			http.NotFound(w, r)
			return
		}
		origin, known := origins[mod]
		if !known {
			http.NotFound(w, r)
			return
		}
		rec := `{"Version":"v1.2.0","Time":"2026-01-01T00:00:00Z"`
		if origin != "" {
			rec += fmt.Sprintf(`,"Origin":{"VCS":"git","URL":%q}`, origin)
		}
		rec += "}"
		switch {
		case rest == "latest" || strings.HasSuffix(rest, ".info"):
			fmt.Fprint(w, rec)
		case rest == "v/list":
			fmt.Fprint(w, "v1.2.0\n")
		case strings.HasSuffix(rest, ".mod"):
			if g, ok := gomods[mod]; ok {
				fmt.Fprint(w, g)
				return
			}
			fmt.Fprintf(w, "module %s\n", mod)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestGitHubBudget measures what a scan of 10 modules in 5 repositories (one of
// them gone, two of them reached through a vanity path) asks GitHub for: the
// proxy scan, the maintainer scan, the archived check, then the activity
// fallback's commits lookup for every github.com module, as the runner does
// with a token. Every GitHub endpoint must be requested at most once, so the
// total is bounded by the per-repository calls times the repositories.
//
// Before this change the same github.com modules (the archived check and the
// vanity repository did not exist) made 17-18 requests: the commits endpoint
// was asked once per module (3x for aws-sdk-go-v2, 2x for foo/mono, 2x for the
// gone repository) and /users/aws twice when two repositories raced for it.
// Now it is 12 for those modules plus 1 for the vanity repository.
func TestGitHubBudget(t *testing.T) {
	gh := newBudgetGitHub(t, "aws/aws-sdk-go-v2", "aws/aws-sdk-go", "foo/mono", "go-yaml/yaml")
	gh.archived["go-yaml/yaml"] = true

	ghMods := []string{
		"github.com/aws/aws-sdk-go-v2", "github.com/aws/aws-sdk-go-v2/service/s3", "github.com/aws/aws-sdk-go-v2/service/ec2",
		"github.com/aws/aws-sdk-go", "github.com/foo/mono", "github.com/foo/mono/v2",
		"github.com/gone/repo", "github.com/gone/repo/v2",
	}
	origins := map[string]string{
		"gopkg.in/yaml.v3": "https://github.com/go-yaml/yaml",
		"gopkg.in/yaml.v2": "https://github.com/go-yaml/yaml.git",
	}
	deps := []struct{ path, ver string }{{"gopkg.in/yaml.v3", "v3.0.1"}, {"gopkg.in/yaml.v2", "v2.4.0"}}
	for _, p := range ghMods {
		owner, repo := parseGitHubPath(p)
		origins[p] = "https://github.com/" + owner + "/" + repo
		deps = append(deps, struct{ path, ver string }{p, "v1.2.0"})
	}
	graph := makeGraphWithDeps(deps...)

	proxy := originProxy(t, origins, nil)
	maint := NewMaintenanceScanner(5 * time.Second)
	maint.proxyURL = proxy.URL
	maint.diskCache = nil
	results, err := maint.ScanAll(context.Background(), graph)
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}

	mnt := gh.scanner("tok")
	mnt.ScanAll(context.Background(), graph)
	if err := maint.ScanArchived(context.Background(), results, mnt); err != nil {
		t.Fatalf("ScanArchived: %v", err)
	}
	var wg sync.WaitGroup
	for _, p := range ghMods {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = mnt.LatestCommit(context.Background(), p) }()
	}
	wg.Wait()

	// 3 live github.com repositories x (repo + contributors + commits), 2
	// owners x 1 profile, the vanity repository x 1 (repo only), the gone
	// repository x 1 (the 404; nothing else is asked about it).
	const perRepo, liveRepos, owners, vanityRepos, goneRepos = 3, 3, 2, 1, 1
	budget := perRepo*liveRepos + owners + vanityRepos + goneRepos
	if got := gh.total(); got > budget {
		t.Errorf("%d GitHub requests for 10 modules in 5 repositories, want at most %d\n%s", got, budget, gh.dump())
	}
	gh.mu.Lock()
	for path, n := range gh.requests {
		if n != 1 {
			t.Errorf("GET %s issued %d times, want 1", path, n)
		}
	}
	gh.mu.Unlock()
	t.Logf("%d GitHub requests for %d modules\n%s", gh.total(), len(deps), gh.dump())

	for _, p := range []string{"gopkg.in/yaml.v3", "gopkg.in/yaml.v2"} {
		if i := results[p]; !i.Archived || i.ArchivedCheck != ArchivedChecked || i.RepositoryURL != "https://github.com/go-yaml/yaml" {
			t.Errorf("%s = archived %v check %q repo %q, want archived, checked, https://github.com/go-yaml/yaml", p, i.Archived, i.ArchivedCheck, i.RepositoryURL)
		}
	}
	for _, p := range []string{"github.com/gone/repo", "github.com/gone/repo/v2"} {
		i := results[p]
		if !i.RepositoryNotFound || i.ArchivedCheck != ArchivedCheckFailed || i.Archived {
			t.Errorf("%s = notfound %v check %q archived %v, want not found, failed, not archived", p, i.RepositoryNotFound, i.ArchivedCheck, i.Archived)
		}
	}
	if i := results["github.com/foo/mono/v2"]; i.ArchivedCheck != ArchivedChecked || i.Archived {
		t.Errorf("foo/mono/v2 check %q archived %v, want checked, not archived", i.ArchivedCheck, i.Archived)
	}
}
