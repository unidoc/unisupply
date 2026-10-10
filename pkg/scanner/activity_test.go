package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/offline"
	"github.com/unidoc/unisupply/pkg/resolver"
)

// activityScanStart pins the scan clock so month arithmetic is deterministic.
var activityScanStart = time.Date(2026, time.October, 9, 0, 0, 0, 0, time.UTC)

// fakeProxy answers branch queries from a map of request path to status and
// commit time, and records every path requested. Unlisted paths are 404. A 404
// or 410 carries the proxy's "unknown revision" body unless bodies overrides it.
type fakeProxy struct {
	*httptest.Server
	mu       sync.Mutex
	answers  map[string]proxyAnswer
	bodies   map[string]string
	requests []string
}

type proxyAnswer struct {
	status int
	time   time.Time
}

// proxyFetchTimedOut is the body proxy.golang.org sends, with a 404, when its
// own fetch of the repository timed out (recorded on a cold aws-sdk-go-v2
// submodule). It says nothing about whether the branch exists.
const proxyFetchTimedOut = "not found: fetch timed out"

func newFakeProxy(t *testing.T, answers map[string]proxyAnswer) *fakeProxy {
	t.Helper()
	p := &fakeProxy{answers: answers, bodies: map[string]string{}}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.requests = append(p.requests, r.URL.Path)
		a, ok := p.answers[r.URL.Path]
		body, hasBody := p.bodies[r.URL.Path]
		p.mu.Unlock()
		if !ok {
			a.status = http.StatusNotFound
		}
		w.WriteHeader(a.status)
		switch {
		case hasBody:
			fmt.Fprint(w, body)
		case a.status == http.StatusOK:
			fmt.Fprintf(w, `{"Version":"v0.0.0-x","Time":%q}`, a.time.Format(time.RFC3339))
		case a.status == http.StatusNotFound || a.status == http.StatusGone:
			// The proxy's answer for a branch that does not exist.
			rev := strings.TrimSuffix(r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:], ".info")
			fmt.Fprintf(w, "not found: %s@%s: invalid version: unknown revision %s", actMod, rev, rev)
		}
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *fakeProxy) setBody(path, body string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bodies[path] = body
}

func (p *fakeProxy) requested() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.requests)
}

// fakeCommits is a CommitLookup that records which modules it was asked about.
type fakeCommits struct {
	mu    sync.Mutex
	asked []string
	t     time.Time
	err   error
}

func (f *fakeCommits) LatestCommit(_ context.Context, modPath string) (time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, modPath)
	return f.t, f.err
}

func monthsBefore(n int) time.Time { return activityScanStart.AddDate(0, -n, 0) }

func newActivityScanner(p *fakeProxy) *MaintenanceScanner {
	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = p.URL
	ms.ScanStart = activityScanStart
	ms.diskCache = nil
	return ms
}

const actMod = "github.com/acme/widget"

func actGraph() *resolver.Graph {
	return makeGraphWithDeps(struct{ path, ver string }{actMod, "v1.0.0"})
}

func TestScanActivity_UsesGitHubDefaultBranch(t *testing.T) {
	p := newFakeProxy(t, map[string]proxyAnswer{
		"/github.com/acme/widget/@v/develop.info": {http.StatusOK, monthsBefore(2)},
		"/github.com/acme/widget/@v/main.info":    {http.StatusOK, monthsBefore(30)},
	})
	maint := map[string]*MaintenanceInfo{actMod: {MonthsSinceRelease: 40}}
	maintainers := map[string]*MaintainerInfo{actMod: {DataAvailable: true, DefaultBranch: "develop"}}

	if err := newActivityScanner(p).ScanActivity(context.Background(), actGraph(), maint, maintainers, nil); err != nil {
		t.Fatalf("ScanActivity: %v", err)
	}
	got := maint[actMod]
	if got.ActivitySource != ActivityViaProxy || got.ActivityBranch != "develop" || got.MonthsSinceActivity != 2 {
		t.Errorf("activity = %s/%s %d months, want proxy_branch/develop 2", got.ActivitySource, got.ActivityBranch, got.MonthsSinceActivity)
	}
	if got.MonthsInactive() != 2 {
		t.Errorf("MonthsInactive = %d, want 2 (the newer of release and commit)", got.MonthsInactive())
	}
	if reqs := p.requested(); !slices.Equal(reqs, []string{"/github.com/acme/widget/@v/develop.info"}) {
		t.Errorf("requests = %v, want only the default branch", reqs)
	}
}

// Without GitHub's answer, main is tried before master. A repository with a
// stale master and an active main (hashicorp/go-multierror) reads as main.
func TestScanActivity_MainBeforeMaster(t *testing.T) {
	p := newFakeProxy(t, map[string]proxyAnswer{
		"/github.com/acme/widget/@v/main.info":   {http.StatusOK, monthsBefore(6)},
		"/github.com/acme/widget/@v/master.info": {http.StatusOK, monthsBefore(42)},
	})
	maint := map[string]*MaintenanceInfo{actMod: {MonthsSinceRelease: 60}}
	if err := newActivityScanner(p).ScanActivity(context.Background(), actGraph(), maint, nil, nil); err != nil {
		t.Fatalf("ScanActivity: %v", err)
	}
	if got := maint[actMod]; got.ActivityBranch != "main" || got.MonthsSinceActivity != 6 {
		t.Errorf("activity = %s %d months, want main 6", got.ActivityBranch, got.MonthsSinceActivity)
	}

	p = newFakeProxy(t, map[string]proxyAnswer{
		"/github.com/acme/widget/@v/master.info": {http.StatusOK, monthsBefore(3)},
	})
	maint = map[string]*MaintenanceInfo{actMod: {MonthsSinceRelease: 60}}
	if err := newActivityScanner(p).ScanActivity(context.Background(), actGraph(), maint, nil, nil); err != nil {
		t.Fatalf("ScanActivity: %v", err)
	}
	if got := maint[actMod]; got.ActivityBranch != "master" || got.MonthsSinceActivity != 3 {
		t.Errorf("activity = %s %d months, want master 3 after main 404", got.ActivityBranch, got.MonthsSinceActivity)
	}
}

// A 404 or 410 on every candidate is "no such branch for this module" (for
// example foo/v2 whose default branch moved to v3): unknown, not a failure, and
// no GitHub fallback, whose repository-wide commit would describe another
// module.
func TestScanActivity_NoBranchIsUnknownNotFailure(t *testing.T) {
	p := newFakeProxy(t, map[string]proxyAnswer{
		"/github.com/acme/widget/@v/master.info": {http.StatusGone, time.Time{}},
	})
	fb := &fakeCommits{t: monthsBefore(1)}
	maint := map[string]*MaintenanceInfo{actMod: {MonthsSinceRelease: 30}}
	if err := newActivityScanner(p).ScanActivity(context.Background(), actGraph(), maint, nil, fb); err != nil {
		t.Errorf("ScanActivity = %v, want nil: a missing branch is not a failure", err)
	}
	if maint[actMod].HasActivity() {
		t.Errorf("activity set to %v, want unknown", maint[actMod].LastActivity)
	}
	if len(fb.asked) != 0 {
		t.Errorf("fallback asked for %v, want not asked on 404/410", fb.asked)
	}
	if maint[actMod].MonthsInactive() != 30 {
		t.Errorf("MonthsInactive = %d, want the release age 30", maint[actMod].MonthsInactive())
	}
}

func TestScanActivity_TransientFailureUsesFallback(t *testing.T) {
	p := newFakeProxy(t, map[string]proxyAnswer{
		"/github.com/acme/widget/@v/main.info":   {http.StatusBadGateway, time.Time{}},
		"/github.com/acme/widget/@v/master.info": {http.StatusOK, monthsBefore(50)},
	})
	fb := &fakeCommits{t: monthsBefore(1)}
	maint := map[string]*MaintenanceInfo{actMod: {MonthsSinceRelease: 30}}
	if err := newActivityScanner(p).ScanActivity(context.Background(), actGraph(), maint, nil, fb); err != nil {
		t.Fatalf("ScanActivity: %v", err)
	}
	got := maint[actMod]
	if got.ActivitySource != ActivityViaGitHub || got.MonthsSinceActivity != 1 {
		t.Errorf("activity = %s %d months, want github_commits 1", got.ActivitySource, got.MonthsSinceActivity)
	}
	if slices.Contains(p.requested(), "/github.com/acme/widget/@v/master.info") {
		t.Error("master queried after a transient failure on main; the answer for main is unknown, not absent")
	}
}

func TestScanActivity_TransientFailureWithoutFallbackIsCounted(t *testing.T) {
	p := newFakeProxy(t, map[string]proxyAnswer{
		"/github.com/acme/widget/@v/main.info": {http.StatusServiceUnavailable, time.Time{}},
	})
	maint := map[string]*MaintenanceInfo{actMod: {MonthsSinceRelease: 30}}
	err := newActivityScanner(p).ScanActivity(context.Background(), actGraph(), maint, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "1 of 1") {
		t.Fatalf("ScanActivity = %v, want a failure count of 1 of 1", err)
	}
	if strings.Contains(err.Error(), actMod) {
		t.Errorf("error %q names the module; warnings must not disclose module paths", err)
	}
	if maint[actMod].HasActivity() {
		t.Error("activity set after a failed lookup")
	}

	// A failing fallback leaves it failed too.
	fb := &fakeCommits{err: errors.New("rate limited")}
	if err := newActivityScanner(p).ScanActivity(context.Background(), actGraph(), maint, nil, fb); err == nil {
		t.Error("ScanActivity = nil, want a failure when the fallback fails as well")
	}
}

// The proxy answers a fetch it gave up on with a 404 too, and keeps serving
// that answer for a while. It says nothing about the branch: reading it as "no
// such branch" skipped the fallback, warned about nothing, and fell through to
// a years-stale master (aws-sdk-go-v2 read as 70 months inactive).
func TestScanActivity_FetchTimedOutIsTransient(t *testing.T) {
	p := newFakeProxy(t, map[string]proxyAnswer{
		"/github.com/acme/widget/@v/main.info":   {http.StatusNotFound, time.Time{}},
		"/github.com/acme/widget/@v/master.info": {http.StatusOK, monthsBefore(70)},
	})
	p.setBody("/github.com/acme/widget/@v/main.info", proxyFetchTimedOut)

	fb := &fakeCommits{t: monthsBefore(1)}
	maint := map[string]*MaintenanceInfo{actMod: {MonthsSinceRelease: 30}}
	if err := newActivityScanner(p).ScanActivity(context.Background(), actGraph(), maint, nil, fb); err != nil {
		t.Fatalf("ScanActivity: %v", err)
	}
	if got := maint[actMod]; got.ActivitySource != ActivityViaGitHub || got.MonthsSinceActivity != 1 {
		t.Errorf("activity = %s/%s %d months, want github_commits 1", got.ActivitySource, got.ActivityBranch, got.MonthsSinceActivity)
	}
	if slices.Contains(p.requested(), "/github.com/acme/widget/@v/master.info") {
		t.Error("master queried after a timed-out fetch of main; the answer for main is unknown, not absent")
	}

	// Without a fallback it is a counted failure, not a quiet unknown.
	maint = map[string]*MaintenanceInfo{actMod: {MonthsSinceRelease: 30}}
	err := newActivityScanner(p).ScanActivity(context.Background(), actGraph(), maint, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "1 of 1") {
		t.Errorf("ScanActivity = %v, want a failure count of 1 of 1", err)
	}
	if maint[actMod].HasActivity() {
		t.Errorf("activity set to %s %v, want unknown", maint[actMod].ActivityBranch, maint[actMod].LastActivity)
	}
}

func TestIsDefinitiveNotFound(t *testing.T) {
	for _, tc := range []struct {
		body string
		want bool
	}{
		// Recorded from proxy.golang.org.
		{"not found: github.com/hashicorp/go-multierror@nosuchbranch: invalid version: unknown revision nosuchbranch", true},
		{`not found: github.com/go-chi/chi/v4@v4.1.3-0.20260929233827-167e1e3bd039: invalid version: go.mod has non-.../v4 module path "github.com/go-chi/chi/v5" (and .../v4/go.mod does not exist) at revision 167e1e3bd039`, true},
		{"not found: github.com/nosuch/repo@main: invalid version: git ls-remote -q --end-of-options https://github.com/nosuch/repo in /tmp/gopath/pkg/mod/cache/vcs/x: exit status 128", true},
		{proxyFetchTimedOut, false},
		{"", false},
		{"404 page not found", false},
	} {
		if got := isDefinitiveNotFound([]byte(tc.body)); got != tc.want {
			t.Errorf("isDefinitiveNotFound(%q) = %v, want %v", tc.body, got, tc.want)
		}
	}
}

// A branch query has a short timeout of its own: a cold monorepo submodule
// would otherwise hold the scan for the full client timeout. Cut short, it is
// transient, so the fallback still answers.
func TestScanActivity_BranchQueryTimeout(t *testing.T) {
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(slow.Close)
	t.Cleanup(func() { close(release) })

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = slow.URL
	ms.ScanStart = activityScanStart
	ms.diskCache = nil
	ms.branchTimeout = 50 * time.Millisecond

	fb := &fakeCommits{t: monthsBefore(2)}
	maint := map[string]*MaintenanceInfo{actMod: {MonthsSinceRelease: 30}}
	start := time.Now()
	if err := ms.ScanActivity(context.Background(), actGraph(), maint, nil, fb); err != nil {
		t.Fatalf("ScanActivity: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("ScanActivity took %v, want the branch timeout (50ms) to cut the query short, not the client timeout (5s)", elapsed)
	}
	if got := maint[actMod]; got.ActivitySource != ActivityViaGitHub || got.MonthsSinceActivity != 2 {
		t.Errorf("activity = %s %d months, want github_commits 2 after a timed-out query", got.ActivitySource, got.MonthsSinceActivity)
	}
}

// A resolved branch is kept on disk, so a rerun within the day makes no
// request for it. Anything else is asked again.
func TestScanActivity_DiskCache(t *testing.T) {
	p := newFakeProxy(t, map[string]proxyAnswer{
		"/github.com/acme/widget/@v/main.info": {http.StatusOK, monthsBefore(6)},
	})
	dir := t.TempDir()
	scan := func() *MaintenanceInfo {
		t.Helper()
		ms := newActivityScanner(p)
		ms.diskCache = newMaintainerCache(dir, time.Hour)
		maint := map[string]*MaintenanceInfo{actMod: {MonthsSinceRelease: 30}}
		if err := ms.ScanActivity(context.Background(), actGraph(), maint, nil, nil); err != nil {
			t.Fatalf("ScanActivity: %v", err)
		}
		return maint[actMod]
	}

	if got := scan(); got.ActivityBranch != "main" || got.MonthsSinceActivity != 6 {
		t.Fatalf("first scan: activity = %s %d months, want main 6", got.ActivityBranch, got.MonthsSinceActivity)
	}
	if got := scan(); got.ActivityBranch != "main" || got.MonthsSinceActivity != 6 {
		t.Errorf("second scan: activity = %s %d months, want main 6 from the cache", got.ActivityBranch, got.MonthsSinceActivity)
	}
	if reqs := p.requested(); len(reqs) != 1 {
		t.Errorf("requests = %v, want one: the second scan reads the cache", reqs)
	}

	// A branch that did not resolve is not cached.
	p = newFakeProxy(t, map[string]proxyAnswer{
		"/github.com/acme/widget/@v/master.info": {http.StatusOK, monthsBefore(3)},
	})
	dir = t.TempDir()
	scan()
	scan()
	want := []string{
		"/github.com/acme/widget/@v/main.info", "/github.com/acme/widget/@v/master.info", // first scan
		"/github.com/acme/widget/@v/main.info", // second scan: master comes from the cache
	}
	if reqs := p.requested(); !slices.Equal(reqs, want) {
		t.Errorf("requests = %v, want %v", reqs, want)
	}
}

// A default branch that cannot be a proxy query ("release/1.x", or a name the
// proxy would read as a version, such as pelletier/go-toml's "v2") goes
// straight to the fallback. Without one it is unknown, not a failed lookup.
func TestScanActivity_UnusableDefaultBranch(t *testing.T) {
	for _, branch := range []string{"release/1.x", "v1.2.3", "v2"} {
		t.Run(branch, func(t *testing.T) {
			p := newFakeProxy(t, nil)
			fb := &fakeCommits{t: monthsBefore(4)}
			maint := map[string]*MaintenanceInfo{actMod: {MonthsSinceRelease: 30}}
			maintainers := map[string]*MaintainerInfo{actMod: {DataAvailable: true, DefaultBranch: branch}}
			if err := newActivityScanner(p).ScanActivity(context.Background(), actGraph(), maint, maintainers, fb); err != nil {
				t.Fatalf("ScanActivity: %v", err)
			}
			if reqs := p.requested(); len(reqs) != 0 {
				t.Errorf("proxy queried %v, want no request for an unusable branch", reqs)
			}
			if got := maint[actMod]; got.ActivitySource != ActivityViaGitHub || got.ActivityBranch != branch {
				t.Errorf("activity = %s/%s, want github_commits/%s", got.ActivitySource, got.ActivityBranch, branch)
			}

			// Without a fallback: unknown, no warning, no proxy request.
			maint = map[string]*MaintenanceInfo{actMod: {MonthsSinceRelease: 30}}
			if err := newActivityScanner(p).ScanActivity(context.Background(), actGraph(), maint, maintainers, nil); err != nil {
				t.Errorf("ScanActivity without fallback = %v, want nil: the proxy was never asked, so nothing failed", err)
			}
			if maint[actMod].HasActivity() || len(p.requested()) != 0 {
				t.Errorf("activity %v, requests %v: want unknown and no proxy request", maint[actMod].LastActivity, p.requested())
			}
		})
	}
}

// Uppercase in a branch name is escaped like a module path ("!x").
func TestScanActivity_EscapesBranchCase(t *testing.T) {
	p := newFakeProxy(t, map[string]proxyAnswer{
		"/github.com/acme/widget/@v/!main.info": {http.StatusOK, monthsBefore(1)},
	})
	maint := map[string]*MaintenanceInfo{actMod: {MonthsSinceRelease: 30}}
	maintainers := map[string]*MaintainerInfo{actMod: {DataAvailable: true, DefaultBranch: "Main"}}
	if err := newActivityScanner(p).ScanActivity(context.Background(), actGraph(), maint, maintainers, nil); err != nil {
		t.Fatalf("ScanActivity: %v", err)
	}
	if !maint[actMod].HasActivity() {
		t.Errorf("requests = %v, want the escaped branch !main resolved", p.requested())
	}
}

func TestScanActivity_SkipsArchivedAndUnmeasured(t *testing.T) {
	p := newFakeProxy(t, nil)
	graph := makeGraphWithDeps(
		struct{ path, ver string }{"github.com/acme/archived", "v1.0.0"},
		struct{ path, ver string }{"github.com/acme/unmeasured", "v1.0.0"},
	)
	maint := map[string]*MaintenanceInfo{"github.com/acme/archived": {Archived: true}}
	if err := newActivityScanner(p).ScanActivity(context.Background(), graph, maint, nil, nil); err != nil {
		t.Fatalf("ScanActivity: %v", err)
	}
	if reqs := p.requested(); len(reqs) != 0 {
		t.Errorf("requests = %v, want none for archived and unmeasured modules", reqs)
	}
	if _, ok := maint["github.com/acme/unmeasured"]; ok {
		t.Error("an entry was created for a module the maintenance scan did not measure")
	}
}

func TestScanActivity_OfflineMakesNoRequest(t *testing.T) {
	offline.Enable()
	t.Cleanup(offline.Disable)
	p := newFakeProxy(t, nil)
	fb := &fakeCommits{t: monthsBefore(1)}
	maint := map[string]*MaintenanceInfo{actMod: {MonthsSinceRelease: 30}}
	if err := newActivityScanner(p).ScanActivity(context.Background(), actGraph(), maint, nil, fb); err != nil {
		t.Errorf("ScanActivity offline = %v, want nil", err)
	}
	if len(p.requested()) != 0 || len(fb.asked) != 0 {
		t.Errorf("offline made requests: proxy %v, fallback %v", p.requested(), fb.asked)
	}
}

func TestMaintainerScanner_LatestCommit(t *testing.T) {
	newScanner := func(token string, requests *[]string, status int, body string) *MaintainerScanner {
		ms := NewMaintainerScanner(5*time.Second, token)
		ms.diskCache = nil
		ms.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			*requests = append(*requests, req.URL.Host+req.URL.RequestURI())
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: req}, nil
		})
		return ms
	}
	const commits = `[{"sha":"abc","commit":{"author":{"date":"2026-01-01T00:00:00Z"},"committer":{"date":"2026-04-01T05:28:02Z"}}}]`

	t.Run("reads the committer date of the default branch head", func(t *testing.T) {
		var reqs []string
		got, err := newScanner("tok", &reqs, http.StatusOK, commits).LatestCommit(context.Background(), "github.com/hashicorp/go-multierror")
		if err != nil {
			t.Fatalf("LatestCommit: %v", err)
		}
		if want := time.Date(2026, time.April, 1, 5, 28, 2, 0, time.UTC); !got.Equal(want) {
			t.Errorf("LatestCommit = %v, want %v (committer, not author, date)", got, want)
		}
		if !slices.Equal(reqs, []string{"api.github.com/repos/hashicorp/go-multierror/commits?per_page=1"}) {
			t.Errorf("requests = %v", reqs)
		}
	})

	t.Run("no token makes no request", func(t *testing.T) {
		var reqs []string
		if _, err := newScanner("", &reqs, http.StatusOK, commits).LatestCommit(context.Background(), "github.com/a/b"); err == nil {
			t.Error("LatestCommit without a token succeeded")
		}
		if len(reqs) != 0 {
			t.Errorf("requests = %v, want none without a token", reqs)
		}
	})

	t.Run("non-GitHub module path makes no request", func(t *testing.T) {
		var reqs []string
		if _, err := newScanner("tok", &reqs, http.StatusOK, commits).LatestCommit(context.Background(), "golang.org/x/text"); err == nil {
			t.Error("LatestCommit for a non-GitHub path succeeded")
		}
		if len(reqs) != 0 {
			t.Errorf("requests = %v, want none", reqs)
		}
	})

	t.Run("empty or failed answers are errors", func(t *testing.T) {
		for _, tc := range []struct {
			status int
			body   string
		}{{http.StatusOK, `[]`}, {http.StatusInternalServerError, `{}`}, {http.StatusOK, `not json`}} {
			var reqs []string
			if _, err := newScanner("tok", &reqs, tc.status, tc.body).LatestCommit(context.Background(), "github.com/a/b"); err == nil {
				t.Errorf("status %d body %q: LatestCommit succeeded", tc.status, tc.body)
			}
		}
	})
}

// The maintainer scan records GitHub's default branch for the activity lookup.
func TestMaintainerScanner_RecordsDefaultBranch(t *testing.T) {
	ms := NewMaintainerScanner(5*time.Second, "tok")
	ms.diskCache = nil
	ms.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := `[]`
		if req.URL.Path == "/repos/acme/widget" {
			body = `{"name":"widget","default_branch":"trunk","pushed_at":"2026-10-07T00:00:00Z","owner":{"login":"acme","type":"Organization"}}`
		} else if strings.HasPrefix(req.URL.Path, "/users/") {
			body = `{"login":"acme"}`
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: req}, nil
	})
	mi := ms.ScanAll(context.Background(), actGraph())[actMod]
	if mi == nil || mi.DefaultBranch != "trunk" {
		t.Fatalf("maintainer info = %+v, want DefaultBranch trunk", mi)
	}
}
