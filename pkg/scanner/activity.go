package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/mod/semver"

	"github.com/unidoc/unisupply/pkg/offline"
	"github.com/unidoc/unisupply/pkg/progress"
	"github.com/unidoc/unisupply/pkg/resolver"
)

// CommitLookup reports the commit time of the head of the default branch of a
// module's repository. It is the fallback ScanActivity uses when the module
// proxy cannot answer a branch query; MaintainerScanner implements it with the
// GitHub commits API.
type CommitLookup interface {
	LatestCommit(ctx context.Context, modPath string) (time.Time, error)
}

// fallbackBranches are tried, in order, when the repository's default branch
// is not known.
var fallbackBranches = []string{"main", "master"}

// branchQueryName matches a branch name that can be sent as a module proxy
// version query: one path segment of safe characters. A name with a "/" (for
// example "release/1.x") cannot be a path segment.
var branchQueryName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// branchOutcome is the result of one branch query.
type branchOutcome int

const (
	branchFound     branchOutcome = iota // the proxy resolved the branch
	branchNotFound                       // a definitive 404 or 410: no such branch for this module
	branchTransient                      // any other failure: the answer is unknown
)

// defaultBranchQueryTimeout bounds one branch query. A warm answer takes well
// under a second, but a cold fetch of a large repository (a monorepo submodule
// such as aws-sdk-go-v2/service/s3) can run until the proxy gives up after
// about a minute. Waiting for that costs the scan the full client timeout per
// module for a date the release usually already covers; a query cut short is
// transient, so the GitHub fallback or the warning still accounts for it.
const defaultBranchQueryTimeout = 10 * time.Second

// proxyNotFoundMarkers are the substrings of a proxy 404 or 410 body that make
// it a definitive "no such branch for this module": the revision does not
// exist (`invalid version: unknown revision main`), or it exists but does not
// hold this module (`invalid version: go.mod has non-.../v4 module path`). The
// proxy also answers a fetch it gave up on with a 404 (`not found: fetch timed
// out`), and caches that answer for a while; that one says nothing about the
// branch and must stay transient. No 410 body has been observed for a branch
// query; a 410 is held to the same rule. The rule is broad in one place: a
// repository the proxy cannot list answers `invalid version: git ls-remote
// ... exit status 128` whether it does not exist or the host failed during the
// proxy's fetch, and the body does not tell them apart.
var proxyNotFoundMarkers = []string{"unknown revision", "invalid version:"}

// ScanActivity sets LastActivity, MonthsSinceActivity, ActivitySource and
// ActivityBranch on each entry of maintenance from the head commit of the
// default branch of the module's repository. It must run after the maintainer
// scan, whose results supply GitHub's default branch name; maintainers may be
// nil.
//
// The commit time comes from the module proxy, which resolves a branch query
// (`@v/<branch>.info`) to the branch head's pseudo-version and commit time.
// That needs no token or GitHub quota and works for modules not hosted on
// GitHub. The branch is GitHub's default_branch when the maintainer scan has
// it, otherwise main, then master. The `HEAD` query is deliberately not used:
// the proxy can serve it stale by months.
//
// A 404 or 410 whose body says the revision is unknown or does not hold the
// module is "no such branch". On every candidate, that leaves activity unknown
// without a fallback: for a module such as foo/v2 whose default branch has
// moved to v3, the repository's latest commit would describe a different
// module. Any other failure (a timeout, a 5xx, the proxy's own `fetch timed
// out` 404) is transient, and fallback is asked instead, if it is non-nil.
// Each query is bounded by a short timeout of its own, and a successful answer
// is kept in the on-disk response cache for a day.
//
// Modules without a maintenance entry (the proxy lookup failed, so the axis is
// unmeasured) and archived modules (whose score does not depend on activity)
// are skipped. Offline, nothing is requested. The returned error, when
// non-nil, counts the modules whose lookup failed; their maintenance falls back
// to the release age alone.
func (ms *MaintenanceScanner) ScanActivity(ctx context.Context, graph *resolver.Graph, maintenance map[string]*MaintenanceInfo, maintainers map[string]*MaintainerInfo, fallback CommitLookup) error {
	if offline.Enabled() {
		return nil
	}
	rep := progress.From(ctx)

	var todo []*resolver.Dependency
	for _, dep := range graph.Dependencies {
		if info := maintenance[dep.Module.Path]; info != nil && !info.Archived {
			todo = append(todo, dep)
		}
	}
	total := len(todo)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	var failed, done atomic.Int64
	for _, dep := range todo {
		wg.Add(1)
		go func(modPath string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rep.Step("%s", modPath)
			if !ms.lookupActivity(ctx, modPath, maintenance[modPath], maintainers[modPath], fallback) {
				failed.Add(1)
			}
			rep.Progress(int(done.Add(1)), total)
		}(dep.Module.Path)
	}
	wg.Wait()

	if n := failed.Load(); n > 0 {
		return fmt.Errorf("default-branch activity lookup failed for %d of %d module(s) (module proxy unreachable or erroring); their maintenance uses the release age alone", n, total)
	}
	return nil
}

// lookupActivity fills info's activity fields for modPath. It reports false
// only when the answer is unknown because a lookup failed; a module with no
// resolvable branch is not a failure.
func (ms *MaintenanceScanner) lookupActivity(ctx context.Context, modPath string, info *MaintenanceInfo, mi *MaintainerInfo, fallback CommitLookup) bool {
	branches := fallbackBranches
	if mi != nil && mi.DataAvailable && mi.DefaultBranch != "" {
		branches = []string{mi.DefaultBranch}
		if !usableBranchQuery(mi.DefaultBranch) {
			branches = nil
		}
	}

	transient := false
	for _, branch := range branches {
		t, outcome := ms.fetchBranchTime(ctx, modPath, branch)
		if outcome == branchFound {
			ms.setActivity(info, t, ActivityViaProxy, branch)
			return true
		}
		if outcome == branchTransient {
			transient = true
			break
		}
	}
	if !transient && len(branches) > 0 {
		return true // no such branch for this module: activity unknown, not failed
	}

	// The proxy failed, or the default branch cannot be sent as a proxy query
	// (a name with "/", or one such as "v2" that the proxy would read as a
	// version). Only the fallback can answer.
	if fallback != nil {
		t, err := fallback.LatestCommit(ctx, modPath)
		if err != nil || t.IsZero() {
			return false
		}
		branch := ""
		if mi != nil {
			branch = mi.DefaultBranch
		}
		ms.setActivity(info, t, ActivityViaGitHub, branch)
		return true
	}
	// Without a fallback, an unqueryable branch name is a known limit, not a
	// failed lookup: the proxy was never asked.
	return !transient
}

func (ms *MaintenanceScanner) setActivity(info *MaintenanceInfo, t time.Time, source, branch string) {
	info.LastActivity = t
	info.MonthsSinceActivity = monthsSince(ms.ScanStart, t)
	info.ActivitySource = source
	info.ActivityBranch = branch
}

// usableBranchQuery reports whether branch can be sent as a proxy version
// query: a single safe path segment that the proxy would not read as a
// semantic version instead.
func usableBranchQuery(branch string) bool {
	return branchQueryName.MatchString(branch) && !semver.IsValid(branch)
}

// fetchBranchTime asks the module proxy for `<module>/@v/<branch>.info` and
// returns the commit time of the branch head. A fresh answer in the disk cache
// is used without a request; only a resolved branch is cached.
func (ms *MaintenanceScanner) fetchBranchTime(ctx context.Context, modPath, branch string) (time.Time, branchOutcome) {
	url := fmt.Sprintf("%s/%s/@v/%s.info", ms.proxyURL, encodeModulePath(modPath), encodeModulePath(branch))
	if body, hit := ms.cachedProxyBody(url); hit {
		if t, ok := parseBranchTime(body); ok {
			return t, branchFound
		}
	}

	if ms.branchTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, ms.branchTimeout)
		defer cancel()
	}
	body, resp, err := ms.client.Get(ctx, url, GetOptions{
		Host:    proxyHost(ms.proxyURL),
		Purpose: "maintenance:branch-info",
	})
	if err != nil {
		if errors.Is(err, offline.ErrOffline) {
			return time.Time{}, branchNotFound
		}
		return time.Time{}, branchTransient
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusGone:
		if isDefinitiveNotFound(body) {
			return time.Time{}, branchNotFound
		}
		return time.Time{}, branchTransient
	default:
		return time.Time{}, branchTransient
	}
	t, ok := parseBranchTime(body)
	if !ok {
		return time.Time{}, branchTransient
	}
	ms.putProxyBody(url, body)
	return t, branchFound
}

// parseBranchTime reads the commit time from a proxy `.info` answer.
func parseBranchTime(body []byte) (time.Time, bool) {
	var v proxyVersionInfo
	if err := json.Unmarshal(body, &v); err != nil || v.Time.IsZero() {
		return time.Time{}, false
	}
	return v.Time, true
}

// isDefinitiveNotFound reports whether a proxy 404 or 410 body says the branch
// does not exist for the module, rather than that the proxy failed to find out.
func isDefinitiveNotFound(body []byte) bool {
	text := string(body)
	for _, marker := range proxyNotFoundMarkers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}
