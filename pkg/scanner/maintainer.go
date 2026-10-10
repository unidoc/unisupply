package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/unidoc/unisupply/pkg/progress"
	"github.com/unidoc/unisupply/pkg/resolver"
)

// errRateLimited is returned by githubGet when the GitHub API rate limit is
// exhausted: any 429 response, or a 403 with X-RateLimit-Remaining: 0.
var errRateLimited = errors.New("github rate limit exceeded")

// Values of MaintainerInfo.UnavailableReason.
const (
	// UnavailableRateLimited means GitHub rejected the request for exceeding
	// the API rate limit.
	UnavailableRateLimited = "rate_limited"

	// UnavailableAPIError means the repository request failed for any other
	// reason: a network error, a non-200 status, or an unusable response.
	UnavailableAPIError = "github_api_error"
)

// MaintainerInfo holds maintainer/ownership data for a module.
type MaintainerInfo struct {
	// DataAvailable is false when the GitHub API was unreachable, returned a
	// non-200 status (e.g. 403 rate-limit or 404), or when the token was
	// missing for an authenticated-only endpoint. When false, all numeric
	// fields (Stars, BusFactor, etc.) are zero-valued and MUST NOT be
	// interpreted as real measurements.
	DataAvailable     bool   `json:"data_available"`
	UnavailableReason string `json:"unavailable_reason,omitempty"`

	// Owner and Repo are the repository's canonical GitHub name as reported by
	// the API, which differs from the name in the module path when the
	// repository was renamed or transferred. They are the requested name when
	// the repository could not be fetched.
	Owner string `json:"owner"`
	Repo  string `json:"repo"`

	OwnerName        string   `json:"owner_name"`     // display name of owner
	OwnerLocation    string   `json:"owner_location"` // country/city
	OwnerCompany     string   `json:"owner_company"`  // company affiliation
	OwnerBio         string   `json:"owner_bio"`      // bio/description
	OwnerURL         string   `json:"owner_url"`      // website/blog
	IsOrg            bool     `json:"is_org"`         // org vs personal
	OwnerVerified    bool     `json:"owner_verified"`
	BusinessModel    string   `json:"business_model"` // "open_source", "company_backed", "foundation", "unknown"
	License          string   `json:"license"`        // SPDX license identifier
	Description      string   `json:"description"`    // repo description
	ContributorCount int      `json:"contributor_count"`
	TopContributors  []string `json:"top_contributors"` // top 5 contributor logins
	BusFactor        int      `json:"bus_factor"`
	IsArchived       bool     `json:"is_archived"`
	IsFork           bool     `json:"is_fork"`
	ActivityPattern  string   `json:"activity_pattern"` // "active", "sporadic", "inactive"
	// LastCommitDate is GitHub's pushed_at: the last push to any branch of the
	// repository, bot and Dependabot branches included. It is kept as
	// evidence and drives ActivityPattern, but the maintenance score does not
	// use it; see MaintenanceInfo.LastActivity.
	LastCommitDate time.Time `json:"last_commit_date"`
	// DefaultBranch is the repository's default branch, which the activity
	// lookup (MaintenanceScanner.ScanActivity) queries.
	DefaultBranch   string    `json:"default_branch,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	Stars           int       `json:"stars"`
	Forks           int       `json:"forks"`
	OpenIssues      int       `json:"open_issues"`
	SubDependencies int       `json:"sub_dependencies"` // how many deps this dep pulls in
	// Takeover analysis.
	TakeoverCandidate bool   `json:"takeover_candidate"`
	TakeoverReason    string `json:"takeover_reason,omitempty"`
}

// EnrichMaintainersFromTrustIndex overwrites OwnerVerified for any module that
// has a Trust Index entry. When UniTrust is authoritative (entry present),
// MaintainerVerified replaces the GitHub org-type fallback set during scanning.
// Modules absent from trustIndex are left unchanged.
//
// UniTrust omits modules it has not curated, so a false MaintainerVerified on a
// returned entry means the maintainer was reviewed and explicitly not verified —
// not merely "no opinion". It is therefore safe to treat the value as
// authoritative for any module present in trustIndex.
func EnrichMaintainersFromTrustIndex(maintainers map[string]*MaintainerInfo, trustIndex map[string]*TrustIndexEntry) {
	for mod, entry := range trustIndex {
		if mi, ok := maintainers[mod]; ok {
			mi.OwnerVerified = entry.MaintainerVerified
		}
	}
}

// TakeoverCandidates returns one entry per repository flagged as a takeover
// candidate, sorted by owner/repo. maintainers is keyed by module path, so
// ranging it directly would reorder the report's takeover list on every run,
// and several modules can come from one repository (foo/bar and foo/bar/v2).
// The reports print only repository-level fields, so one entry per repository
// is kept.
func TakeoverCandidates(maintainers map[string]*MaintainerInfo) []*MaintainerInfo {
	byRepo := make(map[string]*MaintainerInfo)
	for _, mod := range slices.Sorted(maps.Keys(maintainers)) {
		mi := maintainers[mod]
		if !mi.TakeoverCandidate {
			continue
		}
		key := mi.Owner + "/" + mi.Repo
		if _, seen := byRepo[key]; !seen {
			byRepo[key] = mi
		}
	}

	var candidates []*MaintainerInfo
	for _, key := range slices.Sorted(maps.Keys(byRepo)) {
		candidates = append(candidates, byRepo[key])
	}
	return candidates
}

// MaintainerScanner analyzes module maintainership via the GitHub API.
type MaintainerScanner struct {
	client    *Client
	token     string
	cache     map[string]*MaintainerInfo
	userCache map[string]*githubUser
	diskCache *maintainerCache
	mu        sync.Mutex

	// repoLocks holds one mutex per owner/repo, guarded by mu.
	repoLocks map[string]*sync.Mutex

	// ScanStart is the reference time used for all age/activity classifications.
	// It is truncated to the start of a UTC day so that two scans on the same
	// calendar day produce identical band results for the same lastCommit.
	// Defaults to time.Now().UTC().Truncate(24*time.Hour) when the scanner is
	// constructed. Override in tests or from the CLI entry point.
	ScanStart time.Time

	// TokenRejected records that GitHub rejected the caller's token (401) and
	// the scanner was given an empty token in its place, so the rate-limit
	// warning does not tell the user to set a token they did set.
	TokenRejected bool

	// rateLimitWarnOnce ensures the rate-limit warning is emitted at most once
	// per scanner instance, even when many goroutines hit the limit simultaneously.
	rateLimitWarnOnce sync.Once
}

// CountGitHubDeps returns the number of dependencies in graph whose module path
// resolves to a GitHub-hosted repository. Used to estimate API call volume
// before scanning so callers can warn when the unauthenticated rate limit
// (60 req/hr, ~20 deps at 3 calls each) is likely to be exceeded.
func CountGitHubDeps(graph *resolver.Graph) int {
	n := 0
	for _, dep := range graph.Dependencies {
		if owner, repo := parseGitHubPath(dep.Module.Path); owner != "" && repo != "" {
			n++
		}
	}
	return n
}

// NewMaintainerScanner creates a new maintainer scanner with a disk-backed
// response cache rooted at the OS user cache directory. Consecutive same-day
// scans will serve GitHub API responses from disk, eliminating per-scan drift
// caused by GitHub edge-cache variance.
func NewMaintainerScanner(timeout time.Duration, githubToken string) *MaintainerScanner {
	return &MaintainerScanner{
		client:    NewClient(ClientOptions{Timeout: timeout}),
		token:     githubToken,
		cache:     make(map[string]*MaintainerInfo),
		userCache: make(map[string]*githubUser),
		diskCache: newMaintainerCache("", 0), // defaults: OS cache dir, 24h TTL
		ScanStart: time.Now().UTC().Truncate(24 * time.Hour),
	}
}

// githubRepo represents relevant fields from the GitHub repos API.
type githubRepo struct {
	Name          string `json:"name"`
	FullName      string `json:"full_name"`
	Description   string `json:"description"`
	Archived      bool   `json:"archived"`
	Disabled      bool   `json:"disabled"`
	Fork          bool   `json:"fork"`
	Stars         int    `json:"stargazers_count"`
	Forks         int    `json:"forks_count"`
	OpenIssues    int    `json:"open_issues_count"`
	PushedAt      string `json:"pushed_at"`
	CreatedAt     string `json:"created_at"`
	DefaultBranch string `json:"default_branch"`
	License       *struct {
		SPDXID string `json:"spdx_id"`
		Name   string `json:"name"`
	} `json:"license"`
	Owner struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"owner"`
}

// githubUser represents a GitHub user or org profile.
type githubUser struct {
	Login    string `json:"login"`
	Name     string `json:"name"`
	Company  string `json:"company"`
	Location string `json:"location"`
	Bio      string `json:"bio"`
	Blog     string `json:"blog"`
	Type     string `json:"type"`
}

// githubContributor represents a contributor from the GitHub API.
type githubContributor struct {
	Login         string `json:"login"`
	Contributions int    `json:"contributions"`
}

// ScanAll analyzes maintainer info for all dependencies.
func (ms *MaintainerScanner) ScanAll(ctx context.Context, graph *resolver.Graph) map[string]*MaintainerInfo {
	rep := progress.From(ctx)

	results := make(map[string]*MaintainerInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 5)

	// Pre-count GitHub-resolvable modules so Progress totals are accurate.
	var ghDeps []*resolver.Dependency
	type ownerRepo struct{ owner, repo string }
	repos := make(map[*resolver.Dependency]ownerRepo)
	for _, dep := range graph.Dependencies {
		owner, repo := parseGitHubPath(dep.Module.Path)
		if owner == "" || repo == "" {
			continue
		}
		ghDeps = append(ghDeps, dep)
		repos[dep] = ownerRepo{owner, repo}
	}
	total := len(ghDeps)

	var done int64

	for _, dep := range ghDeps {
		or := repos[dep]
		wg.Add(1)
		go func(d *resolver.Dependency, owner, repo string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rep.Step("%s", d.Module.Path)
			info := ms.analyzeRepo(ctx, owner, repo)
			n := atomic.AddInt64(&done, 1)
			rep.Progress(int(n), total)
			if info != nil {
				// analyzeRepo caches one *MaintainerInfo per owner/repo, shared
				// by every module from that repo. Copy it before setting
				// per-module fields, or those modules race on the shared value
				// and all report whichever one wrote last.
				mi := *info
				mi.SubDependencies = d.TransitiveDeps
				mu.Lock()
				results[d.Module.Path] = &mi
				mu.Unlock()
			}
		}(dep, or.owner, or.repo)
	}

	wg.Wait()
	return results
}

func (ms *MaintainerScanner) analyzeRepo(ctx context.Context, owner, repo string) *MaintainerInfo {
	cacheKey := owner + "/" + repo
	ms.mu.Lock()
	if cached, ok := ms.cache[cacheKey]; ok {
		ms.mu.Unlock()
		return cached
	}
	// Serialize lookups of one repository. Modules from the same repository
	// (foo/bar and foo/bar/v2) are scanned
	// concurrently, and checking the cache alone lets each of them miss and
	// fetch the repository again, spending the API quota several times over.
	if ms.repoLocks == nil {
		ms.repoLocks = make(map[string]*sync.Mutex)
	}
	lock, ok := ms.repoLocks[cacheKey]
	if !ok {
		lock = new(sync.Mutex)
		ms.repoLocks[cacheKey] = lock
	}
	ms.mu.Unlock()

	lock.Lock()
	defer lock.Unlock()

	ms.mu.Lock()
	if cached, ok := ms.cache[cacheKey]; ok {
		ms.mu.Unlock()
		return cached
	}
	ms.mu.Unlock()

	info := &MaintainerInfo{
		Owner: owner,
		Repo:  repo,
	}

	// Fetch repo info. On any failure (network error, 403, 404, etc.) we
	// leave DataAvailable as false so callers know zero-values are not real.
	repoData, err := ms.fetchRepo(ctx, owner, repo)
	if err != nil {
		if errors.Is(err, errRateLimited) {
			info.UnavailableReason = UnavailableRateLimited
			rep := progress.From(ctx)
			hint := "set GITHUB_TOKEN for higher limits"
			switch {
			case ms.TokenRejected:
				hint = "the GitHub token was rejected (401), so requests ran unauthenticated"
			case ms.token != "":
				// Authenticated requests still hit the token's quota or a
				// secondary limit (a 429); asking for a token would not help.
				hint = "requests were authenticated, so the token's quota or a secondary rate limit was reached; wait and re-run"
			}
			ms.rateLimitWarnOnce.Do(func() {
				rep.Warn("GitHub API rate limit hit — %s; %s: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api", err, hint)
			})
		} else {
			info.UnavailableReason = UnavailableAPIError
		}
		ms.mu.Lock()
		ms.cache[cacheKey] = info
		ms.mu.Unlock()
		return info
	}

	// The primary API call succeeded: all fields that follow are real data.
	info.DataAvailable = true

	// Use the repository's canonical name from here on. A renamed or
	// transferred repository (an old name in go.mod) is
	// served through a redirect, and the owner and contributors endpoints
	// built from the old name would redirect or 404 as well.
	if o, r := canonicalRepoName(repoData.FullName); o != "" {
		owner, repo = o, r
		info.Owner, info.Repo = o, r
	}

	info.Description = repoData.Description
	info.IsArchived = repoData.Archived
	info.IsFork = repoData.Fork
	info.Stars = repoData.Stars
	info.Forks = repoData.Forks
	info.OpenIssues = repoData.OpenIssues
	info.IsOrg = repoData.Owner.Type == "Organization"
	info.OwnerVerified = repoData.Owner.Type == "Organization"

	if repoData.License != nil {
		info.License = repoData.License.SPDXID
	}

	if repoData.PushedAt != "" {
		if t, err := time.Parse(time.RFC3339, repoData.PushedAt); err == nil {
			info.LastCommitDate = t
		}
	}
	info.DefaultBranch = repoData.DefaultBranch
	if repoData.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, repoData.CreatedAt); err == nil {
			info.CreatedAt = t
		}
	}

	info.ActivityPattern = classifyActivity(ms.ScanStart, info.LastCommitDate)

	// Fetch owner profile (user or org).
	user := ms.fetchUser(ctx, owner)
	if user != nil {
		info.OwnerName = user.Name
		if info.OwnerName == "" {
			info.OwnerName = user.Login
		}
		info.OwnerLocation = user.Location
		info.OwnerCompany = user.Company
		info.OwnerBio = user.Bio
		info.OwnerURL = user.Blog
	}

	// Determine business model.
	info.BusinessModel = classifyBusinessModel(info, repoData)

	// Fetch contributors for bus factor analysis.
	contributors := ms.fetchContributors(ctx, owner, repo)
	info.ContributorCount = len(contributors)
	info.BusFactor = computeBusFactor(contributors)

	// Top contributors (up to 5).
	for i, c := range contributors {
		if i >= 5 {
			break
		}
		info.TopContributors = append(info.TopContributors, c.Login)
	}

	// Takeover candidate analysis.
	assessTakeover(info)

	ms.mu.Lock()
	ms.cache[cacheKey] = info
	ms.mu.Unlock()

	return info
}

func (ms *MaintainerScanner) fetchRepo(ctx context.Context, owner, repo string) (*githubRepo, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
	body, err := ms.githubGet(ctx, url, "maintainer:repo")
	if err != nil {
		return nil, err
	}
	var result githubRepo
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// githubCommit is the subset of a GitHub commits API entry LatestCommit reads.
type githubCommit struct {
	Commit struct {
		Committer struct {
			Date time.Time `json:"date"`
		} `json:"committer"`
	} `json:"commit"`
}

// LatestCommit returns the committer time of the latest commit on the default
// branch of the GitHub repository behind modPath, from
// `GET /repos/{owner}/{repo}/commits?per_page=1` (which lists the default
// branch). It implements CommitLookup, the fallback MaintenanceScanner uses
// when the module proxy cannot answer a branch query. It returns an error for
// a module path that is not on github.com, and without a token, so the
// fallback never spends the unauthenticated quota the maintainer scan needs.
func (ms *MaintainerScanner) LatestCommit(ctx context.Context, modPath string) (time.Time, error) {
	if ms.token == "" {
		return time.Time{}, errors.New("no GitHub token")
	}
	owner, repo := parseGitHubPath(modPath)
	if owner == "" || repo == "" {
		return time.Time{}, fmt.Errorf("%s is not a GitHub module path", modPath)
	}
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits?per_page=1", owner, repo)
	body, err := ms.githubGet(ctx, url, "maintenance:github-commits")
	if err != nil {
		return time.Time{}, err
	}
	var commits []githubCommit
	if err := json.Unmarshal(body, &commits); err != nil {
		return time.Time{}, err
	}
	if len(commits) == 0 || commits[0].Commit.Committer.Date.IsZero() {
		return time.Time{}, errors.New("no commits reported")
	}
	return commits[0].Commit.Committer.Date, nil
}

func (ms *MaintainerScanner) fetchUser(ctx context.Context, login string) *githubUser {
	ms.mu.Lock()
	if cached, ok := ms.userCache[login]; ok {
		ms.mu.Unlock()
		return cached
	}
	ms.mu.Unlock()

	url := fmt.Sprintf("https://api.github.com/users/%s", login)
	body, err := ms.githubGet(ctx, url, "maintainer:user")
	if err != nil {
		return nil
	}
	var user githubUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil
	}

	ms.mu.Lock()
	ms.userCache[login] = &user
	ms.mu.Unlock()

	return &user
}

func (ms *MaintainerScanner) fetchContributors(ctx context.Context, owner, repo string) []githubContributor {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contributors?per_page=100", owner, repo)
	body, err := ms.githubGet(ctx, url, "maintainer:contributors")
	if err != nil {
		return nil
	}
	var contributors []githubContributor
	if err := json.Unmarshal(body, &contributors); err != nil {
		return nil
	}
	return contributors
}

// githubGet fetches url from the disk cache when a fresh entry exists (within
// the 24-hour TTL). On a miss or expiry it issues an HTTP GET, persists the
// response body on HTTP 200, and returns the body. Non-200 responses are not
// cached — the error is returned directly to the caller as before.
func (ms *MaintainerScanner) githubGet(ctx context.Context, url, purpose string) ([]byte, error) {
	// Consult the disk cache first.
	if ms.diskCache != nil {
		if cached, hit, err := ms.diskCache.Get(url); err == nil && hit {
			return cached, nil
		}
	}

	auth := ""
	if ms.token != "" {
		auth = "Bearer " + ms.token
	}
	opts := GetOptions{
		Host:       githubAPIHost,
		MaxBytes:   1 * 1024 * 1024, // 1 MB — paginated contributor lists can be large.
		AuthHeader: auth,
		Accept:     "application/vnd.github.v3+json",
		Purpose:    purpose,
	}
	body, resp, err := ms.client.Get(ctx, url, opts)
	if err != nil {
		return nil, err
	}

	// GitHub answers a renamed or transferred repository with a redirect to
	// its canonical /repositories/{id} URL, and the shared client blocks
	// redirects. Follow one hop here, same host only, and only for this
	// scanner: a second redirect or any other target is an error below.
	if isRedirectStatus(resp.StatusCode) {
		target, ok := githubAPIRedirectTarget(resp.Header.Get("Location"))
		if !ok {
			return nil, fmt.Errorf("GitHub API returned %d for %s with an unusable redirect", resp.StatusCode, url)
		}
		body, resp, err = ms.client.Get(ctx, target, opts)
		if err != nil {
			return nil, err
		}
	}
	if resp.StatusCode != http.StatusOK {
		// A 429 is always a rate limit: GitHub also sends it without
		// X-RateLimit-Remaining (a secondary limit). A 403 is one only
		// when the remaining count says so; otherwise it is a permission error.
		if resp.StatusCode == http.StatusTooManyRequests ||
			(resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0") {
			if resetUnix, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
				resetAt := time.Unix(resetUnix, 0).UTC()
				untilReset := time.Until(resetAt).Round(time.Second)
				if untilReset < 0 {
					untilReset = 0
				}
				return nil, fmt.Errorf("%w: resets at %s (%s from now)",
					errRateLimited, resetAt.Format(time.RFC3339), untilReset)
			}
			return nil, fmt.Errorf("%w", errRateLimited)
		}
		return nil, fmt.Errorf("GitHub API returned %d for %s", resp.StatusCode, url)
	}

	// Persist only on success; non-200 responses are never cached. The body is
	// stored under the original URL, so a later run is served from the cache
	// without repeating the redirect.
	if ms.diskCache != nil {
		_ = ms.diskCache.Put(url, body) // ignore cache-write errors — not fatal
	}

	return body, nil
}

// githubAPIHost is the only host the maintainer scanner talks to, and the only
// host a redirect may lead to.
const githubAPIHost = "api.github.com"

// isRedirectStatus reports whether code is a redirect GitHub uses for moved
// resources.
func isRedirectStatus(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// githubAPIRedirectTarget returns location when it is an absolute https URL on
// api.github.com, with no credentials or port. Anything else (another host,
// plain http, a relative reference, an empty header) is rejected, so a
// redirect cannot move the request, or its Authorization header, off GitHub's
// API.
func githubAPIRedirectTarget(location string) (string, bool) {
	u, err := url.Parse(location)
	if err != nil || u.Scheme != "https" || u.User != nil || !strings.EqualFold(u.Host, githubAPIHost) {
		return "", false
	}
	if !strings.HasPrefix(u.Path, "/") {
		return "", false
	}
	return u.String(), true
}

// ownerNamePattern and repoNamePattern are GitHub's own name alphabets. They
// are enforced on the full_name a response reports, so a garbled or hostile
// value cannot inject path segments or query strings into the GitHub API URLs
// built from it.
var (
	ownerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)
	repoNamePattern  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
)

// canonicalRepoName splits a GitHub full_name ("owner/repo") into its parts,
// returning empty strings when it is not exactly that shape.
func canonicalRepoName(fullName string) (owner, repo string) {
	owner, repo, ok := strings.Cut(fullName, "/")
	if !ok || !ownerNamePattern.MatchString(owner) || !repoNamePattern.MatchString(repo) {
		return "", ""
	}
	return owner, repo
}

// classifyActivity returns "active", "sporadic", "inactive", or "unknown"
// based on the elapsed months between now and lastCommit. now should be the
// scan-start time (truncated to a UTC day) so that two scans on the same
// calendar day yield identical classifications for the same lastCommit.
func classifyActivity(now, lastCommit time.Time) string {
	if lastCommit.IsZero() {
		return "unknown"
	}
	months := monthsSince(now, lastCommit)
	switch {
	case months < 3:
		return "active"
	case months < 12:
		return "sporadic"
	default:
		return "inactive"
	}
}

// classifyBusinessModel guesses the business model based on available signals.
func classifyBusinessModel(info *MaintainerInfo, repo *githubRepo) string {
	ownerLower := strings.ToLower(info.Owner)
	companyLower := strings.ToLower(info.OwnerCompany)

	// Known foundations / orgs.
	foundations := []string{"golang", "kubernetes", "cncf", "apache", "linux", "mozilla"}
	for _, f := range foundations {
		if strings.Contains(ownerLower, f) || strings.Contains(companyLower, f) {
			return "foundation"
		}
	}

	// Known companies.
	companies := []string{"google", "microsoft", "amazon", "aws", "meta", "facebook",
		"hashicorp", "docker", "elastic", "datadog", "grafana", "unidoc", "stripe",
		"cloudflare", "uber", "github", "gitlab", "jetbrains", "redhat", "ibm", "oracle"}
	for _, c := range companies {
		if strings.Contains(ownerLower, c) || strings.Contains(companyLower, c) {
			return "company_backed"
		}
	}

	// Org with company name.
	if info.IsOrg && info.OwnerCompany != "" {
		return "company_backed"
	}

	// golang.org/x/ is Go team.
	if strings.HasPrefix(info.Owner, "golang") {
		return "foundation"
	}

	if info.IsOrg {
		return "organization"
	}

	return "individual"
}

func computeBusFactor(contributors []githubContributor) int {
	if len(contributors) == 0 {
		return 0
	}
	totalContribs := 0
	for _, c := range contributors {
		totalContribs += c.Contributions
	}
	if totalContribs == 0 {
		return 0
	}
	threshold := float64(totalContribs) * 0.05
	keyMaintainers := 0
	for _, c := range contributors {
		if float64(c.Contributions) >= threshold {
			keyMaintainers++
		}
	}
	return keyMaintainers
}

func assessTakeover(info *MaintainerInfo) {
	if info.Stars >= 100 && info.ActivityPattern == "inactive" {
		info.TakeoverCandidate = true
		info.TakeoverReason = "widely used but inactive"
		return
	}
	if info.BusFactor <= 1 && info.ActivityPattern == "inactive" {
		info.TakeoverCandidate = true
		info.TakeoverReason = "single maintainer, inactive"
		return
	}
	if info.IsArchived {
		info.TakeoverCandidate = true
		info.TakeoverReason = "repository archived"
		return
	}
}

func parseGitHubPath(modPath string) (owner, repo string) {
	if !strings.HasPrefix(modPath, "github.com/") {
		return "", ""
	}
	parts := strings.Split(strings.TrimPrefix(modPath, "github.com/"), "/")
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}
