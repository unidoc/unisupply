package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"

	"github.com/unidoc/unisupply/pkg/offline"
	"github.com/unidoc/unisupply/pkg/progress"
	"github.com/unidoc/unisupply/pkg/resolver"
)

// proxyHost extracts the hostname from the configured proxy URL for use as
// the host-pin value in httpclient.GetOptions. Tests override proxyURL to
// point at a local httptest server, so we cannot hardcode "proxy.golang.org".
func proxyHost(proxyURL string) string {
	if u, err := url.Parse(proxyURL); err == nil {
		return u.Host
	}
	return ""
}

// MaintenanceInfo holds maintenance health data for a module.
type MaintenanceInfo struct {
	LastRelease        time.Time `json:"last_release"`
	MonthsSinceRelease int       `json:"months_since_release"`

	// LastActivity is the commit time of the head of the default branch of
	// the module's repository (see ScanActivity). It is zero when activity is
	// unknown: offline, archived, no branch resolved, or the lookup failed.
	// Unlike GitHub's pushed_at it does not move on pushes to other branches,
	// such as Dependabot's.
	LastActivity time.Time `json:"last_activity,omitzero"`

	// MonthsSinceActivity is the calendar-month age of LastActivity. It is
	// meaningful only when LastActivity is non-zero.
	MonthsSinceActivity int `json:"months_since_activity,omitempty"`

	// ActivitySource says where LastActivity came from (ActivityViaProxy or
	// ActivityViaGitHub), and ActivityBranch names the branch whose head was
	// read when it is known. Both are empty when LastActivity is zero.
	ActivitySource string `json:"activity_source,omitempty"`
	ActivityBranch string `json:"activity_branch,omitempty"`

	Archived   bool `json:"archived"`
	Deprecated bool `json:"deprecated"`

	// DeprecationMessage is the text of the `// Deprecated:` notice in the
	// go.mod of the module's latest version, which usually names the
	// successor. It is empty when the module is not deprecated that way (a
	// 410 from the proxy sets Deprecated without a message).
	DeprecationMessage string `json:"deprecation_message,omitempty"`

	LatestVersion string `json:"latest_version"`

	// Retracted is true when the pinned version of the module is retracted by a `retract` directive in
	// the go.mod of the module's latest version; RetractionMessage is the maintainers' rationale
	// ("" when they gave none; see RetractionNotice for a one-line form). A retracted version reads as
	// deprecated for consumers, but the scanner does NOT set Deprecated for it: the grade treats
	// `Retracted || Deprecated` as one state, so the two flags stay separate evidence.
	Retracted         bool   `json:"retracted,omitempty"`
	RetractionMessage string `json:"retraction_message,omitempty"`

	// ModCheckFailed is true when the deprecation and retraction notices could not be read: the proxy
	// has no latest version for the module, or the go.mod of the latest version could not be fetched
	// (transport error or non-200 answer) or parsed. Deprecated == false and Retracted == false then
	// mean "not checked", never "not deprecated" or "not retracted"; the grade treats the upkeep of
	// such a module as missing data (Pending) unless the module is archived anyway. A 410 on the
	// version list still sets Deprecated.
	ModCheckFailed bool `json:"mod_check_failed,omitempty"`

	// RepositoryURL is the repository the module is published from (https://host/owner/repo), resolved from
	// the module path via the module proxy's origin record, so a vanity path (gopkg.in/yaml.v3, k8s.io/api) can
	// be checked for archival like a github.com path. Empty when it could not be resolved.
	RepositoryURL string `json:"repository_url,omitempty"`

	// ArchivedCheck says whether the repository's archived flag was actually read: "checked" (it was: Archived is
	// the answer), "failed" (the lookup was attempted and did not answer: rate-limited, no token, an error; Archived
	// is NOT an answer), "unsupported" (the repository is on a host gorisk cannot ask), or "" (not attempted).
	// Archived == false with a check other than "checked" means "could not be checked", never "not archived":
	// the grade turns a failed check into Pending instead of a clean letter.
	ArchivedCheck string `json:"archived_check,omitempty"`

	// RepositoryNotFound is true when GitHub answered 404 for the repository behind the module (RepositoryURL):
	// it was deleted, made private, or renamed away without a redirect. The archived flag could not be read,
	// so ArchivedCheck is "failed", but the cause is a definitive answer rather than a rate limit or an outage;
	// the lookup was made once and is not retried.
	RepositoryNotFound bool `json:"repository_not_found,omitempty"`
}

// Values of MaintenanceInfo.ActivitySource.
const (
	// ActivityViaProxy means the module proxy resolved a branch query
	// (`@v/<branch>.info`) to the branch head's commit time.
	ActivityViaProxy = "proxy_branch"

	// ActivityViaGitHub means the GitHub commits API reported the default
	// branch's latest commit, used when the proxy query failed.
	ActivityViaGitHub = "github_commits"
)

// HasActivity reports whether repository activity is known for the module.
func (m *MaintenanceInfo) HasActivity() bool {
	return m != nil && !m.LastActivity.IsZero()
}

// DeprecationNotice returns DeprecationMessage on one line, for display. The
// Go reference lets a notice run over several comment lines, which modfile
// joins with newlines; those would break a report line or a policy violation.
// JSON keeps the raw message.
func (m *MaintenanceInfo) DeprecationNotice() string {
	if m == nil {
		return ""
	}
	return strings.Join(strings.Fields(m.DeprecationMessage), " ")
}

// RetractionNotice returns RetractionMessage on one line, for display, like
// DeprecationNotice.
func (m *MaintenanceInfo) RetractionNotice() string {
	if m == nil {
		return ""
	}
	return strings.Join(strings.Fields(m.RetractionMessage), " ")
}

// MonthsInactive returns the months since the module last showed signs of
// maintenance: the smaller of MonthsSinceRelease and MonthsSinceActivity when
// activity is known, otherwise MonthsSinceRelease alone. A repository whose
// default branch is worked on but that rarely tags a release is therefore not
// mistaken for an abandoned one, while a module with no activity data keeps
// the release-only behaviour. MonthsSinceRelease stays the right value for
// statements that are specifically about releases.
func (m *MaintenanceInfo) MonthsInactive() int {
	if m == nil {
		return 0
	}
	if !m.HasActivity() {
		return m.MonthsSinceRelease
	}
	return min(m.MonthsSinceRelease, m.MonthsSinceActivity)
}

// MaintenanceScanner checks module maintenance health via the Go module proxy.
type MaintenanceScanner struct {
	client   *Client
	proxyURL string
	cache    map[string]*MaintenanceInfo
	mu       sync.Mutex

	// diskCache keeps the branch and go.mod answers across scans for a day,
	// like the GitHub responses: a rerun does not pay again for a cold
	// monorepo fetch, and a go.mod at a fixed version never changes. Nil
	// disables it.
	diskCache *maintainerCache

	// branchTimeout bounds one default-branch query (see ScanActivity); the
	// client timeout still applies when it is shorter. Zero leaves only the
	// client timeout.
	branchTimeout time.Duration

	// ScanStart is the reference time used for MonthsSinceRelease calculations.
	// Truncated to the start of a UTC day so that two scans on the same calendar
	// day produce identical band results. Defaults to
	// time.Now().UTC().Truncate(24*time.Hour) at construction time.
	ScanStart time.Time
}

// NewMaintenanceScanner creates a new maintenance health scanner.
func NewMaintenanceScanner(timeout time.Duration) *MaintenanceScanner {
	return &MaintenanceScanner{
		client:        NewClient(ClientOptions{Timeout: timeout}),
		proxyURL:      "https://proxy.golang.org",
		cache:         make(map[string]*MaintenanceInfo),
		diskCache:     newMaintainerCache(defaultCacheDir("proxy"), 0), // OS cache dir, 24h TTL
		branchTimeout: defaultBranchQueryTimeout,
		ScanStart:     time.Now().UTC().Truncate(24 * time.Hour),
	}
}

// cachedProxyBody returns a fresh disk-cached body for url, if there is one.
func (ms *MaintenanceScanner) cachedProxyBody(url string) ([]byte, bool) {
	if ms.diskCache == nil {
		return nil, false
	}
	body, hit, err := ms.diskCache.Get(url)
	return body, err == nil && hit
}

// putProxyBody stores a 200 body for url in the disk cache. A failed write
// only costs the next scan a request.
func (ms *MaintenanceScanner) putProxyBody(url string, body []byte) {
	if ms.diskCache != nil {
		_ = ms.diskCache.Put(url, body)
	}
}

// proxyVersionInfo represents the JSON response from proxy.golang.org.
type proxyVersionInfo struct {
	Version string    `json:"Version"`
	Time    time.Time `json:"Time"`
	Origin  *struct {
		VCS  string `json:"VCS"`
		URL  string `json:"URL"`
		Ref  string `json:"Ref"`
		Hash string `json:"Hash"`
	} `json:"Origin,omitempty"`
}

// ScanAll checks maintenance health for all dependencies.
func (ms *MaintenanceScanner) ScanAll(ctx context.Context, graph *resolver.Graph) (map[string]*MaintenanceInfo, error) {
	rep := progress.From(ctx)
	total := len(graph.Dependencies)

	results := make(map[string]*MaintenanceInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 10)

	var firstErr error
	var errOnce sync.Once
	var failCount atomic.Int64
	var done int64

	for _, dep := range graph.Dependencies {
		wg.Add(1)
		go func(d *resolver.Dependency) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rep.Step("%s", d.Module.Path)
			info, err := ms.checkModule(ctx, d.Module.Path, d.Module.Version)
			n := atomic.AddInt64(&done, 1)
			rep.Progress(int(n), total)
			if err != nil {
				failCount.Add(1)
				errOnce.Do(func() { firstErr = err })
				return
			}

			mu.Lock()
			results[d.Module.Path] = info
			mu.Unlock()
		}(dep)
	}

	wg.Wait()
	if n := failCount.Load(); n > 0 {
		if errors.Is(firstErr, offline.ErrOffline) {
			// Report the shape of the degradation, not the wrapped error. The
			// cause is already known and identical for every module, and the
			// wrapped *url.Error would embed a full proxy URL — that is a
			// private module path in a message that reaches ps.Warnings and
			// the progress log, which the network-transparency docs promise
			// will disclose hosts, not paths.
			return results, fmt.Errorf("offline — maintenance data unavailable (%d of %d modules); maintenance axis not measured", n, total)
		}
		return results, fmt.Errorf("%d of %d module(s) failed maintenance lookup (first: %w)", n, total, firstErr)
	}
	return results, nil
}

func (ms *MaintenanceScanner) checkModule(ctx context.Context, modPath, version string) (*MaintenanceInfo, error) {
	ms.mu.Lock()
	if cached, ok := ms.cache[modPath]; ok {
		ms.mu.Unlock()
		return cached, nil
	}
	ms.mu.Unlock()

	info := &MaintenanceInfo{}

	// Get version info for the specific version used.
	// A pinned version that is not a full canonical version is never sent to
	// the proxy: the request would name a version no release has.
	versionInfo, versionErr := ms.fetchVersionInfo(ctx, modPath, version)
	if versionErr == nil && versionInfo != nil {
		info.LastRelease = versionInfo.Time
		info.MonthsSinceRelease = monthsSince(ms.ScanStart, versionInfo.Time)
	}

	// Check latest version to see if there's a newer release.
	latestInfo := ms.fetchLatestInfo(ctx, modPath)
	var latestVersion string
	var latestTime time.Time
	if latestInfo != nil {
		latestVersion, latestTime = latestInfo.Version, latestInfo.Time
	}
	if latestVersion != "" {
		info.LatestVersion = latestVersion
		if !latestTime.IsZero() {
			info.LastRelease = latestTime
			info.MonthsSinceRelease = monthsSince(ms.ScanStart, latestTime)
		}
	}

	// Both lookups failed — we have no data at all; propagate the error.
	if versionErr != nil && latestVersion == "" {
		return nil, fmt.Errorf("maintenance lookup for %s: %w", modPath, versionErr)
	}

	// The repository behind the module path, from the origin the proxy records
	// for the latest version (no extra request), else for the pinned one.
	var origins []*proxyVersionInfo
	origins = append(origins, latestInfo)
	if versionErr == nil {
		origins = append(origins, versionInfo)
	}
	ms.resolveRepository(modPath, info, origins...)

	// Check for deprecation: a 410 on @v/list, or a `// Deprecated:` notice
	// in the latest version's go.mod. The same go.mod carries the `retract`
	// directives, checked against the pinned version.
	ms.checkDeprecation(ctx, modPath, info)
	if latestVersion != "" {
		ms.checkGoModDeprecation(ctx, modPath, latestVersion, version, info)
	} else {
		// No latest version, so no go.mod to read the notices from.
		info.ModCheckFailed = true
	}

	ms.mu.Lock()
	ms.cache[modPath] = info
	ms.mu.Unlock()

	return info, nil
}

func (ms *MaintenanceScanner) fetchVersionInfo(ctx context.Context, modPath, version string) (*proxyVersionInfo, error) {
	if err := CheckModuleVersion(version); err != nil {
		return nil, err
	}
	escapedPath := encodeModulePath(modPath)
	url := fmt.Sprintf("%s/%s/@v/%s.info", ms.proxyURL, escapedPath, encodeModulePath(version))

	body, resp, err := ms.client.Get(ctx, url, GetOptions{
		Host:    proxyHost(ms.proxyURL),
		Purpose: "maintenance:version-info",
	})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy returned %d", resp.StatusCode)
	}

	var info proxyVersionInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

func (ms *MaintenanceScanner) fetchLatestVersion(ctx context.Context, modPath string) (string, time.Time) {
	info := ms.fetchLatestInfo(ctx, modPath)
	if info == nil {
		return "", time.Time{}
	}
	return info.Version, info.Time
}

// fetchLatestInfo returns the proxy's `@latest` record for modPath, which also
// carries the origin (the repository) the version was built from, or nil when
// the proxy cannot answer.
func (ms *MaintenanceScanner) fetchLatestInfo(ctx context.Context, modPath string) *proxyVersionInfo {
	escapedPath := encodeModulePath(modPath)
	url := fmt.Sprintf("%s/%s/@latest", ms.proxyURL, escapedPath)

	body, resp, err := ms.client.Get(ctx, url, GetOptions{
		Host:    proxyHost(ms.proxyURL),
		Purpose: "maintenance:latest",
	})
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil
	}

	var info proxyVersionInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil
	}

	return &info
}

func (ms *MaintenanceScanner) checkDeprecation(ctx context.Context, modPath string, info *MaintenanceInfo) {
	// The Go module proxy @latest endpoint may include deprecation info
	// in the response headers or body. For MVP, we check if the module
	// returns a 410 Gone status, which indicates it's been retracted.
	escapedPath := encodeModulePath(modPath)
	url := fmt.Sprintf("%s/%s/@v/list", ms.proxyURL, escapedPath)

	_, resp, err := ms.client.Get(ctx, url, GetOptions{
		Host:    proxyHost(ms.proxyURL),
		Purpose: "maintenance:version-list",
	})
	if err != nil {
		return
	}

	if resp.StatusCode == http.StatusGone {
		info.Deprecated = true
	}
}

// checkGoModDeprecation reads the go.mod of latest (the module's latest
// version) from the proxy and records a `// Deprecated:` notice attached to
// its module directive, the way `go list -m -u` and `go get` report it, and
// whether the pinned version falls in one of its `retract` directives. The
// Go modules reference reads both from the latest version's go.mod, so
// a notice in an older version does not count, and a comment elsewhere in the
// file is not a deprecation. The go.mod of a version never changes, so a
// fetched one is kept in the disk cache. A failed fetch or an unparsable go.mod sets
// info.ModCheckFailed and reports no deprecation or retraction rather than a wrong one;
// ModCheckFailed is what tells "not checked" from "not deprecated".
// A retracted pinned version sets Retracted, not Deprecated.
func (ms *MaintenanceScanner) checkGoModDeprecation(ctx context.Context, modPath, latest, pinned string, info *MaintenanceInfo) {
	url := fmt.Sprintf("%s/%s/@v/%s.mod", ms.proxyURL, encodeModulePath(modPath), encodeModulePath(latest))
	body, hit := ms.cachedProxyBody(url)
	if !hit {
		var resp *http.Response
		var err error
		body, resp, err = ms.client.Get(ctx, url, GetOptions{
			Host:    proxyHost(ms.proxyURL),
			Purpose: "maintenance:go-mod",
		})
		if err != nil || resp.StatusCode != http.StatusOK {
			info.ModCheckFailed = true
			return
		}
	}
	if _, err := modfile.ParseLax("go.mod", body, nil); err != nil {
		info.ModCheckFailed = true
		return
	}
	if !hit {
		// cached only once it parsed: a 200 answer that is not a go.mod must not keep the module unread for a day
		ms.putProxyBody(url, body)
	}
	if msg := goModDeprecation(body); msg != "" {
		info.Deprecated = true
		info.DeprecationMessage = msg
	}
	if retracted, msg := goModRetraction(body, pinned); retracted {
		info.Retracted = true
		info.RetractionMessage = msg
	}
}

// goModRetraction reports whether version lies in a `retract` directive of the
// go.mod data (a single version, or a [low,high] range, compared as semantic
// versions) and returns the first matching directive's rationale. It returns
// false for an unparsable go.mod or a version that is not valid semver.
func goModRetraction(data []byte, version string) (retracted bool, message string) {
	if !semver.IsValid(version) {
		return false, ""
	}
	f, err := modfile.ParseLax("go.mod", data, nil)
	if err != nil {
		return false, ""
	}
	for _, r := range f.Retract {
		if semver.Compare(version, r.Low) >= 0 && semver.Compare(version, r.High) <= 0 {
			return true, strings.TrimSpace(r.Rationale)
		}
	}
	return false, ""
}

// goModDeprecation returns the deprecation message of a go.mod file, or "" when
// the module directive carries no `// Deprecated:` notice or the file does not
// parse. The notice is recognised by golang.org/x/mod/modfile, which applies
// the Go modules reference rules (a paragraph starting with "Deprecated:" in
// the comments before the module directive or on its line).
func goModDeprecation(data []byte) string {
	f, err := modfile.ParseLax("go.mod", data, nil)
	if err != nil || f.Module == nil {
		return ""
	}
	return strings.TrimSpace(f.Module.Deprecated)
}

// encodeModulePath encodes a module path for use with the Go module proxy.
// Uppercase letters are escaped as !lowercase per the module proxy spec.
func encodeModulePath(path string) string {
	var b strings.Builder
	for _, r := range path {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func monthsSince(now, t time.Time) int {
	if t.IsZero() {
		return 0
	}
	years := now.Year() - t.Year()
	months := int(now.Month()) - int(t.Month())
	total := years*12 + months
	if total < 0 {
		return 0
	}
	return total
}

// ArchiveLookup reads the archived flag of a GitHub repository. MaintainerScanner
// implements it from its per-repository cache, so a repository the maintainer scan
// already fetched costs no further request.
type ArchiveLookup interface {
	// RepositoryArchived returns ErrRepositoryNotFound when GitHub answers 404;
	// any other error means the flag could not be read.
	RepositoryArchived(ctx context.Context, owner, repo string) (bool, error)
}

// resolveRepository sets info.RepositoryURL to the https repository the module
// is published from: the first usable origin the proxy recorded (the proxy's
// version records carry Origin{VCS, URL}), else, for a github.com module path,
// the repository the path names. A repository on a host other than GitHub is
// marked ArchivedUnsupported, since only GitHub can be asked; a module whose
// repository is unknown keeps ArchivedCheck "" (nothing attempted). The GitHub
// lookup itself is ScanArchived's.
func (ms *MaintenanceScanner) resolveRepository(modPath string, info *MaintenanceInfo, origins ...*proxyVersionInfo) {
	for _, v := range origins {
		if v == nil || v.Origin == nil {
			continue
		}
		if u := normalizeRepositoryURL(v.Origin.URL); u != "" {
			info.RepositoryURL = u
			break
		}
	}
	if info.RepositoryURL == "" {
		if owner, repo := parseGitHubPath(modPath); owner != "" && repo != "" {
			info.RepositoryURL = normalizeRepositoryURL("https://github.com/" + owner + "/" + repo)
		}
	}
	if info.RepositoryURL == "" {
		// The module proxy records no origin for most gopkg.in modules, but the host's own convention names the repository:
		// gopkg.in/pkg.vN is github.com/go-pkg/pkg and gopkg.in/user/pkg.vN is github.com/user/pkg.
		if u := gopkgInRepository(modPath); u != "" {
			info.RepositoryURL = u
		}
	}
	if info.RepositoryURL != "" {
		if _, _, ok := githubRepoFromURL(info.RepositoryURL); !ok {
			info.ArchivedCheck = ArchivedUnsupported
		}
	}
}

// normalizeRepositoryURL returns raw as https://host/path (no credentials,
// default port :443, query or ".git" suffix; a GitHub URL is cut to owner/repo),
// or "" when it is not an https repository URL, its path holds a control
// character or whitespace, or it is a GitHub URL with names GitHub does not
// allow. Any other explicit port is kept: it names a different server.
func normalizeRepositoryURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" {
		return ""
	}
	host := strings.ToLower(u.Host)
	if u.Port() == "443" {
		host = strings.ToLower(u.Hostname())
		if strings.Contains(host, ":") { // IPv6 literal
			host = "[" + host + "]"
		}
	}
	path := strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
	if path == "" || strings.ContainsFunc(path, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) {
		return ""
	}
	if host == "github.com" {
		parts := strings.Split(path, "/")
		if len(parts) < 2 || !ownerNamePattern.MatchString(parts[0]) || !repoNamePattern.MatchString(parts[1]) {
			return ""
		}
		path = parts[0] + "/" + parts[1]
	}
	return "https://" + host + "/" + path
}

// githubRepoFromURL splits a normalized repository URL on github.com into its
// owner and repository.
func githubRepoFromURL(repoURL string) (owner, repo string, ok bool) {
	rest, found := strings.CutPrefix(repoURL, "https://github.com/")
	if !found {
		return "", "", false
	}
	owner, repo, ok = strings.Cut(rest, "/")
	return owner, repo, ok && owner != "" && repo != "" && !strings.Contains(repo, "/")
}

// ScanArchived reads the archived flag of the repository behind every module in
// maintenance whose RepositoryURL is on GitHub (resolved by ScanAll from the
// module proxy, so vanity paths such as gopkg.in/yaml.v3 or k8s.io/api are
// covered, not only github.com paths) and sets ArchivedCheck, and Archived when
// the flag was read:
//
//   - "checked": GitHub answered; Archived is the answer.
//   - "failed": the lookup was attempted and did not answer (rate limit, 401/403,
//     5xx, network error). Archived stays false and must not be read as "not
//     archived". A 404 is also "failed", with RepositoryNotFound set; it is a
//     definitive answer, asked once, and not counted in the returned error.
//
// Modules on other hosts are marked "unsupported" by ScanAll and are not asked.
// lookup is normally the MaintainerScanner, so run it after the maintainer scan
// (a repository that scan fetched costs nothing more) and before ScanActivity,
// which skips archived modules. With a nil lookup, or offline, nothing is
// attempted and ArchivedCheck stays as ScanAll left it. The returned error, when
// non-nil, counts the modules whose lookup failed.
func (ms *MaintenanceScanner) ScanArchived(ctx context.Context, maintenance map[string]*MaintenanceInfo, lookup ArchiveLookup) error {
	if lookup == nil || offline.Enabled() {
		return nil
	}
	rep := progress.From(ctx)

	var todo []string
	for modPath, info := range maintenance {
		if info == nil {
			continue
		}
		if _, _, ok := githubRepoFromURL(info.RepositoryURL); ok {
			todo = append(todo, modPath)
		}
	}
	slices.Sort(todo)
	total := len(todo)

	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	var failed, done atomic.Int64
	for _, modPath := range todo {
		info := maintenance[modPath]
		owner, repo, _ := githubRepoFromURL(info.RepositoryURL)
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rep.Step("%s", modPath)
			archived, err := lookup.RepositoryArchived(ctx, owner, repo)
			switch {
			case err == nil:
				info.ArchivedCheck = ArchivedChecked
				if archived {
					info.Archived = true
				}
			case errors.Is(err, ErrRepositoryNotFound):
				info.ArchivedCheck = ArchivedCheckFailed
				info.RepositoryNotFound = true
			default:
				info.ArchivedCheck = ArchivedCheckFailed
				failed.Add(1)
			}
			rep.Progress(int(done.Add(1)), total)
		}()
	}
	wg.Wait()

	if n := failed.Load(); n > 0 {
		return fmt.Errorf("archived status could not be read for %d of %d module(s) (GitHub API rate-limited or erroring); they are reported as unchecked, not as not archived", n, total)
	}
	return nil
}

// Values of MaintenanceInfo.ArchivedCheck.
const (
	ArchivedChecked     = "checked"
	ArchivedCheckFailed = "failed"
	ArchivedUnsupported = "unsupported"
)

// gopkgInRepository is the GitHub repository a gopkg.in module path stands for, by the host's documented convention:
// gopkg.in/pkg.vN -> github.com/go-pkg/pkg, gopkg.in/user/pkg.vN -> github.com/user/pkg. It returns "" for any other
// path, or one that does not end in a .vN version.
func gopkgInRepository(modPath string) string {
	rest, ok := strings.CutPrefix(modPath, "gopkg.in/")
	if !ok {
		return ""
	}
	parts := strings.Split(rest, "/")
	last := parts[len(parts)-1]
	dot := strings.LastIndex(last, ".v")
	if dot <= 0 || len(last) == dot+2 {
		return ""
	}
	for _, r := range last[dot+2:] {
		if r < '0' || r > '9' {
			return ""
		}
	}
	name := last[:dot]
	switch len(parts) {
	case 1:
		return normalizeRepositoryURL("https://github.com/go-" + name + "/" + name)
	case 2:
		return normalizeRepositoryURL("https://github.com/" + parts[0] + "/" + name)
	}
	return ""
}
