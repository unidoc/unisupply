package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"

	"github.com/unidoc/unisupply/pkg/offline"
)

const (
	defaultResponseHistoryProxy = "https://proxy.golang.org"
	defaultResponseHistoryOSV   = "https://api.osv.dev"

	// defaultResponseHistoryVersions and defaultResponseHistoryDeps bound the work of one call when the options leave
	// them zero.
	defaultResponseHistoryVersions = 40
	defaultResponseHistoryDeps     = 60

	// responseHistoryConcurrency caps the requests in flight at once.
	responseHistoryConcurrency = 8

	// responseHistoryOSVPages caps the pages read for one dependency's advisories.
	responseHistoryOSVPages = 5

	responseHistoryOSVMaxBytes = 4 * 1024 * 1024
	responseHistoryListBytes   = 1024 * 1024

	// defaultResponseHistoryDeadline bounds one whole call when the options leave Deadline zero, and
	// defaultResponseHistoryRequests is the most requests one call makes when MaxRequests is zero.
	defaultResponseHistoryDeadline = 2 * time.Minute
	defaultResponseHistoryRequests = 2000

	// responseHistoryMaxFixes is how many of a dependency's fixes, the newest ones, are examined. A
	// dependency with hundreds of advisories would otherwise cost hundreds of release-time requests.
	responseHistoryMaxFixes = 20
)

// errResponseHistoryBudget is the failure of a lookup the request budget did not allow.
var errResponseHistoryBudget = errors.New("response history: request budget spent")

// ResponseHistoryOptions controls ScanResponseHistory. Zero values take the defaults noted per field.
type ResponseHistoryOptions struct {
	// ProxyURL is the Go module proxy the version lists, release times and go.mod files come from. Default
	// https://proxy.golang.org. Tests point it at a local server.
	ProxyURL string

	// OSVURL is the OSV API the advisories of each dependency come from. Default https://api.osv.dev.
	OSVURL string

	// Timeout bounds each request. Zero falls back to the client default of 10s.
	Timeout time.Duration

	// Deadline bounds the whole call, all requests together; work still pending at the deadline is
	// skipped, so the result covers what was read in time. Default 2 minutes.
	Deadline time.Duration

	// MaxRequests is the most requests the call makes (proxy and OSV together). Once it is spent every
	// further lookup counts as failed and is skipped. Default 2000.
	MaxRequests int

	// MaxVersions is how many of the module's most recent release versions are read. Default 40.
	MaxVersions int

	// MaxDependencies caps how many dependencies are examined, in the order given. Default 60.
	MaxDependencies int
}

// responseHistoryRelease is one sampled release of the graded module: its time and the versions its go.mod requires.
type responseHistoryRelease struct {
	version  string
	time     time.Time
	requires map[string]string // module path -> required version
}

// responseHistoryFetcher holds the per-call state: the client, the endpoints and one cache for everything fetched, so a
// go.mod, a release time or an advisory list is requested once per call however many dependencies ask for it.
type responseHistoryFetcher struct {
	client   *Client
	proxyURL string
	osvURL   string
	sem      chan struct{}
	mu       sync.Mutex
	cache    map[string]*responseHistoryEntry

	// budget is the number of requests the call may still make.
	budget atomic.Int64
}

// spend takes one request from the budget and reports whether there was one.
func (f *responseHistoryFetcher) spend() bool {
	return f.budget.Add(-1) >= 0
}

// responseHistoryEntry is a cache slot filled exactly once, so concurrent callers of the same key share one request.
type responseHistoryEntry struct {
	once sync.Once
	val  any
	err  error
}

// do returns the cached result for key, running fn (under the concurrency cap) on the first call only. A failure is
// cached too: one failed lookup is not retried within the call.
func (f *responseHistoryFetcher) do(key string, fn func() (any, error)) (any, error) {
	f.mu.Lock()
	e, ok := f.cache[key]
	if !ok {
		e = &responseHistoryEntry{}
		f.cache[key] = e
	}
	f.mu.Unlock()
	e.once.Do(func() {
		f.sem <- struct{}{}
		defer func() { <-f.sem }()
		e.val, e.err = fn()
	})
	return e.val, e.err
}

// get fetches one proxy URL and returns the body of a 200 answer.
func (f *responseHistoryFetcher) get(ctx context.Context, u, base, purpose string, maxBytes int64) ([]byte, error) {
	if !f.spend() {
		return nil, errResponseHistoryBudget
	}
	body, resp, err := f.client.Get(ctx, u, GetOptions{
		Host:     proxyHost(base),
		MaxBytes: maxBytes,
		Purpose:  purpose,
	})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy returned %d", resp.StatusCode)
	}
	return body, nil
}

func (f *responseHistoryFetcher) versionList(ctx context.Context, module string) ([]string, error) {
	u := fmt.Sprintf("%s/%s/@v/list", f.proxyURL, encodeModulePath(module))
	body, err := f.get(ctx, u, f.proxyURL, "responsehistory:version-list", responseHistoryListBytes)
	if err != nil {
		return nil, err
	}
	var versions []string
	for _, line := range strings.Split(string(body), "\n") {
		v := strings.TrimSpace(line)
		// Release versions only: a pre-release is not what a user adopts a fix in.
		if semver.IsValid(v) && semver.Prerelease(v) == "" {
			versions = append(versions, v)
		}
	}
	semver.Sort(versions)
	return versions, nil
}

// releaseTime returns the time the proxy records for module@version.
func (f *responseHistoryFetcher) releaseTime(ctx context.Context, module, version string) (time.Time, error) {
	v, err := f.do("info\x00"+module+"@"+version, func() (any, error) {
		u := fmt.Sprintf("%s/%s/@v/%s.info", f.proxyURL, encodeModulePath(module), encodeModulePath(version))
		body, err := f.get(ctx, u, f.proxyURL, "responsehistory:version-info", DefaultMaxBytes)
		if err != nil {
			return nil, err
		}
		var info proxyVersionInfo
		if err := json.Unmarshal(body, &info); err != nil {
			return nil, err
		}
		if info.Time.IsZero() {
			return nil, fmt.Errorf("proxy gave no time for %s@%s", module, version)
		}
		return info.Time.UTC(), nil
	})
	if err != nil {
		return time.Time{}, err
	}
	return v.(time.Time), nil
}

// requirements returns the modules (and versions) module@version's go.mod requires, indirect ones included.
func (f *responseHistoryFetcher) requirements(ctx context.Context, module, version string) (map[string]string, error) {
	v, err := f.do("mod\x00"+module+"@"+version, func() (any, error) {
		u := fmt.Sprintf("%s/%s/@v/%s.mod", f.proxyURL, encodeModulePath(module), encodeModulePath(version))
		body, err := f.get(ctx, u, f.proxyURL, "responsehistory:go-mod", DefaultMaxBytes)
		if err != nil {
			return nil, err
		}
		mf, err := modfile.ParseLax("go.mod", body, nil)
		if err != nil {
			return nil, err
		}
		req := make(map[string]string, len(mf.Require))
		for _, r := range mf.Require {
			if old, ok := req[r.Mod.Path]; !ok || semver.Compare(r.Mod.Version, old) > 0 {
				req[r.Mod.Path] = r.Mod.Version
			}
		}
		return req, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(map[string]string), nil
}

// osvQuery and osvQueryResponse are the parts of OSV's /v1/query that fixed-version lookup reads.
type osvQuery struct {
	Package   osvQueryPackage `json:"package"`
	PageToken string          `json:"page_token,omitempty"`
}

type osvQueryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvQueryResponse struct {
	Vulns         []osvQueryVuln `json:"vulns"`
	NextPageToken string         `json:"next_page_token"`
}

type osvQueryVuln struct {
	ID        string `json:"id"`
	Withdrawn string `json:"withdrawn"`
	Affected  []struct {
		Package osvQueryPackage `json:"package"`
		Ranges  []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// fixedVersions returns the distinct versions in which dep's advisories were first fixed, sorted ascending. An advisory
// with no fix, a withdrawn one and a fixed version that is not valid semver contribute nothing.
func (f *responseHistoryFetcher) fixedVersions(ctx context.Context, dep string) ([]string, error) {
	v, err := f.do("osv\x00"+dep, func() (any, error) {
		host := proxyHost(f.osvURL)
		fixed := map[string]bool{}
		token := ""
		for page := 0; page < responseHistoryOSVPages; page++ {
			if !f.spend() {
				return nil, errResponseHistoryBudget
			}
			reqBody, err := json.Marshal(osvQuery{Package: osvQueryPackage{Name: dep, Ecosystem: "Go"}, PageToken: token})
			if err != nil {
				return nil, err
			}
			body, resp, err := f.client.Post(ctx, f.osvURL+"/v1/query", "application/json", bytes.NewReader(reqBody), GetOptions{
				Host:     host,
				MaxBytes: responseHistoryOSVMaxBytes,
				Accept:   "application/json",
				Purpose:  "responsehistory:osv",
			})
			if err != nil {
				return nil, err
			}
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("OSV returned %d", resp.StatusCode)
			}
			var qr osvQueryResponse
			if err := json.Unmarshal(body, &qr); err != nil {
				return nil, err
			}
			for _, vuln := range qr.Vulns {
				if vuln.Withdrawn != "" {
					continue
				}
				if fv := firstFixedVersion(vuln, dep); fv != "" {
					fixed[fv] = true
				}
			}
			token = qr.NextPageToken
			if token == "" {
				break
			}
		}
		out := make([]string, 0, len(fixed))
		for fv := range fixed {
			out = append(out, fv)
		}
		semver.Sort(out)
		return out, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]string), nil
}

// firstFixedVersion returns the lowest version in which the advisory is fixed for module dep, as a "v"-prefixed semver
// (OSV writes Go versions without the prefix), or "" when there is none.
func firstFixedVersion(v osvQueryVuln, dep string) string {
	first := ""
	for _, a := range v.Affected {
		if a.Package.Ecosystem != "Go" || a.Package.Name != dep {
			continue
		}
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed == "" {
					continue
				}
				fv := e.Fixed
				if !strings.HasPrefix(fv, "v") {
					fv = "v" + fv
				}
				if !semver.IsValid(fv) {
					continue
				}
				if first == "" || semver.Compare(fv, first) < 0 {
					first = fv
				}
			}
		}
	}
	return first
}

// ScanResponseHistory measures, for each dependency in dependencies, how fast module adopted that dependency's fixes
// in the past, and returns the dependencies for which there are at least MinResponseSamples samples; the others are
// left out of the map, and the caller then says there is not enough response history. It is context for a finding and
// is never part of a grade.
//
// For each advisory of dependency D that was fixed in version F (released at T_F) it takes the first sampled release of
// module whose go.mod requires D at F or later, and records that release's time minus T_F in whole days, never
// negative (a release that required F before the proxy's T_F counts 0). The result is the median of those days
// (rounded half up) with the number of fixes and the span of their release times. Sampled releases are the module's
// MaxVersions newest versions without a pre-release, ordered by semver; a fix released before the oldest sampled
// release is skipped, because the module could not have reacted to it within the sample. Fixes sharing one fixed
// version are one sample, so an advisory that OSV lists under several identifiers is not counted twice.
//
// Bias: a fix the module never adopted within the sampled range is not a sample. It is not counted as a long
// adoption, because the true time is unknown, so the median is biased towards faster adoption than the full record
// would show. The sample count lets the reader judge it.
//
// The call fails only when offline mode is on (no request is made) or the module's own version list cannot be read.
// Any other failed lookup (one go.mod, one release time, one dependency's advisories) skips that item. Nothing is
// cached on disk; one cache lives for the call. Requests are bounded by MaxVersions, MaxDependencies, the newest
// responseHistoryMaxFixes fixes of each dependency, a request budget (MaxRequests) and one overall Deadline, and stop
// with ctx. A call with no dependencies makes no request.
func ScanResponseHistory(ctx context.Context, opts ResponseHistoryOptions, module string, dependencies []string) (map[string]*ResponseHistory, error) {
	if offline.Enabled() {
		return nil, offline.ErrOffline
	}
	if opts.ProxyURL == "" {
		opts.ProxyURL = defaultResponseHistoryProxy
	}
	if opts.OSVURL == "" {
		opts.OSVURL = defaultResponseHistoryOSV
	}
	if opts.MaxVersions <= 0 {
		opts.MaxVersions = defaultResponseHistoryVersions
	}
	if opts.MaxDependencies <= 0 {
		opts.MaxDependencies = defaultResponseHistoryDeps
	}
	if opts.Deadline <= 0 {
		opts.Deadline = defaultResponseHistoryDeadline
	}
	if opts.MaxRequests <= 0 {
		opts.MaxRequests = defaultResponseHistoryRequests
	}
	if _, err := url.Parse(opts.ProxyURL); err != nil {
		return nil, fmt.Errorf("response history: proxy URL: %w", err)
	}

	// Dependencies in the order given, without repeats, the module itself or blanks, capped.
	var deps []string
	seen := map[string]bool{module: true, "": true}
	for _, d := range dependencies {
		if seen[d] {
			continue
		}
		seen[d] = true
		if len(deps) < opts.MaxDependencies {
			deps = append(deps, d)
		}
	}
	if len(deps) == 0 {
		// Nothing to measure: not even the module's own version list is worth a request.
		return map[string]*ResponseHistory{}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Deadline)
	defer cancel()

	f := &responseHistoryFetcher{
		client:   NewClient(ClientOptions{Timeout: opts.Timeout}),
		proxyURL: strings.TrimRight(opts.ProxyURL, "/"),
		osvURL:   strings.TrimRight(opts.OSVURL, "/"),
		sem:      make(chan struct{}, responseHistoryConcurrency),
		cache:    make(map[string]*responseHistoryEntry),
	}
	f.budget.Store(int64(opts.MaxRequests))

	versions, err := f.versionList(ctx, module)
	if err != nil {
		return nil, fmt.Errorf("response history: version list of %s: %w", module, err)
	}
	if len(versions) > opts.MaxVersions {
		versions = versions[len(versions)-opts.MaxVersions:]
	}
	releases := f.loadReleases(ctx, module, versions)
	if len(releases) == 0 {
		return map[string]*ResponseHistory{}, nil
	}

	results := make([]*ResponseHistory, len(deps))
	var wg sync.WaitGroup
	for i, dep := range deps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = f.history(ctx, dep, releases)
		}()
	}
	wg.Wait()

	out := make(map[string]*ResponseHistory)
	for i, h := range results {
		if h != nil {
			out[deps[i]] = h
		}
	}
	return out, nil
}

// loadReleases reads the time and go.mod of each version, ascending. A version whose time or go.mod cannot be read is
// left out.
func (f *responseHistoryFetcher) loadReleases(ctx context.Context, module string, versions []string) []responseHistoryRelease {
	loaded := make([]*responseHistoryRelease, len(versions))
	var wg sync.WaitGroup
	for i, v := range versions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t, err := f.releaseTime(ctx, module, v)
			if err != nil {
				return
			}
			req, err := f.requirements(ctx, module, v)
			if err != nil {
				return
			}
			loaded[i] = &responseHistoryRelease{version: v, time: t, requires: req}
		}()
	}
	wg.Wait()
	var out []responseHistoryRelease
	for _, r := range loaded {
		if r != nil {
			out = append(out, *r)
		}
	}
	return out
}

// history computes one dependency's response history from the sampled releases (ascending), or nil when it has fewer
// than MinResponseSamples samples.
func (f *responseHistoryFetcher) history(ctx context.Context, dep string, releases []responseHistoryRelease) *ResponseHistory {
	// A dependency no sampled release requires has nothing to measure; skip the OSV request.
	required := false
	for _, r := range releases {
		if _, ok := r.requires[dep]; ok {
			required = true
			break
		}
	}
	if !required {
		return nil
	}
	fixes, err := f.fixedVersions(ctx, dep)
	if err != nil {
		return nil
	}

	// Only the newest fixes are examined (fixes ascend).
	if len(fixes) > responseHistoryMaxFixes {
		fixes = fixes[len(fixes)-responseHistoryMaxFixes:]
	}

	oldest := releases[0].time
	var days []int
	var from, to time.Time
	for _, fv := range fixes {
		// The release that adopted the fix, found without a request: a fix no sampled release adopted is
		// not a sample, so its release time is not fetched.
		var adopter *responseHistoryRelease
		for i := range releases {
			if rv, ok := releases[i].requires[dep]; ok && semver.Compare(rv, fv) >= 0 {
				adopter = &releases[i]
				break
			}
		}
		if adopter == nil {
			continue
		}
		tf, err := f.releaseTime(ctx, dep, fv)
		if err != nil || !tf.After(oldest) {
			continue
		}
		var d int
		if adopter.time.After(tf) {
			d = int(adopter.time.Sub(tf) / (24 * time.Hour))
		}
		days = append(days, d)
		if from.IsZero() || tf.Before(from) {
			from = tf
		}
		if tf.After(to) {
			to = tf
		}
	}
	if len(days) < MinResponseSamples {
		return nil
	}
	return &ResponseHistory{Dependency: dep, MedianDays: medianDays(days), Samples: len(days), From: from, To: to}
}

// medianDays is the integer median of days, rounding half up when the count is even.
func medianDays(days []int) int {
	s := append([]int(nil), days...)
	sort.Ints(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2] + 1) / 2
}
