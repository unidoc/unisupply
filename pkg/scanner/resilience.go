package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/mod/semver"

	"github.com/unidoc/unisupply/pkg/progress"
	"github.com/unidoc/unisupply/pkg/resolver"
)

// ResilienceInfo holds long-term reliability indicators for a module.
type ResilienceInfo struct {
	// DataAvailable is false when the Go module proxy returned a network
	// error or a non-200 status for the version list — meaning no release
	// history could be fetched. When false, all numeric fields are
	// zero-valued and MUST NOT be interpreted as real measurements.
	DataAvailable bool `json:"data_available"`

	// Release cadence.
	TotalReleases    int       `json:"total_releases"`
	AvgDaysBetween   float64   `json:"avg_days_between_releases"`
	ReleaseCadence   string    `json:"release_cadence"` // "frequent", "regular", "slow", "stale"
	LastReleaseDate  time.Time `json:"last_release_date"`
	FirstReleaseDate time.Time `json:"first_release_date"`
	ProjectAgeDays   int       `json:"project_age_days"`

	// Stability.
	HasStableRelease bool   `json:"has_stable_release"` // v1+ exists
	MajorVersions    int    `json:"major_versions"`
	PreReleaseOnly   bool   `json:"pre_release_only"` // only v0.x or rc/beta
	VersionScheme    string `json:"version_scheme"`   // "semver", "date", "pseudo", "mixed"

	// Succession / governance.
	HasSecurityPolicy      bool `json:"has_security_policy"` // SECURITY.md exists (from GitHub)
	HasContribGuide        bool `json:"has_contrib_guide"`   // CONTRIBUTING.md
	HasCodeOfConduct       bool `json:"has_code_of_conduct"` // CODE_OF_CONDUCT.md
	HasMultipleMaintainers bool `json:"has_multiple_maintainers"`

	// Limited is true when the release dates were computed from a sample of the
	// versions rather than all of them: the module has more than
	// maxResilienceVersionSamples versions, the per-scan request budget ran out,
	// or some date requests failed. TotalReleases, the version flags and
	// VersionScheme still come from the full version list. When the sample
	// includes the oldest and the newest release, AvgDaysBetween is the span
	// divided by the full release count; otherwise it is spaced over the sample.
	// Set only when DataAvailable is true.
	Limited bool `json:"limited,omitempty"`

	// SampledVersions is the number of versions whose release date was fetched.
	// Set only when Limited is true.
	SampledVersions int `json:"sampled_versions,omitempty"`

	// Computed resilience score (0-100).
	Score int `json:"score"`
}

const (
	// maxResilienceVersionSamples caps how many version dates are fetched per
	// module: the newest maxResilienceVersionSamples-1 versions plus the oldest
	// one. Every date costs one proxy request, so an unbounded fetch makes a
	// module with thousands of tags (docker/docker has 26,422 versions) time the
	// whole scan out. 24 recent releases are enough to classify the cadence, the
	// oldest one anchors the project age, and the full version list still gives
	// the release count.
	maxResilienceVersionSamples = 24

	// maxResilienceScanInfoRequests is the per-scan budget of version-date
	// requests, shared by all modules, so that many large modules cannot together
	// exceed it. Modules scanned after it is spent get Limited results.
	maxResilienceScanInfoRequests = 3000

	// resilienceInfoConcurrency bounds the version-date requests in flight at
	// once across the whole scan.
	resilienceInfoConcurrency = 16

	// resilienceModuleConcurrency bounds the modules analysed at once.
	resilienceModuleConcurrency = 10
)

// ResilienceScanner computes resilience scores from release history.
type ResilienceScanner struct {
	client   *Client
	proxyURL string
	cache    map[string]*ResilienceInfo
	mu       sync.Mutex

	// infoBudget is the number of version-date requests this scan may still
	// make, and infoSem bounds those in flight. Both are shared by every module.
	infoBudget int

	// scanBudget is the budget ScanAll starts each scan with.
	scanBudget int
	infoSem    chan struct{}

	// ScanStart is the reference time used for cadence and age calculations.
	// Truncated to the start of a UTC day so that two scans on the same calendar
	// day produce identical classifications. Defaults to
	// time.Now().UTC().Truncate(24*time.Hour) at construction time.
	ScanStart time.Time
}

// NewResilienceScanner creates a new resilience scanner.
func NewResilienceScanner(timeout time.Duration) *ResilienceScanner {
	return &ResilienceScanner{
		client:     NewClient(ClientOptions{Timeout: timeout}),
		proxyURL:   "https://proxy.golang.org",
		cache:      make(map[string]*ResilienceInfo),
		infoBudget: maxResilienceScanInfoRequests,
		scanBudget: maxResilienceScanInfoRequests,
		infoSem:    make(chan struct{}, resilienceInfoConcurrency),
		ScanStart:  time.Now().UTC().Truncate(24 * time.Hour),
	}
}

// ScanAll computes resilience info for all dependencies.
func (rs *ResilienceScanner) ScanAll(ctx context.Context, graph *resolver.Graph, maintainers map[string]*MaintainerInfo) map[string]*ResilienceInfo {
	rep := progress.From(ctx)
	total := len(graph.Dependencies)

	results := make(map[string]*ResilienceInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var done int64

	rs.mu.Lock()
	rs.infoBudget = rs.scanBudget
	rs.mu.Unlock()

	sem := make(chan struct{}, resilienceModuleConcurrency)

	for _, dep := range graph.Dependencies {
		wg.Add(1)
		go func(d *resolver.Dependency) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rep.Step("%s", d.Module.Path)
			info := rs.analyzeModule(ctx, d.Module.Path)

			// Enrich with maintainer data if available.
			if mi, ok := maintainers[d.Module.Path]; ok {
				info.HasMultipleMaintainers = mi.BusFactor > 1
			}

			info.Score = computeResilienceScore(info)
			n := atomic.AddInt64(&done, 1)
			rep.Progress(int(n), total)

			mu.Lock()
			results[d.Module.Path] = info
			mu.Unlock()
		}(dep)
	}

	wg.Wait()
	return results
}

func (rs *ResilienceScanner) analyzeModule(ctx context.Context, modPath string) *ResilienceInfo {
	rs.mu.Lock()
	if cached, ok := rs.cache[modPath]; ok {
		rs.mu.Unlock()
		return cached
	}
	rs.mu.Unlock()

	info := &ResilienceInfo{}

	// Fetch version list from Go proxy. An empty list means the proxy was
	// unreachable or returned an error: leave DataAvailable false so callers
	// know zero-values are not real.
	versions := rs.fetchVersionList(ctx, modPath)
	if len(versions) == 0 {
		rs.mu.Lock()
		rs.cache[modPath] = info
		rs.mu.Unlock()
		return info
	}

	// Version list is available: all fields that follow are real data.
	info.DataAvailable = true

	info.TotalReleases = len(versions)

	// Flags that need no request come from the full version list.
	majorVersions := make(map[string]bool)
	for _, ver := range versions {
		// Track major versions.
		if strings.HasPrefix(ver, "v") {
			parts := strings.SplitN(strings.TrimPrefix(ver, "v"), ".", 2)
			if len(parts) > 0 {
				majorVersions[parts[0]] = true
			}
		}

		// Check for stable release.
		if !strings.HasPrefix(ver, "v0.") && strings.HasPrefix(ver, "v") && !strings.Contains(ver, "-") {
			info.HasStableRelease = true
		}

		// Check for pre-release markers.
		if strings.Contains(ver, "-rc") || strings.Contains(ver, "-beta") || strings.Contains(ver, "-alpha") {
			info.PreReleaseOnly = true // Will be overridden if stable found
		}
	}

	if info.HasStableRelease {
		info.PreReleaseOnly = false
	}

	// Fetch timestamps for a bounded sample of the versions to compute cadence.
	sample, oldest := sampleVersions(versions, maxResilienceVersionSamples)
	timestamps, oldestFound := rs.fetchVersionTimes(ctx, modPath, sample, oldest)
	if len(timestamps) < len(versions) {
		info.Limited = true
		info.SampledVersions = len(timestamps)
	}
	if len(timestamps) == 0 && len(sample) > 0 && rs.budgetSpent() {
		// The budget left no date at all: say there is no data rather than
		// scoring a cadence computed from nothing.
		unavailable := &ResilienceInfo{Limited: true}
		rs.mu.Lock()
		rs.cache[modPath] = unavailable
		rs.mu.Unlock()
		return unavailable
	}

	info.MajorVersions = len(majorVersions)

	// Compute cadence from timestamps.
	if len(timestamps) > 0 {
		sort.Slice(timestamps, func(i, j int) bool {
			return timestamps[i].Before(timestamps[j])
		})

		info.FirstReleaseDate = timestamps[0]
		info.LastReleaseDate = timestamps[len(timestamps)-1]
		info.ProjectAgeDays = int(rs.ScanStart.Sub(info.FirstReleaseDate).Hours() / 24)

		if len(timestamps) > 1 {
			totalDays := info.LastReleaseDate.Sub(info.FirstReleaseDate).Hours() / 24
			intervals := len(timestamps) - 1
			if info.Limited && oldestFound {
				// The sample spans the whole history, so spread it over the real
				// release count; spacing it over the sample would overstate the
				// gap between releases.
				intervals = info.TotalReleases - 1
			}
			info.AvgDaysBetween = totalDays / float64(intervals)
		}
	}

	// Classify cadence.
	info.ReleaseCadence = classifyCadence(rs.ScanStart, info)

	// Classify version scheme.
	info.VersionScheme = classifyVersionScheme(versions)

	// Check for governance files (if GitHub).
	owner, repo := parseGitHubPath(modPath)
	if owner != "" && repo != "" {
		rs.checkGovernanceFiles(ctx, owner, repo, info)
	}

	rs.mu.Lock()
	rs.cache[modPath] = info
	rs.mu.Unlock()

	return info
}

// sampleVersions returns the versions whose dates are fetched, most important
// first: the newest, then the oldest, then the next newest, up to limit. oldest
// is the oldest version, or "" when versions fit within limit and nothing is
// cut. The proxy's list is unordered, so the versions are ordered by semver
// (invalid ones first, then by string) before the cut.
func sampleVersions(versions []string, limit int) (sample []string, oldest string) {
	ordered := slices.Clone(versions)
	slices.SortFunc(ordered, func(a, b string) int {
		if c := semver.Compare(a, b); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	slices.Reverse(ordered) // newest first
	if len(ordered) <= limit {
		return ordered, ""
	}
	oldest = ordered[len(ordered)-1]
	sample = append(sample, ordered[0], oldest)
	sample = append(sample, ordered[1:limit-1]...)
	return sample, oldest
}

// budgetSpent reports whether no version-date request is left in this scan.
func (rs *ResilienceScanner) budgetSpent() bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.infoBudget <= 0
}

// reserveInfoRequests takes up to n requests from the per-scan budget and
// returns how many it got.
func (rs *ResilienceScanner) reserveInfoRequests(n int) int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	n = max(0, min(n, rs.infoBudget))
	rs.infoBudget -= n
	return n
}

// fetchVersionTimes fetches the release date of each sampled version, as many
// as the per-scan budget allows (the sample is ordered by priority, so the
// budget cuts the least important first), with at most resilienceInfoConcurrency
// requests in flight scan-wide. It returns the dates that were obtained and
// whether the date of oldest was among them.
func (rs *ResilienceScanner) fetchVersionTimes(ctx context.Context, modPath string, sample []string, oldest string) (times []time.Time, oldestFound bool) {
	granted := rs.reserveInfoRequests(len(sample))
	sample = sample[:granted]
	got := make([]time.Time, len(sample))
	var wg sync.WaitGroup
	for i, ver := range sample {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rs.infoSem <- struct{}{}
			defer func() { <-rs.infoSem }()
			got[i] = rs.fetchVersionTime(ctx, modPath, ver)
		}()
	}
	wg.Wait()
	for i, t := range got {
		if t.IsZero() {
			continue
		}
		times = append(times, t)
		if oldest != "" && sample[i] == oldest {
			oldestFound = true
		}
	}
	return times, oldestFound
}

func (rs *ResilienceScanner) fetchVersionList(ctx context.Context, modPath string) []string {
	escapedPath := encodeModulePath(modPath)
	url := fmt.Sprintf("%s/%s/@v/list", rs.proxyURL, escapedPath)

	body, resp, err := rs.client.Get(ctx, url, GetOptions{
		Host:    proxyHost(rs.proxyURL),
		Purpose: "resilience:version-list",
	})
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil
	}

	var versions []string
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			versions = append(versions, line)
		}
	}
	return versions
}

func (rs *ResilienceScanner) fetchVersionTime(ctx context.Context, modPath, version string) time.Time {
	escapedPath := encodeModulePath(modPath)
	url := fmt.Sprintf("%s/%s/@v/%s.info", rs.proxyURL, escapedPath, version)

	body, resp, err := rs.client.Get(ctx, url, GetOptions{
		Host:    proxyHost(rs.proxyURL),
		Purpose: "resilience:version-info",
	})
	if err != nil || resp.StatusCode != http.StatusOK {
		return time.Time{}
	}

	var info struct {
		Time time.Time `json:"Time"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return time.Time{}
	}
	return info.Time
}

func (rs *ResilienceScanner) checkGovernanceFiles(ctx context.Context, owner, repo string, info *ResilienceInfo) {
	// Check for SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md via GitHub API.
	files := []struct {
		path string
		flag *bool
	}{
		{"SECURITY.md", &info.HasSecurityPolicy},
		{"CONTRIBUTING.md", &info.HasContribGuide},
		{"CODE_OF_CONDUCT.md", &info.HasCodeOfConduct},
	}

	for _, f := range files {
		url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, f.path)
		resp, err := rs.client.Head(ctx, url, GetOptions{
			Host:    "api.github.com",
			Purpose: "resilience:governance",
		})
		if err == nil && resp.StatusCode == http.StatusOK {
			*f.flag = true
		}
	}
}

func classifyCadence(now time.Time, info *ResilienceInfo) string {
	if info.TotalReleases <= 1 {
		return "stale"
	}

	monthsSinceLast := monthsSince(now, info.LastReleaseDate)

	if monthsSinceLast > 24 {
		return "stale"
	}

	avg := info.AvgDaysBetween
	switch {
	case avg < 30:
		return "frequent" // Monthly or faster
	case avg < 90:
		return "regular" // Quarterly
	case avg < 180:
		return "slow" // Semi-annual
	default:
		return "stale"
	}
}

func classifyVersionScheme(versions []string) string {
	hasSemver := false
	hasPseudo := false

	for _, v := range versions {
		if strings.Contains(v, "-0.") && len(v) > 30 {
			hasPseudo = true
		} else if strings.HasPrefix(v, "v") {
			hasSemver = true
		}
	}

	if hasSemver && hasPseudo {
		return "mixed"
	}
	if hasPseudo {
		return "pseudo"
	}
	return "semver"
}

func computeResilienceScore(info *ResilienceInfo) int {
	score := 0.0

	// Release cadence (0-30 points).
	switch info.ReleaseCadence {
	case "frequent":
		score += 30
	case "regular":
		score += 25
	case "slow":
		score += 10
	case "stale":
		score += 0
	}

	// Project age & track record (0-20 points).
	switch {
	case info.ProjectAgeDays > 365*5:
		score += 20 // 5+ years
	case info.ProjectAgeDays > 365*2:
		score += 15 // 2+ years
	case info.ProjectAgeDays > 365:
		score += 10 // 1+ year
	default:
		score += 5
	}

	// Release count depth (0-15 points).
	switch {
	case info.TotalReleases >= 20:
		score += 15
	case info.TotalReleases >= 10:
		score += 10
	case info.TotalReleases >= 5:
		score += 7
	default:
		score += 2
	}

	// Stability — has v1+ (0-10 points).
	if info.HasStableRelease {
		score += 10
	}

	// Governance (0-15 points).
	if info.HasSecurityPolicy {
		score += 5
	}
	if info.HasContribGuide {
		score += 5
	}
	if info.HasCodeOfConduct {
		score += 2
	}
	if info.HasMultipleMaintainers {
		score += 3
	}

	// Version scheme (0-10 points).
	switch info.VersionScheme {
	case "semver":
		score += 10
	case "mixed":
		score += 5
	case "pseudo":
		score += 2
	}

	s := int(score)
	if s > 100 {
		s = 100
	}
	return s
}
