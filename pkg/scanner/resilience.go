package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/unidoc/unisupply/pkg/resolver"
)

// ResilienceInfo holds long-term reliability indicators for a module.
type ResilienceInfo struct {
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

	// Computed resilience score (0-100).
	Score int `json:"score"`
}

// ResilienceScanner computes resilience scores from release history.
type ResilienceScanner struct {
	client   *http.Client
	proxyURL string
	cache    map[string]*ResilienceInfo
	mu       sync.Mutex
}

// NewResilienceScanner creates a new resilience scanner.
func NewResilienceScanner(timeout time.Duration) *ResilienceScanner {
	return &ResilienceScanner{
		client: &http.Client{
			Timeout: timeout,
		},
		proxyURL: "https://proxy.golang.org",
		cache:    make(map[string]*ResilienceInfo),
	}
}

// ScanAll computes resilience info for all dependencies.
func (rs *ResilienceScanner) ScanAll(graph *resolver.Graph, maintainers map[string]*MaintainerInfo) map[string]*ResilienceInfo {
	results := make(map[string]*ResilienceInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 10)

	for _, dep := range graph.Dependencies {
		wg.Add(1)
		go func(d *resolver.Dependency) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			info := rs.analyzeModule(d.Module.Path)

			// Enrich with maintainer data if available.
			if mi, ok := maintainers[d.Module.Path]; ok {
				info.HasMultipleMaintainers = mi.BusFactor > 1
			}

			info.Score = computeResilienceScore(info)

			mu.Lock()
			results[d.Module.Path] = info
			mu.Unlock()
		}(dep)
	}

	wg.Wait()
	return results
}

func (rs *ResilienceScanner) analyzeModule(modPath string) *ResilienceInfo {
	rs.mu.Lock()
	if cached, ok := rs.cache[modPath]; ok {
		rs.mu.Unlock()
		return cached
	}
	rs.mu.Unlock()

	info := &ResilienceInfo{}

	// Fetch version list from Go proxy.
	versions := rs.fetchVersionList(modPath)
	if len(versions) == 0 {
		rs.mu.Lock()
		rs.cache[modPath] = info
		rs.mu.Unlock()
		return info
	}

	info.TotalReleases = len(versions)

	// Fetch timestamps for versions to compute cadence.
	var timestamps []time.Time
	majorVersions := make(map[string]bool)

	for _, ver := range versions {
		t := rs.fetchVersionTime(modPath, ver)
		if !t.IsZero() {
			timestamps = append(timestamps, t)
		}

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

	info.MajorVersions = len(majorVersions)

	// Compute cadence from timestamps.
	if len(timestamps) > 0 {
		sort.Slice(timestamps, func(i, j int) bool {
			return timestamps[i].Before(timestamps[j])
		})

		info.FirstReleaseDate = timestamps[0]
		info.LastReleaseDate = timestamps[len(timestamps)-1]
		info.ProjectAgeDays = int(time.Since(info.FirstReleaseDate).Hours() / 24)

		if len(timestamps) > 1 {
			totalDays := info.LastReleaseDate.Sub(info.FirstReleaseDate).Hours() / 24
			info.AvgDaysBetween = totalDays / float64(len(timestamps)-1)
		}
	}

	// Classify cadence.
	info.ReleaseCadence = classifyCadence(time.Now(), info)

	// Classify version scheme.
	info.VersionScheme = classifyVersionScheme(versions)

	// Check for governance files (if GitHub).
	owner, repo := parseGitHubPath(modPath)
	if owner != "" && repo != "" {
		rs.checkGovernanceFiles(owner, repo, info)
	}

	rs.mu.Lock()
	rs.cache[modPath] = info
	rs.mu.Unlock()

	return info
}

func (rs *ResilienceScanner) fetchVersionList(modPath string) []string {
	escapedPath := encodeModulePath(modPath)
	url := fmt.Sprintf("%s/%s/@v/list", rs.proxyURL, escapedPath)

	resp, err := rs.client.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
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

func (rs *ResilienceScanner) fetchVersionTime(modPath, version string) time.Time {
	escapedPath := encodeModulePath(modPath)
	url := fmt.Sprintf("%s/%s/@v/%s.info", rs.proxyURL, escapedPath, version)

	resp, err := rs.client.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		return time.Time{}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
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

func (rs *ResilienceScanner) checkGovernanceFiles(owner, repo string, info *ResilienceInfo) {
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
		resp, err := rs.client.Head(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				*f.flag = true
			}
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
	if info.ProjectAgeDays > 365*5 {
		score += 20 // 5+ years
	} else if info.ProjectAgeDays > 365*2 {
		score += 15 // 2+ years
	} else if info.ProjectAgeDays > 365 {
		score += 10 // 1+ year
	} else {
		score += 5
	}

	// Release count depth (0-15 points).
	if info.TotalReleases >= 20 {
		score += 15
	} else if info.TotalReleases >= 10 {
		score += 10
	} else if info.TotalReleases >= 5 {
		score += 7
	} else {
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
