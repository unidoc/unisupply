package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/mod/modfile"

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

	// ScanStart is the reference time used for MonthsSinceRelease calculations.
	// Truncated to the start of a UTC day so that two scans on the same calendar
	// day produce identical band results. Defaults to
	// time.Now().UTC().Truncate(24*time.Hour) at construction time.
	ScanStart time.Time
}

// NewMaintenanceScanner creates a new maintenance health scanner.
func NewMaintenanceScanner(timeout time.Duration) *MaintenanceScanner {
	return &MaintenanceScanner{
		client:    NewClient(ClientOptions{Timeout: timeout}),
		proxyURL:  "https://proxy.golang.org",
		cache:     make(map[string]*MaintenanceInfo),
		ScanStart: time.Now().UTC().Truncate(24 * time.Hour),
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
	versionInfo, versionErr := ms.fetchVersionInfo(ctx, modPath, version)
	if versionErr == nil && versionInfo != nil {
		info.LastRelease = versionInfo.Time
		info.MonthsSinceRelease = monthsSince(ms.ScanStart, versionInfo.Time)
	}

	// Check latest version to see if there's a newer release.
	latestVersion, latestTime := ms.fetchLatestVersion(ctx, modPath)
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

	// Check for deprecation: a 410 on @v/list, or a `// Deprecated:` notice
	// in the latest version's go.mod.
	ms.checkDeprecation(ctx, modPath, info)
	if latestVersion != "" {
		ms.checkGoModDeprecation(ctx, modPath, latestVersion, info)
	}

	ms.mu.Lock()
	ms.cache[modPath] = info
	ms.mu.Unlock()

	return info, nil
}

func (ms *MaintenanceScanner) fetchVersionInfo(ctx context.Context, modPath, version string) (*proxyVersionInfo, error) {
	escapedPath := encodeModulePath(modPath)
	url := fmt.Sprintf("%s/%s/@v/%s.info", ms.proxyURL, escapedPath, version)

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
	escapedPath := encodeModulePath(modPath)
	url := fmt.Sprintf("%s/%s/@latest", ms.proxyURL, escapedPath)

	body, resp, err := ms.client.Get(ctx, url, GetOptions{
		Host:    proxyHost(ms.proxyURL),
		Purpose: "maintenance:latest",
	})
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", time.Time{}
	}

	var info proxyVersionInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return "", time.Time{}
	}

	return info.Version, info.Time
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

// checkGoModDeprecation reads the go.mod of version (the module's latest
// version) from the proxy and records a `// Deprecated:` notice attached to
// its module directive, the way `go list -m -u` and `go get` report it. The
// Go modules reference reads deprecation from the latest version's go.mod, so
// a notice in an older version does not count, and a comment elsewhere in the
// file is not a deprecation. A failed fetch or an unparsable go.mod leaves
// info unchanged: no deprecation is reported rather than a wrong one.
func (ms *MaintenanceScanner) checkGoModDeprecation(ctx context.Context, modPath, version string, info *MaintenanceInfo) {
	url := fmt.Sprintf("%s/%s/@v/%s.mod", ms.proxyURL, encodeModulePath(modPath), encodeModulePath(version))
	body, resp, err := ms.client.Get(ctx, url, GetOptions{
		Host:    proxyHost(ms.proxyURL),
		Purpose: "maintenance:go-mod",
	})
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	if msg := goModDeprecation(body); msg != "" {
		info.Deprecated = true
		info.DeprecationMessage = msg
	}
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
