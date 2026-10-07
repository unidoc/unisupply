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

	// LastActivity is the GitHub pushed_at date of the module's repository
	// (MaintainerInfo.LastCommitDate). It counts a push to any branch, bots
	// included, so it is a looser signal than the default branch's latest
	// commit. The module proxy does not expose it: the scorer backfills it from
	// the maintainer scan, and it stays zero when that data is unavailable
	// (no token, non-GitHub module, API failure).
	LastActivity time.Time `json:"last_activity,omitzero"`

	// MonthsSinceActivity is the calendar-month age of LastActivity. It is
	// meaningful only when LastActivity is non-zero.
	MonthsSinceActivity int `json:"months_since_activity,omitempty"`

	Archived      bool   `json:"archived"`
	Deprecated    bool   `json:"deprecated"`
	LatestVersion string `json:"latest_version"`

	// OriginURL is the source repository URL from the module proxy's .info
	// Origin field, taken from the responses already fetched for this module
	// (the latest version's, else the scanned version's). It is empty when the
	// proxy reports no Origin, which is common for old and gopkg.in modules.
	// It feeds the maintainer scanner's repository resolution and is not part
	// of the JSON output.
	OriginURL string `json:"-"`
}

// OriginURLs returns the proxy Origin.URL of every module in maintenance that
// has one, keyed by module path, for MaintainerScanner.OriginURLs.
func OriginURLs(maintenance map[string]*MaintenanceInfo) map[string]string {
	out := make(map[string]string, len(maintenance))
	for path, info := range maintenance {
		if info != nil && info.OriginURL != "" {
			out[path] = info.OriginURL
		}
	}
	return out
}

// HasActivity reports whether repository activity is known for the module.
func (m *MaintenanceInfo) HasActivity() bool {
	return m != nil && !m.LastActivity.IsZero()
}

// MonthsInactive returns the months since the module last showed signs of
// maintenance: the smaller of MonthsSinceRelease and MonthsSinceActivity when
// activity is known, otherwise MonthsSinceRelease alone. A repository that is
// pushed to but rarely tagged is therefore not mistaken for an abandoned one,
// while a module with no activity data keeps the release-only behaviour.
// MonthsSinceRelease stays the right value for statements that are specifically
// about releases.
func (m *MaintenanceInfo) MonthsInactive() int {
	if m == nil {
		return 0
	}
	if !m.HasActivity() {
		return m.MonthsSinceRelease
	}
	return min(m.MonthsSinceRelease, m.MonthsSinceActivity)
}

// MonthsSince returns the whole calendar months from t to now, clamped at 0.
// It is the single month formula behind MonthsSinceRelease and
// MonthsSinceActivity.
func MonthsSince(now, t time.Time) int {
	return monthsSince(now, t)
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

// originURL returns the Origin.URL, or "" when the proxy reported none.
func (v *proxyVersionInfo) originURL() string {
	if v == nil || v.Origin == nil {
		return ""
	}
	return v.Origin.URL
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
		info.OriginURL = versionInfo.originURL()
	}

	// Check latest version to see if there's a newer release.
	latestVersion, latestTime, latestOrigin := ms.fetchLatestVersion(ctx, modPath)
	if latestVersion != "" {
		info.LatestVersion = latestVersion
		// The latest version's Origin is preferred: it reflects where the
		// module lives now. The scanned version's is the fallback.
		if latestOrigin != "" {
			info.OriginURL = latestOrigin
		}
		if !latestTime.IsZero() {
			info.LastRelease = latestTime
			info.MonthsSinceRelease = monthsSince(ms.ScanStart, latestTime)
		}
	}

	// Both lookups failed — we have no data at all; propagate the error.
	if versionErr != nil && latestVersion == "" {
		return nil, fmt.Errorf("maintenance lookup for %s: %w", modPath, versionErr)
	}

	// Check for deprecation via the @latest endpoint.
	ms.checkDeprecation(ctx, modPath, info)

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

func (ms *MaintenanceScanner) fetchLatestVersion(ctx context.Context, modPath string) (version string, t time.Time, originURL string) {
	escapedPath := encodeModulePath(modPath)
	url := fmt.Sprintf("%s/%s/@latest", ms.proxyURL, escapedPath)

	body, resp, err := ms.client.Get(ctx, url, GetOptions{
		Host:    proxyHost(ms.proxyURL),
		Purpose: "maintenance:latest",
	})
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", time.Time{}, ""
	}

	var info proxyVersionInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return "", time.Time{}, ""
	}

	return info.Version, info.Time, info.originURL()
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
