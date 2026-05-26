package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	Archived           bool      `json:"archived"`
	Deprecated         bool      `json:"deprecated"`
	LatestVersion      string    `json:"latest_version"`
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
	var done int64

	for _, dep := range graph.Dependencies {
		wg.Add(1)
		go func(d *resolver.Dependency) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rep.Step("%s", d.Module.Path)
			info, err := ms.checkModule(d.Module.Path, d.Module.Version)
			n := atomic.AddInt64(&done, 1)
			rep.Progress(int(n), total)
			if err != nil {
				errOnce.Do(func() {
					firstErr = fmt.Errorf("checking maintenance for %s: %w", d.Module.Path, err)
				})
				return
			}

			mu.Lock()
			results[d.Module.Path] = info
			mu.Unlock()
		}(dep)
	}

	wg.Wait()
	return results, firstErr
}

func (ms *MaintenanceScanner) checkModule(modPath, version string) (*MaintenanceInfo, error) {
	ms.mu.Lock()
	if cached, ok := ms.cache[modPath]; ok {
		ms.mu.Unlock()
		return cached, nil
	}
	ms.mu.Unlock()

	info := &MaintenanceInfo{}

	// Get version info for the specific version used.
	versionInfo, err := ms.fetchVersionInfo(modPath, version)
	if err == nil && versionInfo != nil {
		info.LastRelease = versionInfo.Time
		info.MonthsSinceRelease = monthsSince(ms.ScanStart, versionInfo.Time)
	}

	// Check latest version to see if there's a newer release.
	latestVersion, latestTime := ms.fetchLatestVersion(modPath)
	if latestVersion != "" {
		info.LatestVersion = latestVersion
		if !latestTime.IsZero() {
			info.LastRelease = latestTime
			info.MonthsSinceRelease = monthsSince(ms.ScanStart, latestTime)
		}
	}

	// Check for deprecation via the @latest endpoint.
	ms.checkDeprecation(modPath, info)

	ms.mu.Lock()
	ms.cache[modPath] = info
	ms.mu.Unlock()

	return info, nil
}

func (ms *MaintenanceScanner) fetchVersionInfo(modPath, version string) (*proxyVersionInfo, error) {
	escapedPath := encodeModulePath(modPath)
	url := fmt.Sprintf("%s/%s/@v/%s.info", ms.proxyURL, escapedPath, version)

	body, resp, err := ms.client.Get(context.Background(), url, GetOptions{
		Host: proxyHost(ms.proxyURL),
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

func (ms *MaintenanceScanner) fetchLatestVersion(modPath string) (string, time.Time) {
	escapedPath := encodeModulePath(modPath)
	url := fmt.Sprintf("%s/%s/@latest", ms.proxyURL, escapedPath)

	body, resp, err := ms.client.Get(context.Background(), url, GetOptions{
		Host: proxyHost(ms.proxyURL),
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

func (ms *MaintenanceScanner) checkDeprecation(modPath string, info *MaintenanceInfo) {
	// The Go module proxy @latest endpoint may include deprecation info
	// in the response headers or body. For MVP, we check if the module
	// returns a 410 Gone status, which indicates it's been retracted.
	escapedPath := encodeModulePath(modPath)
	url := fmt.Sprintf("%s/%s/@v/list", ms.proxyURL, escapedPath)

	_, resp, err := ms.client.Get(context.Background(), url, GetOptions{
		Host: proxyHost(ms.proxyURL),
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
