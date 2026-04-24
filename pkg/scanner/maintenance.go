package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/unidoc/unisupply/pkg/resolver"
)

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
	client   *http.Client
	proxyURL string
	cache    map[string]*MaintenanceInfo
	mu       sync.Mutex
}

// NewMaintenanceScanner creates a new maintenance health scanner.
func NewMaintenanceScanner(timeout time.Duration) *MaintenanceScanner {
	return &MaintenanceScanner{
		client: &http.Client{
			Timeout: timeout,
		},
		proxyURL: "https://proxy.golang.org",
		cache:    make(map[string]*MaintenanceInfo),
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
func (ms *MaintenanceScanner) ScanAll(graph *resolver.Graph) (map[string]*MaintenanceInfo, error) {
	results := make(map[string]*MaintenanceInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 10)

	var firstErr error
	var errOnce sync.Once

	for _, dep := range graph.Dependencies {
		wg.Add(1)
		go func(d *resolver.Dependency) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			info, err := ms.checkModule(d.Module.Path, d.Module.Version)
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
		info.MonthsSinceRelease = monthsSince(versionInfo.Time)
	}

	// Check latest version to see if there's a newer release.
	latestVersion, latestTime := ms.fetchLatestVersion(modPath)
	if latestVersion != "" {
		info.LatestVersion = latestVersion
		if !latestTime.IsZero() {
			info.LastRelease = latestTime
			info.MonthsSinceRelease = monthsSince(latestTime)
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

	resp, err := ms.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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

	resp, err := ms.client.Get(url)
	if err != nil {
		return "", time.Time{}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
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

	resp, err := ms.client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

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

func monthsSince(t time.Time) int {
	if t.IsZero() {
		return 0
	}
	now := time.Now()
	years := now.Year() - t.Year()
	months := int(now.Month()) - int(t.Month())
	total := years*12 + months
	if total < 0 {
		return 0
	}
	return total
}
