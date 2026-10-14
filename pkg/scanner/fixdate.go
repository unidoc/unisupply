package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/unidoc/unisupply/pkg/offline"
)

const (
	defaultFixDateProxyURL = "https://proxy.golang.org"

	// fixDateMaxConcurrency bounds parallel proxy lookups.
	fixDateMaxConcurrency = 8

	fixDateTimeout = 30 * time.Second

	// fixDateInfoMaxBytes caps a proxy .info body; a real one is ~100 bytes.
	fixDateInfoMaxBytes int64 = 64 * 1024

	// FixDateModuleProxy and FixDateAdvisory are the Vulnerability.FixDateSource values.
	FixDateModuleProxy = "module_proxy"
	FixDateAdvisory    = "advisory"

	// stdlibToolchainModule and stdlibToolchainSuffix build the pseudo-version
	// under which the Go project publishes each release to the module proxy:
	// golang.org/toolchain@v0.0.1-go1.26.9.linux-amd64.
	stdlibToolchainModule = "golang.org/toolchain"
	stdlibToolchainSuffix = ".linux-amd64"
)

// stdlibVersionPattern matches a Go release as written by OSV and
// govulncheck: "go1.26.9", "v1.26.9" or "1.26.9", also "1.21" (the release
// that Go calls go1.21.0 in its toolchain versions) and "go1.22rc1".
var stdlibVersionPattern = regexp.MustCompile(`^(?:go|v)?(\d+\.\d+(?:\.\d+)?(?:(?:rc|beta)\d+)?)$`)

// FixDateOptions controls ResolveFixDates and ResolveStdlibFixDates. The zero
// value queries proxy.golang.org with the default timeout.
type FixDateOptions struct {
	// ProxyURL is the module proxy root. Empty means https://proxy.golang.org,
	// as for the maintenance scanner; tests point it at an httptest server.
	// Its host is the host pin.
	ProxyURL string

	// Timeout bounds all lookups together. Zero falls back to 30s. Lookups
	// still pending at the deadline leave their vulns on the advisory date.
	Timeout time.Duration

	// Client overrides the HTTP client. Nil builds the default. Intended for tests.
	Client *Client

	// clockFn is the time source for DaysUnpatched. Defaults to time.Now.
	clockFn func() time.Time
}

// ResolveFixDates fills FixReleasedAt and FixDateSource on every vuln of
// module that has a FixedVersion, in place.
//
// FixReleasedAt is the later of the advisory's FixPublishedAt and the time the
// module proxy gives the first fixed version: the advisory can be published
// before the fixed version exists, and a version tagged long before the
// advisory was not a fix until the advisory said so. FixDateSource is
// "module_proxy" when the proxy's time was the later or equal one, "advisory"
// when the advisory's date was later or the proxy had no time for the version,
// and "" with FixReleasedAt nil when neither is known. A vuln with no
// FixedVersion gets neither field.
//
// It never fails the scan and never invents a date: a failed lookup leaves the
// vuln on the advisory date, or unknown. Lookups are de-duplicated per fixed
// version and run at most 8 at a time. When FixReleasedAt is set, DaysUnpatched
// is recomputed from it, so the figure counts from the release, not from the
// advisory. Offline mode does no lookup and leaves the advisory dates.
func ResolveFixDates(ctx context.Context, opts FixDateOptions, module string, vulns []Vulnerability) {
	resolveFixDates(ctx, opts, vulns, func(v *Vulnerability) (string, string, bool) {
		fixed := canonicalVersion(v.FixedVersion)
		return module, fixed, fixed != ""
	})
}

// ResolveStdlibFixDates is ResolveFixDates for the standard library. A fixed
// version "go1.26.9" (or "v1.26.9" or "1.26.9", as OSV and govulncheck write
// it) was released when the proxy says golang.org/toolchain@v0.0.1-go1.26.9.linux-amd64
// was published; the rest of the rule is the same.
func ResolveStdlibFixDates(ctx context.Context, opts FixDateOptions, vulns []Vulnerability) {
	resolveFixDates(ctx, opts, vulns, func(v *Vulnerability) (string, string, bool) {
		m := stdlibVersionPattern.FindStringSubmatch(strings.TrimSpace(v.FixedVersion))
		if m == nil {
			return "", "", false
		}
		rel := m[1]
		if strings.Count(rel, ".") == 1 && !strings.ContainsAny(rel, "rb") {
			rel += ".0" // "1.21" is published as go1.21.0
		}
		return stdlibToolchainModule, "v0.0.1-go" + rel + stdlibToolchainSuffix, true
	})
}

// fixLookup names one proxy .info request.
type fixLookup struct{ module, version string }

// resolveFixDates is the shared body. target maps a vuln to the proxy module
// and version to look up; ok is false when the fixed version cannot be looked
// up, which leaves the advisory date in place.
func resolveFixDates(ctx context.Context, opts FixDateOptions, vulns []Vulnerability, target func(*Vulnerability) (mod, ver string, ok bool)) {
	now := opts.clockFn
	if now == nil {
		now = time.Now
	}

	// Collect the distinct lookups; many vulns share a fixed version.
	targets := make([]fixLookup, len(vulns))
	hasTarget := make([]bool, len(vulns))
	var lookups []fixLookup
	queued := map[fixLookup]bool{}
	for i := range vulns {
		v := &vulns[i]
		v.FixReleasedAt, v.FixDateSource = nil, ""
		if v.FixedVersion == "" {
			continue
		}
		if m, ver, ok := target(v); ok {
			targets[i], hasTarget[i] = fixLookup{m, ver}, true
			if !queued[targets[i]] {
				queued[targets[i]] = true
				lookups = append(lookups, targets[i])
			}
		}
	}

	var released map[fixLookup]time.Time
	if len(lookups) > 0 && !offline.Enabled() {
		released = fetchProxyTimes(ctx, opts, lookups)
	}

	for i := range vulns {
		v := &vulns[i]
		if v.FixedVersion == "" {
			continue
		}
		var proxyTime time.Time
		if hasTarget[i] {
			proxyTime = released[targets[i]]
		}
		switch {
		case !proxyTime.IsZero() && (v.FixPublishedAt == nil || !proxyTime.Before(*v.FixPublishedAt)):
			t := proxyTime
			v.FixReleasedAt, v.FixDateSource = &t, FixDateModuleProxy
		case v.FixPublishedAt != nil:
			t := *v.FixPublishedAt
			v.FixReleasedAt, v.FixDateSource = &t, FixDateAdvisory
		default:
			continue
		}
		days := int(now().Sub(*v.FixReleasedAt).Hours() / 24)
		if days < 0 {
			days = 0
		}
		v.DaysUnpatched = days
	}
}

// fetchProxyTimes looks up every target on the module proxy, at most
// fixDateMaxConcurrency at a time and within opts.Timeout overall. A target
// the proxy cannot date (404/410, other status, bad body, no time, error,
// deadline) is simply absent from the result.
func fetchProxyTimes(ctx context.Context, opts FixDateOptions, lookups []fixLookup) map[fixLookup]time.Time {
	proxy := strings.TrimRight(opts.ProxyURL, "/")
	if proxy == "" {
		proxy = defaultFixDateProxyURL
	}
	u, err := url.Parse(proxy)
	if err != nil || u.Host == "" {
		return nil
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = fixDateTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client := opts.Client
	if client == nil {
		client = NewClient(ClientOptions{Timeout: 10 * time.Second})
	}

	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		out = make(map[fixLookup]time.Time, len(lookups))
		sem = make(chan struct{}, fixDateMaxConcurrency)
	)
	for _, l := range lookups {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return out
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if t, ok := proxyInfoTime(ctx, client, proxy, u.Host, l); ok {
				mu.Lock()
				out[l] = t
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out
}

// proxyInfoTime reads the release time of one module version from
// <proxy>/<module>/@v/<version>.info.
func proxyInfoTime(ctx context.Context, client *Client, proxy, host string, l fixLookup) (time.Time, bool) {
	escPath, err := module.EscapePath(l.module)
	if err != nil {
		return time.Time{}, false
	}
	escVer, err := module.EscapeVersion(l.version)
	if err != nil || (!semver.IsValid(l.version)) {
		return time.Time{}, false
	}
	body, resp, err := client.Get(ctx, fmt.Sprintf("%s/%s/@v/%s.info", proxy, escPath, escVer), GetOptions{
		Host:     host,
		MaxBytes: fixDateInfoMaxBytes,
		Accept:   "application/json",
		Purpose:  "fixdate:proxy-info",
	})
	if err != nil || resp.StatusCode != http.StatusOK {
		return time.Time{}, false
	}
	var info proxyVersionInfo
	if err := json.Unmarshal(body, &info); err != nil || info.Time.IsZero() {
		return time.Time{}, false
	}
	return info.Time, true
}
