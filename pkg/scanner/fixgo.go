package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"

	"github.com/unidoc/unisupply/pkg/offline"
)

// fixGoModMaxBytes caps a proxy .mod body; a real go.mod is a few kilobytes.
const fixGoModMaxBytes int64 = 512 * 1024

// ResolveFixGoRequirements fills FixRequiresGo on every vuln of module that has a FixedVersion: the `go` directive of the fixed
// version's go.mod (for example "1.26"), read from the module proxy (GET <proxy>/<module>/@v/<fixed>.mod).
//
// Many fixes are only published in versions that need a newer Go than the module being graded supports: the x/* modules, for
// example, raise their minimum to the previous Go release shortly after each Go release, so a project that supports older Go
// versions cannot take the fix without raising its own minimum. The grade does not change for that (the fix exists), but the
// report says it, so the choice (raise the minimum, or live with the finding) is visible.
//
// It never fails the scan: a lookup that failed leaves FixRequiresGo empty ("unknown"), and nothing is invented. Lookups are
// de-duplicated per fixed version, run at most fixDateMaxConcurrency at a time, share opts.Timeout (default 30 s) and send no
// request in offline mode. Only the fix date options are reused (ProxyURL, Timeout, Client).
func ResolveFixGoRequirements(ctx context.Context, opts FixDateOptions, modulePath string, vulns []Vulnerability) {
	var versions []string
	seen := map[string]bool{}
	for i := range vulns {
		vulns[i].FixRequiresGo = ""
		if v := canonicalVersion(vulns[i].FixedVersion); v != "" && !seen[v] {
			seen[v] = true
			versions = append(versions, v)
		}
	}
	if len(versions) == 0 || offline.Enabled() {
		return
	}
	proxy := strings.TrimRight(opts.ProxyURL, "/")
	if proxy == "" {
		proxy = defaultFixDateProxyURL
	}
	u, err := url.Parse(proxy)
	if err != nil || u.Host == "" {
		return
	}
	escPath, err := module.EscapePath(modulePath)
	if err != nil {
		return
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
		got = map[string]string{}
		sem = make(chan struct{}, fixDateMaxConcurrency)
	)
loop:
	for _, v := range versions {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break loop
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			escVer, err := module.EscapeVersion(v)
			if err != nil {
				return
			}
			body, resp, err := client.Get(ctx, fmt.Sprintf("%s/%s/@v/%s.mod", proxy, escPath, escVer), GetOptions{
				Host:     u.Host,
				MaxBytes: fixGoModMaxBytes,
				Purpose:  "fixgo:proxy-mod",
			})
			if err != nil || resp.StatusCode != http.StatusOK {
				return
			}
			f, err := modfile.ParseLax("go.mod", body, nil)
			if err != nil || f.Go == nil {
				return
			}
			mu.Lock()
			got[v] = f.Go.Version
			mu.Unlock()
		}()
	}
	wg.Wait()
	for i := range vulns {
		vulns[i].FixRequiresGo = got[canonicalVersion(vulns[i].FixedVersion)]
	}
}
