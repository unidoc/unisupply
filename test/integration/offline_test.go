package integration_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/offline"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// panicOnDialTransport fails the test loudly if any request reaches the point
// where a real transport would dial. Installed *under* offline.Enable, so a
// refusal that works never reaches it and a refusal that leaks does.
type panicOnDialTransport struct{}

func (panicOnDialTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	panic("offline mode leaked a request to " + req.URL.Host)
}

// enterOffline installs the panic transport, enables offline mode over it, and
// redirects every on-disk cache to a temp dir.
//
// The cache redirection is not incidental: the maintainer, vulnenrich, and
// threatintel caches all resolve through os.UserCacheDir, so a developer with
// a warm cache from an earlier real scan would see this test pass on cache
// hits without any scanner ever attempting a request — proving nothing. Both
// env vars are set because os.UserCacheDir reads XDG_CACHE_HOME on Unix and
// HOME on darwin.
//
// Redirecting HOME also moves GOMODCACHE for anything that shells out to the
// `go` toolchain. That is safe only while directOnly = true keeps `go mod
// graph` and `go list` out of these tests; flipping it would make the toolchain
// resolve against an empty cache.
func enterOffline(t *testing.T) {
	t.Helper()

	cacheDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheDir)
	t.Setenv("HOME", cacheDir)

	original := http.DefaultTransport
	http.DefaultTransport = panicOnDialTransport{}

	offline.Enable()
	t.Cleanup(func() {
		offline.Disable()
		http.DefaultTransport = original
	})
}

func offlineGraph(t *testing.T) *resolver.Graph {
	t.Helper()

	graph, _, err := resolver.Resolve(context.Background(), testdataPath("gomod", "simple.mod"), directOnly)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(graph.Dependencies) == 0 {
		t.Fatal("fixture resolved to 0 dependencies; the test would prove nothing")
	}
	return graph
}

// TestOffline_NoScannerDials is the acceptance criterion for --offline: every
// network-touching scanner runs to completion against the fixture without a
// single dial. Each subtest would panic rather than fail if refusal leaked.
func TestOffline_NoScannerDials(t *testing.T) {
	enterOffline(t)
	graph := offlineGraph(t)
	ctx := context.Background()
	const timeout = 5 * time.Second

	t.Run("maintenance", func(t *testing.T) {
		// Returns a non-nil error when checks fail, which offline guarantees;
		// the contract under test is that it degrades rather than dials.
		got, _ := scanner.NewMaintenanceScanner(timeout).ScanAll(ctx, graph)
		if got == nil {
			t.Error("ScanAll returned a nil map; offline must degrade, not drop the result")
		}
	})

	var maintainers map[string]*scanner.MaintainerInfo

	t.Run("maintainer", func(t *testing.T) {
		maintainers = scanner.NewMaintainerScanner(timeout, "").ScanAll(ctx, graph)
		if maintainers == nil {
			t.Error("ScanAll returned a nil map; offline must degrade, not drop the result")
		}
	})

	t.Run("resilience", func(t *testing.T) {
		if got := scanner.NewResilienceScanner(timeout).ScanAll(ctx, graph, maintainers); got == nil {
			t.Error("ScanAll returned a nil map; offline must degrade, not drop the result")
		}
	})

	t.Run("threatintel", func(t *testing.T) {
		ti := scanner.NewThreatIntelClient(scanner.ThreatIntelOptions{CacheDir: t.TempDir()})
		if _, err := ti.LookupEPSS(ctx, []string{"CVE-2023-45288"}); err == nil {
			t.Error("LookupEPSS returned nil error offline; the failure must be reported, not swallowed")
		}
		if _, err := ti.LoadKEV(ctx); err == nil {
			t.Error("LoadKEV returned nil error offline; the failure must be reported, not swallowed")
		}
	})

	t.Run("govulncheck", func(t *testing.T) {
		// Skipped rather than attempted: govulncheck runs in-process against
		// vuln.go.dev, so the only honest offline outcome is "not run", said
		// out loud. An empty result with no warning would read as "clean".
		vulns, warnings, scanned, err := scanner.ScanVulns(ctx, testdataPath("gomod"), "")
		if err != nil {
			t.Fatalf("ScanVulns returned error %v, want nil (skip is not a failure)", err)
		}
		if scanned {
			t.Error("scanned = true for a skipped scan; the scorer would count the vulnerability axis as measured and score it clean")
		}
		if len(vulns) != 0 {
			t.Errorf("vulns = %d entries, want 0 when skipped", len(vulns))
		}
		if len(warnings) == 0 {
			t.Fatal("no warning emitted; a silently skipped vuln scan reads as a clean scan")
		}
		if !strings.Contains(warnings[0], "offline") {
			t.Errorf("warning = %q, want it to name offline as the reason", warnings[0])
		}
	})

	t.Run("vulnenrich", func(t *testing.T) {
		v := &scanner.Vulnerability{ID: "GO-2023-1234", Severity: "UNKNOWN"}
		scanner.NewVulnEnricher(scanner.VulnEnricherOptions{CacheDir: t.TempDir()}).Enrich(ctx, v)

		// Honest-UNKNOWN contract: enrichment was tried, it failed, and the
		// severity stays UNKNOWN rather than being fabricated.
		if v.Severity != "UNKNOWN" {
			t.Errorf("Severity = %q, want UNKNOWN — offline must not fabricate a severity", v.Severity)
		}
		if !v.EnrichmentAttempted {
			t.Error("EnrichmentAttempted = false, want true")
		}
		if !v.EnrichmentFailed {
			t.Error("EnrichmentFailed = false, want true — a refused request is a failed enrichment")
		}
	})
}

// TestOffline_IntegrityReportsOffline pins the go.sum verification state to
// the honest-UNKNOWN value rather than a verification failure, which would
// read as tampering.
func TestOffline_IntegrityReportsOffline(t *testing.T) {
	enterOffline(t)

	is := scanner.NewIntegrityScanner()
	is.Offline = true

	report := &scanner.IntegrityReport{}
	is.VerifyGoSum(context.Background(), testdataPath("gomod", "simple.mod"), report)

	if report.GoSumVerified != scanner.GoSumVerifiedOffline {
		t.Errorf("GoSumVerified = %q, want %q", report.GoSumVerified, scanner.GoSumVerifiedOffline)
	}
	if len(report.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 — offline is not a verification failure", len(report.Findings))
	}
}
