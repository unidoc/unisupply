package scanner

import (
	"bytes"
	"context"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

func TestParseGovulncheck_ReadsConfigMessage(t *testing.T) {
	var info ScanInfo
	_, err := parseGovulncheckJSONWithOptions(loadGovulncheckFixture(t, "govulncheck_called_config.json"), gvcParseOptions{info: &info})
	if err != nil {
		t.Fatal(err)
	}
	if info.GovulncheckVersion != "" || info.GoVersion != "go1.26.9" ||
		info.VulnDB != "https://vuln.go.dev" || info.VulnDBLastModified != "2026-10-01T15:04:05Z" {
		t.Errorf("info = %+v", info)
	}
}

func TestParseGovulncheck_NoConfigMessageLeavesInfoEmpty(t *testing.T) {
	var info ScanInfo
	res, err := parseGovulncheckJSONWithOptions(loadGovulncheckFixture(t, "govulncheck_called.json"), gvcParseOptions{info: &info})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) == 0 {
		t.Error("findings lost")
	}
	if info != (ScanInfo{}) {
		t.Errorf("info = %+v, want empty for output without a config message", info)
	}
}

func TestScanPlatform(t *testing.T) {
	t.Setenv("GOOS", "plan9")
	t.Setenv("GOARCH", "mips")
	if got := scanPlatform(); got != "plan9/mips" {
		t.Errorf("got %q", got)
	}
	t.Setenv("GOOS", "")
	t.Setenv("GOARCH", "")
	if got := scanPlatform(); !strings.Contains(got, "/") || strings.HasPrefix(got, "/") || strings.HasSuffix(got, "/") {
		t.Errorf("got %q, want goos/goarch of the binary", got)
	}
}

// A finding with a known severity has no enrichment pass, so the advisory date
// must come from govulncheck's own osv message, and a proxy that cannot date
// the fixed version must leave that date as the fix date.
func TestParseGovulncheck_AdvisoryDateFeedsFixDate(t *testing.T) {
	res, err := parseGovulncheckJSON(loadGovulncheckFixture(t, "govulncheck_called.json"))
	if err != nil {
		t.Fatal(err)
	}
	vulns := res["github.com/example/vulnpkg"]
	if len(vulns) != 1 {
		t.Fatalf("vulns = %+v", res)
	}
	v := vulns[0]
	if v.Severity != "HIGH" || v.EnrichmentAttempted {
		t.Fatalf("fixture must carry a known severity: %+v", v)
	}
	want := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	if v.FixPublishedAt == nil || !v.FixPublishedAt.Equal(want) {
		t.Fatalf("FixPublishedAt = %v, want %v", v.FixPublishedAt, want)
	}

	f := newProxyFixture(t, nil) // every lookup 404s
	ResolveFixDates(context.Background(), f.opts(), "github.com/example/vulnpkg", vulns)
	if vulns[0].FixReleasedAt == nil || !vulns[0].FixReleasedAt.Equal(want) || vulns[0].FixDateSource != FixDateAdvisory {
		t.Errorf("FixReleasedAt = %v source %q, want the advisory date and %q", vulns[0].FixReleasedAt, vulns[0].FixDateSource, FixDateAdvisory)
	}
}

func TestParseGovulncheck_NoFixNoFixPublishedAt(t *testing.T) {
	in := `{"osv":{"id":"GO-1","published":"2024-03-01T00:00:00Z","summary":"s","affected":[{"package":{"name":"example.com/m","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}],"database_specific":{"severity":"HIGH"}}]}}
{"finding":{"osv":"GO-1","trace":[{"module":"example.com/m","version":"v1.0.0"}]}}
`
	res, err := parseGovulncheckJSON(bytes.NewBufferString(in))
	if err != nil {
		t.Fatal(err)
	}
	v := res["example.com/m"][0]
	if v.FixPublishedAt != nil || v.PublishedAt == nil {
		t.Errorf("FixPublishedAt=%v PublishedAt=%v, want no fix date but a disclosure date", v.FixPublishedAt, v.PublishedAt)
	}
}

// F28: govulncheck_version is the version of golang.org/x/vuln from the build info, never unisupply's own (Main) version
// and never the config message's scanner_version (which is the embedding binary's, i.e. unisupply's).
func TestGovulncheckVersion_FromDeps(t *testing.T) {
	read := func(bi *debug.BuildInfo, ok bool) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) { return bi, ok }
	}
	main := debug.Module{Path: "github.com/unidoc/unisupply", Version: "v0.7.0"}
	for _, tc := range []struct {
		name string
		read func() (*debug.BuildInfo, bool)
		want string
	}{
		{"listed", read(&debug.BuildInfo{Main: main, Deps: []*debug.Module{{Path: "github.com/spf13/pflag", Version: "v1.0.5"}, {Path: "golang.org/x/vuln", Version: "v1.8.0"}}}, true), "v1.8.0"},
		{"replaced by a version", read(&debug.BuildInfo{Main: main, Deps: []*debug.Module{{Path: "golang.org/x/vuln", Version: "v1.8.0", Replace: &debug.Module{Path: "example.com/fork", Version: "v1.9.0"}}}}, true), "v1.9.0"},
		{"replaced by a directory", read(&debug.BuildInfo{Main: main, Deps: []*debug.Module{{Path: "golang.org/x/vuln", Version: "v1.8.0", Replace: &debug.Module{Path: "../vuln"}}}}, true), ""},
		{"not among the deps: not unisupply's version", read(&debug.BuildInfo{Main: main}, true), ""},
		{"no build info", read(nil, false), ""},
	} {
		if got := govulncheckVersion(tc.read); got != tc.want {
			t.Errorf("%s: govulncheckVersion = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The config message's scanner_version (unisupply's own version when govulncheck runs in-process) must not reach the info.
func TestGovulncheckVersion_ConfigScannerVersionIgnored(t *testing.T) {
	var info ScanInfo
	info.apply([]byte(`{"scanner_version":"v0.7.0-unisupply","go_version":"go1.26.9"}`))
	if info.GovulncheckVersion != "" {
		t.Errorf("apply copied scanner_version %q into govulncheck_version", info.GovulncheckVersion)
	}
}
