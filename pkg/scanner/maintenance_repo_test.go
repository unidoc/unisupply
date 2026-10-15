package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGoModRetraction(t *testing.T) {
	const gomod = `// Deprecated: nope
module example.com/m

go 1.21

retract v1.0.1 // published by mistake
retract (
	// Contains a data race.
	[v1.2.0, v1.2.5]
	v1.4.0
)
retract v2.0.0-beta.1
`
	tests := []struct {
		version string
		want    bool
		msg     string
	}{
		{"v1.0.0", false, ""},
		{"v1.0.1", true, "published by mistake"},
		{"v1.1.9", false, ""},
		{"v1.2.0", true, "Contains a data race."},
		{"v1.2.3", true, "Contains a data race."},
		{"v1.2.5", true, "Contains a data race."},
		{"v1.2.6", false, ""},
		{"v1.4.0", true, ""},
		{"v1.4.1", false, ""},
		{"v2.0.0-beta.1", true, ""},
		{"v2.0.0", false, ""},
		{"", false, ""},
		{"not-a-version", false, ""},
	}
	for _, tt := range tests {
		got, msg := goModRetraction([]byte(gomod), tt.version)
		if got != tt.want || msg != tt.msg {
			t.Errorf("goModRetraction(%q) = %v, %q; want %v, %q", tt.version, got, msg, tt.want, tt.msg)
		}
	}
	if got, _ := goModRetraction([]byte("this is not a go.mod\n"), "v1.0.0"); got {
		t.Error("an unparsable go.mod retracted a version")
	}
}

// The pinned version is checked against the retractions in the latest
// version's go.mod, from the same single go.mod request; Deprecated stays unset.
func TestMaintenanceScanner_Retraction(t *testing.T) {
	const gomod = "module example.com/m\n\nretract (\n\t// Broken\n\t// release.\n\t[v1.0.0, v1.1.0]\n)\n"
	var modRequests int
	proxy := originProxy(t, map[string]string{"example.com/m": ""}, map[string]string{"example.com/m": gomod})
	counting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".mod") {
			modRequests++
		}
		resp, err := http.Get(proxy.URL + r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		w.Write(buf[:n])
	}))
	defer counting.Close()

	for _, tt := range []struct {
		version string
		want    bool
	}{{"v1.0.5", true}, {"v1.2.0", false}} {
		ms := NewMaintenanceScanner(5 * time.Second)
		ms.proxyURL = counting.URL
		ms.diskCache = nil
		modRequests = 0
		info, err := ms.checkModule(context.Background(), "example.com/m", tt.version)
		if err != nil {
			t.Fatal(err)
		}
		if info.Retracted != tt.want {
			t.Errorf("%s: Retracted = %v, want %v", tt.version, info.Retracted, tt.want)
		}
		if info.Deprecated {
			t.Errorf("%s: Deprecated set for a retraction", tt.version)
		}
		if tt.want && info.RetractionNotice() != "Broken release." {
			t.Errorf("%s: RetractionNotice = %q, want %q", tt.version, info.RetractionNotice(), "Broken release.")
		}
		if !tt.want && info.RetractionMessage != "" {
			t.Errorf("%s: RetractionMessage = %q on a version that is not retracted", tt.version, info.RetractionMessage)
		}
		if modRequests != 1 {
			t.Errorf("%s: %d go.mod requests, want 1 (deprecation and retraction share it)", tt.version, modRequests)
		}
	}
}

func TestNormalizeRepositoryURL(t *testing.T) {
	tests := map[string]string{
		"https://github.com/go-yaml/yaml":      "https://github.com/go-yaml/yaml",
		"https://github.com/go-yaml/yaml.git":  "https://github.com/go-yaml/yaml",
		"https://GitHub.com/Go-Yaml/yaml/":     "https://github.com/Go-Yaml/yaml",
		"https://github.com/o/r/tree/main/sub": "https://github.com/o/r",
		"https://go.googlesource.com/crypto":   "https://go.googlesource.com/crypto",
		"https://gitlab.com/g/sub/r.git":       "https://gitlab.com/g/sub/r",
		"git://github.com/o/r":                 "",
		"http://github.com/o/r":                "",
		"https://u:p@github.com/o/r":           "",
		"https://github.com/o":                 "",
		"https://github.com/o/r%3Fx":           "",
		"https://github.com/../r":              "",
		"":                                     "",
	}
	for in, want := range tests {
		if got := normalizeRepositoryURL(in); got != want {
			t.Errorf("normalizeRepositoryURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// gopkg.in/yaml.v3 is archived on GitHub; the proxy's origin record points
// there, so the vanity path reads as archived with the flag actually checked.
func TestMaintenanceScanner_ArchivedViaProxyOrigin(t *testing.T) {
	gh := newBudgetGitHub(t, "go-yaml/yaml")
	gh.archived["go-yaml/yaml"] = true
	proxy := originProxy(t, map[string]string{"gopkg.in/yaml.v3": "https://github.com/go-yaml/yaml"}, nil)

	ms := NewMaintenanceScanner(5 * time.Second)
	ms.proxyURL = proxy.URL
	ms.diskCache = nil
	graph := makeGraphWithDeps(struct{ path, ver string }{"gopkg.in/yaml.v3", "v1.2.0"})
	results, err := ms.ScanAll(context.Background(), graph)
	if err != nil {
		t.Fatal(err)
	}
	if err := ms.ScanArchived(context.Background(), results, gh.scanner("")); err != nil {
		t.Fatal(err)
	}
	i := results["gopkg.in/yaml.v3"]
	if !i.Archived || i.ArchivedCheck != ArchivedChecked || i.RepositoryURL != "https://github.com/go-yaml/yaml" {
		t.Errorf("yaml.v3: archived %v, check %q, repo %q", i.Archived, i.ArchivedCheck, i.RepositoryURL)
	}
	if n := gh.count("/repos/go-yaml/yaml"); n != 1 {
		t.Errorf("repository requested %d times, want 1", n)
	}
}

type fixedArchive struct{ err error }

func (f fixedArchive) RepositoryArchived(context.Context, string, string) (bool, error) {
	return false, f.err
}

// Archived=false is an answer only with ArchivedCheck "checked": a failed
// lookup says "failed", a non-GitHub host "unsupported", and a module with no
// known repository (or no lookup at all) leaves the check empty.
func TestMaintenanceScanner_ArchivedCheckStates(t *testing.T) {
	origins := map[string]string{
		"github.com/o/r":      "",
		"golang.org/x/crypto": "https://go.googlesource.com/crypto",
		"example.com/private": "",
	}
	graph := makeGraphWithDeps(
		struct{ path, ver string }{"github.com/o/r", "v1.2.0"},
		struct{ path, ver string }{"golang.org/x/crypto", "v1.2.0"},
		struct{ path, ver string }{"example.com/private", "v1.2.0"},
	)
	scan := func(t *testing.T, lookup ArchiveLookup) map[string]*MaintenanceInfo {
		t.Helper()
		ms := NewMaintenanceScanner(5 * time.Second)
		ms.proxyURL = originProxy(t, origins, nil).URL
		ms.diskCache = nil
		results, err := ms.ScanAll(context.Background(), graph)
		if err != nil {
			t.Fatal(err)
		}
		_ = ms.ScanArchived(context.Background(), results, lookup)
		return results
	}

	t.Run("rate limited", func(t *testing.T) {
		res := scan(t, fixedArchive{errRateLimited})
		if i := res["github.com/o/r"]; i.ArchivedCheck != ArchivedCheckFailed || i.Archived || i.RepositoryNotFound {
			t.Errorf("rate limited: check %q archived %v notfound %v", i.ArchivedCheck, i.Archived, i.RepositoryNotFound)
		}
	})
	t.Run("not found", func(t *testing.T) {
		ms := NewMaintenanceScanner(time.Second)
		info := &MaintenanceInfo{RepositoryURL: "https://github.com/o/r"}
		err := ms.ScanArchived(context.Background(), map[string]*MaintenanceInfo{"m": info}, fixedArchive{ErrRepositoryNotFound})
		if err != nil {
			t.Errorf("a 404 is not a failed scan, got %v", err)
		}
		if !info.RepositoryNotFound || info.ArchivedCheck != ArchivedCheckFailed {
			t.Errorf("404: notfound %v check %q", info.RepositoryNotFound, info.ArchivedCheck)
		}
	})
	t.Run("failure is counted", func(t *testing.T) {
		ms := NewMaintenanceScanner(time.Second)
		info := &MaintenanceInfo{RepositoryURL: "https://github.com/o/r"}
		err := ms.ScanArchived(context.Background(), map[string]*MaintenanceInfo{"m": info}, fixedArchive{errors.New("boom")})
		if err == nil || !strings.Contains(err.Error(), "1 of 1") {
			t.Errorf("err = %v, want a count of the failed module", err)
		}
	})
	t.Run("unsupported and unknown", func(t *testing.T) {
		res := scan(t, fixedArchive{nil})
		if i := res["golang.org/x/crypto"]; i.ArchivedCheck != ArchivedUnsupported || i.Archived || i.RepositoryURL != "https://go.googlesource.com/crypto" {
			t.Errorf("googlesource: check %q repo %q", i.ArchivedCheck, i.RepositoryURL)
		}
		if i := res["example.com/private"]; i.ArchivedCheck != "" || i.RepositoryURL != "" {
			t.Errorf("unknown repository: check %q repo %q, want both empty", i.ArchivedCheck, i.RepositoryURL)
		}
		// No origin for a github.com path: the repository the path names.
		if i := res["github.com/o/r"]; i.RepositoryURL != "https://github.com/o/r" || i.ArchivedCheck != ArchivedChecked {
			t.Errorf("github path: repo %q check %q", i.RepositoryURL, i.ArchivedCheck)
		}
	})
	t.Run("nil lookup attempts nothing", func(t *testing.T) {
		res := scan(t, nil)
		if i := res["github.com/o/r"]; i.ArchivedCheck != "" || i.Archived {
			t.Errorf("nil lookup: check %q", i.ArchivedCheck)
		}
	})
}

// A real 404 and a real 403 through the GitHub client: the 404 is cached
// negatively and reported as not found, the 403 (no rate-limit header) as a
// failure, and neither is retried by a second module of the same repository.
func TestMaintainerScanner_RepositoryArchived_Errors(t *testing.T) {
	gh := newBudgetGitHub(t)
	ms := gh.scanner("")
	for range 3 {
		if _, err := ms.RepositoryArchived(context.Background(), "gone", "repo"); !errors.Is(err, ErrRepositoryNotFound) {
			t.Fatalf("err = %v, want ErrRepositoryNotFound", err)
		}
	}
	if n := gh.count("/repos/gone/repo"); n != 1 {
		t.Errorf("404 repository requested %d times, want 1", n)
	}

	info := ms.analyzeRepo(context.Background(), "gone", "repo")
	if info.DataAvailable || info.UnavailableReason != UnavailableNotFound {
		t.Errorf("analyzeRepo on a 404: available %v reason %q, want %q", info.DataAvailable, info.UnavailableReason, UnavailableNotFound)
	}
	if n := gh.count("/repos/gone/repo"); n != 1 {
		t.Errorf("after analyzeRepo: %d requests, want 1 (shared answer)", n)
	}

	denied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusForbidden)
	}))
	defer denied.Close()
	ms2 := newTestMaintainerScanner(denied.URL)
	_, err := ms2.RepositoryArchived(context.Background(), "o", "r")
	if err == nil || errors.Is(err, ErrRepositoryNotFound) {
		t.Errorf("403: err = %v, want a failure that is not 'not found'", err)
	}
}

func TestGopkgInRepository(t *testing.T) {
	for in, want := range map[string]string{
		"gopkg.in/yaml.v2":                 "https://github.com/go-yaml/yaml",
		"gopkg.in/yaml.v3":                 "https://github.com/go-yaml/yaml",
		"gopkg.in/check.v1":                "https://github.com/go-check/check",
		"gopkg.in/natefinch/lumberjack.v2": "https://github.com/natefinch/lumberjack",
		"gopkg.in/yaml":                    "", // no .vN
		"gopkg.in/yaml.v":                  "",
		"gopkg.in/yaml.vx":                 "",
		"gopkg.in/a/b/c.v1":                "", // too deep
		"github.com/go-yaml/yaml":          "",
	} {
		if got := gopkgInRepository(in); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
	// without a proxy origin the repository comes from the convention and the archived flag is then checked
	ms := NewMaintenanceScanner(time.Second)
	info := &MaintenanceInfo{}
	ms.resolveRepository("gopkg.in/yaml.v2", info, &proxyVersionInfo{})
	if info.RepositoryURL != "https://github.com/go-yaml/yaml" || info.ArchivedCheck != "" {
		t.Errorf("%+v", info)
	}
}

// A 200 answer that does not parse as a go.mod is not cached: the next scan asks again, so the module is not kept
// "unread" for the cache's lifetime after the proxy recovers.
func TestMaintenanceScanner_UnparsableGoModIsNotCached(t *testing.T) {
	var mod atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/example.com/m/@latest", "/example.com/m/@v/v1.0.0.info":
			fmt.Fprint(w, `{"Version":"v1.0.0","Time":"2026-01-01T00:00:00Z"}`)
		case "/example.com/m/@v/v1.0.0.mod":
			mod.Add(1)
			fmt.Fprint(w, "module (\nexample.com/m\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	scan := func() *MaintenanceInfo {
		ms := NewMaintenanceScanner(5 * time.Second)
		ms.proxyURL = srv.URL
		ms.diskCache = newMaintainerCache(dir, time.Hour)
		info, err := ms.checkModule(context.Background(), "example.com/m", "v1.0.0")
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
	if a := scan(); !a.ModCheckFailed {
		t.Fatalf("an unparsable go.mod is an unread notice: %+v", a)
	}
	scan()
	if n := mod.Load(); n != 2 {
		t.Errorf("the unparsable body was cached: %d go.mod requests for two scans, want 2", n)
	}
}
