package runner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/offline"
	"github.com/unidoc/unisupply/pkg/progress"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// TestRun_NoDependencies exercises Run's zero-dependency fast path (no
// scanner network calls at all) end to end against a real temp module —
// deterministic and network-free, unlike the rest of the pipeline (which
// calls the Go Module Proxy / GitHub API and is instead covered by
// cmd/unisupply's own black-box CLI tests, run against this same
// refactored pkg/runner.Run underneath).
func TestRun_NoDependencies(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")
	content := "module github.com/example/empty\n\ngo 1.25\n"
	if err := os.WriteFile(gomodPath, []byte(content), 0o644); err != nil {
		t.Fatalf("writing fixture go.mod: %v", err)
	}

	stubGitHub(t, http.StatusOK) // hermetic: every request but a token probe is refused
	stubScan(t, nil, nil, true, nil)
	result, err := Run(context.Background(), Options{
		Path: tmpDir,
		Now:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.GoMod == nil {
		t.Fatal("result.GoMod is nil")
	}
	if result.Graph == nil {
		t.Fatal("result.Graph is nil")
	}
	if len(result.Graph.Dependencies) != 0 {
		t.Errorf("len(Graph.Dependencies) = %d, want 0", len(result.Graph.Dependencies))
	}
	if result.ProjectScore == nil {
		t.Fatal("result.ProjectScore is nil — even a zero-dependency project must get a scored (if empty) ProjectScore, callers rely on it being non-nil")
	}
	if len(result.ProjectScore.Dependencies) != 0 {
		t.Errorf("len(ProjectScore.Dependencies) = %d, want 0", len(result.ProjectScore.Dependencies))
	}
	// The zero-dependency path must skip every network-calling scanner
	// entirely — Maintainers/Typosquats/CIReport/StdlibVulns
	// should all be at their zero value, not partially populated.
	if result.CIReport != nil {
		t.Errorf("result.CIReport = %+v, want nil (ScanWorkflows/ScanCI were not requested)", result.CIReport)
	}
	// The standard library is listed, not graded, by default: the scan runs anyway (F31), and with nothing found the grade
	// is the module's own row (an A, "not assessed").
	stubScan(t, nil, nil, true, nil)
	result, err = Run(context.Background(), Options{Path: tmpDir, Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Grade == nil || result.Grade.Letter != "A" || result.Grade.Pending != nil || result.VulnScanErr != nil {
		t.Errorf("result.Grade = %+v, VulnScanErr = %v, want a graded A", result.Grade, result.VulnScanErr)
	}
	if result.Grade != nil && len(result.Grade.Rows) == 1 && result.Grade.Rows[0].UpkeepState != "not_assessed" {
		t.Errorf("the module itself was not assessed: %+v", result.Grade.Rows[0])
	}

	// When the caller grades the standard library and the scan did not run, the grade is Pending.
	stubScan(t, nil, []string{"govulncheck: network refused"}, false, nil)
	graded, err := Run(context.Background(), Options{Path: tmpDir, GradeStdlib: true, Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if graded.Grade == nil || graded.Grade.Letter != "" || graded.Grade.Pending == nil || graded.Grade.Pending.Check != "vulnerability_scan" || graded.VulnScanErr == nil {
		t.Errorf("graded stdlib, scan refused: %+v / %v, want Pending (vulnerability_scan)", graded.Grade, graded.VulnScanErr)
	}
	// The scan was attempted on the zero-dependency path, so it states its platform.
	if graded.ScanInfo == nil || !strings.Contains(graded.ScanInfo.Platform, "/") {
		t.Errorf("graded.ScanInfo = %+v, want a platform for the scan that was attempted", graded.ScanInfo)
	}
	if result.ScanInfo == nil || !strings.Contains(result.ScanInfo.Platform, "/") {
		t.Errorf("the scan ran by default, so it states its platform: %+v", result.ScanInfo)
	}
}

// stubScan replaces the vulnerability scanner for one test: it returns the given findings (a copy, so a test may reuse
// them) and records its platform like the real scanner does.
func stubScan(t *testing.T, vulns map[string][]scanner.Vulnerability, warnings []string, scanned bool, err error) {
	t.Helper()
	prev := scanVulns
	t.Cleanup(func() { scanVulns = prev })
	scanVulns = func(_ context.Context, _ string, opts scanner.VulnScanOptions) (map[string][]scanner.Vulnerability, []string, bool, error) {
		if opts.Info != nil {
			*opts.Info = scanner.ScanInfo{Platform: "linux/amd64", GoVersion: "go1.26.0"}
		}
		out := map[string][]scanner.Vulnerability{}
		for k, v := range vulns {
			out[k] = append([]scanner.Vulnerability(nil), v...)
		}
		return out, warnings, scanned, err
	}
}

func writeEmptyModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module github.com/example/empty\n\ngo 1.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// F31: a module with no dependencies still runs the vulnerability scan and lists its standard-library findings (with the
// Go release note and the scan block); they are not graded without --grade-stdlib, and then a failed scan is a warning, not
// Pending. F32: a scan that did not run does not claim a standard-library scan at some Go release.
func TestRun_NoDependencies_ListsStdlibFindings(t *testing.T) {
	dir := writeEmptyModule(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	stubGitHub(t, http.StatusOK)
	stubScan(t, map[string][]scanner.Vulnerability{"stdlib": {
		{ID: "GO-2026-0002", Severity: "HIGH", Reachability: "called"},
		{ID: "GO-2026-0001", Severity: "HIGH", Reachability: "called"},
	}}, nil, true, nil)

	res, err := Run(context.Background(), Options{Path: dir, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.StdlibVulns) != 2 || res.StdlibVulns[0].ID != "GO-2026-0001" {
		t.Errorf("StdlibVulns = %+v, want the two findings listed (sorted)", res.StdlibVulns)
	}
	if res.Grade == nil || res.Grade.Letter != "A" || res.Grade.Pending != nil {
		t.Errorf("not graded by default: %+v", res.Grade)
	}
	if res.ScanInfo == nil {
		t.Error("the scan block is missing")
	}
	var noted bool
	for _, n := range res.Grade.Notes {
		if strings.Contains(n, "was scanned at") && strings.Contains(n, "listed, not graded") {
			noted = true
		}
	}
	if !noted {
		t.Errorf("no note naming the Go release the standard library was scanned at: %v", res.Grade.Notes)
	}

	graded, err := Run(context.Background(), Options{Path: dir, Now: now, GradeStdlib: true})
	if err != nil {
		t.Fatal(err)
	}
	if graded.Grade.Letter == "A" || graded.Grade.Letter == "" {
		t.Errorf("--grade-stdlib grades the called highs: %+v", graded.Grade)
	}

	// the scan did not run
	stubScan(t, nil, []string{"govulncheck: no network"}, false, nil)
	failed, err := Run(context.Background(), Options{Path: dir, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if failed.Grade.Pending != nil || failed.Grade.Letter != "A" {
		t.Errorf("a failed scan is Pending only under --grade-stdlib: %+v", failed.Grade)
	}
	if failed.VulnScanErr == nil {
		t.Error("the failure must still be reported in VulnScanErr")
	}
	if !strings.Contains(strings.Join(failed.ProjectScore.Warnings, "\n"), "govulncheck: no network") {
		t.Errorf("a failed scan must be a warning: %v", failed.ProjectScore.Warnings)
	}
	for _, n := range failed.Grade.Notes {
		if strings.Contains(n, "was scanned at") || strings.Contains(n, "is graded at") {
			t.Errorf("F32: a scan that did not run must not claim a standard-library scan: %q", n)
		}
	}
	failedGraded, err := Run(context.Background(), Options{Path: dir, Now: now, GradeStdlib: true})
	if err != nil {
		t.Fatal(err)
	}
	if failedGraded.Grade.Pending == nil || failedGraded.Grade.Pending.Check != "vulnerability_scan" {
		t.Errorf("--grade-stdlib with a failed scan is Pending: %+v", failedGraded.Grade)
	}
	for _, n := range failedGraded.Grade.Notes {
		if strings.Contains(n, "was scanned at") || strings.Contains(n, "is graded at") {
			t.Errorf("F32: Pending result claims a scan: %q", n)
		}
	}
}

func TestRun_OfflineHasNoScanInfo(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte("module github.com/example/empty\n\ngo 1.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	offline.Enable()
	t.Cleanup(offline.Disable)
	result, err := Run(context.Background(), Options{Path: tmpDir, Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ScanInfo != nil {
		t.Errorf("ScanInfo = %+v, want nil: no scan ran offline", result.ScanInfo)
	}
}

// TestRun_MissingGoMod confirms Run surfaces parser.FindGoMod's error
// directly rather than swallowing it — a caller (like gorisk, scanning an
// arbitrary cloned repo) needs a clear, typed-enough failure here.
func TestRun_MissingGoMod(t *testing.T) {
	tmpDir := t.TempDir() // no go.mod written
	_, err := Run(context.Background(), Options{Path: tmpDir})
	if err == nil {
		t.Fatal("Run with no go.mod present: want an error, got nil")
	}
}

func TestVulnScanFailure(t *testing.T) {
	if vulnScanFailure(nil, true, []string{"GitHub API unauthenticated"}) != nil {
		t.Error("a completed vulnerability scan is not a failure, whatever else it warned about")
	}
	if err := vulnScanFailure(nil, false, []string{"govulncheck: no go.mod file\n\nonly works with Go modules"}); err == nil || err.Error() != "govulncheck: no go.mod file" {
		t.Errorf("a scan that did not run must report its warning (first line only), got %v", err)
	}
	if err := vulnScanFailure(nil, false, nil); err == nil {
		t.Error("a scan that did not run and said nothing must still be a failure")
	}
	if vulnScanFailure(errors.New("starting govulncheck: boom"), true, nil) == nil {
		t.Error("a ScanVulns error must be reported")
	}
}

// The activity scan falls back to the GitHub commits API only with a token
// (the unauthenticated quota belongs to the maintainer scan) and never offline.
func TestActivityFallback(t *testing.T) {
	ms := scanner.NewMaintainerScanner(time.Second, "tok")
	tests := []struct {
		name    string
		token   string
		offline bool
		want    bool
	}{
		{"token, online", "tok", false, true},
		{"no token", "", false, false},
		{"token, offline", "tok", true, false},
		{"no token, offline", "", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := activityFallback(tt.token, tt.offline, ms)
			if tt.want && got != scanner.CommitLookup(ms) {
				t.Errorf("activityFallback = %v, want the maintainer scanner", got)
			}
			if !tt.want && got != nil {
				t.Errorf("activityFallback = %v, want nil", got)
			}
		})
	}
}

// TestTakeStdlibVulns verifies the stdlib entry is removed from the map and
// returned sorted by ID, and that its absence yields nil.
func TestTakeStdlibVulns(t *testing.T) {
	t.Run("sorted and removed", func(t *testing.T) {
		vulns := map[string][]scanner.Vulnerability{
			"stdlib":          {{ID: "GO-2026-0030"}, {ID: "GO-2026-0010"}, {ID: "GO-2026-0020"}},
			"example.com/dep": {{ID: "GO-2026-0001"}},
		}
		got := takeStdlibVulns(vulns)

		var ids []string
		for _, v := range got {
			ids = append(ids, v.ID)
		}
		if want := "GO-2026-0010,GO-2026-0020,GO-2026-0030"; strings.Join(ids, ",") != want {
			t.Errorf("ids = %v, want %s", ids, want)
		}
		if _, ok := vulns["stdlib"]; ok {
			t.Error("stdlib key still in the map")
		}
		if len(vulns["example.com/dep"]) != 1 {
			t.Error("dependency entries must be untouched")
		}
	})

	t.Run("absent", func(t *testing.T) {
		vulns := map[string][]scanner.Vulnerability{"example.com/dep": {{ID: "GO-2026-0001"}}}
		if got := takeStdlibVulns(vulns); got != nil {
			t.Errorf("takeStdlibVulns() = %v, want nil", got)
		}
	})
}

// The fix-date stage has one deadline for all modules together, not one per
// module: with a proxy that never answers, five modules take the stage
// timeout, not five times the per-module timeout.
func TestResolveAllFixDates_OneSharedDeadline(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	defer proxy.Close()

	published := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	vulns := map[string][]scanner.Vulnerability{}
	for i := range 5 {
		vulns[fmt.Sprintf("example.com/m%d", i)] = []scanner.Vulnerability{{ID: "GO-1", FixedVersion: "v1.0.1", FixPublishedAt: &published}}
	}
	opts := scanner.FixDateOptions{ProxyURL: proxy.URL, Timeout: 400 * time.Millisecond}

	start := time.Now()
	resolveAllFixDates(context.Background(), opts, 400*time.Millisecond, vulns)
	if d := time.Since(start); d > 1200*time.Millisecond {
		t.Errorf("fix-date stage took %v for 5 stalled modules, want about the 400ms stage deadline", d)
	}
	// A stalled proxy leaves every finding on the advisory date.
	for path, list := range vulns {
		if list[0].FixDateSource != scanner.FixDateAdvisory {
			t.Errorf("%s: FixDateSource = %q, want %q", path, list[0].FixDateSource, scanner.FixDateAdvisory)
		}
	}
}

// F37: a scan refused by the toolchain check comes back as an error, not a warning. The published warnings carry its text
// (the JSON report has no stderr), once, with and without dependencies.
func TestRun_NoDependencies_ToolchainErrorIsAPublishedWarning(t *testing.T) {
	dir := writeEmptyModule(t)
	const msg = "this unisupply was built with go1.26.9 and cannot scan code that needs go1.27; rebuild unisupply with go1.27 or newer"
	stubScan(t, nil, nil, false, errors.New(msg))
	res, err := Run(context.Background(), Options{Path: dir, Now: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, w := range res.ProjectScore.Warnings {
		if strings.Contains(w, msg) {
			n++
		}
	}
	if n != 1 {
		t.Errorf("the refusal must be in the report warnings once, found %d: %v", n, res.ProjectScore.Warnings)
	}
}

// packageErrorScan is a scan error shaped like a package-loading failure: the text starts with a blank line and a header,
// and the cause is on a line of its own.
func packageErrorScan() (*scanner.ScanError, []string) {
	text := "govulncheck: loading packages: \nThere are errors with the provided package patterns:\n\n" +
		"/p/b.go:3:6: main redeclared in this block\n/p/a.go:3:6: \tother declaration of main\n\nFor details, see https://pkg.go.dev/cmd/go.\n"
	return &scanner.ScanError{Kind: scanner.FailPermanent, Reason: scanner.ReasonMultipleMains, Err: errors.New(text)}, []string{text}
}

// A failed scan reaches the caller as the scanner's own error, with the whole cause, and the published reason is one line.
func TestRun_ScanErrorReachesTheCaller(t *testing.T) {
	dir := writeEmptyModule(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	stubGitHub(t, http.StatusOK)
	scanErr, warnings := packageErrorScan()
	stubScan(t, nil, warnings, false, scanErr)

	res, err := Run(context.Background(), Options{Path: dir, Now: now, GradeStdlib: true})
	if err != nil {
		t.Fatal(err)
	}
	var got *scanner.ScanError
	if !errors.As(res.VulnScanErr, &got) || got != scanErr {
		t.Fatalf("VulnScanErr = %v, want the scanner's *ScanError", res.VulnScanErr)
	}
	if got.Reason != scanner.ReasonMultipleMains || got.Kind != scanner.FailPermanent || !strings.Contains(got.Err.Error(), "b.go:3:6: main redeclared") {
		t.Errorf("the cause was lost: %+v", got)
	}
	if res.Grade.Pending == nil || res.Grade.Pending.Check != "vulnerability_scan" {
		t.Fatalf("Grade = %+v, want Pending (vulnerability_scan)", res.Grade)
	}
	if want := "the vulnerability scan did not run: multiple_mains: /p/b.go:3:6: main redeclared in this block"; res.Grade.Pending.Reason != want {
		t.Errorf("pending reason = %q, want %q", res.Grade.Pending.Reason, want)
	}
	// the scanner's warning is in the report whole, and the failure is not said a second time
	var said, failed int
	for _, w := range res.ProjectScore.Warnings {
		if w == warnings[0] {
			said++
		}
		if strings.HasPrefix(w, "Vulnerability scan failed") {
			failed++
		}
	}
	if said != 1 || failed != 0 {
		t.Errorf("report warnings = %q, want the scanner's warning once and no second line for the failure", res.ProjectScore.Warnings)
	}
}

// The same on the path with dependencies, where the scan runs after the dependency graph is resolved.
func TestRun_ScanErrorWithDependencies(t *testing.T) {
	dir := t.TempDir()
	gomod := "module github.com/example/app\n\ngo 1.25\n\nrequire github.com/example/dep v1.0.0\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
		t.Fatal(err)
	}
	stubGitHub(t, http.StatusOK)
	scanErr, warnings := packageErrorScan()
	stubScan(t, nil, warnings, false, scanErr)

	res, err := Run(context.Background(), Options{Path: dir, DirectOnly: true, Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	var got *scanner.ScanError
	if !errors.As(res.VulnScanErr, &got) || got != scanErr {
		t.Fatalf("VulnScanErr = %v, want the scanner's *ScanError", res.VulnScanErr)
	}
	if res.Grade.Pending == nil || !strings.HasSuffix(res.Grade.Pending.Reason, "multiple_mains: /p/b.go:3:6: main redeclared in this block") || strings.Contains(res.Grade.Pending.Reason, "\n") {
		t.Errorf("Pending = %+v, want one line naming the cause", res.Grade.Pending)
	}
}

// A scan error that carries no warning (a refused toolchain) is still said once in the report warnings, in one line.
func TestRun_ScanErrorWithoutWarning(t *testing.T) {
	dir := writeEmptyModule(t)
	stubGitHub(t, http.StatusOK)
	stubScan(t, nil, nil, false, &scanner.ScanError{Kind: scanner.FailPermanent, Reason: scanner.ReasonNeedsNewerGo, Err: errors.New("this unisupply was built with go1.26.9 and cannot scan code that needs go1.99")})

	res, err := Run(context.Background(), Options{Path: dir, Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	want := "Vulnerability scan failed: needs_newer_go: this unisupply was built with go1.26.9 and cannot scan code that needs go1.99"
	if len(res.ProjectScore.Warnings) != 1 || res.ProjectScore.Warnings[0] != want {
		t.Errorf("report warnings = %q, want %q", res.ProjectScore.Warnings, want)
	}
}

// The progress output says a failed scan once: by the scanner's warning when it carries the cause (a package-loading
// failure), else by the "Vulnerability scan failed" line (a refused toolchain, which has no warning).
func TestRun_ScanFailureIsWarnedOnce(t *testing.T) {
	toolchainErr := &scanner.ScanError{Kind: scanner.FailPermanent, Reason: scanner.ReasonNeedsNewerGo, Err: errors.New("this unisupply was built with go1.26.9 and cannot scan code that needs go1.99")}
	pkgErr, pkgWarnings := packageErrorScan()
	tests := []struct {
		name     string
		err      error
		warnings []string
		// want is the number of progress warnings that name the cause, and failed how many of them are the runner's
		// own "Vulnerability scan failed" line.
		cause        string
		want, failed int
	}{
		{"package error", pkgErr, pkgWarnings, "main redeclared in this block", 1, 0},
		{"refused toolchain", toolchainErr, nil, "cannot scan code that needs go1.99", 1, 1},
	}
	for _, withDeps := range []bool{false, true} {
		for _, tc := range tests {
			t.Run(fmt.Sprintf("%s/deps=%v", tc.name, withDeps), func(t *testing.T) {
				dir := writeEmptyModule(t)
				if withDeps {
					gomod := "module github.com/example/app\n\ngo 1.25\n\nrequire github.com/example/dep v1.0.0\n"
					if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				stubGitHub(t, http.StatusOK)
				stubScan(t, nil, tc.warnings, false, tc.err)
				rep := &recordingReporter{}
				ctx := progress.WithReporter(context.Background(), rep)

				if _, err := Run(ctx, Options{Path: dir, DirectOnly: true, Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}); err != nil {
					t.Fatal(err)
				}
				var said, failed int
				for _, w := range rep.warnings {
					if strings.Contains(w, tc.cause) {
						said++
						if strings.HasPrefix(w, "Vulnerability scan failed") {
							failed++
						}
					}
				}
				if said != tc.want || failed != tc.failed {
					t.Errorf("progress warnings = %q, want the cause %d time(s), %d by the failure line", rep.warnings, tc.want, tc.failed)
				}
			})
		}
	}
}

// Run's own early failures are scan errors too, so a caller has one type to branch on, and what they wrap is still there.
func TestRun_EarlyFailuresAreScanErrors(t *testing.T) {
	_, err := Run(context.Background(), Options{Path: t.TempDir()})
	var se *scanner.ScanError
	if !errors.As(err, &se) || se.Reason != scanner.ReasonNoGoMod || se.Kind != scanner.FailPermanent {
		t.Errorf("no go.mod: err = %v, want a permanent no_go_mod ScanError", err)
	}
	if err != nil && !strings.Contains(err.Error(), "no go.mod found in") {
		t.Errorf("err = %q, want FindGoMod's text kept", err)
	}

	_, err = Run(context.Background(), Options{Path: filepath.Join(t.TempDir(), "missing")})
	if !errors.As(err, &se) || se.Reason != scanner.ReasonNoGoMod || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing path: err = %v, want a no_go_mod ScanError that still wraps fs.ErrNotExist", err)
	}
}

func TestAppendScanFailure(t *testing.T) {
	if got := appendScanFailure(nil, nil, nil); len(got) != 0 {
		t.Errorf("no failure, no warning: %v", got)
	}
	got := appendScanFailure([]string{"a"}, nil, errors.New("boom\nsecond line"))
	if len(got) != 2 || got[1] != "Vulnerability scan failed: boom" {
		t.Errorf("%v", got)
	}
	// the failure derived from a warning is not said twice
	got = appendScanFailure(nil, []string{"govulncheck: x\ndetail"}, errors.New("govulncheck: x"))
	if len(got) != 1 {
		t.Errorf("%v", got)
	}
}

// A panic on Run's own goroutine is a scan failure for the caller, not the end of its process.
func TestRun_PanicInTheScanIsAScanError(t *testing.T) {
	dir := writeEmptyModule(t)
	stubGitHub(t, http.StatusOK)
	prev := scanVulns
	t.Cleanup(func() { scanVulns = prev })
	scanVulns = func(context.Context, string, scanner.VulnScanOptions) (map[string][]scanner.Vulnerability, []string, bool, error) {
		panic("boom in the scan")
	}

	res, err := Run(context.Background(), Options{Path: dir, Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	if res != nil {
		t.Errorf("Result = %+v, want nil", res)
	}
	var se *scanner.ScanError
	if !errors.As(err, &se) || se.Reason != scanner.ReasonInternalPanic || se.Kind != scanner.FailPermanent {
		t.Fatalf("err = %v, want a permanent internal_panic ScanError", err)
	}
	if got, want := se.Summary(), "internal_panic: panic: boom in the scan"; got != want {
		t.Errorf("Summary() = %q, want %q", got, want)
	}
	// the stack is kept whole, top frames included: it names the function that panicked
	if text := se.Err.Error(); !strings.HasPrefix(text, "panic: boom in the scan\n") || !strings.Contains(text, "TestRun_PanicInTheScanIsAScanError") {
		t.Errorf("Err = %q, want the panic value and the stack of the panic site", text)
	}
}

// A panic in one of the scanners' worker goroutines, which no recover in Run could catch, fails the scan the same way,
// and the error carries the worker's stack. The panic comes from the HTTP transport the module-proxy lookups use.
func TestRun_PanicInAWorkerGoroutineIsAScanError(t *testing.T) {
	dir := t.TempDir()
	gomod := "module github.com/example/app\n\ngo 1.25\n\nrequire github.com/example/dep v1.0.0\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
		t.Fatal(err)
	}
	stubScan(t, nil, nil, true, nil)
	original := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		panic("boom in a lookup")
	})
	t.Cleanup(func() { http.DefaultTransport = original })

	res, err := Run(context.Background(), Options{Path: dir, DirectOnly: true, Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
	if res != nil {
		t.Errorf("Result = %+v, want nil", res)
	}
	var se *scanner.ScanError
	if !errors.As(err, &se) || se.Reason != scanner.ReasonInternalPanic {
		t.Fatalf("err = %v, want an internal_panic ScanError", err)
	}
	if got, want := se.Summary(), "internal_panic: panic: boom in a lookup"; got != want {
		t.Errorf("Summary() = %q, want %q", got, want)
	}
	if text := se.Err.Error(); !strings.Contains(text, "MaintenanceScanner") {
		t.Errorf("Err = %q, want the stack of the worker goroutine", text)
	}
}
