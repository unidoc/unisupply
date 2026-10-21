package runner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/facts"
	"github.com/unidoc/unisupply/pkg/grade"
	"github.com/unidoc/unisupply/pkg/offline"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/vulndb"
)

var gradeDate = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// depModule writes a module with one direct dependency (not resolved over the network: DirectOnly).
func depModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gomod := "module github.com/example/app\n\ngo 1.25\n\nrequire github.com/example/dep v1.0.0\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte("github.com/example/dep v1.0.0 h1:x=\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func someFindings() map[string][]scanner.Vulnerability {
	fixed := time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)
	return map[string][]scanner.Vulnerability{
		"github.com/example/dep": {
			{ID: "GO-2025-0001", Severity: "HIGH", Reachability: "called", FixedVersion: "v1.2.0", FixPublishedAt: &fixed,
				CallPath: []string{"github.com/example/app.main", "github.com/example/dep.Do"}},
			{ID: "GO-2025-0002", Severity: "UNKNOWN", Reachability: "imported"},
		},
		"stdlib": {{ID: "GO-2025-0003", Severity: "MEDIUM", Reachability: "imported", FixedVersion: "go1.26.9"}},
	}
}

// result reduces a Result to what a report is made of, so two Results can be compared.
func result(t *testing.T, r *Result) string {
	t.Helper()
	b, err := json.Marshal(struct {
		Grade       any
		Score       any
		Vulns       any
		Stdlib      any
		VulnScanErr string
		Status      any
		Scan        any
		CI          any
		Integrity   any
		Interrupted bool
	}{r.Grade, r.ProjectScore, depVulns(r), r.StdlibVulns, errString(r.VulnScanErr), r.ScanStatus, r.ScanInfo, r.CIReport, r.IntegrityReport, r.Interrupted})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func depVulns(r *Result) any {
	out := map[string]any{}
	for _, d := range r.ProjectScore.Dependencies {
		out[d.Module] = d.Vulns
	}
	return out
}

// Run is Analyse followed by Grade: through a JSON round trip of the analysis too, as a stored analysis would be.
func TestAnalyseThenGrade_MatchesRun(t *testing.T) {
	dir := depModule(t)
	stubGitHub(t, http.StatusOK)
	stubScan(t, someFindings(), []string{"a warning"}, true, nil)
	opts := Options{Path: dir, DirectOnly: true, Now: gradeDate, SelfVersion: "v0.3.0"}

	want, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	an, err := Analyse(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Grade(context.Background(), an, nil, gradeDate, Options{Timeout: opts.Timeout})
	if err != nil {
		t.Fatal(err)
	}
	if a, b := result(t, got), result(t, want); a != b {
		t.Errorf("Grade(Analyse) differs from Run:\n%s\n%s", a, b)
	}

	// stored and read back
	raw, err := json.Marshal(an)
	if err != nil {
		t.Fatal(err)
	}
	var back Analysis
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if raw2, _ := json.Marshal(&back); string(raw2) != string(raw) || back.Identity != an.Identity || back.Identity.Key() != an.Identity.Key() {
		t.Errorf("the analysis does not survive JSON:\n%s\n%s", raw, raw2)
	}
	again, err := Grade(context.Background(), &back, nil, gradeDate, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if a, b := result(t, again), result(t, want); a != b {
		t.Errorf("Grade(stored analysis) differs from Run:\n%s\n%s", a, b)
	}
	if want.Grade.Letter == "" && want.Grade.Pending == nil {
		t.Errorf("the grade has neither a letter nor a pending check: %+v", want.Grade)
	}
}

// One analysis is graded on many days without being changed, and the grade follows the date.
func TestGrade_DoesNotChangeTheAnalysisAndFollowsTheDate(t *testing.T) {
	dir := depModule(t)
	stubGitHub(t, http.StatusOK)
	stubScan(t, someFindings(), nil, true, nil)
	an, err := Analyse(context.Background(), Options{Path: dir, DirectOnly: true, Now: gradeDate})
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(an)

	r1, err := Grade(context.Background(), an, nil, gradeDate, Options{})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Grade(context.Background(), an, nil, gradeDate.AddDate(0, 3, 0), Options{})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(an)
	if string(before) != string(after) {
		t.Errorf("grading changed the analysis:\n%s\n%s", before, after)
	}
	days := func(r *Result) int {
		for _, d := range r.ProjectScore.Dependencies {
			for _, v := range d.Vulns {
				if v.ID == "GO-2025-0001" {
					return v.DaysUnpatched
				}
			}
		}
		return -1
	}
	if d1, d2 := days(r1), days(r2); d1 != 31 || d2 != 31+90 {
		t.Errorf("days unpatched = %d and %d on the two dates, want 31 and 121", d1, d2)
	}
}

func TestGrade_RefusesWhatItCannotRead(t *testing.T) {
	if _, err := Grade(context.Background(), nil, nil, gradeDate, Options{}); err == nil {
		t.Error("nil analysis")
	}
	dir := depModule(t)
	stubGitHub(t, http.StatusOK)
	stubScan(t, nil, nil, true, nil)
	an, err := Analyse(context.Background(), Options{Path: dir, DirectOnly: true, Now: gradeDate})
	if err != nil {
		t.Fatal(err)
	}
	an.SchemaVersion = 99
	if _, err := Grade(context.Background(), an, nil, gradeDate, Options{}); err == nil || !strings.Contains(err.Error(), "schema version 99") {
		t.Errorf("err = %v", err)
	}
	an.SchemaVersion = AnalysisSchemaVersion
	if _, err := Grade(context.Background(), an, nil, gradeDate, Options{RequireGithubToken: true}); !errors.Is(err, ErrGithubTokenPrecondition) {
		t.Errorf("err = %v, want the token precondition", err)
	}
}

func TestAnalysis_FailedScanIsRecordedAndGradedPending(t *testing.T) {
	dir := depModule(t)
	stubGitHub(t, http.StatusOK)
	scanErr := &scanner.ScanError{Kind: scanner.FailTransient, Reason: scanner.ReasonModuleFetch, Err: errors.New("dial tcp 127.0.0.1:1: refused")}
	stubScan(t, nil, []string{"govulncheck: x"}, false, scanErr)
	an, err := Analyse(context.Background(), Options{Path: dir, DirectOnly: true, Now: gradeDate})
	if err != nil {
		t.Fatal(err)
	}
	if an.Complete() || an.VulnScan.Reason != scanner.ReasonModuleFetch || an.VulnScan.Kind != "transient" {
		t.Errorf("VulnScan = %+v", an.VulnScan)
	}
	if st := an.Status(); st.Status != scanner.StatusFailed || st.Reason != scanner.ReasonModuleFetch {
		t.Errorf("Status = %+v", st)
	}
	// stored and read back, the failure is still a typed error
	raw, _ := json.Marshal(an)
	var back Analysis
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	res, err := Grade(context.Background(), &back, nil, gradeDate, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var se *scanner.ScanError
	if !errors.As(res.VulnScanErr, &se) || se.Reason != scanner.ReasonModuleFetch || se.Kind != scanner.FailTransient {
		t.Fatalf("VulnScanErr = %v", res.VulnScanErr)
	}
	if res.Grade.Pending == nil || res.Grade.Pending.Check != "vulnerability_scan" || res.ScanStatus.Status != scanner.StatusFailed || res.ScanStatus.Reason != scanner.ReasonModuleFetch {
		t.Errorf("grade %+v, status %+v", res.Grade.Pending, res.ScanStatus)
	}
}

func TestIdentity_KeyFollowsWhatTheAnalysisDependsOn(t *testing.T) {
	dir := depModule(t)
	stubGitHub(t, http.StatusOK)
	stubScan(t, nil, nil, true, nil)
	var indexCalls atomic.Int32
	prev := fetchVulnIndex
	t.Cleanup(func() { fetchVulnIndex = prev })
	index := `[{"path":"github.com/example/dep","vulns":[{"id":"GO-2025-0001","modified":"2025-06-01T00:00:00Z"}]},{"path":"stdlib","vulns":[]}]`
	fetchVulnIndex = func(context.Context, time.Duration) (*vulndb.Index, error) {
		indexCalls.Add(1)
		return vulndb.ParseIndex([]byte(index))
	}
	analyse := func(o Options) *Analysis {
		t.Helper()
		o.Path, o.DirectOnly, o.Now = dir, true, gradeDate
		an, err := Analyse(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		return an
	}
	base := analyse(Options{SelfVersion: "v0.3.0"})
	id := base.Identity
	if id.Module != "github.com/example/app" || id.Version != "v0.3.0" || id.GoSumHash == "none" || id.GoModHash == "" || id.UnisupplyVersion == "" ||
		id.GoVersion == "" || id.AdvisoryFingerprint == "" || id.CalledPass != "auto" || len(id.Key()) != 64 {
		t.Fatalf("identity = %+v", id)
	}
	if got := analyse(Options{SelfVersion: "v0.3.0"}).Identity.Key(); got != id.Key() {
		t.Error("the key must be the same for the same analysis")
	}
	for name, o := range map[string]Options{
		"version":     {SelfVersion: "v0.4.0"},
		"commit":      {Commit: "abc123"},
		"called pass": {SelfVersion: "v0.3.0", CalledPass: scanner.CalledPassNever},
	} {
		if analyse(o).Identity.Key() == id.Key() {
			t.Errorf("%s must change the key", name)
		}
	}
	// the advisories of a module of the build list change
	index = strings.Replace(index, "2025-06-01", "2025-09-01", 1)
	if analyse(Options{SelfVersion: "v0.3.0"}).Identity.Key() == id.Key() {
		t.Error("a changed advisory for a module of the build list must change the key")
	}
	index = strings.Replace(index, "2025-09-01", "2025-06-01", 1)
	// go.sum
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte("github.com/example/dep v1.0.0 h1:y=\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if analyse(Options{SelfVersion: "v0.3.0"}).Identity.Key() == id.Key() {
		t.Error("go.sum must change the key")
	}

	// Run does not ask for the index, so the CLI makes no extra request
	indexCalls.Store(0)
	if _, err := Run(context.Background(), Options{Path: dir, DirectOnly: true, Now: gradeDate}); err != nil {
		t.Fatal(err)
	}
	if indexCalls.Load() != 0 {
		t.Errorf("Run read the advisory index %d times", indexCalls.Load())
	}
	// and an index that cannot be read leaves the fingerprint empty, not the analysis failed
	fetchVulnIndex = func(context.Context, time.Duration) (*vulndb.Index, error) { return nil, errors.New("down") }
	if an := analyse(Options{}); an.Identity.AdvisoryFingerprint != "" || !an.Complete() {
		t.Errorf("fingerprint %q, complete %v", an.Identity.AdvisoryFingerprint, an.Complete())
	}
}

// Grade reads facts through the store: a fresh status is used with no lookup, a newer severity and known-exploited status
// replace the analysis's, and an old fact is ignored.
func TestGrade_ReadsFactsThroughTheStore(t *testing.T) {
	dir := depModule(t)
	var requests atomic.Int32
	stubGitHub(t, http.StatusOK)
	inner := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/rate_limit" {
			requests.Add(1)
		}
		return inner.RoundTrip(r)
	})
	t.Cleanup(func() { http.DefaultTransport = inner })

	stubScan(t, map[string][]scanner.Vulnerability{"github.com/example/dep": {
		{ID: "GO-2025-0009", Severity: "UNKNOWN", Reachability: "called", Aliases: []string{"CVE-2025-1"}},
	}}, nil, true, nil)
	an, err := Analyse(context.Background(), Options{Path: dir, DirectOnly: true, Now: gradeDate.AddDate(0, 0, -1)})
	if err != nil {
		t.Fatal(err)
	}
	requests.Store(0) // the analysis asked for the advisory index; the grade must ask for nothing

	store := facts.NewMemory()
	ctx := context.Background()
	_ = store.PutModule(ctx, &facts.Module{Path: "github.com/example/dep", Version: "v1.0.0", FetchedAt: gradeDate,
		Info: scanner.MaintenanceInfo{Archived: true, ArchivedCheck: scanner.ArchivedChecked, LastRelease: gradeDate.AddDate(-3, 0, 0), LatestVersion: "v1.0.0"}})
	_ = store.PutAdvisory(ctx, &facts.Advisory{ID: "GO-2025-0009", Severity: "CRITICAL", SeveritySource: "osv", KEVChecked: true, InKEV: false, FetchedAt: gradeDate})

	res, err := Grade(ctx, an, store, gradeDate, Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("%d lookups were made although the store had the module's status", n)
	}
	found := false
	for _, r := range res.Grade.Rows {
		if r.Module == "github.com/example/dep" {
			found = true
			if r.UpkeepState != "archived" {
				t.Errorf("upkeep state = %q, want archived (from the store)", r.UpkeepState)
			}
			if len(r.Findings) != 1 || r.Findings[0].Severity != "CRITICAL" || r.Findings[0].Estimated {
				t.Errorf("finding = %+v, want the store's CRITICAL severity", r.Findings)
			}
		}
	}
	if !found {
		t.Fatalf("no row for the dependency: %+v", res.Grade.Rows)
	}
	if got := res.ProjectScore.Dependencies[0].Vulns[0].Severity; got != "CRITICAL" {
		t.Errorf("severity in the score = %q", got)
	}
	if an.Vulns["github.com/example/dep"][0].Severity != "UNKNOWN" {
		t.Error("the analysis's own severity must not change")
	}

	// an advisory fact older than the analysis is not used
	stale := facts.NewMemory()
	_ = stale.PutAdvisory(ctx, &facts.Advisory{ID: "GO-2025-0009", Severity: "LOW", FetchedAt: gradeDate.AddDate(0, 0, -5)})
	res, err = Grade(ctx, an, stale, gradeDate, Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.ProjectScore.Dependencies[0].Vulns[0].Severity; got != "UNKNOWN" {
		t.Errorf("an old fact replaced the analysis's severity: %q", got)
	}
	// the analysis's own advisory data is written back for the next grade, without forgetting what it could not learn
	if a, ok, _ := stale.GetAdvisory(ctx, "GO-2025-0009"); !ok || a.Severity != "LOW" || !a.FetchedAt.Equal(an.AnalysedAt) || a.Aliases[0] != "CVE-2025-1" {
		t.Errorf("stored advisory = %+v", a)
	}
	// a fact newer than the analysis is kept as it is
	if a, _, _ := store.GetAdvisory(ctx, "GO-2025-0009"); a.Severity != "CRITICAL" || !a.FetchedAt.Equal(gradeDate) {
		t.Errorf("the newer fact was overwritten: %+v", a)
	}
}

// scan.go_version is the Go release the standard library was matched against, and it is there even when govulncheck's own
// output did not say (a scan that failed early): the runner fills in the release it gave govulncheck.
func TestAnalyse_ScanGoVersionFallsBackToTheToolchain(t *testing.T) {
	dir := depModule(t)
	stubGitHub(t, http.StatusOK)
	prev := scanVulns
	t.Cleanup(func() { scanVulns = prev })
	scanVulns = func(_ context.Context, _ string, opts scanner.VulnScanOptions) (map[string][]scanner.Vulnerability, []string, bool, error) {
		*opts.Info = scanner.ScanInfo{Platform: "linux/amd64"} // no go_version: govulncheck said nothing
		return nil, nil, false, &scanner.ScanError{Kind: scanner.FailPermanent, Reason: scanner.ReasonNoPackages, Err: errors.New("no packages matched")}
	}
	an, err := Analyse(context.Background(), Options{Path: dir, DirectOnly: true, Now: gradeDate})
	if err != nil {
		t.Fatal(err)
	}
	if an.ToolchainVersion == "" || an.Scan == nil || an.Scan.GoVersion != an.ToolchainVersion || !strings.HasPrefix(an.Scan.GoVersion, "go1.") {
		t.Errorf("toolchain %q, scan %+v", an.ToolchainVersion, an.Scan)
	}
}

// Offline mode skips the vulnerability scan on purpose: the status is pending, not failed; a typed failure still fails.
func TestScanStatusOf_OfflineIsPendingNotFailed(t *testing.T) {
	pending := &grade.Result{Pending: &grade.Pending{Check: "vulnerability_scan", Reason: "offline"}}
	skipped := errors.New("offline — vulnerability scan skipped (no local vuln DB mirror configured)")
	typed := &scanner.ScanError{Kind: scanner.FailPermanent, Reason: scanner.ReasonNoPackages, Err: errors.New("x")}

	if st := scanStatusOf(pending, skipped, false); st.Status != scanner.StatusFailed {
		t.Errorf("online, an untyped failure is a failed scan: %+v", st)
	}
	offline.Enable()
	t.Cleanup(offline.Disable)
	if st := scanStatusOf(pending, skipped, false); st.Status != scanner.StatusPending || st.Reason != "vulnerability_scan" {
		t.Errorf("offline: %+v", st)
	}
	if st := scanStatusOf(pending, typed, false); st.Status != scanner.StatusFailed || st.Reason != scanner.ReasonNoPackages {
		t.Errorf("offline, a typed failure still fails: %+v", st)
	}
}
