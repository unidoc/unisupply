package runner

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/facts"
	"github.com/unidoc/unisupply/pkg/grade"
	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// recordNetwork replaces http.DefaultTransport with one that answers every request 404 and records its URL, headers and body.
func recordNetwork(t *testing.T) func() string {
	t.Helper()
	var mu sync.Mutex
	var all []string
	prev := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(r.Body)
		}
		mu.Lock()
		all = append(all, r.Method+" "+r.URL.String()+"\n"+headerDump(r.Header)+"\n"+string(body))
		mu.Unlock()
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}, Request: r}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = prev })
	return func() string { mu.Lock(); defer mu.Unlock(); return strings.Join(all, "\n---\n") }
}

func headerDump(h http.Header) string {
	var b bytes.Buffer
	_ = h.Write(&b)
	return b.String()
}

// privateAnalysis is a stored analysis by hand: one public and two private dependencies. Grade needs no module directory.
func privateAnalysis(selfPath string) *Analysis {
	dep := func(path string) *resolver.Dependency {
		return &resolver.Dependency{Module: parser.Module{Path: path, Version: "v1.0.0"}, Direct: true, UsedBy: []string{selfPath}}
	}
	return &Analysis{
		SchemaVersion: AnalysisSchemaVersion, AnalysedAt: gradeDate,
		GoMod:     &parser.GoMod{ModulePath: selfPath, GoVersion: "1.25"},
		Graph:     &resolver.Graph{Root: selfPath, Dependencies: map[string]*resolver.Dependency{"example.org/pub": dep("example.org/pub"), "acme.example/secret": dep("acme.example/secret"), "acme.example/team/lib/v2": dep("acme.example/team/lib/v2")}},
		Integrity: &scanner.IntegrityReport{}, VulnScan: VulnScanOutcome{Scanned: true},
	}
}

// No request, to any host, carries a private module's path; public modules are still looked up.
func TestGrade_PrivateModulePathsAreInNoRequest(t *testing.T) {
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOPROXY", "")
	dump := recordNetwork(t)
	opts := Options{PrivatePatterns: []string{"acme.example"}, Timeout: time.Second, TrustIndexURL: ""}
	// the module itself is private too, and a version is given: its status and advisories are not looked up either
	an := privateAnalysis("acme.example/app")
	opts.SelfVersion = "v0.3.0"
	opts.ResponseHistory = true

	if _, err := Grade(context.Background(), an, nil, gradeDate, opts); err != nil {
		t.Fatal(err)
	}
	got := dump()
	for _, leak := range []string{"acme.example", "acme%2eexample", "secret", "team/lib", "team%2Flib"} {
		if strings.Contains(strings.ToLower(got), strings.ToLower(leak)) {
			t.Fatalf("%q is in an outbound request:\n%s", leak, got)
		}
	}
	if !strings.Contains(got, "example.org/pub") {
		t.Errorf("the public module must still be looked up; requests:\n%s", got)
	}

	// the same with the environment's GOPRIVATE, and a public self module with a version: it is looked up, the private ones not
	t.Setenv("GOPRIVATE", "acme.example")
	dump2 := recordNetwork(t)
	opts = Options{Timeout: time.Second, SelfVersion: "v0.3.0"}
	if _, err := Grade(context.Background(), privateAnalysis("github.com/example/app"), nil, gradeDate, opts); err != nil {
		t.Fatal(err)
	}
	got = dump2()
	if strings.Contains(got, "acme.example") || !strings.Contains(got, "github.com/example/app") || !strings.Contains(got, "example.org/pub") {
		t.Errorf("requests:\n%s", got)
	}
}

type spyStore struct {
	facts.Store
	mu   sync.Mutex
	keys []string
}

func (s *spyStore) note(k string) { s.mu.Lock(); s.keys = append(s.keys, k); s.mu.Unlock() }
func (s *spyStore) GetModule(ctx context.Context, p, v string) (*facts.Module, bool, error) {
	s.note("GetModule " + p)
	return s.Store.GetModule(ctx, p, v)
}
func (s *spyStore) PutModule(ctx context.Context, m *facts.Module) error {
	s.note("PutModule " + m.Path)
	return s.Store.PutModule(ctx, m)
}
func (s *spyStore) GetFix(ctx context.Context, m, v string) (*facts.Fix, bool, error) {
	s.note("GetFix " + m)
	return s.Store.GetFix(ctx, m, v)
}
func (s *spyStore) PutFix(ctx context.Context, f *facts.Fix) error {
	s.note("PutFix " + f.Module)
	return s.Store.PutFix(ctx, f)
}
func (s *spyStore) GetAdvisory(ctx context.Context, id string) (*facts.Advisory, bool, error) {
	s.note("GetAdvisory " + id)
	return s.Store.GetAdvisory(ctx, id)
}
func (s *spyStore) PutAdvisory(ctx context.Context, a *facts.Advisory) error {
	s.note("PutAdvisory " + a.ID)
	return s.Store.PutAdvisory(ctx, a)
}

// A private module reaches the facts store neither by Get nor by Put (findings and fix dates included), is not what makes the
// grade Pending, and is marked private in the grade, with a note.
func TestGrade_PrivateModuleIsNotAskedOfTheStoreAndDoesNotMakeTheGradePending(t *testing.T) {
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOPROXY", "")
	recordNetwork(t)
	an := privateAnalysis("github.com/example/app")
	an.Vulns = map[string][]scanner.Vulnerability{
		"acme.example/secret": {{ID: "GO-2025-0100", Severity: "LOW", Reachability: "imported", FixedVersion: "v1.1.0"}},
		"example.org/pub":     {{ID: "GO-2025-0101", Severity: "LOW", Reachability: "imported", FixedVersion: "v1.1.0"}},
	}
	mem := facts.NewMemory()
	ctx := context.Background()
	// the public module's status is in the store, so only the private one could make the grade Pending
	_ = mem.PutModule(ctx, &facts.Module{Path: "example.org/pub", Version: "v1.0.0", FetchedAt: gradeDate,
		Info: scanner.MaintenanceInfo{ArchivedCheck: scanner.ArchivedChecked, LastRelease: gradeDate.AddDate(0, -2, 0), LatestVersion: "v1.0.0"}})
	_ = mem.PutFix(ctx, &facts.Fix{Module: "example.org/pub", Version: "v1.1.0", ReleasedAt: gradeDate.AddDate(0, 0, -3), Source: "module_proxy", RequiresGo: "1.21", FetchedAt: gradeDate})
	spy := &spyStore{Store: mem}

	res, err := Grade(ctx, an, spy, gradeDate, Options{PrivatePatterns: []string{"acme.example"}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range spy.keys {
		if strings.Contains(k, "acme.example") {
			t.Errorf("the facts store was called for a private module: %s", k)
		}
	}
	if len(spy.keys) == 0 {
		t.Error("the spy saw no call at all: the public module must still go through the store")
	}
	if res.Grade.Pending != nil || res.Grade.Letter == "" {
		t.Fatalf("a private module must not make the grade Pending: %+v", res.Grade.Pending)
	}
	var found bool
	for _, r := range res.Grade.Rows {
		switch r.Module {
		case "acme.example/secret":
			found = true
			if !r.Private || r.UpkeepState != grade.StateNotAssessed || r.UpkeepMissed || r.ArchivedUnread {
				t.Errorf("private row = %+v", r)
			}
			// its finding is graded like any other's: imported low is not above A/B here, and it is listed
			if len(r.Findings) != 1 {
				t.Errorf("findings = %+v", r.Findings)
			}
		case "example.org/pub":
			if r.Private {
				t.Error("a public module is not private")
			}
		}
	}
	if !found {
		t.Fatal("the private module has no row")
	}
	notes := strings.Join(res.Grade.Notes, "\n")
	if !strings.Contains(notes, "2 private modules were not looked up") {
		t.Errorf("notes = %q", notes)
	}
	// nothing about it in the maintenance data, and never "not archived"
	for _, m := range []string{"acme.example/secret", "acme.example/team/lib/v2"} {
		for _, d := range res.ProjectScore.Dependencies {
			if d.Module == m && d.Maintenance != nil {
				t.Errorf("%s has maintenance data: %+v", m, d.Maintenance)
			}
		}
	}
}

// With nothing private the behaviour is as before: the same graph with no patterns looks every module up and a lookup that fails
// makes the grade Pending.
func TestGrade_WithoutPrivatePatternsEveryModuleIsLookedUp(t *testing.T) {
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOPROXY", "")
	dump := recordNetwork(t)
	res, err := Grade(context.Background(), privateAnalysis("github.com/example/app"), nil, gradeDate, Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dump(), "acme.example/secret") || res.Grade.Pending == nil || res.Grade.Pending.Check != "dependency_maintenance" {
		t.Errorf("pending = %+v", res.Grade.Pending)
	}
	for _, r := range res.Grade.Rows {
		if r.Private {
			t.Errorf("%s marked private with no patterns", r.Module)
		}
	}
}
