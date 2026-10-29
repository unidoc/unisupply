package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeGovulncheck answers each scan level with recorded-shape output: a finding in module m is "imported" at package level
// and "called" at symbol level.
type fakeGovulncheck struct {
	severity string
	levels   []string
	failAt   string // a level that fails
}

func (f *fakeGovulncheck) run(_ context.Context, _ []string, _, level string, stdout, _ io.Writer) error {
	f.levels = append(f.levels, level)
	if level == f.failAt {
		return errors.New("govulncheck: loading packages: killed")
	}
	fmt.Fprintf(stdout, `{"osv":{"id":"GO-2026-0001","summary":"s","affected":[{"package":{"name":"example.com/dep","ecosystem":"Go"},"database_specific":{"severity":%q},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"v1.2.0"}]}]}]}}`+"\n", f.severity)
	trace := `{"module":"example.com/dep","version":"v1.1.0","package":"example.com/dep/p"}`
	if level == scanLevelSymbol {
		trace = `{"module":"example.com/dep","version":"v1.1.0","package":"example.com/dep/p","function":"Do","position":{"filename":"p.go","line":3,"column":1}},{"module":"example.com/app","package":"example.com/app","function":"main","position":{"filename":"main.go","line":5,"column":2}}`
	}
	fmt.Fprintf(stdout, `{"finding":{"osv":"GO-2026-0001","trace":[%s]}}`+"\n", trace)
	return nil
}

func scanWithFake(t *testing.T, f *fakeGovulncheck, opts VulnScanOptions) (map[string][]Vulnerability, []string, bool, error, *ScanInfo, int) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/app\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prevRun, prevFree := runGovulncheck, releaseMemory
	freed := 0
	runGovulncheck, releaseMemory = f.run, func() { freed++ }
	t.Cleanup(func() { runGovulncheck, releaseMemory = prevRun, prevFree })
	info := &ScanInfo{}
	opts.Info = info
	vulns, warnings, scanned, err := ScanVulnsWithOptions(context.Background(), dir, opts)
	return vulns, warnings, scanned, err, info, freed
}

func reachOf(vulns map[string][]Vulnerability) string {
	for _, vs := range vulns {
		for _, v := range vs {
			return v.Reachability
		}
	}
	return ""
}

func TestCalledPass_AutoSkipsWhenItCannotMatter(t *testing.T) {
	f := &fakeGovulncheck{severity: "LOW"}
	asked := 0
	vulns, _, scanned, err, info, freed := scanWithFake(t, f, VulnScanOptions{NeedsCalledPass: func(m map[string][]Vulnerability) (bool, string) {
		asked++
		if reachOf(m) != "imported" {
			t.Errorf("the test must see the imported findings, got %q", reachOf(m))
		}
		return false, "all low"
	}})
	if err != nil || !scanned {
		t.Fatalf("scanned=%v err=%v", scanned, err)
	}
	if strings.Join(f.levels, ",") != "package" || asked != 1 {
		t.Errorf("levels = %v, asked %d times", f.levels, asked)
	}
	if got := reachOf(vulns); got != "imported" {
		t.Errorf("reachability = %q, want imported", got)
	}
	if info.CalledPass != CalledPassSkipped || info.CalledPassReason != "all low" || info.CalledPassMode != "auto" {
		t.Errorf("info = %+v", info)
	}
	if freed != 1 {
		t.Errorf("memory released %d times, want once per govulncheck pass (1)", freed)
	}
}

func TestCalledPass_AutoRunsSecondPassWhenNeeded(t *testing.T) {
	f := &fakeGovulncheck{severity: "HIGH"}
	vulns, _, scanned, err, info, freed := scanWithFake(t, f, VulnScanOptions{NeedsCalledPass: func(map[string][]Vulnerability) (bool, string) {
		return true, "a high advisory"
	}})
	if err != nil || !scanned {
		t.Fatalf("scanned=%v err=%v", scanned, err)
	}
	if strings.Join(f.levels, ",") != "package,symbol" {
		t.Errorf("levels = %v", f.levels)
	}
	if got := reachOf(vulns); got != "called" {
		t.Errorf("reachability = %q, the called pass's result must replace the imported one", got)
	}
	if len(vulns["example.com/dep"]) != 1 {
		t.Errorf("one advisory expected, not one per pass: %+v", vulns)
	}
	if info.CalledPass != CalledPassRan || info.CalledPassReason != "a high advisory" {
		t.Errorf("info = %+v", info)
	}
	if freed != 2 {
		t.Errorf("memory released %d times, want 2", freed)
	}
}

func TestCalledPass_AlwaysAndNever(t *testing.T) {
	f := &fakeGovulncheck{severity: "HIGH"}
	vulns, _, _, _, info, _ := scanWithFake(t, f, VulnScanOptions{CalledPass: CalledPassAlways, NeedsCalledPass: func(map[string][]Vulnerability) (bool, string) {
		t.Error("always must not ask")
		return false, ""
	}})
	if strings.Join(f.levels, ",") != "symbol" || reachOf(vulns) != "called" || info.CalledPass != CalledPassRan || info.CalledPassMode != "always" {
		t.Errorf("always: levels %v, %q, %+v", f.levels, reachOf(vulns), info)
	}

	f = &fakeGovulncheck{severity: "CRITICAL"}
	vulns, _, _, _, info, _ = scanWithFake(t, f, VulnScanOptions{CalledPass: CalledPassNever})
	if strings.Join(f.levels, ",") != "package" || reachOf(vulns) != "imported" || info.CalledPass != CalledPassSkipped || !strings.Contains(info.CalledPassReason, "turned off") {
		t.Errorf("never: levels %v, %q, %+v", f.levels, reachOf(vulns), info)
	}
}

func TestCalledPass_NoPredicateKeepsOldBehaviour(t *testing.T) {
	f := &fakeGovulncheck{severity: "LOW"}
	vulns, _, _, _, info, _ := scanWithFake(t, f, VulnScanOptions{})
	if strings.Join(f.levels, ",") != "symbol" || reachOf(vulns) != "called" || info.CalledPass != CalledPassRan {
		t.Errorf("levels %v, %q, %+v", f.levels, reachOf(vulns), info)
	}
}

// A called pass that fails after the imported pass succeeded is a failed scan: the imported findings must not stand in for it.
func TestCalledPass_SecondPassFailureIsAFailedScan(t *testing.T) {
	f := &fakeGovulncheck{severity: "HIGH", failAt: scanLevelSymbol}
	_, warnings, scanned, err, info, _ := scanWithFake(t, f, VulnScanOptions{NeedsCalledPass: func(map[string][]Vulnerability) (bool, string) { return true, "x" }})
	if scanned || err == nil {
		t.Fatalf("scanned=%v err=%v, want a failed scan", scanned, err)
	}
	var se *ScanError
	if !errors.As(err, &se) {
		t.Errorf("want a typed ScanError, got %T", err)
	}
	if info.CalledPass == CalledPassSkipped {
		t.Errorf("the called pass was not skipped, it failed: %+v", info)
	}
	if len(warnings) == 0 {
		t.Error("the failure must be in the warnings")
	}
}

func TestCalledPass_FirstPassFailureStops(t *testing.T) {
	f := &fakeGovulncheck{severity: "HIGH", failAt: scanLevelPackage}
	_, _, scanned, err, _, _ := scanWithFake(t, f, VulnScanOptions{NeedsCalledPass: func(map[string][]Vulnerability) (bool, string) {
		t.Error("must not ask after a failed pass")
		return true, ""
	}})
	if scanned || err == nil || strings.Join(f.levels, ",") != "package" {
		t.Errorf("scanned=%v err=%v levels=%v", scanned, err, f.levels)
	}
}

func TestParseCalledPassMode(t *testing.T) {
	for in, want := range map[string]CalledPassMode{"": CalledPassAuto, "auto": CalledPassAuto, " Always ": CalledPassAlways, "never": CalledPassNever} {
		if got, err := ParseCalledPassMode(in); err != nil || got != want {
			t.Errorf("%q: %v, %v", in, got, err)
		}
	}
	if _, err := ParseCalledPassMode("sometimes"); err == nil {
		t.Error("want an error")
	}
}
