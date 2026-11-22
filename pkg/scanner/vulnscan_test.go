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
	// notCalled makes the symbol-level pass report the package as imported but its vulnerable function as not called
	notCalled bool
}

func (f *fakeGovulncheck) run(_ context.Context, _ []string, _, level string, stdout, _ io.Writer) error {
	f.levels = append(f.levels, level)
	if level == f.failAt {
		return errors.New("govulncheck: loading packages: killed")
	}
	fmt.Fprintf(stdout, `{"osv":{"id":"GO-2026-0001","summary":"s","affected":[{"package":{"name":"example.com/dep","ecosystem":"Go"},"database_specific":{"severity":%q},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"v1.2.0"}]}]}]}}`+"\n", f.severity)
	trace := `{"module":"example.com/dep","version":"v1.1.0","package":"example.com/dep/p"}`
	if level == scanLevelSymbol && !f.notCalled {
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
	// The memory is released by the in-process run, not by pass: the stub stands in for that run, so it releases too.
	inProcess := func(ctx context.Context, env []string, dir, level string, stdout, stderr io.Writer) error {
		defer releaseMemory()
		return f.run(ctx, env, dir, level, stdout, stderr)
	}
	runGovulncheck, releaseMemory = inProcess, func() { freed++ }
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

func checkedOf(vulns map[string][]Vulnerability) (checked, total int) {
	for _, vs := range vulns {
		for _, v := range vs {
			total++
			if v.CallPathChecked {
				checked++
			}
		}
	}
	return checked, total
}

// call_path_checked is true exactly when the findings come from a finished called pass: an imported finding of a skipped
// called pass may still be called, while one the called pass left at imported is govulncheck's verdict.
func TestCalledPass_CallPathChecked(t *testing.T) {
	for _, c := range []struct {
		name string
		fake fakeGovulncheck
		opts VulnScanOptions
		want bool
	}{
		{"auto, skipped", fakeGovulncheck{severity: "LOW"}, VulnScanOptions{NeedsCalledPass: func(map[string][]Vulnerability) (bool, string) { return false, "low" }}, false},
		{"auto, ran", fakeGovulncheck{severity: "HIGH"}, VulnScanOptions{NeedsCalledPass: func(map[string][]Vulnerability) (bool, string) { return true, "high" }}, true},
		{"auto, ran, not called", fakeGovulncheck{severity: "HIGH", notCalled: true}, VulnScanOptions{NeedsCalledPass: func(map[string][]Vulnerability) (bool, string) { return true, "high" }}, true},
		{"always", fakeGovulncheck{severity: "LOW"}, VulnScanOptions{CalledPass: CalledPassAlways}, true},
		{"never", fakeGovulncheck{severity: "CRITICAL"}, VulnScanOptions{CalledPass: CalledPassNever}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := c.fake
			if c.opts.NeedsCalledPass != nil {
				needs := c.opts.NeedsCalledPass
				c.opts.NeedsCalledPass = func(m map[string][]Vulnerability) (bool, string) {
					if n, _ := checkedOf(m); n != 0 {
						t.Error("the imported pass's findings must not read as checked")
					}
					return needs(m)
				}
			}
			vulns, _, scanned, err, _, _ := scanWithFake(t, &f, c.opts)
			if err != nil || !scanned {
				t.Fatalf("scanned=%v err=%v", scanned, err)
			}
			checked, total := checkedOf(vulns)
			if total == 0 || (checked == total) != c.want || (checked == 0) == c.want {
				t.Errorf("%d of %d findings checked (reachability %q), want all %v", checked, total, reachOf(vulns), c.want)
			}
		})
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

// govulncheckEnvOf runs ScanVulnsWithOptions with a fake go that reports projectGo, and returns the environment that reached
// govulncheck (the last one, when it ran twice) and the warnings. inherited is the GOVERSION of unisupply's own environment;
// setInherited false leaves it unset.
func govulncheckEnvOf(t *testing.T, projectGo, inherited string, setInherited bool) (env, warnings []string) {
	t.Helper()
	dir := t.TempDir()
	script := fmt.Sprintf("#!/bin/sh\necho '{\"GOVERSION\":%q,\"GOROOT\":\"/nonexistent\"}'\n", projectGo)
	if err := os.WriteFile(filepath.Join(dir, "go"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	// t.Setenv records the old value and restores it at the end; the Unsetenv that follows leaves it absent meanwhile.
	t.Setenv("GOVERSION", inherited)
	if !setInherited {
		if err := os.Unsetenv("GOVERSION"); err != nil {
			t.Fatal(err)
		}
	}
	prevBuilt := builtWithGo
	t.Cleanup(func() { builtWithGo = prevBuilt })
	builtWithGo = func() string { return "go1.26.9" }
	prevRun := runGovulncheck
	t.Cleanup(func() { runGovulncheck = prevRun })
	runGovulncheck = func(_ context.Context, e []string, _, _ string, _, _ io.Writer) error {
		env = e
		return nil
	}

	// The stub prints nothing, so the scan ends with "govulncheck produced no output"; the env and the warnings are what count.
	_, warnings, _, _ = ScanVulnsWithOptions(context.Background(), t.TempDir(), VulnScanOptions{})
	if env == nil {
		t.Fatal("govulncheck was not run")
	}
	return env, warnings
}

// goVersionEntries are the GOVERSION= entries of env, in order.
func goVersionEntries(env []string) []string {
	var out []string
	for _, e := range env {
		if strings.HasPrefix(e, "GOVERSION=") {
			out = append(out, e)
		}
	}
	return out
}

func hasGoVersionWarning(warnings []string) string {
	for _, w := range warnings {
		if strings.HasPrefix(w, "GOVERSION=") {
			return w
		}
	}
	return ""
}

// The project's Go reaches govulncheck as its GOVERSION, so standard-library matching does not follow the directory
// unisupply was launched from.
func TestScanVulns_PassesProjectGOVERSION(t *testing.T) {
	env, warnings := govulncheckEnvOf(t, "go1.26.5", "", false)
	if got := goVersionEntries(env); len(got) != 1 || got[0] != "GOVERSION=go1.26.5" {
		t.Errorf("GOVERSION entries = %v, want exactly [GOVERSION=go1.26.5]", got)
	}
	if w := hasGoVersionWarning(warnings); w != "" {
		t.Errorf("unexpected warning %q", w)
	}
}

// A GOVERSION in the environment that differs from the project's is kept (the user's setting wins) and said aloud.
func TestScanVulns_InheritedGOVERSIONDiffers(t *testing.T) {
	env, warnings := govulncheckEnvOf(t, "go1.26.5", "go1.20.0", true)
	got := goVersionEntries(env)
	if len(got) == 0 || got[len(got)-1] != "GOVERSION=go1.20.0" {
		t.Errorf("GOVERSION entries = %v, want the last to be GOVERSION=go1.20.0", got)
	}
	want := "GOVERSION=go1.20.0 is set in the environment and differs from the project's Go (go1.26.5); " +
		"standard-library vulnerabilities are matched against go1.20.0. Unset GOVERSION to match the project's Go."
	if w := hasGoVersionWarning(warnings); w != want {
		t.Errorf("warning = %q, want %q (warnings: %v)", w, want, warnings)
	}
}

// An empty GOVERSION= would send govulncheck to `go env` in the launch directory: it counts as unset.
func TestScanVulns_InheritedEmptyGOVERSION(t *testing.T) {
	env, warnings := govulncheckEnvOf(t, "go1.26.5", "", true)
	got := goVersionEntries(env)
	if len(got) != 1 || got[0] != "GOVERSION=go1.26.5" {
		t.Errorf("GOVERSION entries = %v, want exactly [GOVERSION=go1.26.5]", got)
	}
	if w := hasGoVersionWarning(warnings); w != "" {
		t.Errorf("unexpected warning %q", w)
	}
}

// The same value as the project's is kept and is no news.
func TestScanVulns_InheritedGOVERSIONEqual(t *testing.T) {
	env, warnings := govulncheckEnvOf(t, "go1.26.5", "go1.26.5", true)
	if got := goVersionEntries(env); len(got) != 1 || got[0] != "GOVERSION=go1.26.5" {
		t.Errorf("GOVERSION entries = %v, want exactly [GOVERSION=go1.26.5]", got)
	}
	if w := hasGoVersionWarning(warnings); w != "" {
		t.Errorf("unexpected warning %q", w)
	}
}
