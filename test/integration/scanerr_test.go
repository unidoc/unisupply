package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/runner"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// TestScanErr_Fixtures runs one real project per failure cause through runner.Run, under the environment gorisk forces
// on its scans, and checks that the failure comes back typed with the cause in it. The messages in the comments are
// what these fixtures produced when they were recorded; pkg/scanner's classifier tests use the same text.
//
// The tests set process environment (govulncheck runs in-process and reads it), so none of them may call t.Parallel.
func TestScanErr_Fixtures(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		// viaErr is true when Run itself fails; otherwise the failure is Result.VulnScanErr.
		viaErr bool
		reason string
		kind   scanner.FailKind
		// text must appear in the error: the cause, not just the code.
		text string
	}{
		{
			// b.go:3:6: main redeclared in this block
			name: "multiple_mains", reason: scanner.ReasonMultipleMains, kind: scanner.FailPermanent,
			text: "main redeclared in this block",
		},
		{
			// -: found packages main (a.go) and other (b.go) in <dir>
			name: "mixed_packages", reason: scanner.ReasonMixedPackages, kind: scanner.FailPermanent,
			text: "found packages main (a.go) and other (b.go) in .",
		},
		{
			// -: found packages alpha (a.go) and main (b.go) in <dir>
			name: "mixed_packages_main_last", reason: scanner.ReasonMixedPackages, kind: scanner.FailPermanent,
			text: "found packages alpha (a.go) and main (b.go) in .",
		},
		{
			// go: go.mod requires go >= 1.99 (running go 1.26.9; GOTOOLCHAIN=local)
			name: "needs_newer_go", reason: scanner.ReasonNeedsNewerGo, kind: scanner.FailPermanent,
			text: "go.mod requires go >= 1.99",
		},
		{
			// main.go:3:8: missing go.sum entry for module providing package gopkg.in/yaml.v3 (imported by ...)
			name: "missing_gosum", reason: scanner.ReasonMissingGoSum, kind: scanner.FailPermanent,
			env:  map[string]string{"GOPROXY": "off"},
			text: "missing go.sum entry for module providing package gopkg.in/yaml.v3",
		},
		{
			// main.go:3:8: gopkg.in/yaml.v3@v3.0.1: Get "http://127.0.0.1:1/...": dial tcp 127.0.0.1:1: connect: connection refused
			name: "module_fetch", reason: scanner.ReasonModuleFetch, kind: scanner.FailTransient,
			env:  map[string]string{"GOPROXY": "http://127.0.0.1:1", "GOSUMDB": "off"},
			text: "dial tcp 127.0.0.1:1",
		},
		{
			// Run fails before govulncheck: "no go.mod found in <dir>"
			name: "no_go_mod", viaErr: true, reason: scanner.ReasonNoGoMod, kind: scanner.FailPermanent,
			text: "no go.mod found in",
		},
		{
			// govulncheck: no packages matched the provided patterns. With CGO_ENABLED=0 and a non-test file that
			// imports "C", the scan says cgo_only instead (the next case).
			name: "no_packages", reason: scanner.ReasonNoPackages, kind: scanner.FailPermanent,
			text: "no packages matched the provided patterns",
		},
		{
			// the same message, but cgo is off for the scan and the only file imports "C"
			name: "cgo_only", reason: scanner.ReasonCgoOnly, kind: scanner.FailPermanent,
			text: "no packages matched the provided patterns",
		},
		{
			// -: build constraints exclude all Go files in <dir of dep_cgo>
			// The project imports a package whose only file imports "C", and cgo is off for the scan. The directory is
			// printed absolute: it is neither the project nor the module cache.
			name: "cgo_dependency", reason: scanner.ReasonCgoDependency, kind: scanner.FailPermanent,
			text: "build constraints exclude all Go files in",
		},
		{
			// -: build constraints exclude all Go files in <dir of dep_tagged>
			// The same, for a package whose only file carries a custom build tag: excluded on every platform.
			name: "build_constraints", reason: scanner.ReasonBuildConstraints, kind: scanner.FailPermanent,
			text: "build constraints exclude all Go files in",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CGO_ENABLED", "0")
			t.Setenv("GOFLAGS", "-mod=readonly -modcacherw")
			t.Setenv("GOTOOLCHAIN", "local")
			t.Setenv("GOWORK", "off")
			t.Setenv("GOMODCACHE", t.TempDir())
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			// The called pass is what type-checks the packages (see TestScanErr_AutoGradesWhatTheImportedPassCanVouchFor), and
			// the failures here are its: this test is about how they are typed, so it asks for it on every scan.
			res, err := runner.Run(context.Background(), runner.Options{
				Path: testdataPath("scanerr", tc.name), DirectOnly: directOnly, Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				CalledPass: scanner.CalledPassAlways,
			})
			failure := err
			if !tc.viaErr {
				if err != nil {
					t.Fatalf("Run: %v", err)
				}
				failure = res.VulnScanErr
			}
			var se *scanner.ScanError
			if !errors.As(failure, &se) {
				t.Fatalf("failure = %T %v, want a *scanner.ScanError", failure, failure)
			}
			if se.Reason != tc.reason || se.Kind != tc.kind {
				t.Errorf("Reason, Kind = %q, %v; want %q, %v\nErr: %v", se.Reason, se.Kind, tc.reason, tc.kind, se.Err)
			}
			if !strings.Contains(se.Err.Error(), tc.text) {
				t.Errorf("Err = %q, want it to contain the cause %q", se.Err, tc.text)
			}
			// the published text names files relative to the project, never by this machine's path
			if abs, err := filepath.Abs(testdataPath("scanerr", tc.name)); err != nil || strings.Contains(se.Err.Error(), abs) {
				t.Errorf("Err = %q, want it without the project's absolute path %q", se.Err, abs)
			}
			t.Logf("%s", se.Summary())
		})
	}
}

// TestScanErr_PendingReasonNamesTheCause checks the published reason for a failed scan: one line that says which
// error stopped the scan, where it used to end at "govulncheck: loading packages:".
func TestScanErr_PendingReasonNamesTheCause(t *testing.T) {
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("GOFLAGS", "-mod=readonly")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOWORK", "off")

	// The standard library is graded here, so a scan that did not run leaves the grade Pending.
	res, err := runner.Run(context.Background(), runner.Options{
		Path: testdataPath("scanerr", "multiple_mains"), DirectOnly: directOnly, GradeStdlib: true, CalledPass: scanner.CalledPassAlways,
		Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Grade == nil || res.Grade.Pending == nil || res.Grade.Pending.Check != "vulnerability_scan" {
		t.Fatalf("Grade = %+v, want Pending (vulnerability_scan)", res.Grade)
	}
	reason := res.Grade.Pending.Reason
	if want := ": multiple_mains: b.go:3:6: main redeclared in this block"; !strings.HasSuffix(reason, want) || strings.Contains(reason, "\n") {
		t.Errorf("pending reason = %q, want one line ending in %q: the duplicate main, without the project's path", reason, want)
	}
	// the code and the kind are their own fields: a caller deciding on a retry does not parse the reason
	if p := res.Grade.Pending; p.Code != scanner.ReasonMultipleMains || p.Kind != scanner.FailPermanent.String() {
		t.Errorf("pending code, kind = %q, %q; want %q, %q", p.Code, p.Kind, scanner.ReasonMultipleMains, scanner.FailPermanent)
	}
	if out, err := json.Marshal(res.Grade); err != nil || !strings.Contains(string(out), `"code":"multiple_mains","kind":"permanent"`) {
		t.Errorf("grade JSON = %s (%v), want the pending code and kind", out, err)
	}
}

// TestScanErr_AutoGradesWhatTheImportedPassCanVouchFor records a consequence of running the imported pass first: govulncheck's
// package level does not type-check, so a module whose packages do not compile (here two main functions in one package) is
// not a failed scan when the called pass is skipped. Nothing it imports has an advisory, so the called pass could not change
// the letter, and the grade is given from the imports, with the skipped pass said in the scan block. With --called-pass
// always the same module is a typed failure and a Pending grade (TestScanErr_Fixtures).
func TestScanErr_AutoGradesWhatTheImportedPassCanVouchFor(t *testing.T) {
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("GOFLAGS", "-mod=readonly")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOWORK", "off")

	res, err := runner.Run(context.Background(), runner.Options{
		Path: testdataPath("scanerr", "multiple_mains"), DirectOnly: directOnly,
		Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.VulnScanErr != nil || res.Grade == nil || res.Grade.Pending != nil {
		t.Fatalf("VulnScanErr = %v, Grade = %+v: want a graded scan", res.VulnScanErr, res.Grade)
	}
	if res.ScanInfo == nil || res.ScanInfo.CalledPass != scanner.CalledPassSkipped || res.ScanInfo.CalledPassReason == "" {
		t.Errorf("ScanInfo = %+v, want the called pass skipped with a reason", res.ScanInfo)
	}
}
