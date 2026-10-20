package integration_test

import (
	"context"
	"errors"
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
			text: "connection refused",
		},
		{
			// Run fails before govulncheck: "no go.mod found in <dir>"
			name: "no_go_mod", viaErr: true, reason: scanner.ReasonNoGoMod, kind: scanner.FailPermanent,
			text: "no go.mod found in",
		},
		{
			// Known gap: with CGO_ENABLED=0 a package whose only file needs cgo gives x/vuln's generic
			// "govulncheck: no packages matched the provided patterns", which a module with no Go files at all gives
			// as well. The cause cannot be read from the message, so it is not called cgo_only.
			name: "cgo_only", reason: scanner.ReasonUnknown, kind: scanner.FailPermanent,
			text: "no packages matched the provided patterns",
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

			res, err := runner.Run(context.Background(), runner.Options{
				Path: testdataPath("scanerr", tc.name), DirectOnly: directOnly, Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
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
		Path: testdataPath("scanerr", "multiple_mains"), DirectOnly: directOnly, GradeStdlib: true,
		Now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Grade == nil || res.Grade.Pending == nil || res.Grade.Pending.Check != "vulnerability_scan" {
		t.Fatalf("Grade = %+v, want Pending (vulnerability_scan)", res.Grade)
	}
	reason := res.Grade.Pending.Reason
	if strings.Contains(reason, "\n") || !strings.Contains(reason, "main redeclared in this block") {
		t.Errorf("pending reason = %q, want one line naming the duplicate main", reason)
	}
}
