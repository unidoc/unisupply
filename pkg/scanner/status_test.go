package scanner

import (
	"errors"
	"testing"
)

func TestScanStatusOf(t *testing.T) {
	cases := []struct {
		name               string
		in                 StatusInput
		status, reason, kn string
	}{
		{"complete", StatusInput{Graded: true}, StatusComplete, "", ""},
		{"pending on a missing check", StatusInput{Graded: true, PendingCheck: "dependency_maintenance", PendingReason: "x\ny"}, StatusPending, "dependency_maintenance", ""},
		{"not graded", StatusInput{}, StatusPending, "not_graded", ""},
		{"interrupted flag", StatusInput{Graded: true, Interrupted: true, PendingCheck: "scan_incomplete"}, StatusInterrupted, "interrupted", ""},
		{"scan_incomplete without the flag", StatusInput{Graded: true, PendingCheck: "scan_incomplete"}, StatusInterrupted, "interrupted", ""},
		{"deadline error", StatusInput{Graded: true, PendingCheck: "vulnerability_scan",
			VulnErr: &ScanError{Kind: FailTooLarge, Reason: ReasonScanDeadline, Err: errors.New("ctx")}}, StatusInterrupted, ReasonScanDeadline, "too_large"},
		{"failed with a reason code", StatusInput{Graded: true, PendingCheck: "vulnerability_scan",
			VulnErr: &ScanError{Kind: FailPermanent, Reason: ReasonMissingGoSum, Err: errors.New("missing go.sum entry")}}, StatusFailed, ReasonMissingGoSum, "permanent"},
		{"transient failure", StatusInput{Graded: true, PendingCheck: "vulnerability_scan",
			VulnErr: &ScanError{Kind: FailTransient, Reason: ReasonModuleFetch, Err: errors.New("dial tcp")}}, StatusFailed, ReasonModuleFetch, "transient"},
		{"untyped failure", StatusInput{Graded: true, PendingCheck: "vulnerability_scan", VulnErr: errors.New("boom")}, StatusFailed, ReasonUnknown, ""},
		{"failure the letter does not need (untyped)", StatusInput{Graded: true, VulnErr: errors.New("boom")}, StatusFailed, ReasonUnknown, ""},
		{"failure with a letter", StatusInput{Graded: true, VulnErr: &ScanError{Kind: FailPermanent, Reason: ReasonNoPackages, Err: errors.New("no packages matched")}}, StatusFailed, ReasonNoPackages, "permanent"},
	}
	for _, c := range cases {
		got := ScanStatusOf(c.in)
		if got.Status != c.status || got.Reason != c.reason || got.Kind != c.kn {
			t.Errorf("%s: got %+v, want %s/%s/%s", c.name, got, c.status, c.reason, c.kn)
		}
		if got.Status != StatusComplete && got.Detail == "" {
			t.Errorf("%s: no detail", c.name)
		}
		if got.Detail != "" && got.Detail != firstLine(got.Detail) {
			t.Errorf("%s: detail is not one line: %q", c.name, got.Detail)
		}
	}
}
