package scanner

import (
	"errors"
	"strings"
)

// Values of ScanStatus.Status.
const (
	StatusComplete    = "complete"    // every check the grade needs ran
	StatusPending     = "pending"     // the scan ran, but a check the letter needs did not: there is no letter yet
	StatusInterrupted = "interrupted" // the scan's deadline passed or it was cancelled before it finished
	StatusFailed      = "failed"      // the vulnerability scan failed (there may still be a letter, when it does not rest on the scan)
)

// ScanStatus is the machine-readable outcome of a scan: whether a consumer can take the result as final. Only Status
// "complete" means the result is whole; a gate must treat every other status as "no result".
type ScanStatus struct {
	// Status is one of the Status* constants.
	Status string `json:"status"`
	// Reason is a stable code: for "failed" and "interrupted" the ScanError's Reason (scanner.Reason*, "interrupted" when the
	// scan was cancelled with no failure to name), for "pending" the check the grade is waiting for ("vulnerability_scan",
	// "dependency_maintenance", ... as in grade.Pending.Check, or "not_graded" when no grade was computed). Empty when
	// complete.
	Reason string `json:"reason,omitempty"`
	// Kind says whether a retry can help, for a failure that has a ScanError: "transient", "permanent" or "too_large".
	Kind string `json:"kind,omitempty"`
	// Detail is one sentence for a person.
	Detail string `json:"detail,omitempty"`
}

// StatusInput is what ScanStatusOf reads.
type StatusInput struct {
	// VulnErr is the vulnerability scan's failure (a *ScanError when it has a cause), nil when it ran. Any failure makes the
	// status "failed", whether or not the grade needed the scan.
	VulnErr error
	// Interrupted is true when the context ended before every scanner finished.
	Interrupted bool
	// Graded is true when a grade was computed; PendingCheck and PendingReason are its Pending check and reason, empty for
	// a grade with a letter.
	Graded                      bool
	PendingCheck, PendingReason string
}

// ScanStatusOf decides the status. The order is the order of what a consumer should do about it: an interrupted scan is
// retried with more time, a failed one by its Kind, a pending one when the missing data is available.
func ScanStatusOf(in StatusInput) ScanStatus {
	var se *ScanError
	hasSE := errors.As(in.VulnErr, &se)
	switch {
	case in.Interrupted || (hasSE && se.Reason == ReasonScanDeadline) || in.PendingCheck == "scan_incomplete":
		st := ScanStatus{Status: StatusInterrupted, Reason: "interrupted", Detail: "the scan did not finish: its time ran out or it was cancelled"}
		if hasSE {
			st.Reason, st.Kind = se.Reason, se.Kind.String()
		}
		return st
	case in.VulnErr != nil:
		st := ScanStatus{Status: StatusFailed, Reason: ReasonUnknown, Detail: firstLine(in.VulnErr.Error())}
		if hasSE {
			st.Reason, st.Kind, st.Detail = se.Reason, se.Kind.String(), firstLine(se.Summary())
		}
		return st
	case !in.Graded:
		return ScanStatus{Status: StatusPending, Reason: "not_graded", Detail: "no grade was computed"}
	case in.PendingCheck != "":
		return ScanStatus{Status: StatusPending, Reason: in.PendingCheck, Detail: firstLine(in.PendingReason)}
	}
	return ScanStatus{Status: StatusComplete}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return line
}
