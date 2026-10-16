package grade

import (
	"fmt"
	"sort"
	"strings"
)

// pendingFor says whether the grade must be Pending: no letter, the reason, and what is known anyway. A check that failed
// is never read as a clean result. The grade is Pending (Pending.Check names which) if any of these did not run:
//
//  1. vulnerability_scan: the vulnerability scan;
//  2. scan_incomplete: the scan as a whole (a timeout or interruption);
//  3. checksum: `go mod verify`, when a mismatch (F) could still raise the letter;
//  4. known_exploited: the CISA catalog, for a reached finding with a CVE, when an F could still raise the letter;
//  5. module_advisories / module_status: the module's own advisories (the OSV lookup), or its own status (archived,
//     deprecated) when the worst upkeep score it could still get (35) would beat the worst row known so far;
//  6. dependency_maintenance: the maintenance data of a dependency, when the worst upkeep score it could still get (20, or
//     10 if it is test-only or not compiled in) would beat the worst row known so far.
//
// A module with no dependencies has no dependency check to fail; its own row still needs 5, and the vulnerability scan
// (1) runs for it only when the standard library is graded (without it there is nothing the scan could change).
func pendingFor(in *Input, rows []RowResult, score int) *Pending {
	c := in.Checks
	known := knownFacts(in, rows)
	switch {
	case c.VulnScanFailed:
		reason := "the vulnerability scan did not run"
		if c.VulnScanReason != "" {
			reason += ": " + c.VulnScanReason
		}
		return &Pending{Check: "vulnerability_scan", Reason: reason, Known: known}
	case c.ScanTimedOut:
		return &Pending{Check: "scan_incomplete", Reason: "the scan did not finish (it timed out or was interrupted), so some checks never ran", Known: known}
	case c.ChecksumUnverified && bandOf(treeFScore) > bandOf(score):
		return &Pending{Check: "checksum", Reason: "go mod verify could not complete, so a checksum mismatch cannot be ruled out", Known: known}
	case c.KEVUnchecked > 0 && bandOf(treeFScore) > bandOf(score):
		return &Pending{Check: "known_exploited", Reason: fmt.Sprintf("the known-exploited status (CISA's catalog) could not be checked for %d reached finding%s, and one on that list would grade F", c.KEVUnchecked, plural(c.KEVUnchecked, "", "s")), Known: known}
	case (c.SelfStatusFailed || in.Self.Upkeep.Missing) && bandOf(upkeepSelf) > bandOf(score):
		return &Pending{Check: "module_status", Reason: withDetail("the module's own status (archived, deprecated) could not be read", c.SelfStatusReason), Known: known}
	case c.SelfAdvisoriesFailed:
		return &Pending{Check: "module_advisories", Reason: withDetail("the lookup of the module's own advisories failed", c.SelfAdvisoriesReason), Known: known}
	}
	var missing []string
	maxPossible := 0
	for _, d := range in.Deps {
		if !d.Upkeep.Missing {
			continue
		}
		possible := upkeepDependency
		if isConfirmed(d.TestOnly) || isRefuted(d.InBuild) {
			possible = upkeepMinor
		}
		if bandOf(possible) > bandOf(score) {
			missing = append(missing, d.Module)
			if possible > maxPossible {
				maxPossible = possible
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		names := missing
		more := ""
		if len(names) > 3 {
			more = fmt.Sprintf(" and %d more", len(names)-3)
			names = names[:3]
		}
		return &Pending{Check: "dependency_maintenance", Known: known,
			Reason: fmt.Sprintf("the maintenance data of %s%s could not be read, and an archived or deprecated state (%d) would be worse than anything found so far%s", strings.Join(names, ", "), more, maxPossible, hintSuffix(c.MaintenanceHint))}
	}
	return nil
}

func withDetail(base, detail string) string {
	if detail == "" {
		return base
	}
	return base + ": " + detail
}

// knownFacts is what is known when the grade is Pending: the module's own upkeep state, and the worst row found so far.
func knownFacts(in *Input, rows []RowResult) []string {
	var out []string
	for _, r := range rows {
		if r.Self {
			switch r.UpkeepState {
			case StateArchived:
				out = append(out, "Archived")
			case StateDeprecated:
				out = append(out, "Deprecated")
			}
		}
	}
	if len(rows) > 0 && rows[0].Score > 0 && (!rows[0].UpkeepMissed || rows[0].VulnScore >= rows[0].UpkeepScore && rows[0].VulnScore > 0) {
		w := rows[0]
		who := w.Module
		if w.Self {
			who = "the module itself"
		}
		out = append(out, fmt.Sprintf("worst row so far: %s, %s", who, w.Reason))
	}
	return out
}

func hintSuffix(h string) string {
	if h = strings.TrimSpace(h); h == "" {
		return ""
	}
	return ". " + h
}
