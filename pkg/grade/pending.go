package grade

import (
	"fmt"
	"sort"
	"strings"
)

// pendingFor says whether the grade must be Pending: no letter, the reason, and what is known anyway. A check that failed
// is never read as a clean result. The module is Pending if any of these failed:
//
//  1. the vulnerability scan;
//  2. the scan as a whole (a timeout or interruption);
//  3. the module's own advisories (the OSV lookup), or its own status (archived, deprecated) when the worst upkeep score it
//     could still get (35) would beat the worst row known so far;
//  4. the maintenance data of a dependency, when the worst upkeep score it could still get (20, or 10 if it is test-only or
//     not compiled in) would beat the worst row known so far.
//
// A module with no dependencies has nothing to scan and is not Pending for that; its own row still needs 3.
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
	case c.SelfStatusFailed && upkeepSelf > score:
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
		if possible > score {
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
			Reason: fmt.Sprintf("the maintenance data of %s%s could not be read, and an archived or deprecated state (%d) would be worse than anything found so far", strings.Join(names, ", "), more, maxPossible)}
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
	if len(rows) > 0 && rows[0].Score > 0 && !rows[0].UpkeepMissed {
		w := rows[0]
		who := w.Module
		if w.Self {
			who = "the module itself"
		}
		out = append(out, fmt.Sprintf("worst row so far: %s, %s", who, w.Reason))
	}
	return out
}
