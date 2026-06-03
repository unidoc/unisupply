package scorer

import "fmt"

// TimeBomb represents a dependency that poses an undeniable, immediate risk
// regardless of overall scoring. Each entry appears in the report even when
// the headline score already reflects it — the goal is undeniable visibility.
type TimeBomb struct {
	// Kind is one of "archived" or "critical_cve".
	Kind string
	// Module is the module path of the affected dependency.
	Module string
	// Detail is a human-readable description of the risk (e.g. "archived 129 months"
	// or "GO-2024-1234 (CRITICAL, called)").
	Detail string
}

// CollectTimeBombs returns all time-bomb entries for the given project score.
// It collects:
//   - Any non-test dependency that is archived.
//   - Any CRITICAL CVE on a non-test dependency, deduped by CVE ID.
//
// The returned slice is always non-nil; callers may check len without a nil guard.
func CollectTimeBombs(ps *ProjectScore) []TimeBomb {
	bombs := make([]TimeBomb, 0)
	seenCVE := make(map[string]bool)

	for _, dep := range ps.Dependencies {
		// Skip confirmed test-only dependencies.
		if dep.IsTestOnly != nil && *dep.IsTestOnly {
			continue
		}

		// Archived check.
		if dep.Maintenance != nil && dep.Maintenance.Archived {
			detail := "archived"
			if dep.Maintenance.MonthsSinceRelease > 0 {
				detail = fmt.Sprintf("archived %d months", dep.Maintenance.MonthsSinceRelease)
			}
			bombs = append(bombs, TimeBomb{
				Kind:   "archived",
				Module: dep.Module,
				Detail: detail,
			})
		}

		// CRITICAL CVE check (regardless of reachability).
		for i := range dep.Vulns {
			v := &dep.Vulns[i]
			if effectiveTier(v) != "CRITICAL" {
				continue
			}
			if seenCVE[v.ID] {
				continue
			}
			seenCVE[v.ID] = true

			reachSuffix := ""
			if v.Reachability != "" {
				reachSuffix = ", " + v.Reachability
			}
			bombs = append(bombs, TimeBomb{
				Kind:   "critical_cve",
				Module: dep.Module,
				Detail: fmt.Sprintf("%s (CRITICAL%s)", v.ID, reachSuffix),
			})
		}

		// TODO(plan-37): KEV check.
		// TODO(plan-46): pseudo-version provenance check.
	}

	return bombs
}
