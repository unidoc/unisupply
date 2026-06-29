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
	// or "GO-2024-1234 (CRITICAL, required — not on call path)").
	Detail string
	// Reachability is populated for critical_cve entries (e.g. "called", "imported",
	// "required"). Empty when unknown — archived entries never set it, and critical_cve
	// entries omit it when reachability analysis was unavailable.
	Reachability string
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

			reachTag := v.Reachability
			reachSuffix := ""
			if reachTag != "" {
				switch reachTag {
				case "required":
					reachSuffix = ", required — not on call path"
				case "imported":
					reachSuffix = ", imported — in package but not called"
				default:
					reachSuffix = ", " + reachTag
				}
			}
			bombs = append(bombs, TimeBomb{
				Kind:         "critical_cve",
				Module:       dep.Module,
				Detail:       fmt.Sprintf("%s (CRITICAL%s)", v.ID, reachSuffix),
				Reachability: reachTag,
			})
		}

		// TODO: add KEV (Known Exploited Vulnerabilities) check.
		// TODO: add pseudo-version provenance check.
	}

	return bombs
}
