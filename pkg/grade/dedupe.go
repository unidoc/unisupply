package grade

import (
	"sort"
	"strings"
)

// mergeAdvisories folds the findings of one row that are the same vulnerability under different identifiers (a Go
// advisory GO-2020-0017 and the GitHub advisory GHSA-w73w-5m7g-f7qc share a CVE alias) into one finding, so that a
// vulnerability counts once and not once per database. The Go ID represents the group when there is one.
func mergeAdvisories(in []Finding) []Finding {
	if len(in) < 2 {
		return in
	}
	// union-find over every identifier a finding carries
	parent := make([]int, len(in))
	for i := range parent {
		parent[i] = i
	}
	find := func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	owner := map[string]int{}
	for i, f := range in {
		for _, id := range append([]string{f.ID}, f.Aliases...) {
			if id == "" {
				continue
			}
			if j, ok := owner[id]; ok {
				parent[find(i)] = find(j)
			} else {
				owner[id] = i
			}
		}
	}
	groups := map[int][]int{}
	var order []int
	for i := range in {
		r := find(i)
		if _, ok := groups[r]; !ok {
			order = append(order, r)
		}
		groups[r] = append(groups[r], i)
	}
	out := make([]Finding, 0, len(groups))
	for _, r := range order {
		out = append(out, mergeGroup(in, groups[r]))
	}
	return out
}

func mergeGroup(all []Finding, idx []int) Finding {
	if len(idx) == 1 {
		return all[idx[0]]
	}
	// the representative: a Go advisory first, then the smallest ID, so the result never depends on input order
	rep := idx[0]
	for _, i := range idx[1:] {
		a, b := all[i], all[rep]
		ag, bg := strings.HasPrefix(a.ID, "GO-"), strings.HasPrefix(b.ID, "GO-")
		if (ag && !bg) || (ag == bg && a.ID < b.ID) {
			rep = i
		}
	}
	m := all[rep]
	ids := map[string]bool{}
	for _, i := range idx {
		f := all[i]
		ids[f.ID] = true
		for _, a := range f.Aliases {
			ids[a] = true
		}
		if severityRank(f.Severity) > severityRank(m.Severity) {
			m.Severity = f.Severity
		}
		if reachRank(f.Reachability) > reachRank(m.Reachability) {
			m.Reachability = f.Reachability
		}
		if f.Exploited {
			m.Exploited = true
		}
		if m.FixedVersion == "" && f.FixedVersion != "" {
			m.FixedVersion = f.FixedVersion
			m.FixReleasedAt, m.FixDateSource = f.FixReleasedAt, f.FixDateSource
		}
		if m.Summary == "" {
			m.Summary = f.Summary
		}
		if m.Condition == "" {
			m.Condition = f.Condition
		}
		if len(m.AffectedPackages) == 0 {
			m.AffectedPackages = f.AffectedPackages
		}
	}
	delete(ids, m.ID)
	m.Aliases = m.Aliases[:0:0]
	for id := range ids {
		m.Aliases = append(m.Aliases, id)
	}
	sort.Strings(m.Aliases)
	return m
}

func severityRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	}
	return 0 // unknown ranks below every known severity: a known one always wins the merge
}

// reachRank orders reachability by how much it counts; an undetermined one is scored as called, so it ranks with it.
func reachRank(r string) int {
	switch r {
	case "called", "":
		return 3
	case "imported":
		return 2
	}
	return 1
}
