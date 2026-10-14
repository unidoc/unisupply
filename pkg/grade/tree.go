package grade

import (
	"fmt"
	"sort"
)

// treeRule is the whole-tree rules: F only for confirmed problems, counted across the tree with confirmed test-only
// dependencies left out (the checksum rule applies to them in full). A finding counts once per module and advisory.
//
//   - 3 or more called high or critical findings, any called critical finding, a called known-exploited finding or a
//     checksum mismatch: F (score 76);
//   - 5 or more called-or-imported high or critical findings: at least D (score 51).
//
// It returns the highest rule that applies; the caller uses it only when it raises the letter (its score is above the
// worst row's), and then it appears as a row of its own. Without a tree-wide count, splitting one risky dependency into
// several small modules would turn an F into a D.
func treeRule(in Input, rows []RowResult) *TreeRow {
	all := append([]Row{in.Self}, in.Deps...)
	type key struct{ module, id string }
	calledHC := map[key]bool{}
	anyHC := map[key]bool{}
	modules := map[string]bool{}
	modulesAny := map[string]bool{}
	var calledCritical, calledExploited string
	for _, r := range all {
		if isConfirmed(r.TestOnly) {
			continue
		}
		for _, f := range r.Findings {
			sf := scoreFinding(f, r.Self)
			k := key{r.Module, f.ID}
			if sf.tier == TierCalled && highOrCritical(sf.sev) {
				calledHC[k] = true
				modules[r.Module] = true
			}
			if (sf.tier == TierCalled || sf.tier == TierImported) && highOrCritical(sf.sev) {
				anyHC[k] = true
				modulesAny[r.Module] = true
			}
			if sf.tier == TierCalled && sf.sev == "CRITICAL" && (calledCritical == "" || f.ID < calledCritical) {
				calledCritical = f.ID
			}
			if sf.tier == TierCalled && f.Exploited && (calledExploited == "" || f.ID < calledExploited) {
				calledExploited = f.ID
			}
		}
	}

	switch {
	case in.ChecksumMismatch:
		reason := "a module does not match its checksum (go.sum)"
		if in.ChecksumDetail != "" {
			reason += ": " + in.ChecksumDetail
		}
		return &TreeRow{Rule: "checksum_mismatch", Score: treeFScore, Letter: LetterF, Reason: reason}
	case calledExploited != "":
		return &TreeRow{Rule: "called_exploited", Score: treeFScore, Letter: LetterF, Reason: fmt.Sprintf("a called known-exploited finding: %s", calledExploited)}
	case calledCritical != "":
		return &TreeRow{Rule: "called_critical", Score: treeFScore, Letter: LetterF, Reason: fmt.Sprintf("a called critical finding: %s", calledCritical)}
	case len(calledHC) >= treeCalledFindings:
		return &TreeRow{Rule: "called_findings", Score: treeFScore, Letter: LetterF,
			Reason: fmt.Sprintf("%d called high or critical findings across %d module%s", len(calledHC), len(modules), plural(len(modules), "", "s"))}
	case len(anyHC) >= treeImportedOrCalled:
		return &TreeRow{Rule: "imported_and_called_findings", Score: treeDScore, Letter: LetterD,
			Reason: fmt.Sprintf("%d called or imported high or critical findings across %d module%s", len(anyHC), len(modulesAny), plural(len(modulesAny), "", "s"))}
	}
	_ = sort.Strings
	return nil
}
