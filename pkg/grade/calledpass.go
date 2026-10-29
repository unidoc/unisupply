package grade

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/unidoc/unisupply/pkg/scanner"
)

// CalledPassCanChangeLetter says whether govulncheck's called pass (which vulnerable functions the code reaches) could
// change the letter, given what its imported pass found. It is the test scan.VulnScanOptions.NeedsCalledPass wants, and it
// lives here so it follows the grading rules: it asks the rules themselves, not a copy of them.
//
// The called pass can only move a finding from "imported" to "called" (a module that is not imported stays graph-only, and
// a finding that is already called stays so). So the question is whether any imported finding scores in a different band
// as called than as imported, in the module's row or in a whole-tree rule. With the rules as they stand that is true for
// any high or critical finding (called 70 and 90 are D and F, imported at most 50 is C), for a known-exploited one (called
// is at least F) and for one with no severity yet (it is scored as a medium estimate that a lookup could settle, and the
// letter would be marked as estimated); medium and low findings land in the same band either way.
//
// The test is deliberately one-sided: it ignores upkeep, which is added by max() to the same row either way and so cannot
// make two scores that share a band differ; and it checks both with and without the test-only halving, so that an unknown
// test-only status never makes it answer false. A true answer costs time, never a wrong letter; a false one is a promise
// that the letter is the same, which TestCalledPassPredicateMatchesGrade checks against Grade for every severity.
//
// imported is the scan's findings by module path ("stdlib" for the standard library). The reason is one sentence for the
// report, either what makes the called pass worth running or why it was skipped.
func CalledPassCanChangeLetter(imported map[string][]scanner.Vulnerability) (needed bool, reason string) {
	var (
		count    int
		noSev    []string
		exploit  []string
		bandDiff []string
	)
	modules := make([]string, 0, len(imported))
	for m := range imported {
		modules = append(modules, m)
	}
	sort.Strings(modules)

	asImported := Input{}
	asCalled := Input{}
	for _, m := range modules {
		for _, testOnly := range []*bool{nil, boolPtr(true)} {
			var ri, rc Row
			ri, rc = Row{Module: m, Direct: true, TestOnly: testOnly}, Row{Module: m, Direct: true, TestOnly: testOnly}
			for i := range imported[m] {
				v := &imported[m][i]
				if strings.ToLower(strings.TrimSpace(v.Reachability)) != "imported" {
					continue // called, graph-only or undetermined: the called pass cannot change its tier
				}
				if testOnly == nil {
					count++
					if _, est := severityOf(v.Severity); est {
						noSev = append(noSev, v.ID)
					}
					if v.InKEV {
						exploit = append(exploit, v.ID)
					}
				}
				f := Finding{ID: v.ID, Severity: v.Severity, Reachability: "imported", Exploited: v.InKEV}
				ri.Findings = append(ri.Findings, f)
				f.Reachability = "called"
				rc.Findings = append(rc.Findings, f)
			}
			if len(ri.Findings) == 0 {
				continue
			}
			if testOnly == nil {
				asImported.Deps = append(asImported.Deps, ri)
				asCalled.Deps = append(asCalled.Deps, rc)
			}
			// the row alone, with and without the test-only halving
			a, b := rowVulnBand(ri), rowVulnBand(rc)
			if a != b {
				bandDiff = append(bandDiff, m)
			}
		}
	}
	if count == 0 {
		return false, "the code imports no package with an advisory, so no function can be called"
	}
	slices.Sort(noSev)
	slices.Sort(exploit)
	slices.Sort(bandDiff)
	switch {
	case len(exploit) > 0:
		return true, fmt.Sprintf("an imported advisory is known to be exploited (%s), which grades F when called", exploit[0])
	case len(noSev) > 0:
		return true, fmt.Sprintf("an imported advisory has no severity yet (%s), so what its called score would be is not known", noSev[0])
	case len(bandDiff) > 0 || treeBand(&asImported) != treeBand(&asCalled):
		return true, "an imported advisory is high or critical, or scores in a higher band when called"
	}
	return false, fmt.Sprintf("the %d imported advisories are all medium or low, and are in the same band whether called or imported", count)
}

func boolPtr(b bool) *bool { return &b }

// rowVulnBand is the band of a row's vulnerability score alone.
func rowVulnBand(r Row) Letter {
	fs := make([]scored, 0, len(r.Findings))
	for i := range r.Findings {
		fs = append(fs, scoreFinding(&r.Findings[i], &r))
	}
	score, _, _, _ := vulnScore(r, fs)
	return bandOf(score)
}

// treeBand is the band of the whole-tree rule over in's rows, or A when none applies.
func treeBand(in *Input) Letter {
	if t := treeRule(in, nil); t != nil {
		return bandOf(t.Score)
	}
	return LetterA
}
