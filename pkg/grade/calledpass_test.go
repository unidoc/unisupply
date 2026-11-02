package grade

import (
	"strings"
	"testing"

	"github.com/unidoc/unisupply/pkg/scanner"
)

func importedVuln(id, sev string, kev bool) scanner.Vulnerability {
	return scanner.Vulnerability{ID: id, Severity: sev, Reachability: "imported", InKEV: kev}
}

func TestCalledPassCanChangeLetter(t *testing.T) {
	cases := []struct {
		name   string
		in     map[string][]scanner.Vulnerability
		want   bool
		reason string
	}{
		{"nothing imported", map[string][]scanner.Vulnerability{}, false, "imports no package"},
		{"only graph-only findings", map[string][]scanner.Vulnerability{"a": {{ID: "GO-1", Severity: "CRITICAL", Reachability: "required"}}}, false, "imports no package"},
		{"medium and low", map[string][]scanner.Vulnerability{"a": {importedVuln("GO-1", "MEDIUM", false), importedVuln("GO-2", "LOW", false)}}, false, "same band"},
		{"high", map[string][]scanner.Vulnerability{"a": {importedVuln("GO-1", "HIGH", false)}}, true, "high or critical"},
		{"critical", map[string][]scanner.Vulnerability{"a": {importedVuln("GO-1", "CRITICAL", false)}}, true, "high or critical"},
		{"known exploited low", map[string][]scanner.Vulnerability{"a": {importedVuln("GO-1", "LOW", true)}}, true, "known to be exploited (GO-1)"},
		{"no severity yet", map[string][]scanner.Vulnerability{"a": {importedVuln("GO-1", "UNKNOWN", false)}}, true, "no severity yet (GO-1)"},
		{"empty severity", map[string][]scanner.Vulnerability{"a": {importedVuln("GO-1", "", false)}}, true, "no severity yet"},
		{"low next to a high elsewhere", map[string][]scanner.Vulnerability{"a": {importedVuln("GO-1", "LOW", false)}, "b": {importedVuln("GO-2", "HIGH", false)}}, true, "high or critical"},
		{"stdlib counts", map[string][]scanner.Vulnerability{"stdlib": {importedVuln("GO-1", "HIGH", false)}}, true, "high or critical"},
		{"already called is not asked again", map[string][]scanner.Vulnerability{"a": {{ID: "GO-1", Severity: "CRITICAL", Reachability: "called"}}}, false, "imports no package"},
	}
	for _, c := range cases {
		got, reason := CalledPassCanChangeLetter(c.in)
		if got != c.want || !strings.Contains(reason, c.reason) {
			t.Errorf("%s: got (%v, %q), want %v mentioning %q", c.name, got, reason, c.want, c.reason)
		}
	}
}

// TestCalledPassPredicateMatchesGrade is the promise behind skipping the called pass: whenever the predicate says it
// cannot change the letter, grading the same findings as imported and as called gives the same letter, for every severity,
// with and without known-exploited status, test-only status and upkeep. It runs the real Grade, so it fails if the rules change
// and the predicate does not follow.
func TestCalledPassPredicateMatchesGrade(t *testing.T) {
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", ""}
	upkeeps := map[string]Upkeep{
		"active":     {LastRelease: now.AddDate(0, -3, 0)},
		"archived":   {Archived: true, LastRelease: now.AddDate(-3, 0, 0)},
		"deprecated": {Deprecated: true, LastRelease: now.AddDate(-1, 0, 0)},
	}
	testOnly := map[string]*bool{"unknown": nil, "test-only": ptr(true), "production": ptr(false)}
	// one finding of each severity, alone and in pairs and in a crowd (the whole-tree counts)
	var sets [][]string
	for _, a := range severities {
		sets = append(sets, []string{a})
		for _, b := range severities {
			sets = append(sets, []string{a, b})
		}
	}
	sets = append(sets, []string{"MEDIUM", "MEDIUM", "MEDIUM", "MEDIUM", "MEDIUM", "LOW", "LOW"})

	skipped := 0
	for _, set := range sets {
		for _, kev := range []bool{false, true} {
			for un, up := range upkeeps {
				for tn, to := range testOnly {
					var vulns []scanner.Vulnerability
					var asImported, asCalled []Finding
					for i, sev := range set {
						id := "GO-" + string(rune('A'+i))
						vulns = append(vulns, importedVuln(id, sev, kev && i == 0))
						asImported = append(asImported, Finding{ID: id, Severity: sev, Reachability: "imported", Exploited: kev && i == 0})
						asCalled = append(asCalled, Finding{ID: id, Severity: sev, Reachability: "called", Exploited: kev && i == 0})
					}
					needed, _ := CalledPassCanChangeLetter(map[string][]scanner.Vulnerability{"example.com/dep": vulns})
					if needed {
						continue
					}
					skipped++
					mk := func(fs []Finding) Result {
						d := dep("example.com/dep", fs...)
						d.Upkeep, d.TestOnly = up, to
						return run(Input{Self: self(), Deps: []Row{d}})
					}
					a, c := mk(asImported), mk(asCalled)
					if a.Letter != c.Letter || a.Estimated != c.Estimated {
						t.Errorf("severities %v kev=%v upkeep=%s test-only=%s: predicate says the called pass cannot matter, but imported grades %s%s and called %s%s",
							set, kev, un, tn, a.Letter, star(a), c.Letter, star(c))
					}
				}
			}
		}
	}
	if skipped == 0 {
		t.Fatal("the predicate never said the called pass can be skipped: the test checked nothing")
	}
}

func star(r Result) string {
	if r.Estimated {
		return "*"
	}
	return ""
}
