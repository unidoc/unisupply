package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/grade"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// gradeTestScore is a one-dependency project score used by the grade tests.
func gradeTestScore(dep *scorer.DependencyScore) *scorer.ProjectScore {
	return &scorer.ProjectScore{Dependencies: []*scorer.DependencyScore{dep}}
}

// renderJSON runs WriteJSON and returns the raw bytes and the decoded top-level map.
func renderJSON(t *testing.T, ps *scorer.ProjectScore, opts JSONOptions) ([]byte, map[string]json.RawMessage) {
	t.Helper()
	graph := testutil.MakeGraph(testutil.DepSpec{Path: "github.com/x/y", Version: "v1.0.0", Direct: true})
	var buf bytes.Buffer
	if err := WriteJSON(graph, ps, opts, &buf); err != nil {
		t.Fatalf("WriteJSON() failed: %v", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &top); err != nil {
		t.Fatalf("unmarshal top level: %v", err)
	}
	return buf.Bytes(), top
}

func plainDep() *scorer.DependencyScore {
	return &scorer.DependencyScore{Module: "github.com/x/y", Version: "v1.0.0", Direct: true}
}

// TestWriteJSON_GradeBlock checks that the grade block is emitted and decodes back to what was given, for an A, an F
// with a deciding row, a Pending (no letter, pending object), and an estimated C*.
func TestWriteJSON_GradeBlock(t *testing.T) {
	cases := []struct {
		name      string
		res       *grade.Result
		hasLetter bool
		letter    string
	}{
		{
			name: "A",
			res: &grade.Result{
				RuleVersion: grade.RuleVersion,
				Letter:      grade.LetterA,
				Score:       3,
				Rows: []grade.RowResult{
					{Module: "test/module", Self: true, Score: 0, Letter: grade.LetterA, Reason: "no findings", UpkeepState: grade.StateActive},
					{Module: "github.com/x/y", Version: "v1.0.0", Direct: true, Score: 3, Letter: grade.LetterA, Reason: "active", UpkeepState: grade.StateActive},
				},
				Notes: []string{"module advisories were not looked up: no module version given"},
			},
			hasLetter: true, letter: "A",
		},
		{
			name: "F with deciding row and tree row",
			res: &grade.Result{
				RuleVersion: grade.RuleVersion,
				Letter:      grade.LetterF,
				Score:       90,
				Deciding:    &grade.Deciding{Module: "github.com/x/y", Reason: "called critical finding GO-2024-1", Score: 90},
				Rows: []grade.RowResult{
					{
						Module: "github.com/x/y", Version: "v1.0.0", Direct: true, Score: 90, VulnScore: 90, Letter: grade.LetterF,
						Reason: "called critical finding GO-2024-1", UpkeepState: grade.StateActive,
						Findings: []grade.FindingResult{{ID: "GO-2024-1", Module: "github.com/x/y", Severity: "CRITICAL", Tier: grade.TierCalled, Score: 90, Counted: true}},
					},
				},
				TreeRows: []grade.TreeRow{{Rule: "called_critical", Score: 90, Letter: grade.LetterF, Reason: "1 called critical finding across 1 module"}},
			},
			hasLetter: true, letter: "F",
		},
		{
			name: "Pending",
			res: &grade.Result{
				RuleVersion: grade.RuleVersion,
				Rows:        []grade.RowResult{},
				Pending:     &grade.Pending{Check: "vulnerability_scan", Reason: "govulncheck did not run", Known: []string{"Archived"}},
			},
			hasLetter: false,
		},
		{
			name: "C estimated",
			res: &grade.Result{
				RuleVersion: grade.RuleVersion,
				Letter:      grade.LetterC,
				Estimated:   true,
				Score:       40,
				Deciding:    &grade.Deciding{Module: "github.com/x/y", Reason: "unknown-severity finding scored as medium", Score: 40},
				Rows: []grade.RowResult{
					{Module: "github.com/x/y", Score: 40, Letter: grade.LetterC, Estimated: true, Reason: "unknown-severity finding scored as medium", UpkeepState: grade.StateActive},
				},
			},
			hasLetter: true, letter: "C",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, top := renderJSON(t, gradeTestScore(plainDep()), JSONOptions{GoVersion: "1.21", Grade: tc.res})

			rawGrade, ok := top["grade"]
			if !ok {
				t.Fatal("top-level grade key missing")
			}
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(rawGrade, &obj); err != nil {
				t.Fatalf("grade is not an object: %v (%s)", err, rawGrade)
			}
			_, letterKey := obj["letter"]
			if letterKey != tc.hasLetter {
				t.Errorf("letter key present = %v, want %v", letterKey, tc.hasLetter)
			}
			if _, ok := obj["pending"]; ok == tc.hasLetter {
				t.Errorf("pending key present = %v, want %v", ok, !tc.hasLetter)
			}
			if _, ok := obj["rows"]; !ok {
				t.Error("rows key missing")
			}
			if _, ok := obj["deciding"]; ok != (tc.res.Deciding != nil) {
				t.Errorf("deciding key present = %v, want %v", ok, tc.res.Deciding != nil)
			}
			if _, ok := obj["tree_rows"]; ok != (len(tc.res.TreeRows) > 0) {
				t.Errorf("tree_rows key present = %v, want %v", ok, len(tc.res.TreeRows) > 0)
			}
			if _, ok := obj["notes"]; ok != (len(tc.res.Notes) > 0) {
				t.Errorf("notes key present = %v, want %v", ok, len(tc.res.Notes) > 0)
			}
			if _, ok := obj["estimated"]; ok != tc.res.Estimated {
				t.Errorf("estimated key present = %v, want %v", ok, tc.res.Estimated)
			}

			var got grade.Result
			if err := json.Unmarshal(rawGrade, &got); err != nil {
				t.Fatalf("decode grade: %v", err)
			}
			if string(got.Letter) != tc.letter {
				t.Errorf("letter = %q, want %q", got.Letter, tc.letter)
			}
			if !reflect.DeepEqual(&got, tc.res) {
				t.Errorf("grade did not round-trip:\n got  %+v\n want %+v", got, *tc.res)
			}
		})
	}
}

// TestWriteJSON_GradeNullWhenNil checks that "grade" is present as JSON null, not absent, when no result is given.
func TestWriteJSON_GradeNullWhenNil(t *testing.T) {
	_, top := renderJSON(t, gradeTestScore(plainDep()), JSONOptions{GoVersion: "1.21"})
	raw, ok := top["grade"]
	if !ok {
		t.Fatal("grade key absent; want present as null")
	}
	if string(raw) != "null" {
		t.Errorf("grade = %s, want null", raw)
	}
}

// removedTopLevel, removedSummary and removedDependency are the Grading v1 keys that must no longer be emitted.
var (
	removedTopLevel = []string{
		"overall_risk_score", "overall_risk_level", "mean_dep_risk_score", "severity_adjusted_vuln_score",
		"headline_driver", "headline", "worst_cve_id", "worst_cve_score", "worst_cve_severity", "worst_cve_module",
		"diagnostics", "debug_scoring", "headline_unscored_reason", "takeover_candidates",
	}
	removedSummary    = []string{"critical_risk_count", "high_risk_count", "medium_risk_count", "low_risk_count"}
	removedDependency = []string{"risk_score", "risk_level", "score_breakdown", "risk_factors"}
	removedVuln       = []string{"severity_scored"}
)

// TestWriteJSON_RemovedKeysAbsent decodes the output and checks that no removed key appears at the top level, in the
// summary, in a dependency or in a vulnerability, even when the scorer's own data (which still carries the v1 numbers)
// is populated.
func TestWriteJSON_RemovedKeysAbsent(t *testing.T) {
	dep := plainDep()
	dep.RiskScore = 77
	dep.RiskLevel = scorer.RiskCritical
	dep.Vulns = []scanner.Vulnerability{{ID: "GO-2024-1", Severity: "HIGH", Reachability: "called"}}
	ps := gradeTestScore(dep)
	ps.OverallScore = 77
	ps.OverallLevel = scorer.RiskCritical
	ps.CriticalRiskCount = 1
	ps.HighRiskCount = 2
	ps.TotalVulns = 1

	raw, top := renderJSON(t, ps, JSONOptions{GoVersion: "1.21", Grade: &grade.Result{RuleVersion: grade.RuleVersion, Letter: grade.LetterA, Rows: []grade.RowResult{}}})

	for _, k := range removedTopLevel {
		if _, ok := top[k]; ok {
			t.Errorf("removed top-level key %q is still emitted", k)
		}
	}
	var summary map[string]json.RawMessage
	if err := json.Unmarshal(top["summary"], &summary); err != nil {
		t.Fatalf("summary: %v", err)
	}
	for _, k := range removedSummary {
		if _, ok := summary[k]; ok {
			t.Errorf("removed summary key %q is still emitted", k)
		}
	}
	for _, k := range []string{"total_vulnerabilities", "unmaintained_2yr", "unmaintained_1yr"} {
		if _, ok := summary[k]; !ok {
			t.Errorf("summary key %q missing", k)
		}
	}
	var deps []map[string]json.RawMessage
	if err := json.Unmarshal(top["dependencies"], &deps); err != nil || len(deps) != 1 {
		t.Fatalf("dependencies: %v (len %d)", err, len(deps))
	}
	for _, k := range removedDependency {
		if _, ok := deps[0][k]; ok {
			t.Errorf("removed dependency key %q is still emitted", k)
		}
	}
	var vulns []map[string]json.RawMessage
	if err := json.Unmarshal(deps[0]["vulnerabilities"], &vulns); err != nil || len(vulns) != 1 {
		t.Fatalf("vulnerabilities: %v (len %d)", err, len(vulns))
	}
	for _, k := range removedVuln {
		if _, ok := vulns[0][k]; ok {
			t.Errorf("removed vulnerability key %q is still emitted", k)
		}
	}
	// A cheap guard against a key moving somewhere not covered above.
	for _, k := range []string{`"risk_score"`, `"risk_level"`, `"overall_risk_score"`, `"severity_scored"`} {
		if bytes.Contains(raw, []byte(k)) {
			t.Errorf("raw JSON contains %s", k)
		}
	}
}

// TestWriteJSON_NewVulnFields checks that the Grading v2 vulnerability fields are emitted, and omitted when empty.
func TestWriteJSON_NewVulnFields(t *testing.T) {
	released := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	full := plainDep()
	full.Vulns = []scanner.Vulnerability{{
		ID: "GO-2024-1", Severity: "HIGH", Reachability: "called",
		FixReleasedAt:    &released,
		FixDateSource:    "module_proxy",
		AffectedPackages: []string{"github.com/x/y/parse", "github.com/x/y/render"},
		Condition:        "reached through yaml.Unmarshal",
	}}
	empty := plainDep()
	empty.Vulns = []scanner.Vulnerability{{ID: "GO-2024-2", Severity: "LOW"}}

	vulnKeys := func(ps *scorer.ProjectScore) map[string]json.RawMessage {
		_, top := renderJSON(t, ps, JSONOptions{GoVersion: "1.21"})
		var rawDeps []struct {
			Vulns []map[string]json.RawMessage `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(top["dependencies"], &rawDeps); err != nil || len(rawDeps) != 1 || len(rawDeps[0].Vulns) != 1 {
			t.Fatalf("vulnerabilities not decodable: %v", err)
		}
		return rawDeps[0].Vulns[0]
	}

	k := vulnKeys(gradeTestScore(full))
	var gotTime time.Time
	if err := json.Unmarshal(k["fix_released_at"], &gotTime); err != nil || !gotTime.Equal(released) {
		t.Errorf("fix_released_at = %s (%v), want %v", k["fix_released_at"], err, released)
	}
	if string(k["fix_date_source"]) != `"module_proxy"` {
		t.Errorf("fix_date_source = %s", k["fix_date_source"])
	}
	var pkgs []string
	if err := json.Unmarshal(k["affected_packages"], &pkgs); err != nil || !reflect.DeepEqual(pkgs, full.Vulns[0].AffectedPackages) {
		t.Errorf("affected_packages = %s (%v)", k["affected_packages"], err)
	}
	if string(k["condition"]) != `"reached through yaml.Unmarshal"` {
		t.Errorf("condition = %s", k["condition"])
	}

	k = vulnKeys(gradeTestScore(empty))
	for _, key := range []string{"fix_released_at", "fix_date_source", "affected_packages", "condition"} {
		if _, ok := k[key]; ok {
			t.Errorf("%q emitted although empty", key)
		}
	}
}

// TestWriteJSON_NewMaintenanceFields checks the Grading v2 maintenance fields are emitted, and omitted when empty.
func TestWriteJSON_NewMaintenanceFields(t *testing.T) {
	maintKeys := func(m *scanner.MaintenanceInfo) map[string]json.RawMessage {
		dep := plainDep()
		dep.Maintenance = m
		_, top := renderJSON(t, gradeTestScore(dep), JSONOptions{GoVersion: "1.21"})
		var rawDeps []struct {
			Maintenance map[string]json.RawMessage `json:"maintenance"`
		}
		if err := json.Unmarshal(top["dependencies"], &rawDeps); err != nil || len(rawDeps) != 1 || rawDeps[0].Maintenance == nil {
			t.Fatalf("maintenance not decodable: %v", err)
		}
		return rawDeps[0].Maintenance
	}

	k := maintKeys(&scanner.MaintenanceInfo{
		Retracted:          true,
		RetractionMessage:  "broken release, use v1.0.1",
		RepositoryURL:      "https://github.com/x/y",
		ArchivedCheck:      "failed",
		RepositoryNotFound: true,
	})
	want := map[string]string{
		"retracted":            `true`,
		"retraction_message":   `"broken release, use v1.0.1"`,
		"repository_url":       `"https://github.com/x/y"`,
		"archived_check":       `"failed"`,
		"repository_not_found": `true`,
	}
	for key, w := range want {
		if got := string(k[key]); got != w {
			t.Errorf("%s = %q, want %q", key, got, w)
		}
	}

	k = maintKeys(&scanner.MaintenanceInfo{})
	for key := range want {
		if _, ok := k[key]; ok {
			t.Errorf("%q emitted although empty", key)
		}
	}
	// archived and deprecated stay unconditional.
	for _, key := range []string{"archived", "deprecated"} {
		if _, ok := k[key]; !ok {
			t.Errorf("%q missing", key)
		}
	}
}

// gradedSBOMInput returns a one-dependency graph and a grade with a row for it (and one for the module itself, which
// must not become a component property).
func gradedSBOMInput() (*scorer.ProjectScore, *grade.Result) {
	return gradeTestScore(plainDep()), &grade.Result{
		RuleVersion: grade.RuleVersion,
		Letter:      grade.LetterB,
		Rows: []grade.RowResult{
			{Module: "test/module", Self: true, Letter: grade.LetterA, Reason: "SELF-REASON"},
			{Module: "github.com/x/y", Letter: grade.LetterB, Reason: "quiet for 14 months"},
		},
	}
}

// TestSBOM_GradeProperties checks CycloneDX and SPDX carry the grade for a graded dependency, drop it without a
// grade (no panic), and never use the v1 names.
func TestSBOM_GradeProperties(t *testing.T) {
	graph := testutil.MakeGraph(testutil.DepSpec{Path: "github.com/x/y", Version: "v1.0.0", Direct: true})
	ps, g := gradedSBOMInput()

	t.Run("cyclonedx graded", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteCycloneDX(graph, ps, SBOMOptions{Grade: g}, &buf); err != nil {
			t.Fatal(err)
		}
		var bom cdxBOM
		if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
			t.Fatal(err)
		}
		props := map[string]string{}
		for _, p := range bom.Components[0].Properties {
			props[p.Name] = p.Value
		}
		if props["unisupply:grade"] != "B" || props["unisupply:grade_reason"] != "quiet for 14 months" {
			t.Errorf("properties = %v", props)
		}
		if bom.Metadata.Component != nil {
			for _, p := range bom.Metadata.Component.Properties {
				if strings.HasPrefix(p.Name, "unisupply:grade") {
					t.Errorf("root component carries %s", p.Name)
				}
			}
		}
		if bytes.Contains(buf.Bytes(), []byte("risk_score")) || bytes.Contains(buf.Bytes(), []byte("risk_level")) || bytes.Contains(buf.Bytes(), []byte("SELF-REASON")) {
			t.Errorf("unexpected content:\n%s", buf.String())
		}
	})

	t.Run("cyclonedx nil grade", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteCycloneDX(graph, ps, SBOMOptions{}, &buf); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(buf.Bytes(), []byte("unisupply:grade")) || bytes.Contains(buf.Bytes(), []byte("risk_score")) || bytes.Contains(buf.Bytes(), []byte("risk_level")) {
			t.Errorf("grade or risk property emitted without a grade:\n%s", buf.String())
		}
	})

	t.Run("spdx graded", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteSPDX(graph, ps, SBOMOptions{Grade: g}, &buf); err != nil {
			t.Fatal(err)
		}
		var doc spdxDocument
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Packages[0].Annotations) != 0 {
			t.Errorf("root package has annotations: %+v", doc.Packages[0].Annotations)
		}
		anns := doc.Packages[1].Annotations
		if len(anns) != 1 || anns[0].Comment != "grade=B reason=quiet for 14 months" {
			t.Errorf("annotations = %+v", anns)
		}
		if bytes.Contains(buf.Bytes(), []byte("risk_score")) || bytes.Contains(buf.Bytes(), []byte("risk_level")) {
			t.Errorf("v1 names present:\n%s", buf.String())
		}
	})

	t.Run("spdx nil grade", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteSPDX(graph, ps, SBOMOptions{}, &buf); err != nil {
			t.Fatal(err)
		}
		var doc spdxDocument
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		for _, p := range doc.Packages {
			if len(p.Annotations) != 0 {
				t.Errorf("package %s has annotations without a grade", p.Name)
			}
		}
		if bytes.Contains(buf.Bytes(), []byte("grade=")) || bytes.Contains(buf.Bytes(), []byte("risk_score")) {
			t.Errorf("unexpected content:\n%s", buf.String())
		}
	})
}
