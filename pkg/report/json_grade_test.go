package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/grade"
	"github.com/unidoc/unisupply/pkg/resolver"
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
		"mean_dep_risk_score", "severity_adjusted_vuln_score",
		"headline_driver", "worst_cve_id", "worst_cve_score", "worst_cve_severity", "worst_cve_module",
		"diagnostics", "debug_scoring", "headline_unscored_reason", "takeover_candidates",
	}
	removedSummary    = []string{}
	removedDependency = []string{"score_breakdown", "risk_factors"}
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
	for _, k := range []string{`"mean_dep_risk_score"`, `"severity_scored"`, `"takeover_candidates"`} {
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
		rootProps := map[string]string{}
		for _, p := range bom.Metadata.Component.Properties {
			rootProps[p.Name] = p.Value
		}
		if rootProps["unisupply:grade"] != "B" || rootProps["unisupply:grade_reason"] != "" {
			t.Errorf("root properties = %v, want only the overall letter B", rootProps)
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
		if len(doc.Annotations) != 1 || doc.Annotations[0].Comment != "grade=B" {
			t.Errorf("document annotations = %+v, want grade=B", doc.Annotations)
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

// TestSBOM_PendingAndEstimatedGrades checks a row with no letter gets no grade property or annotation, an estimated
// letter keeps its "*", and the overall grade (a letter or PENDING with the check) is on the root.
func TestSBOM_PendingAndEstimatedGrades(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{Path: "github.com/x/y", Version: "v1.0.0", Direct: true},
		testutil.DepSpec{Path: "github.com/x/z", Version: "v1.0.0", Direct: true},
	)
	ps := gradeTestScore(plainDep())
	g := &grade.Result{
		RuleVersion: grade.RuleVersion,
		Pending:     &grade.Pending{Check: "dependency_maintenance", Reason: "upkeep could not be read"},
		Rows: []grade.RowResult{
			{Module: "github.com/x/y", Letter: "", Reason: "upkeep unknown"},
			{Module: "github.com/x/z", Letter: grade.LetterC, Estimated: true, Reason: "estimated"},
		},
	}

	var buf bytes.Buffer
	if err := WriteCycloneDX(graph, ps, SBOMOptions{Grade: g}, &buf); err != nil {
		t.Fatal(err)
	}
	var bom cdxBOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	for _, c := range bom.Components {
		props := map[string]string{}
		for _, p := range c.Properties {
			props[p.Name] = p.Value
		}
		switch c.Name {
		case "github.com/x/y":
			if len(props) != 0 {
				t.Errorf("unread row has properties %v", props)
			}
		case "github.com/x/z":
			if props["unisupply:grade"] != "C*" {
				t.Errorf("estimated row grade = %q, want C*", props["unisupply:grade"])
			}
		}
	}
	rootProps := map[string]string{}
	for _, p := range bom.Metadata.Component.Properties {
		rootProps[p.Name] = p.Value
	}
	if rootProps["unisupply:grade"] != "PENDING (dependency_maintenance)" {
		t.Errorf("root grade = %q", rootProps["unisupply:grade"])
	}

	buf.Reset()
	if err := WriteSPDX(graph, ps, SBOMOptions{Grade: g}, &buf); err != nil {
		t.Fatal(err)
	}
	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, p := range doc.Packages {
		switch p.Name {
		case "github.com/x/y":
			if len(p.Annotations) != 0 {
				t.Errorf("unread row has annotations %+v", p.Annotations)
			}
		case "github.com/x/z":
			if len(p.Annotations) != 1 || !strings.HasPrefix(p.Annotations[0].Comment, "grade=C* ") {
				t.Errorf("estimated row annotations = %+v", p.Annotations)
			}
		}
	}
	if len(doc.Annotations) != 1 || doc.Annotations[0].Comment != "grade=PENDING (dependency_maintenance)" {
		t.Errorf("document annotations = %+v", doc.Annotations)
	}
}

// The fields published before Grading v2 stay for one release, marked deprecated and derived from the grade (not from the
// scorer's own numbers, which are never published).
func TestWriteJSON_DeprecatedFieldsAreDerivedFromTheGrade(t *testing.T) {
	dep := plainDep()
	dep.RiskScore = 99 // the scorer's own number must never reach the output
	dep.RiskLevel = scorer.RiskLow
	ps := gradeTestScore(dep)
	ps.OverallScore = 3
	g := &grade.Result{
		RuleVersion: grade.RuleVersion, Letter: grade.LetterD, Score: 70,
		Deciding: &grade.Deciding{Module: dep.Module, Reason: "called high GO-1 (70)", Score: 70},
		Rows: []grade.RowResult{
			{Module: dep.Module, Score: 70, Letter: grade.LetterD},
			{Module: "example.com/app", Self: true, Score: 0, Letter: grade.LetterA},
		},
	}
	_, top := renderJSON(t, ps, JSONOptions{GoVersion: "1.21", Grade: g})
	var score int
	var level string
	_ = json.Unmarshal(top["overall_risk_score"], &score)
	_ = json.Unmarshal(top["overall_risk_level"], &level)
	if score != 70 || level != "HIGH" {
		t.Errorf("overall %d %s: from the grade, not the scorer's 3", score, level)
	}
	var head struct {
		Level       string `json:"level"`
		Driver      string `json:"driver"`
		DrivingItem string `json:"driving_item"`
		Candidates  []any  `json:"candidates"`
	}
	_ = json.Unmarshal(top["headline"], &head)
	if head.Level != "HIGH" || head.Driver != "grade_row" || head.DrivingItem != dep.Module || head.Candidates == nil || len(head.Candidates) != 0 {
		t.Errorf("headline %s", top["headline"])
	}
	var summary map[string]int
	_ = json.Unmarshal(top["summary"], &summary)
	if summary["high_risk_count"] != 1 || summary["low_risk_count"] != 0 {
		t.Errorf("summary counts the dependency rows (not the module itself): %v", summary)
	}
	var deps []map[string]any
	_ = json.Unmarshal(top["dependencies"], &deps)
	if deps[0]["risk_score"] != float64(70) || deps[0]["risk_level"] != "HIGH" {
		t.Errorf("dependency %v: from the grade's row, not the scorer's 99", deps[0])
	}
	var names []string
	_ = json.Unmarshal(top["deprecated_fields"], &names)
	if len(names) == 0 {
		t.Error("the report must say which fields are deprecated")
	}
	// no grade, or a Pending one: UNKNOWN, never a made-up level
	_, top = renderJSON(t, ps, JSONOptions{GoVersion: "1.21"})
	_ = json.Unmarshal(top["overall_risk_level"], &level)
	if level != "UNKNOWN" {
		t.Errorf("no grade reads UNKNOWN, got %q", level)
	}
}

func TestWriteJSON_DependencyGraphAndScanStatus(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{Path: "example.com/a", Version: "v1.0.0", Direct: true, UsedBy: []string{"test/module"}},
		testutil.DepSpec{Path: "example.com/b", Version: "v2.0.0", UsedBy: []string{"example.com/a", "test/module", "example.com/a"}},
		testutil.DepSpec{Path: "example.com/c", Version: "v0.1.0", UsedBy: []string{"example.com/b"}},
	)
	graph.Source = resolver.SourceGoModGraph
	var buf bytes.Buffer
	status := &scanner.ScanStatus{Status: scanner.StatusFailed, Reason: scanner.ReasonMissingGoSum, Kind: "permanent", Detail: "missing go.sum entry"}
	if err := WriteJSON(graph, &scorer.ProjectScore{}, JSONOptions{ScanStatus: status}, &buf); err != nil {
		t.Fatal(err)
	}
	var got struct {
		ScanStatus      scanner.ScanStatus `json:"scan_status"`
		DependencyGraph struct {
			Root   string          `json:"root"`
			Source string          `json:"source"`
			Edges  []resolver.Edge `json:"edges"`
		} `json:"dependency_graph"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ScanStatus != *status {
		t.Errorf("scan_status = %+v", got.ScanStatus)
	}
	want := []resolver.Edge{{From: "example.com/a", To: "example.com/b"}, {From: "example.com/b", To: "example.com/c"}, {From: "test/module", To: "example.com/a"}, {From: "test/module", To: "example.com/b"}}
	if got.DependencyGraph.Root != "test/module" || got.DependencyGraph.Source != "go_mod_graph" || !reflect.DeepEqual(got.DependencyGraph.Edges, want) {
		t.Errorf("dependency_graph = %+v, want edges %v", got.DependencyGraph, want)
	}
}

// Without a status from the caller the writer derives one from the grade, and a graph without edges has "edges": [], not null.
func TestWriteJSON_ScanStatusFromGradeAndEmptyEdges(t *testing.T) {
	pending := &grade.Result{RuleVersion: grade.RuleVersion, Pending: &grade.Pending{Check: "dependency_maintenance", Reason: "no data"}}
	body, top := renderJSON(t, gradeTestScore(plainDep()), JSONOptions{Grade: pending})
	var st scanner.ScanStatus
	if err := json.Unmarshal(top["scan_status"], &st); err != nil || st.Status != scanner.StatusPending || st.Reason != "dependency_maintenance" {
		t.Errorf("scan_status = %s (%v)", top["scan_status"], err)
	}
	var dg map[string]json.RawMessage
	if err := json.Unmarshal(top["dependency_graph"], &dg); err != nil || string(dg["edges"]) != "[]" {
		t.Errorf("dependency_graph = %s\n%s", top["dependency_graph"], body)
	}
	_, top = renderJSON(t, gradeTestScore(plainDep()), JSONOptions{Grade: &grade.Result{RuleVersion: grade.RuleVersion, Letter: grade.LetterA}})
	if !strings.Contains(string(top["scan_status"]), `"complete"`) {
		t.Errorf("scan_status = %s", top["scan_status"])
	}
}

func TestWriteJSONFailure(t *testing.T) {
	var buf bytes.Buffer
	cause := &scanner.ScanError{Kind: scanner.FailPermanent, Reason: scanner.ReasonNoGoMod, Err: errors.New("no go.mod found in /x")}
	if err := WriteJSONFailure(cause, &buf); err != nil {
		t.Fatal(err)
	}
	var got JSONFailure
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Tool != "unisupply" || got.Version == "" || got.ScanStatus.Status != scanner.StatusFailed || got.ScanStatus.Reason != "no_go_mod" || got.ScanStatus.Kind != "permanent" || got.Error != "no go.mod found in /x" {
		t.Errorf("%+v", got)
	}
	// a deadline is an interrupted scan, not a failed one
	buf.Reset()
	_ = WriteJSONFailure(&scanner.ScanError{Kind: scanner.FailTooLarge, Reason: scanner.ReasonScanDeadline, Err: errors.New("x")}, &buf)
	_ = json.Unmarshal(buf.Bytes(), &got)
	if got.ScanStatus.Status != scanner.StatusInterrupted || got.ScanStatus.Reason != scanner.ReasonScanDeadline {
		t.Errorf("%+v", got.ScanStatus)
	}
}

func TestWriteJSON_PrivateDependencyIsMarked(t *testing.T) {
	res := &grade.Result{RuleVersion: grade.RuleVersion, Letter: grade.LetterA, Rows: []grade.RowResult{
		{Module: "github.com/x/y", Private: true, Letter: grade.LetterA, Reason: "private module: not looked up, not graded on upkeep", UpkeepState: grade.StateNotAssessed},
	}, Notes: []string{"1 private module was not looked up and is not graded on upkeep: github.com/x/y."}}
	_, top := renderJSON(t, gradeTestScore(plainDep()), JSONOptions{Grade: res})
	var deps []struct {
		Private bool `json:"private"`
	}
	if err := json.Unmarshal(top["dependencies"], &deps); err != nil || len(deps) != 1 || !deps[0].Private {
		t.Errorf("dependencies = %s (%v)", top["dependencies"], err)
	}
	if !strings.Contains(string(top["grade"]), `"private": true`) {
		t.Errorf("the grade row is not marked: %s", top["grade"])
	}
}
