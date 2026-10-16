package report

import (
	"encoding/json"
	"testing"

	"github.com/unidoc/unisupply/pkg/grade"
)

// A Pending result must not publish 0 through the deprecated score fields (F29): a v1 gate such as
// "overall_risk_score <= 60" would read it as the cleanest result.
func TestWriteJSON_PendingOmitsDeprecatedScores(t *testing.T) {
	pending := &grade.Result{RuleVersion: grade.RuleVersion, Pending: &grade.Pending{Check: "vulnerability_scan", Reason: "offline"},
		Rows: []grade.RowResult{{Module: "github.com/x/y", Version: "v1.0.0", Direct: true, Score: 0, Letter: grade.LetterA}}}
	_, top := renderJSON(t, gradeTestScore(plainDep()), JSONOptions{GoVersion: "1.21", Grade: pending})

	if _, ok := top["overall_risk_score"]; ok {
		t.Errorf("overall_risk_score = %s on a Pending result, want it absent", top["overall_risk_score"])
	}
	if string(top["overall_risk_level"]) != `"UNKNOWN"` {
		t.Errorf("overall_risk_level = %s, want UNKNOWN", top["overall_risk_level"])
	}
	var h map[string]json.RawMessage
	if err := json.Unmarshal(top["headline"], &h); err != nil {
		t.Fatal(err)
	}
	if _, ok := h["score"]; ok {
		t.Errorf("headline.score = %s on a Pending result, want it absent", h["score"])
	}
	var deps []map[string]json.RawMessage
	if err := json.Unmarshal(top["dependencies"], &deps); err != nil || len(deps) != 1 {
		t.Fatalf("dependencies: %v %d", err, len(deps))
	}
	if _, ok := deps[0]["risk_score"]; ok {
		t.Errorf("dependencies[].risk_score = %s on a Pending result, want it absent", deps[0]["risk_score"])
	}

	// a graded result still carries the numbers (including a real 0)
	graded := &grade.Result{RuleVersion: grade.RuleVersion, Letter: grade.LetterA, Score: 0,
		Rows: []grade.RowResult{{Module: "github.com/x/y", Version: "v1.0.0", Direct: true, Score: 0, Letter: grade.LetterA}}}
	_, top = renderJSON(t, gradeTestScore(plainDep()), JSONOptions{GoVersion: "1.21", Grade: graded})
	if string(top["overall_risk_score"]) != "0" {
		t.Errorf("graded A: overall_risk_score = %s, want 0", top["overall_risk_score"])
	}
}
