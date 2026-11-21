package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/unidoc/unisupply/pkg/grade"
)

func nextStepResult(step *grade.NextStep) *grade.Result {
	return &grade.Result{
		RuleVersion: grade.RuleVersion,
		Letter:      grade.LetterD,
		Score:       75,
		Deciding:    &grade.Deciding{Module: "golang.org/x/image", Reason: "called high GO-2026-5032 (70)", Score: 75},
		NextStep:    step,
		Rows: []grade.RowResult{{Module: "golang.org/x/image", Version: "v0.30.0", Direct: true, Score: 75, VulnScore: 75, Letter: grade.LetterD,
			Reason: "called high GO-2026-5032 (70)", UpkeepState: grade.StateActive}},
	}
}

var (
	stepD       = &grade.NextStep{Module: "golang.org/x/image", Version: "v0.43.0", Command: "go get golang.org/x/image@v0.43.0", Clears: []string{"GO-1", "GO-2", "GO-3"}, LetterAfter: grade.LetterD, ScoreAfter: 54}
	stepPending = &grade.NextStep{Module: "golang.org/x/image", Version: "v0.43.0", Command: "go get golang.org/x/image@v0.43.0", Clears: []string{"GO-1"}, PendingAfter: "dependency_maintenance"}
)

func TestNextStepText(t *testing.T) {
	requireAll(t, renderGradeText(t, nextStepResult(stepD)),
		"Next step: go get golang.org/x/image@v0.43.0 (clears 3 advisories; the letter would be D)")
	requireAll(t, renderGradeText(t, nextStepResult(&grade.NextStep{Command: "go get example.com/a@v1.0.0", Clears: []string{"GO-1"}, LetterAfter: grade.LetterA})),
		"Next step: go get example.com/a@v1.0.0 (clears 1 advisory; the letter would be A)")
	requireAll(t, renderGradeText(t, nextStepResult(stepPending)),
		"Next step: go get golang.org/x/image@v0.43.0 (clears 1 advisory; the letter after it depends on dependency_maintenance)")
	requireNone(t, renderGradeText(t, nextStepResult(nil)), "Next step")
}

func TestNextStepJSON(t *testing.T) {
	_, top := renderJSON(t, gradeTestScore(plainDep()), JSONOptions{GoVersion: "1.21", Grade: nextStepResult(stepD)})
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(top["grade"], &obj); err != nil {
		t.Fatal(err)
	}
	raw, ok := obj["next_step"]
	if !ok {
		t.Fatalf("next_step is missing from the grade: %s", top["grade"])
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	clears, _ := got["clears"].([]any)
	if got["letter_after"] != "D" || got["score_after"] != float64(54) || got["command"] != "go get golang.org/x/image@v0.43.0" ||
		got["module"] != "golang.org/x/image" || got["version"] != "v0.43.0" || len(clears) != 3 || clears[0] != "GO-1" {
		t.Errorf("next_step = %s", raw)
	}
	if _, ok := got["pending_after"]; ok {
		t.Errorf("pending_after is left out when the letter is known: %s", raw)
	}
	_, top = renderJSON(t, gradeTestScore(plainDep()), JSONOptions{GoVersion: "1.21", Grade: nextStepResult(nil)})
	if strings.Contains(string(top["grade"]), "next_step") {
		t.Errorf("no next step: the key is left out")
	}
}

// the PDF page and the cover draw it (smoke: the text of a PDF needs a licence, the lines are checked through the helper)
func TestNextStepLine(t *testing.T) {
	if got := gradeNextStepText(stepD); got != "go get golang.org/x/image@v0.43.0 (clears 3 advisories; the letter would be D)" {
		t.Errorf("%q", got)
	}
}
