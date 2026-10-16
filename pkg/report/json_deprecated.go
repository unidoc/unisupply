package report

import "github.com/unidoc/unisupply/pkg/grade"

// The fields below were published before Grading v2 and stay for ONE release so consumers can move to the `grade` object in
// steps. They are DEPRECATED and are derived from the grade: the score is the worst row's policy value and the level is the
// coarse band of the letter (A and B read LOW, C MEDIUM, D HIGH, F CRITICAL; no letter reads UNKNOWN). They do not carry the
// meaning they had (a weighted risk score): read `grade` instead. Fields of the old model that have no equivalent in the
// grade (the mean and severity-adjusted scores, the headline driver, worst_cve_*, diagnostics, debug_scoring, the takeover
// list, risk_factors, score_breakdown and severity_scored) are removed.

// deprecatedFields names what the report still carries only for compatibility, so a consumer can find it.
var deprecatedFields = []string{
	"overall_risk_score", "overall_risk_level", "headline",
	"summary.critical_risk_count", "summary.high_risk_count", "summary.medium_risk_count", "summary.low_risk_count",
	"dependencies[].risk_score", "dependencies[].risk_level",
}

// JSONHeadline is the deprecated headline object, derived from the grade's deciding row.
type JSONHeadline struct {
	// Deprecated: read grade.letter and grade.deciding.
	// It is omitted on a Pending result (and without a grade): a 0 would read as the cleanest result.
	Score *float64 `json:"score,omitempty"`
	Level string   `json:"level"`
	// Driver is "grade_row" when a row decides the letter, or the whole-tree rule that does.
	Driver      string `json:"driver,omitempty"`
	DrivingItem string `json:"driving_item,omitempty"`
	Reason      string `json:"reason,omitempty"`
	// Candidates is always empty: the five headline candidates no longer exist.
	Candidates []struct{} `json:"candidates"`
}

// deprecatedLevel is the coarse band of a letter, or UNKNOWN when there is none.
func deprecatedLevel(l grade.Letter) string {
	switch l {
	case grade.LetterA, grade.LetterB:
		return "LOW"
	case grade.LetterC:
		return "MEDIUM"
	case grade.LetterD:
		return "HIGH"
	case grade.LetterF:
		return "CRITICAL"
	}
	return "UNKNOWN"
}

// deprecatedHeadline derives the old headline from the grade.
func deprecatedHeadline(g *grade.Result) JSONHeadline {
	h := JSONHeadline{Level: "UNKNOWN", Candidates: []struct{}{}}
	if g == nil {
		return h
	}
	h.Level = deprecatedLevel(g.Letter)
	if score := gradeScore(g); score != nil {
		v := float64(*score)
		h.Score = &v
	}
	if g.Deciding != nil {
		h.Driver, h.DrivingItem, h.Reason = "grade_row", g.Deciding.Module, g.Deciding.Reason
		if g.Deciding.Tree != "" {
			h.Driver = g.Deciding.Tree
		}
	}
	return h
}

// deprecatedRows indexes the dependency rows (not the module itself) of the grade by module path.
func deprecatedRows(g *grade.Result) map[string]grade.RowResult {
	rows := map[string]grade.RowResult{}
	if g == nil {
		return rows
	}
	for i := range g.Rows {
		if !g.Rows[i].Self {
			rows[g.Rows[i].Module] = g.Rows[i]
		}
	}
	return rows
}

// gradeScore is the worst row's policy value, or nil without a grade or when it is Pending: no check, no number (a
// published 0 reads as the cleanest result, and a v1 gate such as "overall_risk_score <= 60" would pass).
func gradeScore(g *grade.Result) *int {
	if g == nil || g.Pending != nil {
		return nil
	}
	v := g.Score
	return &v
}

// rowScore is a dependency row's policy value, or nil when the grade is Pending or the row has no letter (its upkeep
// could not be read, so the number is partial) or no row exists.
func rowScore(g *grade.Result, r grade.RowResult, found bool) *int {
	if g == nil || g.Pending != nil || !found || r.Letter == "" {
		return nil
	}
	v := r.Score
	return &v
}

// deprecatedCounts counts the dependency rows by coarse level, for the deprecated summary fields.
func deprecatedCounts(g *grade.Result) (critical, high, medium, low int) {
	for _, r := range deprecatedRows(g) {
		switch deprecatedLevel(r.Letter) {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		case "LOW":
			low++
		}
	}
	return
}

func hasRow(rows map[string]grade.RowResult, module string) bool {
	_, ok := rows[module]
	return ok
}
