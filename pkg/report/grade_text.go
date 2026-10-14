package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/unidoc/unisupply/pkg/grade"
)

// Texts shared by the text and PDF reports.
const (
	gradeNoGradeLine     = "No grade: grading was not run"
	gradeEstimatedFoot   = "Estimated: at least one finding had no published severity and was scored as medium"
	gradeNotGradedLabel  = "shown, not graded"
	gradeCountedLabel    = "counted"
	gradeThisModuleLabel = "this module"
)

// gradeLetterLabel is the big letter: "C", "C*" when estimated, "PENDING" when no letter was given.
func gradeLetterLabel(g *grade.Result) string {
	if g.Pending != nil || g.Letter == "" {
		return "PENDING"
	}
	l := string(g.Letter)
	if g.Estimated {
		l += "*"
	}
	return l
}

// gradeRowIndex maps a module path to its grade row. The module's own row ("self") is keyed by its module path too.
func gradeRowIndex(g *grade.Result) map[string]*grade.RowResult {
	idx := map[string]*grade.RowResult{}
	if g == nil {
		return idx
	}
	for i := range g.Rows {
		r := &g.Rows[i]
		if _, ok := idx[r.Module]; !ok {
			idx[r.Module] = r
		}
	}
	return idx
}

// gradeRowLabel is a row's letter for a listing ("-" when the dependency has no row).
func gradeRowLabel(r *grade.RowResult) string {
	if r == nil || r.Letter == "" {
		return "-"
	}
	l := string(r.Letter)
	if r.Estimated {
		l += "*"
	}
	return l
}

// gradeNeedsDetail is true for rows that are C or worse: their detail is always shown.
func gradeNeedsDetail(r *grade.RowResult) bool {
	if r == nil {
		return false
	}
	switch r.Letter {
	case grade.LetterC, grade.LetterD, grade.LetterF:
		return true
	}
	return false
}

// gradeRowCarriesInfo is true for a row that tells the reader something: a letter other than A, any finding, or an upkeep
// state other than finished/active (parked, deprecated, archived, unknown). The rest are "A, nothing found".
func gradeRowCarriesInfo(r *grade.RowResult) bool {
	if r.Letter != grade.LetterA || len(r.Findings) > 0 || r.UpkeepNote != "" {
		return true
	}
	return r.UpkeepState != grade.StateFinished && r.UpkeepState != grade.StateActive
}

// gradeRowsToShow picks the rows of the rows table, worst first. all lists every row (--verbose); otherwise only the rows
// that carry information. quiet is the number of rows left out: all graded A with nothing found.
func gradeRowsToShow(g *grade.Result, all bool) (shown []*grade.RowResult, quiet int) {
	for i := range g.Rows {
		r := &g.Rows[i]
		if all || gradeRowCarriesInfo(r) {
			shown = append(shown, r)
		} else {
			quiet++
		}
	}
	sort.SliceStable(shown, func(i, j int) bool { return shown[i].Score > shown[j].Score })
	return shown, quiet
}

// gradeQuietRowsLine is the one line that stands for the rows left out of the table ("" when none were).
func gradeQuietRowsLine(n int) string {
	switch n {
	case 0:
		return ""
	case 1:
		return "1 more row graded A with nothing found"
	}
	return fmt.Sprintf("%d more rows graded A with nothing found", n)
}

// gradeWrapModulePath breaks a module path into lines of at most width characters, only at '/' boundaries (the slash stays
// at the end of its line). A segment longer than width is cut with "..." rather than split mid-word.
func gradeWrapModulePath(path string, width int) []string {
	if width < 4 {
		width = 4
	}
	var lines []string
	cur := ""
	parts := strings.SplitAfter(path, "/")
	for _, p := range parts {
		if p == "" {
			continue
		}
		if len(p) > width {
			p = p[:width-3] + "..."
		}
		if cur != "" && len(cur)+len(p) > width {
			lines = append(lines, cur)
			cur = ""
		}
		cur += p
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// gradeLetterCounts renders "F 1, C 2, A 10" for the rows, worst first, skipping letters with no rows.
func gradeLetterCounts(g *grade.Result) string {
	counts := map[grade.Letter]int{}
	for _, r := range g.Rows {
		counts[r.Letter]++
	}
	var parts []string
	for _, l := range []grade.Letter{grade.LetterF, grade.LetterD, grade.LetterC, grade.LetterB, grade.LetterA, ""} {
		if n := counts[l]; n > 0 {
			name := string(l)
			if name == "" {
				name = "not graded"
			}
			parts = append(parts, fmt.Sprintf("%s %d", name, n))
		}
	}
	return strings.Join(parts, ", ")
}

func gradeLetterColor(letter string) string {
	switch strings.TrimSuffix(letter, "*") {
	case "F":
		return colorRed
	case "D":
		return colorOrange
	case "C":
		return colorYellow
	case "A", "B":
		return colorGreen
	}
	return colorDim
}

// gradeDecidingText names what set the letter: a module, "this module", or the whole-tree rule.
func gradeDecidingText(d *grade.Deciding) string {
	switch {
	case d.Tree != "":
		return "whole-tree rule " + d.Tree
	case d.Self:
		return gradeThisModuleLabel
	default:
		return d.Module
	}
}

// gradeCountedLabelFor says whether a finding counted toward the letter.
func gradeCountedLabelFor(f *grade.FindingResult) string {
	if f.Counted {
		return gradeCountedLabel
	}
	return gradeNotGradedLabel
}

// gradeVEXText renders the VEX status with its justification.
func gradeVEXText(v grade.VEXStatus) string {
	if v.Justification != "" {
		return v.Status + " (" + v.Justification + ")"
	}
	return v.Status
}

// gradeFindingSeverity is the scored severity, marked when it was estimated.
func gradeFindingSeverity(f *grade.FindingResult) string {
	sev := f.Severity
	if sev == "" {
		sev = "UNKNOWN"
	}
	if f.Estimated {
		sev += " (estimated)"
	}
	return sev
}

// writeGradeText writes the grade block, the rows table, the whole-tree rows and the notes.
func writeGradeText(w io.Writer, c func(string, string) string, g *grade.Result, verbose bool) {
	bar := "═══════════════════════════════════════════════════"
	fmt.Fprintf(w, "%s\n", bar)
	if g == nil {
		fmt.Fprintf(w, "%s\n", c(colorDim, gradeNoGradeLine))
		fmt.Fprintf(w, "%s\n\n", bar)
		return
	}

	label := gradeLetterLabel(g)
	fmt.Fprintf(w, "SUPPLY-CHAIN GRADE: %s\n", c(gradeLetterColor(label), label))
	if g.Pending != nil || g.Letter == "" {
		if p := g.Pending; p != nil {
			fmt.Fprintf(w, "  Why: %s\n", p.Reason)
			fmt.Fprintf(w, "  Check that did not run: %s\n", p.Check)
			if len(p.Known) > 0 {
				fmt.Fprintf(w, "  What we do know:\n")
				for _, k := range p.Known {
					fmt.Fprintf(w, "    - %s\n", k)
				}
			}
		}
	} else if g.Estimated {
		fmt.Fprintf(w, "  %s\n", gradeEstimatedFoot)
	}
	if g.Deciding != nil && g.Pending == nil {
		fmt.Fprintf(w, "  Decided by: %s (score %d) — %s\n", gradeDecidingText(g.Deciding), g.Deciding.Score, g.Deciding.Reason)
	}
	fmt.Fprintf(w, "%s\n\n", bar)

	writeGradeRowsText(w, c, g, verbose)

	if len(g.TreeRows) > 0 {
		fmt.Fprintf(w, "WHOLE-TREE RULES\n")
		for _, t := range g.TreeRows {
			l := string(t.Letter)
			if t.Estimated {
				l += "*"
			}
			fmt.Fprintf(w, "  %s  %s (score %d) — %s\n", c(gradeLetterColor(l), l), t.Rule, t.Score, t.Reason)
		}
		fmt.Fprintln(w)
	}

	if len(g.Notes) > 0 {
		fmt.Fprintf(w, "GRADE NOTES\n")
		for _, n := range g.Notes {
			fmt.Fprintf(w, "  - %s\n", n)
		}
		fmt.Fprintln(w)
	}
}

func writeGradeRowsText(w io.Writer, c func(string, string) string, g *grade.Result, verbose bool) {
	if len(g.Rows) == 0 {
		return
	}
	rows, quiet := gradeRowsToShow(g, verbose)
	modW, verW := len("MODULE"), len("VERSION")
	names := make([]string, len(rows))
	for i, r := range rows {
		names[i] = r.Module
		if r.Self {
			names[i] += " (" + gradeThisModuleLabel + ")"
		}
		if n := len(names[i]); n > modW {
			modW = n
		}
		if n := len(r.Version); n > verW {
			verW = n
		}
	}

	fmt.Fprintf(w, "GRADE TABLE (worst first)\n")
	fmt.Fprintf(w, "  %-*s  %-*s  %-6s %5s  %-10s  %s\n", modW, "MODULE", verW, "VERSION", "GRADE", "SCORE", "UPKEEP", "REASON")
	for i, r := range rows {
		l := gradeRowLabel(r)
		fmt.Fprintf(w, "  %-*s  %-*s  %s %5d  %-10s  %s\n", modW, names[i], verW, r.Version,
			c(gradeLetterColor(l), fmt.Sprintf("%-6s", l)), r.Score, r.UpkeepState, r.Reason)
		if r.UpkeepNote != "" {
			fmt.Fprintf(w, "      Maintainers say: %s\n", r.UpkeepNote)
		}
		for i := range r.Findings {
			f := &r.Findings[i]
			fmt.Fprintf(w, "      %s  severity %s, tier %s, %s\n", f.ID, gradeFindingSeverity(f), f.Tier, gradeCountedLabelFor(f))
			if f.Exploited {
				fmt.Fprintf(w, "        Known exploited (CISA KEV)\n")
			}
			if f.FixedVersion != "" {
				fmt.Fprintf(w, "        Fixed in: %s\n", f.FixedVersion)
			}
			if f.Response.Text != "" {
				fmt.Fprintf(w, "        Response: %s\n", f.Response.Text)
			}
			if f.Response.History != "" {
				fmt.Fprintf(w, "        History: %s\n", f.Response.History)
			}
			fmt.Fprintf(w, "        VEX: %s\n", gradeVEXText(f.VEX))
			if f.Condition != "" {
				fmt.Fprintf(w, "        Condition: %s\n", f.Condition)
			}
			if f.Note != "" {
				fmt.Fprintf(w, "        Note: %s\n", f.Note)
			}
		}
	}
	if line := gradeQuietRowsLine(quiet); line != "" {
		fmt.Fprintf(w, "  %s\n", c(colorDim, line+" — use --verbose to list them"))
	}
	fmt.Fprintln(w)
}
