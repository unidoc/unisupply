package report

import (
	"fmt"
	"sort"

	"github.com/unidoc/unipdf/v5/creator"
	"github.com/unidoc/unipdf/v5/model"

	"github.com/unidoc/unisupply/pkg/grade"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// pdfLetterColor colours a grade letter (with or without the estimate star); "-" and PENDING are grey, never green.
func pdfLetterColor(letter string) creator.Color {
	switch letter {
	case "F", "F*":
		return creator.ColorRGBFromHex("#cc0000")
	case "D", "D*":
		return creator.ColorRGBFromHex("#e67300")
	case "C", "C*":
		return creator.ColorRGBFromHex("#ccaa00")
	case "A", "A*", "B", "B*":
		return creator.ColorRGBFromHex("#009900")
	}
	return creator.ColorRGBFromHex("#666666")
}

func pdfPara(c *creator.Creator, text string, font *model.PdfFont, size float64, color creator.Color, center bool, margins [4]float64) *creator.StyledParagraph {
	p := c.NewStyledParagraph()
	ch := p.Append(text)
	ch.Style.Font = font
	ch.Style.FontSize = size
	ch.Style.Color = color
	if center {
		p.SetTextAlignment(creator.TextAlignmentCenter)
	}
	p.SetMargins(margins[0], margins[1], margins[2], margins[3])
	return p
}

// writeGradeCoverBlock draws the big letter on the cover, with the deciding row, or the pending reason.
func writeGradeCoverBlock(c *creator.Creator, g *grade.Result, regular, bold *model.PdfFont) {
	grey := creator.ColorRGBFromHex("#666666")
	if g == nil {
		_ = c.Draw(pdfPara(c, gradeNoGradeLine, bold, 18, grey, true, [4]float64{0, 0, 40, 10}))
		return
	}
	label := gradeLetterLabel(g)
	_ = c.Draw(pdfPara(c, "Supply-Chain Grade", regular, 14, grey, true, [4]float64{0, 0, 30, 0}))
	_ = c.Draw(pdfPara(c, label, bold, 72, pdfLetterColor(label), true, [4]float64{0, 0, 0, 5}))

	var lines []string
	switch {
	case g.Pending != nil:
		lines = append(lines, "Why: "+g.Pending.Reason)
	case g.Estimated:
		lines = append(lines, gradeEstimatedFoot)
	}
	if g.Deciding != nil && g.Pending == nil {
		lines = append(lines, fmt.Sprintf("Decided by: %s (score %d): %s", gradeDecidingText(g.Deciding), g.Deciding.Score, g.Deciding.Reason))
	}
	for _, l := range lines {
		_ = c.Draw(pdfPara(c, l, regular, 11, grey, true, [4]float64{0, 0, 0, 4}))
	}
}

// writeGradeSection draws the grade page(s): the letter, pending details, the rows table, findings, tree rules, notes.
func writeGradeSection(c *creator.Creator, g *grade.Result, regular, bold *model.PdfFont) {
	c.NewPage()
	heading(c, "Grade", bold)

	if g == nil {
		_ = c.Draw(pdfPara(c, gradeNoGradeLine, regular, 11, creator.ColorBlack, false, [4]float64{0, 0, 0, 10}))
		return
	}

	label := gradeLetterLabel(g)
	_ = c.Draw(pdfPara(c, "Grade: "+label, bold, 20, pdfLetterColor(label), false, [4]float64{0, 0, 0, 6}))
	if g.Pending == nil && g.Estimated {
		_ = c.Draw(pdfPara(c, gradeEstimatedFoot, regular, 10, creator.ColorBlack, false, [4]float64{0, 0, 0, 6}))
	}
	if d := g.Deciding; d != nil && g.Pending == nil {
		subheading(c, "Decided by", bold)
		_ = c.Draw(pdfPara(c, fmt.Sprintf("%s (score %d)", gradeDecidingText(d), d.Score), bold, 11, creator.ColorBlack, false, [4]float64{0, 0, 0, 2}))
		_ = c.Draw(pdfPara(c, d.Reason, regular, 10, creator.ColorBlack, false, [4]float64{0, 0, 0, 8}))
	}
	if p := g.Pending; p != nil {
		subheading(c, "Pending", bold)
		_ = c.Draw(pdfPara(c, "Why: "+p.Reason, regular, 10, creator.ColorBlack, false, [4]float64{0, 0, 0, 2}))
		_ = c.Draw(pdfPara(c, "Check that did not run: "+p.Check, regular, 10, creator.ColorBlack, false, [4]float64{0, 0, 0, 6}))
		if len(p.Known) > 0 {
			known := c.NewStyledParagraph()
			known.SetMargins(0, 0, 0, 8)
			known.SetLineHeight(1.5)
			addBullet(known, "What we do know:", bold)
			for _, k := range p.Known {
				addBullet(known, "  "+k, regular)
			}
			_ = c.Draw(known)
		}
	}

	writeGradeRowsPDF(c, g, regular, bold)

	if len(g.TreeRows) > 0 {
		subheading(c, "Whole-tree rules", bold)
		table := c.NewTable(4)
		table.SetMargins(0, 0, 5, 10)
		if err := table.SetColumnWidths(0.28, 0.1, 0.1, 0.52); err != nil {
			return
		}
		addTableHeader(c, table, []string{"Rule", "Grade", "Score", "Reason"}, bold)
		for _, t := range g.TreeRows {
			l := string(t.Letter)
			if t.Estimated {
				l += "*"
			}
			addTableRow4(c, table, t.Rule, l, fmt.Sprintf("%d", t.Score), t.Reason, regular)
		}
		_ = c.Draw(table)
	}

	if len(g.Notes) > 0 {
		subheading(c, "Notes", bold)
		p := c.NewStyledParagraph()
		p.SetMargins(0, 0, 5, 0)
		p.SetLineHeight(1.5)
		for _, n := range g.Notes {
			addBullet(p, n, regular)
		}
		_ = c.Draw(p)
	}
}

func writeGradeRowsPDF(c *creator.Creator, g *grade.Result, regular, bold *model.PdfFont) {
	if len(g.Rows) == 0 {
		return
	}
	subheading(c, "Rows (worst first)", bold)

	table := c.NewTable(6)
	table.SetMargins(0, 0, 5, 10)
	if err := table.SetColumnWidths(0.27, 0.12, 0.08, 0.08, 0.12, 0.33); err != nil {
		return
	}
	addTableHeader(c, table, []string{"Module", "Version", "Grade", "Score", "Upkeep", "Reason"}, bold)
	for i := range g.Rows {
		r := &g.Rows[i]
		name := r.Module
		if r.Self {
			name += " (" + gradeThisModuleLabel + ")"
		}
		for _, v := range []string{name, r.Version, gradeRowLabel(r), fmt.Sprintf("%d", r.Score), r.UpkeepState, r.Reason} {
			cell := table.NewCell()
			if err := cell.SetContent(pdfPara(c, v, regular, 9, creator.ColorBlack, false, [4]float64{0, 0, 0, 0})); err != nil {
				fmt.Printf("Error setting grade table content: %v\n", err)
			}
		}
	}
	_ = c.Draw(table)

	first := true
	for i := range g.Rows {
		r := &g.Rows[i]
		if len(r.Findings) == 0 {
			continue
		}
		if first {
			subheading(c, "Findings", bold)
			first = false
		}
		name := r.Module
		if r.Self {
			name += " (" + gradeThisModuleLabel + ")"
		}
		_ = c.Draw(pdfPara(c, fmt.Sprintf("%s %s — %s", name, r.Version, gradeRowLabel(r)), bold, 11, pdfLetterColor(gradeRowLabel(r)), false, [4]float64{0, 0, 5, 3}))
		p := c.NewStyledParagraph()
		p.SetMargins(20, 0, 0, 8)
		p.SetLineHeight(1.5)
		for i := range r.Findings {
			f := &r.Findings[i]
			addBullet(p, fmt.Sprintf("%s: severity %s, tier %s, %s", f.ID, gradeFindingSeverity(f), f.Tier, gradeCountedLabelFor(f)), regular)
			if f.Exploited {
				addBullet(p, "  Known exploited (CISA KEV)", regular)
			}
			if f.FixedVersion != "" {
				addBullet(p, "  Fixed in: "+f.FixedVersion, regular)
			}
			if f.Response.Text != "" {
				addBullet(p, "  Response: "+f.Response.Text, regular)
			}
			addBullet(p, "  VEX: "+gradeVEXText(f.VEX), regular)
			if f.Condition != "" {
				addBullet(p, "  Condition: "+f.Condition, regular)
			}
			if f.Note != "" {
				addBullet(p, "  Note: "+f.Note, regular)
			}
		}
		_ = c.Draw(p)
	}
}

// writeDependencyFindings draws the full detail block (call paths, symbols, upkeep) of every dependency that has a
// vulnerability, worst grade row first.
func writeDependencyFindings(c *creator.Creator, ps *scorer.ProjectScore, g *grade.Result, regular, bold *model.PdfFont) {
	rows := gradeRowIndex(g)
	var deps []*scorer.DependencyScore
	for _, ds := range ps.Dependencies {
		if len(ds.Vulns) > 0 {
			deps = append(deps, ds)
		}
	}
	if len(deps) == 0 {
		return
	}
	sort.SliceStable(deps, func(i, j int) bool {
		ri, rj := rows[deps[i].Module], rows[deps[j].Module]
		if ri != nil && rj != nil && ri.Score != rj.Score {
			return ri.Score > rj.Score
		}
		return deps[i].RiskScore > deps[j].RiskScore
	})

	c.NewPage()
	heading(c, fmt.Sprintf("Dependencies with Vulnerabilities (%d)", len(deps)), bold)
	for _, ds := range deps {
		writeDependencyBlock(c, ds, gradeRowLabel(rows[ds.Module]), regular, bold, true)
	}
}
