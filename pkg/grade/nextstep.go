package grade

import (
	"sort"
	"strings"

	"golang.org/x/mod/semver"
)

// stdlibRow is the row name of the Go standard library (the runner's stdlibModule): its upgrade is a Go release, not a module.
const stdlibRow = "stdlib"

// nextStep names the one upgrade that would improve the letter most, and the letter after it, for the final result res of the
// merged input in. It is nil when the grade is Pending, when nothing decides it, or when no candidate has a counted finding with
// a fix.
//
//   - A row decides by its vulnerability score: that row's upgrade. A row that decides by upkeep has no upgrade that changes it.
//   - A whole-tree rule decides: every row with a counted finding that has a fix is a candidate, each is graded again without
//     what its upgrade fixes, and the best result wins: one that is not Pending, then the better letter, then the lower score,
//     then the earlier row (res.Rows is worst first and deterministic). It is named only if it improves the letter: an upgrade
//     that leaves the letter as it is (or after which the grade would be Pending) is not offered. A row that decides keeps its
//     own step even when another row leaves the same letter: that is the honest "D after" answer.
func nextStep(in *Input, res *Result) *NextStep {
	if res.Pending != nil || res.Deciding == nil || len(res.Rows) == 0 {
		return nil
	}
	candidates := res.Rows
	if res.Deciding.Tree == "" {
		w := res.Rows[0]
		if !(w.VulnScore >= w.UpkeepScore && w.VulnScore > 0) {
			return nil
		}
		candidates = res.Rows[:1]
	}
	var best *NextStep
	for i := range candidates {
		n := upgradeFor(in, &candidates[i])
		if n == nil {
			continue
		}
		if best == nil || betterStep(n, best) {
			best = n
		}
	}
	if best != nil && res.Deciding.Tree != "" && (best.LetterAfter == "" || best.LetterAfter >= res.Letter) {
		// a whole-tree rule decides and no upgrade improves the letter (a checksum mismatch, say, which no upgrade clears):
		// nothing is named, so the reader is not told to run something that cannot change the grade
		return nil
	}
	return best
}

// betterStep reports whether a is a better result than b: not Pending, then the better letter, then the lower score. A tie is
// not better, so the earlier candidate stays.
func betterStep(a, b *NextStep) bool {
	if ap, bp := a.LetterAfter == "", b.LetterAfter == ""; ap != bp {
		return !ap
	}
	if a.LetterAfter != b.LetterAfter {
		return a.LetterAfter < b.LetterAfter // "A" < "B" < ... < "F"
	}
	return a.ScoreAfter < b.ScoreAfter
}

// upgradeFor is the upgrade of one row: the highest fixed version among its counted findings, and the grade without what that
// version fixes. nil when no counted finding of the row has a fix that is a version.
func upgradeFor(in *Input, r *RowResult) *NextStep {
	var target string
	for i := range r.Findings {
		f := &r.Findings[i]
		if !f.Counted {
			continue
		}
		v, ok := fixVersion(f.FixedVersion)
		if ok && (target == "" || semver.Compare(v, target) > 0) {
			target = v
		}
	}
	if target == "" {
		return nil
	}
	clears := map[string]bool{}
	for i := range r.Findings {
		if v, ok := fixVersion(r.Findings[i].FixedVersion); ok && semver.Compare(v, target) <= 0 {
			clears[r.Findings[i].ID] = true
		}
	}
	ids := make([]string, 0, len(clears))
	for id := range clears {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	alt := *in
	drop := func(row Row) Row {
		kept := make([]Finding, 0, len(row.Findings))
		for i := range row.Findings {
			if !clears[row.Findings[i].ID] {
				kept = append(kept, row.Findings[i])
			}
		}
		row.Findings = kept
		return row
	}
	if r.Self {
		alt.Self = drop(in.Self)
	} else {
		alt.Deps = make([]Row, len(in.Deps))
		for i, d := range in.Deps {
			if d.Module == r.Module {
				d = drop(d)
			}
			alt.Deps[i] = d
		}
	}
	after := gradeOnce(&alt)
	n := &NextStep{Module: r.Module, Version: target, Clears: ids, LetterAfter: after.Letter, ScoreAfter: after.Score}
	n.Command = "go get " + r.Module + "@" + target
	if r.Module == stdlibRow && !r.Self {
		n.Command = "go get toolchain@go" + strings.TrimPrefix(target, "v")
	}
	if after.Pending != nil {
		n.LetterAfter, n.ScoreAfter, n.PendingAfter = "", 0, after.Pending.Check
	}
	return n
}

// fixVersion reads a fixed version as semver ("v1.2.3"): a leading "v" is added when missing. ok is false for a value that is
// not a version.
func fixVersion(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if !strings.HasPrefix(s, "v") {
		s = "v" + s
	}
	return s, semver.IsValid(s)
}
