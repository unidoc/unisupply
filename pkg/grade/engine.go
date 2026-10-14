package grade

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Vulnerability score by severity and tier (rules version 2). A graph-only finding is shown, not graded: it has no
// entry. The numbers are set so outcomes land in the intended band (one called high is D, three are F, an imported
// high stays below D); they are policy values, not measured risk.
var (
	calledScore   = map[string]int{"CRITICAL": 90, "HIGH": 70, "MEDIUM": 45, "LOW": 15}
	importedScore = map[string]int{"CRITICAL": 50, "HIGH": 49, "MEDIUM": 32, "LOW": 11}
)

const (
	importedCap        = 50 // an imported finding alone can never reach D
	furtherAdvisoryAdd = 5  // for each further distinct called high or critical advisory on a row
	exploitedFloor     = 76 // a called known-exploited finding is F
	testOnlyCap        = 50 // a test-only dependency's vulnerability score, after halving, is at most C

	upkeepSelf       = 35 // archived or deprecated: the module itself, at best C
	upkeepDependency = 20 // archived or deprecated dependency, at best B
	upkeepMinor      = 10 // ... when it is test-only or not compiled into the build

	treeFScore = 76 // the score of a whole-tree rule that makes the letter F
	treeDScore = 51 // ... and of the "at least D" rule

	treeCalledFindings   = 3 // called high or critical findings across the tree: F
	treeImportedOrCalled = 5 // called-or-imported high or critical findings across the tree: at least D

	activeSelfMonths = 12 // the module itself is active if it released or committed within this many months
	activeDepMonths  = 24 // a dependency is active if it released within this many months
)

// Bands: A <= 10, B <= 25, C <= 50, D <= 75, F above.
func bandOf(score int) Letter {
	switch {
	case score <= 10:
		return LetterA
	case score <= 25:
		return LetterB
	case score <= 50:
		return LetterC
	case score <= 75:
		return LetterD
	default:
		return LetterF
	}
}

func isConfirmed(b *bool) bool { return b != nil && *b }
func isRefuted(b *bool) bool   { return b != nil && !*b }

// severityOf normalizes a severity: unknown or missing is scored as MEDIUM and flagged as an estimate.
func severityOf(s string) (sev string, estimated bool) {
	switch u := strings.ToUpper(strings.TrimSpace(s)); u {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return u, false
	}
	return "MEDIUM", true
}

func highOrCritical(sev string) bool { return sev == "HIGH" || sev == "CRITICAL" }

// tierOf maps govulncheck's reachability to a tier. A module's own advisories are scored as called: anyone who uses the
// module can use its vulnerable code, and govulncheck does not check the module it starts from.
func tierOf(reachability string, self bool) (tier string, assumed bool) {
	if self {
		return TierCalled, reachability == ""
	}
	switch strings.ToLower(strings.TrimSpace(reachability)) {
	case "called":
		return TierCalled, false
	case "imported":
		return TierImported, false
	case "required":
		return TierGraphOnly, false
	}
	return TierCalled, true // not determined: the worst case
}

func vexFor(tier string) VEXStatus {
	switch tier {
	case TierGraphOnly:
		return VEXStatus{Status: "not_affected", Justification: "vulnerable_code_not_present"}
	case TierImported:
		return VEXStatus{Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path"}
	}
	return VEXStatus{Status: "affected"}
}

// scored is a finding with what the grade needs to score it.
type scored struct {
	Finding
	sev       string
	estimated bool
	tier      string
	assumed   bool
	score     int // table value (0 for graph-only)
}

func scoreFinding(f Finding, self bool) scored {
	sev, est := severityOf(f.Severity)
	tier, assumed := tierOf(f.Reachability, self)
	s := scored{Finding: f, sev: sev, estimated: est, tier: tier, assumed: assumed}
	switch tier {
	case TierCalled:
		s.score = calledScore[sev]
	case TierImported:
		s.score = importedScore[sev]
	}
	return s
}

// monthsSince is whole calendar months from t to now (0 when t is zero or in the future).
func monthsSince(t, now time.Time) int {
	if t.IsZero() || t.After(now) {
		return 0
	}
	m := (now.Year()-t.Year())*12 + int(now.Month()) - int(t.Month())
	if now.Day() < t.Day() {
		m--
	}
	if m < 0 {
		m = 0
	}
	return m
}

// upkeepState classifies a row. Archived beats deprecated (a deprecated or retracted version reads as Deprecated), then
// active (the module itself: a release or a commit on its default branch in the last 12 months; a dependency: a release in
// the last 24 months), then finished or parked: quiet with nothing open, or quiet with something open.
func upkeepState(r Row, now time.Time) string {
	u := r.Upkeep
	switch {
	case u.Archived:
		return StateArchived
	case u.Deprecated || u.Retracted:
		return StateDeprecated
	case u.Missing:
		return StateUnknown
	}
	active := false
	if r.Self {
		active = (!u.LastRelease.IsZero() && monthsSince(u.LastRelease, now) < activeSelfMonths) ||
			(!u.LastActivity.IsZero() && monthsSince(u.LastActivity, now) < activeSelfMonths)
	} else {
		active = !u.LastRelease.IsZero() && monthsSince(u.LastRelease, now) < activeDepMonths
	}
	if active {
		return StateActive
	}
	for _, f := range r.Findings {
		if strings.TrimSpace(f.FixedVersion) == "" {
			return StateParked
		}
	}
	return StateFinished
}

// upkeepScore is the upkeep half of a row's score: archived or deprecated only; quiet is a fact, not a risk.
func upkeepScore(r Row, state string) int {
	if state != StateArchived && state != StateDeprecated {
		return 0
	}
	if r.Self {
		return upkeepSelf
	}
	if isConfirmed(r.TestOnly) || isRefuted(r.InBuild) {
		return upkeepMinor
	}
	return upkeepDependency
}

// vulnScore applies the order of operations to one row's findings:
//
//  1. called findings: the worst one's table value, plus 5 for each further distinct called high or critical advisory;
//  2. imported findings: the same with the imported column, capped at 50 (C): only called findings push a row to D or F;
//  3. the row's vulnerability score is the higher of the two;
//  4. a called known-exploited finding: at least 76 (F);
//  5. a confirmed test-only dependency: halve it and cap it at 50, so a test-only known-exploited finding lands at C.
func vulnScore(r Row, fs []scored) (score int, est bool, top *scored, reason string) {
	type tierSet struct{ list []*scored }
	var called, imported tierSet
	for i := range fs {
		switch fs[i].tier {
		case TierCalled:
			called.list = append(called.list, &fs[i])
		case TierImported:
			imported.list = append(imported.list, &fs[i])
		}
	}
	best := func(ts tierSet, cap int) (int, *scored, int) {
		if len(ts.list) == 0 {
			return 0, nil, 0
		}
		// distinct advisories by ID: the same advisory seen twice counts once, at its worst
		byID := map[string]*scored{}
		for _, f := range ts.list {
			if cur, ok := byID[f.ID]; !ok || f.score > cur.score {
				byID[f.ID] = f
			}
		}
		ids := make([]string, 0, len(byID))
		for id := range byID {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool {
			a, b := byID[ids[i]], byID[ids[j]]
			if a.score != b.score {
				return a.score > b.score
			}
			return a.ID < b.ID
		})
		top := byID[ids[0]]
		further := 0
		for _, id := range ids[1:] {
			if highOrCritical(byID[id].sev) {
				further++
			}
		}
		s := top.score + further*furtherAdvisoryAdd
		if cap > 0 && s > cap {
			s = cap
		}
		return s, top, further
	}
	cs, ctop, cfurther := best(called, 0)
	is, itop, ifurther := best(imported, importedCap)
	switch {
	case cs >= is && ctop != nil:
		score, top = cs, ctop
		reason = describeVuln(ctop, "called", cfurther)
	case itop != nil:
		score, top = is, itop
		reason = describeVuln(itop, "imported", ifurther)
	}
	for _, f := range called.list {
		if f.Exploited && score < exploitedFloor {
			score, top = exploitedFloor, f
			reason = fmt.Sprintf("called known-exploited %s %s (at least %d)", strings.ToLower(f.sev), f.ID, exploitedFloor)
		}
	}
	if top != nil {
		est = top.estimated
	}
	if isConfirmed(r.TestOnly) && score > 0 {
		half := score / 2
		if half > testOnlyCap {
			half = testOnlyCap
		}
		reason += fmt.Sprintf("; test-only dependency: halved to %d", half)
		score = half
	}
	return score, est, top, reason
}

func describeVuln(top *scored, tier string, further int) string {
	who := top.ID
	est := ""
	if top.estimated {
		est = " (severity unknown, estimated as medium)"
	}
	s := fmt.Sprintf("%s %s %s%s (%d)", tier, strings.ToLower(top.sev), who, est, top.score)
	if further > 0 {
		s += fmt.Sprintf(", +%d for %d more %s high or critical advisor%s", further*furtherAdvisoryAdd, further, tier, plural(further, "y", "ies"))
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func upkeepReason(r Row, state string, score int) string {
	who := "dependency"
	if r.Self {
		who = "module"
	}
	var what string
	switch {
	case r.Upkeep.Archived:
		what = "archived"
	case r.Upkeep.Retracted && !r.Upkeep.Deprecated:
		what = "this version is retracted"
	default:
		what = "deprecated"
	}
	if score == upkeepMinor {
		who += " (test-only or not compiled in)"
	}
	return fmt.Sprintf("%s %s (%d)", what, who, score)
}

// gradeRow scores one row.
func gradeRow(r Row, in Input) RowResult {
	state := upkeepState(r, in.Now)
	fs := make([]scored, 0, len(r.Findings))
	for _, f := range r.Findings {
		fs = append(fs, scoreFinding(f, r.Self))
	}
	vs, est, top, vreason := vulnScore(r, fs)
	us := upkeepScore(r, state)
	score := vs
	if us > score {
		score = us
	}
	if score > 100 {
		score = 100
	}
	rr := RowResult{
		Module: r.Module, Version: r.Version, Self: r.Self, Direct: r.Direct,
		TestOnly: isConfirmed(r.TestOnly), NotBuilt: isRefuted(r.InBuild),
		Score: score, VulnScore: vs, UpkeepScore: us, Letter: bandOf(score),
		UpkeepState: state, UpkeepNote: strings.TrimSpace(r.Upkeep.Message), UpkeepMissed: r.Upkeep.Missing,
	}
	switch {
	case vs > 0 && vs >= us:
		rr.Reason = vreason
		rr.Estimated = est
	case us > 0:
		rr.Reason = upkeepReason(r, state, us)
	case len(fs) > 0:
		rr.Reason = "findings are shown, not graded"
	case state == StateUnknown:
		rr.Reason = "upkeep could not be read"
	default:
		rr.Reason = "nothing found"
	}
	_ = top
	for _, f := range fs {
		rr.Findings = append(rr.Findings, findingResult(f, r, in))
	}
	sort.SliceStable(rr.Findings, func(i, j int) bool {
		a, b := rr.Findings[i], rr.Findings[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.ID < b.ID
	})
	return rr
}

// preferVuln reports whether row a is the deciding row over b when scores are equal: a vulnerability beats upkeep, then the
// module itself, then a direct dependency, then alphabetical by module path.
func preferVuln(a, b RowResult) bool {
	av, bv := a.VulnScore >= a.UpkeepScore && a.VulnScore > 0, b.VulnScore >= b.UpkeepScore && b.VulnScore > 0
	if av != bv {
		return av
	}
	if a.Self != b.Self {
		return a.Self
	}
	if a.Direct != b.Direct {
		return a.Direct
	}
	return a.Module < b.Module
}

// Grade computes the grade.
func Grade(in Input) Result {
	if in.Now.IsZero() {
		in.Now = time.Now().UTC()
	}
	res := Result{RuleVersion: RuleVersion, Rows: []RowResult{}}

	// a vulnerability counts once, however many databases list it
	in.Self.Findings = mergeAdvisories(in.Self.Findings)
	deps := make([]Row, len(in.Deps))
	for i, d := range in.Deps {
		d.Findings = mergeAdvisories(d.Findings)
		deps[i] = d
	}
	in.Deps = deps

	rows := make([]RowResult, 0, len(in.Deps)+1)
	rows = append(rows, gradeRow(in.Self, in))
	for _, d := range in.Deps {
		rows = append(rows, gradeRow(d, in))
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Score != rows[j].Score {
			return rows[i].Score > rows[j].Score
		}
		return preferVuln(rows[i], rows[j])
	})
	res.Rows = rows

	worst := rows[0]
	res.Score = worst.Score

	// whole-tree rules raise the letter only when they beat the worst row
	if tr := treeRule(in, rows); tr != nil && tr.Score > worst.Score {
		res.TreeRows = append(res.TreeRows, *tr)
		res.Score = tr.Score
		res.Estimated = tr.Estimated
		res.Deciding = &Deciding{Tree: tr.Rule, Reason: tr.Reason, Score: tr.Score}
	} else if worst.Score > 0 {
		res.Estimated = worst.Estimated
		res.Deciding = &Deciding{Module: worst.Module, Self: worst.Self, Reason: worst.Reason, Score: worst.Score}
	}
	res.Letter = bandOf(res.Score)

	if p := pendingFor(in, rows, res.Score); p != nil {
		res.Pending, res.Letter, res.Estimated = p, "", false
	}
	if in.Checks.SelfAdvisoriesSkipped {
		res.Notes = append(res.Notes, "The module's own advisories were not looked up: no module version was given.")
	}
	return res
}
