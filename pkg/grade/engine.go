package grade

import (
	"fmt"
	"slices"
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

func scoreFinding(f *Finding, r *Row) scored {
	sev, est := severityOf(f.Severity)
	tier, assumed := tierOf(f.Reachability, r.Self)
	if !r.Self && isRefuted(r.InBuild) {
		// a module that is confirmed not to be compiled in is graph-only whatever the reachability says: its code never runs
		tier, assumed = TierGraphOnly, false
	}
	s := scored{Finding: *f, sev: sev, estimated: est, tier: tier, assumed: assumed}
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
	case u.NotAssessed && !u.Archived && !u.Deprecated && !u.Retracted:
		return StateNotAssessed
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
	for i := range r.Findings {
		if strings.TrimSpace(r.Findings[i].FixedVersion) == "" {
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
	best := func(ts tierSet, cap int, bonus bool) (int, *scored, int) {
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
			if bonus && highOrCritical(byID[id].sev) {
				further++
			}
		}
		s := top.score + further*furtherAdvisoryAdd
		if cap > 0 && s > cap {
			s = cap
		}
		return s, top, further
	}
	cs, ctop, cfurther := best(called, 0, true)
	is, itop, ifurther := best(imported, importedCap, false)
	switch {
	case cs >= is && ctop != nil:
		score, top = cs, ctop
		reason = describeVuln(ctop, "called", cfurther)
	case itop != nil:
		score, top = is, itop
		reason = describeVuln(itop, "imported", ifurther)
	}
	if score > 100 {
		score = 100
		reason += "; capped at 100"
	}
	// a called known-exploited finding: at least 76. The worst such finding names it (highest table value, then the
	// smallest ID), so the text does not depend on the order of the input.
	var kev *scored
	for _, f := range called.list {
		if f.Exploited && (kev == nil || f.score > kev.score || (f.score == kev.score && f.ID < kev.ID)) {
			kev = f
		}
	}
	floored := false
	if kev != nil && score < exploitedFloor {
		score, top, floored = exploitedFloor, kev, true
		reason = fmt.Sprintf("called known-exploited %s %s (at least %d)", strings.ToLower(kev.sev), kev.ID, exploitedFloor)
	}
	if top != nil {
		// the floor decided, not the estimate
		est = top.estimated && !floored
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
func gradeRow(r Row, in *Input) RowResult {
	state := upkeepState(r, in.Now)
	fs := make([]scored, 0, len(r.Findings))
	for i := range r.Findings {
		fs = append(fs, scoreFinding(&r.Findings[i], &r))
	}
	vs, est, _, vreason := vulnScore(r, fs)
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
		UpkeepState: state, UpkeepNote: strings.TrimSpace(r.Upkeep.Message), UpkeepMissed: r.Upkeep.Missing, ArchivedUnread: r.Upkeep.ArchivedUnread,
	}
	// A row whose upkeep could not be read has no letter when what it could still be would change it: a row shown as A
	// while its archived flag is unknown would read as a clean result.
	if r.Upkeep.Missing && !isArchivedOrDeprecated(r) {
		possible := upkeepDependency
		if r.Self {
			possible = upkeepSelf
		}
		if isConfirmed(r.TestOnly) || isRefuted(r.InBuild) {
			possible = upkeepMinor
		}
		if bandOf(possible) > bandOf(score) {
			rr.Letter = ""
		}
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
	case state == StateNotAssessed:
		rr.Reason = "not assessed"
	default:
		rr.Reason = "nothing found"
	}
	for i := range fs {
		rr.Findings = append(rr.Findings, findingResult(&fs[i], r, in))
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
	if a.Estimated != b.Estimated {
		// a row that does not rest on an estimate decides a tie, so the text does not depend on the module names
		return !a.Estimated
	}
	if a.Self != b.Self {
		return a.Self
	}
	if a.Direct != b.Direct {
		return a.Direct
	}
	return a.Module < b.Module
}

// gradeOnce computes the grade without the estimate check (see Grade).
func gradeOnce(input *Input) Result {
	if input == nil {
		input = &Input{}
	}
	in := *input // the merge below must not change the caller's rows
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
	rows = append(rows, gradeRow(in.Self, &in))
	for _, d := range in.Deps {
		rows = append(rows, gradeRow(d, &in))
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
	if tr := treeRule(&in, rows); tr != nil && tr.Score > worst.Score {
		res.TreeRows = append(res.TreeRows, *tr)
		res.Score = tr.Score
		res.Deciding = &Deciding{Tree: tr.Rule, Reason: tr.Reason, Score: tr.Score}
	} else if worst.Score > 0 {
		res.Deciding = &Deciding{Module: worst.Module, Self: worst.Self, Reason: worst.Reason, Score: worst.Score}
	}
	res.Letter = bandOf(res.Score)

	if p := pendingFor(&in, rows, res.Score); p != nil {
		// No letter means no deciding row either: what is known is in Pending.Known.
		res.Pending, res.Letter, res.Deciding, res.Score = p, "", nil, 0
	}
	if in.ChecksumMismatch {
		res.ChecksumMismatch, res.ChecksumDetail = true, in.ChecksumDetail
		if len(res.TreeRows) == 0 {
			// no tree row: another row already scores F. The mismatch is still said.
			note := "A module does not match its checksum (go.sum)"
			if in.ChecksumDetail != "" {
				note += ": " + in.ChecksumDetail
			}
			res.Notes = append(res.Notes, note+".")
		}
	}
	// reached findings whose fix needs a newer Go than the module supports: said once, the grade is unchanged
	for i := range rows {
		for j := range rows[i].Findings {
			if f := &rows[i].Findings[j]; f.Counted && f.Response.FixCompat == FixRaisesMinimum {
				res.FixesNeedNewerGo++
			}
		}
	}
	if n := res.FixesNeedNewerGo; n > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d reached finding%s fixed only in versions that need a newer Go than this module supports (go %s): taking the fix raises the module's minimum Go version. The grade does not change for that.", n, plural(n, " is", "s are"), strings.TrimSpace(in.ProjectGo)))
	}
	for i := range in.Deps {
		if in.Deps[i].Upkeep.ArchivedUnread {
			res.ArchivedUnread = append(res.ArchivedUnread, in.Deps[i].Module)
		}
	}
	if n := len(res.ArchivedUnread); n > 0 {
		sort.Strings(res.ArchivedUnread)
		note := fmt.Sprintf("The archived status of %d module%s could not be read: an archived module would add at most %d to its row, so this letter may be one band better than it would be with the flag.", n, plural(n, "", "s"), upkeepDependency)
		if h := strings.TrimSpace(in.Checks.MaintenanceHint); h != "" {
			note += " " + h + "."
		}
		res.Notes = append(res.Notes, note)
	}
	if t := in.Checks.KEVStaleSince; !t.IsZero() {
		res.Notes = append(res.Notes, "The known-exploited catalog (CISA) could not be refreshed: the copy from "+t.UTC().Format("2006-01-02")+" was used.")
	}
	if v := strings.TrimSpace(in.Checks.StdlibVersion); v != "" {
		// said whether or not it had findings: a clean result holds for this Go release only
		if in.Checks.StdlibGraded {
			res.Notes = append(res.Notes, "The standard library is graded at "+v+", the Go toolchain this scan ran with.")
		} else {
			res.Notes = append(res.Notes, "The standard library was scanned at "+v+", the Go toolchain this scan ran with; its findings are listed, not graded.")
		}
	}
	if in.Checks.SelfAdvisoriesSkipped {
		res.Notes = append(res.Notes, "The module's own advisories were not looked up: no module version was given.")
	}
	if n := archiveUncheckedNote(in.Checks.ArchiveUnchecked); n != "" {
		res.Notes = append(res.Notes, n)
	}
	return res
}

// archiveUncheckedNote words the note for modules whose archived status was not checked: at most three names, sorted,
// then a count of the rest. It is "" for an empty list.
func archiveUncheckedNote(modules []string) string {
	if len(modules) == 0 {
		return ""
	}
	sorted := slices.Clone(modules)
	slices.Sort(sorted)
	shown := sorted[:min(3, len(sorted))]
	list := strings.Join(shown, ", ")
	if more := len(sorted) - len(shown); more > 0 {
		list += fmt.Sprintf(" and %d more", more)
	}
	return fmt.Sprintf("Archived status was not checked for %d module(s) (their repository is not on GitHub or could not be found): %s.", len(sorted), list)
}

func isArchivedOrDeprecated(r Row) bool {
	return r.Upkeep.Archived || r.Upkeep.Deprecated || r.Upkeep.Retracted
}

// Grade turns what the scanners found into the grade. Estimated is set when a severity nobody has published (scored as
// medium) could change the letter: the grade is computed again with every such severity as low and as critical, and a
// different letter in either run marks the result.
func Grade(input *Input) Result {
	if input == nil {
		input = &Input{}
	}
	// Merge the advisories first: a Go advisory with no severity whose GitHub alias is rated HIGH has a published severity
	// once they are one finding, and only what is still estimated after the merge is substituted below.
	merged := mergedInput(input)
	res := gradeOnce(&merged)
	if res.Pending != nil {
		return res
	}
	if p := severityLookupPending(&merged, &res); p != nil {
		res.Pending, res.Letter, res.Deciding, res.Score, res.Estimated = p, "", nil, 0, false
		return res
	}
	if !hasEstimatedSeverity(&merged) {
		return res
	}
	for _, sev := range []string{"LOW", "CRITICAL"} {
		alt := withEstimatedSeverity(&merged, sev)
		if r := gradeOnce(&alt); r.Letter != res.Letter {
			res.Estimated = true
			break
		}
	}
	return res
}

// hasEstimatedSeverity is true when some finding of the input has no published severity.
func hasEstimatedSeverity(in *Input) bool {
	check := func(fs []Finding) bool {
		for i := range fs {
			if _, est := severityOf(fs[i].Severity); est {
				return true
			}
		}
		return false
	}
	if check(in.Self.Findings) {
		return true
	}
	for i := range in.Deps {
		if check(in.Deps[i].Findings) {
			return true
		}
	}
	return false
}

// withEstimatedSeverity is a copy of the input in which every finding without a published severity has the given one.
func withEstimatedSeverity(in *Input, sev string) Input {
	out := *in
	set := func(fs []Finding) []Finding {
		cp := append([]Finding(nil), fs...)
		for i := range cp {
			if _, est := severityOf(cp[i].Severity); est {
				cp[i].Severity = sev
			}
		}
		return cp
	}
	out.Self.Findings = set(in.Self.Findings)
	out.Deps = make([]Row, len(in.Deps))
	for i := range in.Deps {
		out.Deps[i] = in.Deps[i]
		out.Deps[i].Findings = set(in.Deps[i].Findings)
	}
	return out
}

// mergedInput is a copy of the input whose rows have their advisories merged (one finding per vulnerability).
func mergedInput(in *Input) Input {
	out := *in
	out.Self.Findings = mergeAdvisories(in.Self.Findings)
	out.Deps = make([]Row, len(in.Deps))
	for i := range in.Deps {
		out.Deps[i] = in.Deps[i]
		out.Deps[i].Findings = mergeAdvisories(in.Deps[i].Findings)
	}
	return out
}

// severityLookupPending is the Pending answer when a severity whose lookup FAILED could change the letter: the grade is
// computed again with every such severity as low and as critical, and a different letter in either run means the letter
// depends on a check that did not run. A severity nobody has published (not a failed lookup) is an estimate instead, and
// marks the letter with a star (see Grade).
func severityLookupPending(merged *Input, res *Result) *Pending {
	var ids []string
	collect := func(fs []Finding) {
		for i := range fs {
			if fs[i].SeverityLookupFailed {
				ids = append(ids, fs[i].ID)
			}
		}
	}
	collect(merged.Self.Findings)
	for i := range merged.Deps {
		collect(merged.Deps[i].Findings)
	}
	if len(ids) == 0 {
		return nil
	}
	differs := false
	for _, sev := range []string{"LOW", "CRITICAL"} {
		alt := withLookupSeverity(merged, sev)
		if r := gradeOnce(&alt); r.Letter != res.Letter {
			differs = true
			break
		}
	}
	if !differs {
		return nil
	}
	sort.Strings(ids)
	ids = slices.Compact(ids)
	shown, more := ids, ""
	if len(shown) > 3 {
		more = fmt.Sprintf(" and %d more", len(ids)-3)
		shown = shown[:3]
	}
	return &Pending{Check: "severity_lookup", Known: knownFacts(merged, res.Rows),
		Reason: fmt.Sprintf("the severity of %s%s could not be looked up (OSV, NVD and GitHub did not answer, often a rate limit: set NVD_API_KEY), and a different severity would change the letter", strings.Join(shown, ", "), more)}
}

// withLookupSeverity is a copy of the input in which every finding whose severity lookup failed has the given severity.
func withLookupSeverity(in *Input, sev string) Input {
	out := *in
	set := func(fs []Finding) []Finding {
		cp := append([]Finding(nil), fs...)
		for i := range cp {
			if cp[i].SeverityLookupFailed {
				cp[i].Severity = sev
			}
		}
		return cp
	}
	out.Self.Findings = set(in.Self.Findings)
	out.Deps = make([]Row, len(in.Deps))
	for i := range in.Deps {
		out.Deps[i] = in.Deps[i]
		out.Deps[i].Findings = set(in.Deps[i].Findings)
	}
	return out
}
