// Package grade turns what the scanners found into the letter (rules version 2, "Grading v2").
//
// One rule you can trace: every row (the module itself, and each dependency) gets ONE score; the letter comes from the
// worst row, and the result names that row and why. D and F mean a confirmed problem: a known vulnerability in code
// that is actually reached, or a checksum that does not match. Vulnerable code that is never compiled is shown, not
// graded. Upkeep counts, but only up to C. A missing check is Pending, never a letter.
//
//	row score    = max(vulnerability score, upkeep score)                         (0-100)
//	letter       = band(worst row), unless a whole-tree rule raises it            A <= 10, B <= 25, C <= 50, D <= 75, F above
//
// The numbers are policy values that pick a band, not measured probabilities. The package is pure: it reads an Input
// and returns a Result, with no I/O, so two runs on the same input give the same answer.
package grade

import (
	"encoding/json"
	"time"

	"github.com/unidoc/unisupply/pkg/scanner"
)

// RuleVersion is the version of these rules. A result is never re-labelled: new rules produce new results.
const RuleVersion = 2

// ResponseWindowDays is how long after a fix is released a project is "within the response window". It is a label next to
// the letter; it never changes it.
const ResponseWindowDays = 14

// Letter is A to F; "" when the grade is Pending.
type Letter string

const (
	LetterA Letter = "A"
	LetterB Letter = "B"
	LetterC Letter = "C"
	LetterD Letter = "D"
	LetterF Letter = "F"
)

// Tiers of a finding, from govulncheck's reachability.
const (
	TierCalled    = "called"     // a path reaches the vulnerable function
	TierImported  = "imported"   // the vulnerable package is imported, no path reaches the function
	TierGraphOnly = "graph_only" // the package with the bug is never imported: its code is never compiled in
)

// Upkeep states of a row.
const (
	StateActive      = "active"
	StateFinished    = "finished" // quiet, with nothing open
	StateParked      = "parked"   // quiet, with something open (an advisory without a fix)
	StateDeprecated  = "deprecated"
	StateArchived    = "archived"
	StateUnknown     = "unknown"      // the maintenance data is missing
	StateNotAssessed = "not_assessed" // nobody looked (no published version to look up, or the standard library)
)

// Finding is one advisory on one row, as the scanners report it.
type Finding struct {
	ID       string
	Aliases  []string
	Module   string // the module the advisory is in (the row's module, except for the module's own advisories)
	Summary  string
	Severity string // CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN or ""

	// Reachability is govulncheck's verdict: "called", "imported", "required" (graph-only) or "" (not determined, which
	// is scored as called: the worst case, never a free pass).
	Reachability string

	// SeverityLookupFailed is true when the severity is unknown because the lookup FAILED (OSV, NVD and GitHub could not be
	// reached or rate-limited), not because nobody has published one. A failed lookup is a check that did not run: when the
	// letter could depend on it, the grade is Pending ("severity_lookup") instead of an estimate.
	SeverityLookupFailed bool

	// FixRequiresGo is the `go` directive of the fixed version's go.mod ("1.26"); empty when unknown.
	FixRequiresGo string

	Exploited    bool // on CISA's Known Exploited Vulnerabilities list
	FixedVersion string
	// FixReleasedAt is when the first fixed version was released, and FixDateSource where that date came from.
	FixReleasedAt *time.Time
	FixDateSource string

	AffectedPackages []string // import paths the advisory names; empty = the whole module
	Condition        string   // what the project must do to reach it, read from the call path
}

// Upkeep is what is known about whether someone still looks after a module.
type Upkeep struct {
	Archived bool
	// Deprecated is the go.mod `// Deprecated:` notice; Retracted that the version in use is retracted. Both read as
	// Deprecated.
	Deprecated bool
	Retracted  bool
	Message    string // the maintainers' own words, shown next to the state

	LastRelease  time.Time // zero = unknown
	LastActivity time.Time // the default branch's last commit; zero = unknown

	// NotAssessed is true when nobody looked: the module itself without a published version, the standard library. The
	// state is then "not_assessed", never "finished".
	NotAssessed bool

	// ArchivedUnread is true when the only thing that could not be read is the archived flag (GitHub's rate limit, no token),
	// and the caller chose to grade without it: the row is graded on what is known, the result lists the module in
	// Result.ArchivedUnread and says in a note that an archived module would add at most 20 to its row. It is never set for
	// the module itself (an archived module is a C), nor when the caller asked for the strict rule.
	ArchivedUnread bool

	// Missing is true when the maintenance data could not be read (the lookup failed): the state is then unknown, and a
	// check that could change the letter makes the grade Pending.
	Missing bool
}

// Row is one line of the grade: a dependency, or the module itself ("self").
type Row struct {
	Module  string
	Version string
	Self    bool
	Direct  bool

	// TestOnly is true only for a confirmed test-only dependency (nil = unknown, which gets no discount). InBuild is
	// false only for a confirmed graph-only module.
	TestOnly *bool
	InBuild  *bool

	Findings []Finding
	Upkeep   Upkeep
}

// Checks says which of the checks the grade depends on did not run. Anything set here can make the grade Pending.
type Checks struct {
	VulnScanFailed bool
	VulnScanReason string
	// ScanTimedOut is true when the scan as a whole did not finish (timeout or interruption).
	ScanTimedOut bool
	// SelfStatusFailed: the module's own archived/deprecated status could not be read. SelfAdvisoriesFailed: the lookup of
	// its own advisories (OSV) failed. SelfAdvisoriesSkipped: no module version was given, so they were not looked up (not
	// a failure: the result says so, and the module's own advisories are not part of the letter).
	SelfStatusFailed      bool
	SelfAdvisoriesFailed  bool
	SelfAdvisoriesSkipped bool
	// KEVUnchecked is the number of reached findings with a CVE whose known-exploited status (CISA's catalog) could not be
	// checked: the grade says so in a note, since a called finding on that list is an F.
	KEVUnchecked int

	// ChecksumUnverified is true when `go mod verify` could not complete: a checksum mismatch (F) cannot be ruled out.
	ChecksumUnverified bool

	// StdlibVersion is the Go release the standard library was scanned at (the toolchain the scan ran with); StdlibGraded
	// says whether the standard library takes part in the grade (it is listed either way).
	StdlibVersion string
	StdlibGraded  bool

	// KEVStaleSince is set when the CISA catalog could not be refreshed and an older copy was used: the grade says so.
	KEVStaleSince time.Time

	// MaintenanceHint is appended to the reason of a Pending caused by missing maintenance data: why the data is missing
	// and what to do (for example that GitHub allows 60 unauthenticated requests an hour).
	MaintenanceHint string

	SelfStatusReason     string // why the status lookup failed
	SelfAdvisoriesReason string // why the advisory lookup failed

	// ArchiveUnchecked lists the modules whose archived flag was never read for a reason that is not a failed GitHub call
	// (their repository is not on GitHub, is unknown, or could not be found), so "not archived" is unproven for them. It
	// is a note on the result, never a reason for Pending: no retry could change it.
	ArchiveUnchecked []string
}

// Input is everything the grade reads.
type Input struct {
	Self Row
	Deps []Row

	// ProjectGo is the module's own `go` directive ("1.24"): the oldest Go it supports. A fix that needs a newer Go raises it.
	ProjectGo string

	// ChecksumMismatch is true when `go mod verify` / go.sum found a module that does not match: a confirmed problem, F.
	ChecksumMismatch bool
	ChecksumDetail   string

	Checks Checks

	// History is how fast the project has adopted a dependency's fixes in the past, by dependency module path (absent =
	// not enough history).
	History map[string]*scanner.ResponseHistory

	Now time.Time
}

// VEXStatus is a finding's status in the terms a security reviewer already accepts.
type VEXStatus struct {
	Status        string `json:"status"`                  // affected | not_affected | under_investigation
	Justification string `json:"justification,omitempty"` // vulnerable_code_not_present | vulnerable_code_not_in_execute_path
}

// Response is the context around a finding's fix: a label next to the letter, never part of it.
type Response struct {
	// Status: within_window, past_window, no_fix, date_unknown, or exploited (a known-exploited finding counts at once and
	// has no response label).
	Status        string     `json:"status"`
	FixReleasedAt *time.Time `json:"fix_released_at,omitempty"`
	DateSource    string     `json:"fix_date_source,omitempty"`
	WindowEnds    *time.Time `json:"window_ends,omitempty"`
	DaysSinceFix  int        `json:"days_since_fix,omitempty"`
	Text          string     `json:"text"`
	// FixRequiresGo is the `go` directive of the fixed version's go.mod, and FixCompat says whether taking the fix raises the
	// minimum Go version this module supports ("raises_minimum") or not ("compatible"); empty when unknown. Context only: the
	// letter never changes for it.
	FixRequiresGo string `json:"fix_requires_go,omitempty"`
	FixCompat     string `json:"fix_compat,omitempty"`
	// History is "Historically adopted comparable fixes in about 30 days (3 fixes, Jan 2025 to Sep 2026)", or "Not enough
	// response history"; context, not a forecast.
	History string `json:"history,omitempty"`
}

// FindingResult is a finding after grading.
type FindingResult struct {
	ID               string    `json:"id"`
	Aliases          []string  `json:"aliases,omitempty"` // the same vulnerability under other identifiers (CVE, GHSA)
	Module           string    `json:"module"`
	Severity         string    `json:"severity"` // the severity that was scored (UNKNOWN is scored as MEDIUM and Estimated)
	Estimated        bool      `json:"estimated,omitempty"`
	Tier             string    `json:"tier"`
	TierAssumed      bool      `json:"tier_assumed,omitempty"` // reachability was not determined and is scored as called
	Score            int       `json:"score"`                  // the table value; 0 for a graph-only finding
	Counted          bool      `json:"counted"`                // false = shown, not graded
	Exploited        bool      `json:"exploited,omitempty"`
	FixedVersion     string    `json:"fixed_version,omitempty"`
	AffectedPackages []string  `json:"affected_packages,omitempty"`
	Condition        string    `json:"condition,omitempty"`
	Note             string    `json:"note,omitempty"` // "Reachability assumed: ...", "Only if you import X"
	VEX              VEXStatus `json:"vex"`
	Response         Response  `json:"response"`
}

// RowResult is a row after grading.
type RowResult struct {
	Module      string `json:"module"`
	Version     string `json:"version,omitempty"`
	Self        bool   `json:"self,omitempty"`
	Direct      bool   `json:"direct,omitempty"`
	TestOnly    bool   `json:"test_only,omitempty"`
	NotBuilt    bool   `json:"not_built,omitempty"`
	Score       int    `json:"score"`
	VulnScore   int    `json:"vulnerability_score"`
	UpkeepScore int    `json:"upkeep_score"`
	Letter      Letter `json:"letter"`
	// Reason is the one sentence that explains the score.
	Reason         string          `json:"reason"`
	UpkeepState    string          `json:"upkeep_state"`
	UpkeepNote     string          `json:"upkeep_note,omitempty"` // the maintainers' own words (deprecation, retraction)
	Estimated      bool            `json:"estimated,omitempty"`
	UpkeepMissed   bool            `json:"upkeep_missing,omitempty"`
	ArchivedUnread bool            `json:"archived_unread,omitempty"` // graded without the archived flag (see Upkeep.ArchivedUnread)
	Findings       []FindingResult `json:"findings,omitempty"`
}

// TreeRow is a whole-tree rule that raised the letter: it appears as its own row.
type TreeRow struct {
	Rule      string `json:"rule"` // called_findings | called_critical | called_exploited | checksum_mismatch | imported_and_called_findings
	Score     int    `json:"score"`
	Letter    Letter `json:"letter"`
	Reason    string `json:"reason"` // "4 called high-severity findings across 2 modules"
	Estimated bool   `json:"estimated,omitempty"`
}

// Pending is the answer when a check the letter depends on did not run: no letter, the reason, and what is known.
type Pending struct {
	Check  string   `json:"check"` // vulnerability_scan | scan_incomplete | checksum | known_exploited | module_status | module_advisories | dependency_maintenance
	Reason string   `json:"reason"`
	Known  []string `json:"known,omitempty"` // what is known anyway, e.g. "Archived"
}

// Result is the grade.
type Result struct {
	RuleVersion int    `json:"rule_version"`
	Letter      Letter `json:"letter,omitempty"` // "" when Pending
	// Estimated marks a letter that rests on an estimated severity (unknown severity is scored as medium): "C*".
	Estimated bool `json:"estimated,omitempty"`
	// Score is the worst row's score: a policy value that picks the band, not a measurement. It is not a published number.
	Score int `json:"score"`
	// Deciding is the row (or whole-tree rule) that set the letter; nil when nothing crossed the A threshold.
	Deciding *Deciding   `json:"deciding,omitempty"`
	Rows     []RowResult `json:"rows"`
	TreeRows []TreeRow   `json:"tree_rows,omitempty"`
	Pending  *Pending    `json:"pending,omitempty"`
	// Notes are things the letter does not cover or checks that were skipped (e.g. the module's own advisories were not
	// looked up because no module version was given).
	Notes []string `json:"notes,omitempty"`
	// FixesNeedNewerGo is the number of reached findings whose only fix needs a newer Go than the module supports.
	FixesNeedNewerGo int `json:"fixes_need_newer_go,omitempty"`
	// ArchivedUnread lists the dependencies whose archived flag could not be read although the grade was given (see
	// Upkeep.ArchivedUnread): the letter may be one band better than it would be with the flag.
	ArchivedUnread []string `json:"archived_unread,omitempty"`
	// ChecksumMismatch is true when `go mod verify` found a module that does not match its checksum, and ChecksumDetail
	// says which. It is a fact of the result whether or not a whole-tree row is what decides the letter: when a row already
	// scores F, the rule does not raise the letter and so has no tree row, but the mismatch must not be lost.
	ChecksumMismatch bool   `json:"checksum_mismatch,omitempty"`
	ChecksumDetail   string `json:"checksum_detail,omitempty"`
}

// Deciding names what set the letter: a row, or a whole-tree rule.
type Deciding struct {
	Module string `json:"module,omitempty"`
	Self   bool   `json:"self,omitempty"`
	Tree   string `json:"tree_rule,omitempty"`
	Reason string `json:"reason"`
	Score  int    `json:"score"`
}

// MarshalJSON leaves out the score of a Pending result: there is no worst row to take it from, so a published 0 would read
// as a clean result.
func (r Result) MarshalJSON() ([]byte, error) {
	type plain Result // no methods: avoids recursion
	if r.Pending != nil {
		return json.Marshal(struct {
			plain
			Score *int `json:"score,omitempty"`
		}{plain: plain(r)})
	}
	return json.Marshal(plain(r))
}
