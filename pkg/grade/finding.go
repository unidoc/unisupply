package grade

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// findingResult is a finding after grading: its tier, its score, whether it was graded, its VEX status and the context
// around its fix.
func findingResult(f *scored, r Row, in *Input) FindingResult {
	fr := FindingResult{
		ID: f.ID, Aliases: f.Aliases, Module: f.Module, Severity: f.sev, Estimated: f.estimated, Tier: f.tier, TierAssumed: f.assumed,
		Score: f.score, Counted: f.tier != TierGraphOnly, Exploited: f.Exploited, FixedVersion: f.FixedVersion,
		AffectedPackages: f.AffectedPackages, Condition: f.Condition, VEX: vexFor(f.tier),
	}
	if fr.Module == "" {
		fr.Module = r.Module
	}
	var notes []string
	if r.Self {
		notes = append(notes, "Reachability is assumed: anyone who uses the module can use its vulnerable code.")
	} else if f.assumed {
		notes = append(notes, "Reachability was not determined and is scored as called.")
	}
	if len(f.AffectedPackages) > 0 {
		notes = append(notes, "Only if you import "+joinLimited(f.AffectedPackages, 3)+".")
	}
	if f.estimated {
		notes = append(notes, "Severity is unknown and is scored as medium.")
	}
	fr.Note = strings.Join(notes, " ")
	fr.Response = responseFor(&f.Finding, r, in)
	return fr
}

func joinLimited(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:n], ", "), len(items)-n)
}

// responseFor words the situation around a fix: a label next to the letter, never part of it.
//
//	while the fix is new:   "Fix released 8 October · response window ends 22 October."
//	after 14 days:          "Fix available for 14 days; the graded version still requires the affected x/net version."
//	scanned version known:  "Fix available for 87 days before this version was released (120 days to the scan date); ..."
//	no fix:                 "No fix available" (no clock);  no fix date: "Fix release date unavailable" (no deadline)
//	known exploited:        counts at once; no response label.
//
// A generic "overdue" label is deliberately not used: users can usually take the fix themselves.
func responseFor(f *Finding, r Row, in *Input) Response {
	resp := responseBase(f, r, in)
	addFixGo(&resp, f, in)
	return resp
}

func responseBase(f *Finding, r Row, in *Input) Response {
	resp := Response{}
	if f.Exploited {
		resp.Status = "exploited"
		resp.Text = "Known to be exploited (CISA KEV): it counts at once."
		return resp
	}
	if strings.TrimSpace(f.FixedVersion) == "" {
		resp.Status = "no_fix"
		resp.Text = "No fix available."
		return resp
	}
	if f.FixReleasedAt == nil {
		resp.Status = "date_unknown"
		resp.Text = "Fix release date unavailable."
		resp.History = historyText(f, in)
		return resp
	}
	t := f.FixReleasedAt.UTC()
	ends := t.Add(ResponseWindowDays * 24 * time.Hour)
	resp.FixReleasedAt, resp.DateSource, resp.WindowEnds = &t, f.FixDateSource, &ends
	days := int(in.Now.Sub(t).Hours() / 24)
	if days < 0 {
		days = 0
	}
	resp.DaysSinceFix = days
	if in.SelfReleasedAt != nil && t.Before(*in.SelfReleasedAt) {
		resp.FixAgeAtReleaseDays = int(in.SelfReleasedAt.Sub(t).Hours() / 24)
	}
	if in.Now.Before(ends) {
		resp.Status = "within_window"
		resp.Text = fmt.Sprintf("Fix released %s · response window ends %s.", dayMonth(t, in.Now), dayMonth(ends, in.Now))
		if resp.FixAgeAtReleaseDays > 0 {
			resp.Text += fmt.Sprintf(" The fix was available for %d days before this version was released.", resp.FixAgeAtReleaseDays)
		}
	} else {
		resp.Status = "past_window"
		module := f.Module
		if module == "" {
			module = r.Module
		}
		if resp.FixAgeAtReleaseDays > 0 {
			resp.Text = fmt.Sprintf("Fix available for %d days before this version was released (%d days to the scan date); the graded version still requires the affected %s version.", resp.FixAgeAtReleaseDays, days, module)
		} else {
			resp.Text = fmt.Sprintf("Fix available for %d days; the graded version still requires the affected %s version.", days, module)
		}
	}
	resp.History = historyText(f, in)
	return resp
}

// historyText is the response-history context, or "Not enough response history".
func historyText(f *Finding, in *Input) string {
	module := f.Module
	if module == "" {
		return ""
	}
	h := in.History[module]
	if h == nil || h.Samples <= 0 {
		return "Not enough response history."
	}
	return fmt.Sprintf("Historically adopted comparable fixes in about %d days (%d fixes, %s to %s).", h.MedianDays, h.Samples, monthYear(h.From), monthYear(h.To))
}

func dayMonth(t, now time.Time) string {
	if t.Year() != now.Year() {
		return t.Format("2 January 2006")
	}
	return t.Format("2 January")
}

func monthYear(t time.Time) string { return t.UTC().Format("Jan 2006") }

// fix compatibility with the Go the graded module supports (Response.FixCompat).
const (
	FixCompatible     = "compatible"     // the fix needs no newer Go than the module supports
	FixRaisesMinimum  = "raises_minimum" // the fix needs a newer Go: taking it raises the module's minimum Go version
	fixGoNoteTemplate = " The fix requires Go %s or newer; this module supports Go %s, so taking it raises the minimum Go version."
)

// addFixGo adds what the fix asks of the Go version. The grade does not change for it (the fix exists), but the choice it
// forces is visible: a module that supports older Go releases cannot take a fix that only exists in a version needing a newer
// one without dropping them (the x/* modules raise their minimum to the previous Go release soon after each Go release).
func addFixGo(resp *Response, f *Finding, in *Input) {
	need := strings.TrimSpace(f.FixRequiresGo)
	if need == "" || strings.TrimSpace(f.FixedVersion) == "" {
		return
	}
	resp.FixRequiresGo = need
	have := strings.TrimSpace(in.ProjectGo)
	switch cmp, ok := compareGo(need, have); {
	case have == "" || !ok:
		resp.Text += " The fix requires Go " + need + " or newer."
	case cmp > 0:
		resp.FixCompat = FixRaisesMinimum
		resp.Text += fmt.Sprintf(fixGoNoteTemplate, need, have)
	default:
		resp.FixCompat = FixCompatible
	}
}

// compareGo compares two Go versions as written in a go directive ("1.24", "1.26.0"); ok is false when either is not one.
func compareGo(a, b string) (int, bool) {
	x, y := "v"+strings.TrimPrefix(a, "go"), "v"+strings.TrimPrefix(b, "go")
	if !semver.IsValid(x) || !semver.IsValid(y) {
		return 0, false
	}
	return semver.Compare(x, y), true
}
