package grade

import (
	"fmt"
	"strings"
	"time"
)

// findingResult is a finding after grading: its tier, its score, whether it was graded, its VEX status and the context
// around its fix.
func findingResult(f scored, r Row, in Input) FindingResult {
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
	fr.Response = responseFor(f.Finding, r, in)
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
//	no fix:                 "No fix available" (no clock);  no fix date: "Fix release date unavailable" (no deadline)
//	known exploited:        counts at once; no response label.
//
// A generic "overdue" label is deliberately not used: users can usually take the fix themselves.
func responseFor(f Finding, r Row, in Input) Response {
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
	if in.Now.Before(ends) {
		resp.Status = "within_window"
		resp.Text = fmt.Sprintf("Fix released %s · response window ends %s.", dayMonth(t, in.Now), dayMonth(ends, in.Now))
	} else {
		resp.Status = "past_window"
		module := f.Module
		if module == "" {
			module = r.Module
		}
		resp.Text = fmt.Sprintf("Fix available for %d days; the graded version still requires the affected %s version.", days, module)
	}
	resp.History = historyText(f, in)
	return resp
}

// historyText is the response-history context, or "Not enough response history".
func historyText(f Finding, in Input) string {
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
