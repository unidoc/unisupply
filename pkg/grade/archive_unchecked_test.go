package grade

import (
	"reflect"
	"strings"
	"testing"
)

func TestArchiveUncheckedNote(t *testing.T) {
	for _, tc := range []struct {
		name    string
		modules []string
		want    string
	}{
		{"none", nil, ""},
		{"one", []string{"b.example/x"}, "Archived status was not checked for 1 module(s) (their repository is not on GitHub or could not be found): b.example/x."},
		{"three sorted", []string{"c", "a", "b"}, "Archived status was not checked for 3 module(s) (their repository is not on GitHub or could not be found): a, b, c."},
		{"five, three shown", []string{"e", "d", "c", "b", "a"}, "Archived status was not checked for 5 module(s) (their repository is not on GitHub or could not be found): a, b, c and 2 more."},
	} {
		in := Input{Self: self(), Checks: Checks{ArchiveUnchecked: tc.modules}}
		r := run(in)
		if r.Pending != nil || r.Letter == "" {
			t.Errorf("%s: unchecked archive status made the grade Pending: %+v", tc.name, r.Pending)
		}
		var got string
		for _, n := range r.Notes {
			if strings.HasPrefix(n, "Archived status was not checked") {
				if got != "" {
					t.Errorf("%s: more than one archive note: %v", tc.name, r.Notes)
				}
				got = n
			}
		}
		if got != tc.want {
			t.Errorf("%s: note = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The input slice is not reordered by Grade.
func TestArchiveUncheckedNote_DoesNotReorderInput(t *testing.T) {
	mods := []string{"c", "a", "b"}
	run(Input{Self: self(), Checks: Checks{ArchiveUnchecked: mods}})
	if mods[0] != "c" || mods[1] != "a" || mods[2] != "b" {
		t.Errorf("Grade reordered its input: %v", mods)
	}
}

// An unread archived flag adds at most 20 to its row (10 when test-only). The note and the list appear only when that can
// change the letter: A or B letters can move, C, D and F cannot (gunnsth nit).
func TestArchivedUnread_OnlyWhenTheLetterCouldChange(t *testing.T) {
	unread := func(module string, f ...Finding) Row {
		r := dep(module, f...)
		r.Upkeep.ArchivedUnread = true
		return r
	}
	hasNote := func(r Result) bool {
		for _, n := range r.Notes {
			if strings.Contains(n, "could not be read") {
				return true
			}
		}
		return false
	}
	for _, tc := range []struct {
		name string
		deps []Row
		want []string
		note bool
	}{
		{"A letter: +20 reaches B", []Row{unread("example.com/a")}, []string{"example.com/a"}, true},
		{"B letter from another row (20): +20 stays B", []Row{unread("example.com/a"), dep("example.com/b", Finding{ID: "GO-1", Module: "example.com/b", Severity: "LOW", Reachability: "called"})}, nil, false},
		{"C letter", []Row{unread("example.com/a"), dep("example.com/b", called("GO-2", "example.com/b", "MEDIUM"))}, nil, false},
		{"F letter", []Row{unread("example.com/a"), dep("example.com/b", called("GO-3", "example.com/b", "CRITICAL"))}, nil, false},
		{"own findings already above 20", []Row{unread("example.com/a", called("GO-4", "example.com/a", "MEDIUM"))}, nil, false},
	} {
		r := run(Input{Self: self(), Deps: tc.deps})
		if !reflect.DeepEqual(r.ArchivedUnread, tc.want) {
			t.Errorf("%s: archived_unread = %v, want %v (letter %s)", tc.name, r.ArchivedUnread, tc.want, r.Letter)
		}
		if hasNote(r) != tc.note {
			t.Errorf("%s: note present = %v, want %v: %v", tc.name, hasNote(r), tc.note, r.Notes)
		}
	}
}

// A stale KEV catalog within the age cap is used, and the note states how old the copy is.
func TestStaleKEVNote_StatesTheAge(t *testing.T) {
	r := run(Input{Self: self(), Checks: Checks{KEVStaleSince: now.AddDate(0, 0, -14)}})
	want := "The known-exploited catalog (CISA) could not be refreshed: the copy from 2026-09-26 (14 days old) was used."
	for _, n := range r.Notes {
		if n == want {
			return
		}
	}
	t.Errorf("notes = %q, want %q", r.Notes, want)
}
