package grade

import (
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
