package scanner

import "testing"

func TestPrivateModules_Match(t *testing.T) {
	cases := []struct {
		patterns []string
		path     string
		want     bool
	}{
		{[]string{"acme.example"}, "acme.example", true},
		{[]string{"acme.example"}, "acme.example/x", true},
		{[]string{"acme.example"}, "acme.example/x/y/v2", true},
		{[]string{"acme.example"}, "acme.example.evil.com/x", false},
		{[]string{"acme.example"}, "xacme.example/x", false},
		{[]string{"acme.example"}, "github.com/acme.example/x", false},
		{[]string{"github.com/acme/*"}, "github.com/acme/secret", true},
		{[]string{"github.com/acme/*"}, "github.com/acme/secret/v3", true},
		{[]string{"github.com/acme/*"}, "github.com/acme", false},
		{[]string{"github.com/acme/*"}, "github.com/acmecorp/x", false},
		{[]string{"*.corp.example"}, "git.corp.example/x", true},
		{[]string{"*.corp.example"}, "a.b.corp.example/x", true}, // * stops at a slash, not a dot
		{[]string{"*.corp.example"}, "corp.example/x", false},
		{[]string{"*.corp.example"}, "x.corp.example.evil.com/p", false},
		{[]string{"git.?.example"}, "git.x.example/p", true},
		{[]string{"a.example, b.example"}, "b.example/p", true},
		{[]string{"a.example,b.example"}, "c.example/p", false},
		{[]string{"a.example", "b.example"}, "b.example/p", true},
		{nil, "acme.example/x", false},
		{[]string{""}, "acme.example/x", false},
		{[]string{" , "}, "acme.example/x", false},
	}
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOPROXY", "")
	for _, c := range cases {
		if got := NewPrivateModules(c.patterns).Match(c.path); got != c.want {
			t.Errorf("patterns %q, path %q: got %v, want %v", c.patterns, c.path, got, c.want)
		}
	}
	var nilP *PrivateModules
	if nilP.Match("a/b") || nilP.Any() || NewPrivateModules(nil).Any() {
		t.Error("a nil or empty matcher matches nothing")
	}
}

func TestPrivateModules_EnvironmentAndExplicitWins(t *testing.T) {
	t.Setenv("GOPRIVATE", "acme.example")
	t.Setenv("GONOPROXY", "corp.example/*")
	p := NewPrivateModules(nil)
	if !p.Match("acme.example/x") || !p.Match("corp.example/team") || p.Match("other.example/x") {
		t.Error("GOPRIVATE and GONOPROXY are both read")
	}
	e := NewPrivateModules([]string{"other.example"})
	if !e.Match("other.example/x") || e.Match("acme.example/x") || e.Match("corp.example/team") {
		t.Error("an explicit list replaces the environment")
	}
	// the Go semantics of the empty element: an empty explicit list falls back to the environment
	if !NewPrivateModules([]string{""}).Match("acme.example/x") {
		t.Error("an empty explicit list is not an explicit setting")
	}
}
