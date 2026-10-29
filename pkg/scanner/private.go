package scanner

import (
	"os"
	"strings"

	"golang.org/x/mod/module"
)

// PrivateModules says which module paths are private: the customer's own code, whose names must not leave their boundary. It
// uses the Go command's own matching (module.MatchPrefixPatterns, as GOPRIVATE does): a pattern matches a path or any
// path below it, `*` and `?` match within one path element, and a list is comma-separated. So "acme.example" matches
// "acme.example/x" but not "acme.example.evil.com/x".
//
// A nil *PrivateModules matches nothing. Every lookup that would put a module path into a request (the module proxy, GitHub,
// the Trust Index, OSV by module, the facts store) must ask Match first and skip a private module.
type PrivateModules struct {
	globs string
}

// NewPrivateModules is the matcher for the given patterns. When patterns has any non-empty entry they are the whole
// list (an explicit setting wins); otherwise the patterns of the environment, GOPRIVATE and GONOPROXY, as the go command reads
// them. Entries may themselves be comma lists.
func NewPrivateModules(patterns []string) *PrivateModules {
	var parts []string
	add := func(s string) {
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				parts = append(parts, p)
			}
		}
	}
	for _, p := range patterns {
		add(p)
	}
	if len(parts) == 0 {
		add(os.Getenv("GOPRIVATE"))
		add(os.Getenv("GONOPROXY"))
	}
	return &PrivateModules{globs: strings.Join(parts, ",")}
}

// Match reports whether path is private. The empty list matches nothing.
func (p *PrivateModules) Match(path string) bool {
	if p == nil || p.globs == "" || path == "" {
		return false
	}
	return module.MatchPrefixPatterns(p.globs, path)
}

// Any reports whether any pattern is set.
func (p *PrivateModules) Any() bool { return p != nil && p.globs != "" }
