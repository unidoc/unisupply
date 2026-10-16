package report

import (
	"fmt"
	"strings"

	"github.com/unidoc/unisupply/pkg/scanner"
)

// Separators between call path entries. The PDF cannot use the arrow because
// its Standard14 Helvetica font is WinAnsi-encoded and has no U+2192 glyph.
const (
	callPathSepText = " → "
	callPathSepPDF  = " > "
)

// reachedVia renders the call path of a called vulnerability, entries joined
// by sep, or "" when there is nothing to show. Only the project's own frames
// carry a "(file:line)" suffix: dependency positions are module-relative and
// meaningless without a module and version, so they stay in the JSON report.
func reachedVia(v *scanner.Vulnerability, sep string) string {
	if v.Reachability != "called" || len(v.CallPath) == 0 {
		return ""
	}
	// A Vulnerability built without a trace (or with a misaligned one) falls
	// back to the plain names rather than guessing which frame is which.
	aligned := len(v.CallTrace) == len(v.CallPath)

	entries := make([]string, len(v.CallPath))
	for i, name := range v.CallPath {
		entries[i] = name
		if !aligned {
			continue
		}
		f := &v.CallTrace[i]
		if f.Elided {
			entries[i] = "..."
			continue
		}
		if f.Project && f.File != "" && f.Line > 0 {
			entries[i] = fmt.Sprintf("%s (%s:%d)", name, f.File, f.Line)
		}
	}
	return strings.Join(entries, sep)
}

// calledSymbolsLine renders the vulnerable symbols found called for a
// vulnerability, or "" when there are fewer than two. With one symbol the line
// would repeat the last entry of the call path.
func calledSymbolsLine(v *scanner.Vulnerability) string {
	if v.Reachability != "called" || len(v.CalledSymbols) < 2 {
		return ""
	}
	return strings.Join(v.CalledSymbols, ", ")
}
