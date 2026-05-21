package progress

import (
	"os"

	"golang.org/x/term"
)

// New constructs the appropriate Reporter for the given mode. Renderers are
// hard-wired to os.Stderr; callers cannot redirect output.
func New(mode Mode) Reporter {
	switch mode {
	case ModeNone:
		return noopReporter{}
	case ModePlain:
		return newPlainReporter(os.Stderr, realClock{})
	case ModeAuto:
		if isTerminal(os.Stderr) {
			return newTTYReporter(os.Stderr)
		}
		return newPlainReporter(os.Stderr, realClock{})
	}
	return noopReporter{}
}

// isTerminal reports whether f is attached to an interactive terminal. It
// uses golang.org/x/term (already a dependency for the TTY renderer) so
// non-terminal character devices like /dev/null are correctly excluded.
func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}
