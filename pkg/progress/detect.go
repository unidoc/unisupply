package progress

import "os"

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

// isTerminal reports whether f is attached to a character device (a TTY in
// practice on the platforms unisupply targets). It avoids pulling in
// golang.org/x/term so we add no new module dependency.
func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
