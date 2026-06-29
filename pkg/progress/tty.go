package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

const (
	ansiEraseLine   = "\r\033[2K"
	ansiEraseToEnd  = "\r\033[J"
	ansiGreen       = "\033[32m"
	ansiYellow      = "\033[33m"
	ansiDim         = "\033[2m"
	ansiReset       = "\033[0m"
	ttyFallbackCols = 80

	ttyRedrawMinGap  = 80 * time.Millisecond // throttle redraws to ≤~12 Hz
	ttyProgressEvery = 50 * time.Millisecond
)

var spinnerFrames = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

// ttyReporter renders progress on a single mutable status line on os.Stderr.
type ttyReporter struct {
	w       io.Writer
	widthFn func() int

	mu         sync.Mutex
	stage      string
	stageStart time.Time
	step       string
	cur, total int
	frame      int
	lastDraw   time.Time
	active     bool
}

func newTTYReporter(w io.Writer) *ttyReporter {
	if w == nil {
		w = os.Stderr
	}
	return &ttyReporter{w: w, widthFn: stderrWidth}
}

// newTTYReporterWidth returns a reporter with a fixed column width. Test-only.
func newTTYReporterWidth(w io.Writer, width int) *ttyReporter {
	if w == nil {
		w = os.Stderr
	}
	return &ttyReporter{
		w:       w,
		widthFn: func() int { return width },
	}
}

// stderrWidth queries the current terminal width of os.Stderr, falling back to
// ttyFallbackCols if stderr is not a terminal or the query fails. Called on
// every redraw so resizes during long runs are honored.
func stderrWidth() int {
	w, _, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || w <= 0 {
		return ttyFallbackCols
	}
	return w
}

func (t *ttyReporter) Stage(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.active {
		// Close the previous stage without a custom summary.
		t.closeStageLocked("")
	}
	t.stage = name
	t.stageStart = time.Now()
	t.step = ""
	t.cur, t.total = 0, 0
	t.active = true
	t.drawLocked(true)
}

func (t *ttyReporter) Step(format string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.step = fmt.Sprintf(format, args...)
	t.drawLocked(false)
}

func (t *ttyReporter) Progress(current, total int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cur, t.total = current, total
	t.drawLocked(false)
}

func (t *ttyReporter) Warn(format string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	fmt.Fprint(t.w, ansiEraseToEnd)
	fmt.Fprintf(t.w, "%sWARN%s %s\n", ansiYellow, ansiReset, msg)
	if t.active {
		t.drawLocked(true)
	}
}

func (t *ttyReporter) Done(format string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closeStageLocked(fmt.Sprintf(format, args...))
}

func (t *ttyReporter) closeStageLocked(summary string) {
	if !t.active {
		return
	}
	dur := time.Since(t.stageStart).Round(time.Millisecond)
	// Belt-and-suspenders: erase from the cursor to the end of the screen so
	// any soft-wrapped tail of the prior status line is wiped before we stamp
	// the summary on a fresh line.
	fmt.Fprint(t.w, ansiEraseToEnd)
	if summary == "" {
		fmt.Fprintf(t.w, "%s✓%s %s %s(%s)%s\n", ansiGreen, ansiReset, t.stage, ansiDim, dur, ansiReset)
	} else {
		fmt.Fprintf(t.w, "%s✓%s %s — %s %s(%s)%s\n", ansiGreen, ansiReset, t.stage, summary, ansiDim, dur, ansiReset)
	}
	t.active = false
	t.stage = ""
	t.step = ""
	t.cur, t.total = 0, 0
}

func (t *ttyReporter) drawLocked(force bool) {
	if !t.active {
		return
	}
	now := time.Now()
	if !force && now.Sub(t.lastDraw) < ttyRedrawMinGap {
		return
	}
	t.lastDraw = now
	t.frame = (t.frame + 1) % len(spinnerFrames)

	width := ttyFallbackCols
	if t.widthFn != nil {
		width = t.widthFn()
	}
	if width <= 0 {
		width = ttyFallbackCols
	}
	// Reserve one column so the cursor never lands on the wrap boundary,
	// which some terminals interpret as the next row.
	maxRunes := width - 1
	if maxRunes < 1 {
		maxRunes = 1
	}

	// Build the unstyled line first so we can truncate by display width.
	var plain strings.Builder
	plain.WriteRune(spinnerFrames[t.frame])
	plain.WriteByte(' ')
	plain.WriteString(t.stage)
	if t.total > 0 {
		fmt.Fprintf(&plain, " [%d/%d]", t.cur, t.total)
	}
	if t.step != "" {
		fmt.Fprintf(&plain, " · %s", t.step)
	}

	plainStr := plain.String()
	runes := []rune(plainStr)
	if len(runes) > maxRunes {
		// Truncated: skip ANSI styling entirely — the unstyled trim is
		// guaranteed to fit on one row.
		fmt.Fprint(t.w, ansiEraseLine, string(runes[:maxRunes]))
		return
	}

	// Fits on one row: re-render with dim styling for the counter and step.
	var styled strings.Builder
	styled.WriteString(ansiEraseLine)
	styled.WriteRune(spinnerFrames[t.frame])
	styled.WriteByte(' ')
	styled.WriteString(t.stage)
	if t.total > 0 {
		fmt.Fprintf(&styled, " %s[%d/%d]%s", ansiDim, t.cur, t.total, ansiReset)
	}
	if t.step != "" {
		fmt.Fprintf(&styled, " %s· %s%s", ansiDim, t.step, ansiReset)
	}
	fmt.Fprint(t.w, styled.String())
}
