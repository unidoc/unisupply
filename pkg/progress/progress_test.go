package progress

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestParseMode(t *testing.T) {
	cases := []struct {
		in      string
		want    Mode
		wantErr bool
	}{
		{"", ModeAuto, false},
		{"auto", ModeAuto, false},
		{"plain", ModePlain, false},
		{"none", ModeNone, false},
		{"quiet", ModeAuto, true},
		{"verbose", ModeAuto, true},
	}
	for _, c := range cases {
		got, err := ParseMode(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("ParseMode(%q) err=%v, wantErr=%v", c.in, err, c.wantErr)
		}
		if err == nil && got != c.want {
			t.Errorf("ParseMode(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestFromEmptyContextReturnsNoop(t *testing.T) {
	r := From(context.Background())
	if _, ok := r.(noopReporter); !ok {
		t.Fatalf("From(empty) = %T, want noopReporter", r)
	}
	// Calling every method must not panic and must not write anywhere.
	r.Stage("x")
	r.Step("y %d", 1)
	r.Progress(1, 2)
	r.Warn("z")
	r.Done("done")
}

func TestWithReporterRoundTrip(t *testing.T) {
	want := newPlainReporter(&bytes.Buffer{}, &fixedClock{})
	ctx := WithReporter(context.Background(), want)
	got := From(ctx)
	if got != want {
		t.Fatalf("From after WithReporter returned %p, want %p", got, want)
	}
}

func TestWithReporterNilNoop(t *testing.T) {
	ctx := WithReporter(context.Background(), nil)
	// Should still return noop, not panic.
	if _, ok := From(ctx).(noopReporter); !ok {
		t.Fatalf("From(WithReporter(nil)) did not return noop")
	}
}

// fixedClock returns a fixed time, advancing by 100ms on each Now() call so
// duration assertions are stable.
type fixedClock struct {
	t time.Time
	n int
}

func (c *fixedClock) Now() time.Time {
	if c.t.IsZero() {
		c.t = time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)
	}
	out := c.t.Add(time.Duration(c.n) * 100 * time.Millisecond)
	c.n++
	return out
}

func TestPlainReporterEmitsLines(t *testing.T) {
	var buf bytes.Buffer
	r := newPlainReporter(&buf, &fixedClock{})

	r.Stage("Resolving dependency graph")
	r.Step("module %s", "github.com/foo/bar")
	r.Progress(1, 4)
	r.Progress(2, 4)
	r.Progress(4, 4) // final tick must emit even if delta < 5%
	r.Warn("rate limit hit")
	r.Done("done with %d modules", 4)

	out := buf.String()
	mustContain := []string{
		"STAGE: Resolving dependency graph",
		"module github.com/foo/bar",
		"1/4",
		"4/4 (100%)",
		"WARN: rate limit hit",
		"DONE: Resolving dependency graph",
		"done with 4 modules",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("plain output missing %q\ngot:\n%s", s, out)
		}
	}

	// Every line is timestamped HH:MM:SS.
	tsRe := regexp.MustCompile(`^\[\d{2}:\d{2}:\d{2}\]`)
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if !tsRe.MatchString(line) {
			t.Errorf("plain line missing timestamp prefix: %q", line)
		}
	}
}

func TestPlainReporterProgressThrottling(t *testing.T) {
	var buf bytes.Buffer
	r := newPlainReporter(&buf, &fixedClock{})
	r.Stage("scan")

	// 100 fast ticks: expect roughly 1 per 5% delta (~20 lines) plus the
	// final tick. Far less than 100.
	for i := 1; i <= 100; i++ {
		r.Progress(i, 100)
	}

	progressLines := strings.Count(buf.String(), "/100")
	if progressLines >= 100 {
		t.Errorf("progress not throttled: %d lines for 100 ticks", progressLines)
	}
	if !strings.Contains(buf.String(), "100/100 (100%)") {
		t.Errorf("final 100/100 tick missing\n%s", buf.String())
	}
}

func TestPlainReporterProgressIgnoresZeroTotal(t *testing.T) {
	var buf bytes.Buffer
	r := newPlainReporter(&buf, &fixedClock{})
	r.Stage("x")
	r.Progress(5, 0) // must be a silent no-op
	if strings.Contains(buf.String(), "5/0") {
		t.Errorf("Progress(5, 0) emitted output: %q", buf.String())
	}
}

func TestNewWithModeNoneIsSilent(t *testing.T) {
	r := New(ModeNone)
	if _, ok := r.(noopReporter); !ok {
		t.Fatalf("New(ModeNone) = %T, want noopReporter", r)
	}
}

// Compile-time guarantee that every shipped reporter satisfies the interface.
var (
	_ Reporter = noopReporter{}
	_ Reporter = (*plainReporter)(nil)
	_ Reporter = (*ttyReporter)(nil)
)

func TestTTYReporterSmoke(t *testing.T) {
	// The TTY reporter writes ANSI sequences; we only verify it doesn't
	// panic when driven through a representative lifecycle with a buffer
	// substituted for the terminal.
	var buf bytes.Buffer
	r := newTTYReporter(&buf)
	r.Stage("scan")
	r.Step("module foo")
	r.Progress(1, 2)
	r.Warn("rate limit")
	r.Done("ok")
	// Closing with Done should leave no active stage; a second Done is a no-op.
	r.Done("")
	if buf.Len() == 0 {
		t.Fatalf("ttyReporter produced no output")
	}
}

func TestNewAutoWithNonTerminalReturnsPlain(t *testing.T) {
	// Under `go test`, os.Stderr is not a character device, so ModeAuto
	// must resolve to the plain renderer.
	r := New(ModeAuto)
	if _, ok := r.(*plainReporter); !ok {
		t.Fatalf("New(ModeAuto) under non-TTY = %T, want *plainReporter", r)
	}
}

// TestTTYReporterTruncatesToWidth verifies that long status lines never emit
// a contiguous run of visible characters wider than the terminal width. This
// is the regression test for Bug 1 — a wrapped status line would stack
// snapshots in the scrollback because \r\033[2K only erases one row.
func TestTTYReporterTruncatesToWidth(t *testing.T) {
	const width = 60
	var buf bytes.Buffer
	r := newTTYReporterWidth(&buf, width)

	r.Stage("Analyzing maintainers (GitHub API)")
	// A representative long module path (≈90 chars) that on its own would
	// blow past a 60-col terminal.
	longPath := "github.com/very-long-organization-name/" + strings.Repeat("subpath/", 8) + "module"
	// Force a redraw even though the throttle would normally suppress it.
	r.lastDraw = time.Time{}
	r.Step("module %s", longPath)
	r.Done("ok")

	out := buf.String()
	if out == "" {
		t.Fatalf("expected ttyReporter output, got empty buffer")
	}

	// Strip ANSI sequences (CSI: ESC[ ... letter) so we can measure rune
	// runs as the terminal would render them.
	ansiRe := regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)
	for i, line := range strings.Split(out, "\n") {
		visible := ansiRe.ReplaceAllString(line, "")
		// Lines may legitimately contain embedded "\r" because the
		// renderer uses CR to rewrite in place. Split on CR so each
		// rewritten segment is measured separately — that's what the
		// terminal actually renders.
		for _, seg := range strings.Split(visible, "\r") {
			if rc := len([]rune(seg)); rc >= width {
				t.Errorf("line %d segment exceeds width %d (%d runes): %q",
					i, width, rc, seg)
			}
		}
	}
}
