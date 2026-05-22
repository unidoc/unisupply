package progress

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// plainReporter emits one timestamped line per event. Suitable for CI logs
// and capture-to-file.
type plainReporter struct {
	w     io.Writer
	clock clock

	mu          sync.Mutex
	stage       string
	stageStart  time.Time
	lastPercent int
	lastTick    time.Time
}

// clock isolates time so tests can pin output without sleeping.
type clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// newPlainReporter is unexported so external callers cannot route progress to
// a non-stderr writer. Tests in this package may construct one with a buffer.
func newPlainReporter(w io.Writer, c clock) *plainReporter {
	if w == nil {
		w = os.Stderr
	}
	if c == nil {
		c = realClock{}
	}
	return &plainReporter{w: w, clock: c}
}

func (p *plainReporter) ts() string {
	return p.clock.Now().Format("15:04:05")
}

func (p *plainReporter) Stage(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stage = name
	p.stageStart = p.clock.Now()
	p.lastPercent = -1
	p.lastTick = time.Time{}
	fmt.Fprintf(p.w, "[%s] STAGE: %s\n", p.ts(), name)
}

func (p *plainReporter) Step(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, "[%s]   %s\n", p.ts(), fmt.Sprintf(format, args...))
}

func (p *plainReporter) Progress(current, total int) {
	if total <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	percent := current * 100 / total
	now := p.clock.Now()
	emit := current == total || // always emit the final tick
		p.lastPercent < 0 || // first tick
		percent-p.lastPercent >= 5 || // ≥5% delta since last
		now.Sub(p.lastTick) >= 2*time.Second // or 2s elapsed
	if !emit {
		return
	}
	p.lastPercent = percent
	p.lastTick = now
	fmt.Fprintf(p.w, "[%s]   %d/%d (%d%%)\n", p.ts(), current, total, percent)
}

func (p *plainReporter) Warn(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, "[%s] WARN: %s\n", p.ts(), fmt.Sprintf(format, args...))
}

func (p *plainReporter) Done(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	dur := p.clock.Now().Sub(p.stageStart).Round(time.Millisecond)
	msg := fmt.Sprintf(format, args...)
	if msg == "" {
		fmt.Fprintf(p.w, "[%s] DONE: %s (%s)\n", p.ts(), p.stage, dur)
	} else {
		fmt.Fprintf(p.w, "[%s] DONE: %s — %s (%s)\n", p.ts(), p.stage, msg, dur)
	}
	p.stage = ""
}
