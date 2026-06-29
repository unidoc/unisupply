// Package progress reports user-facing progress for long-running unisupply
// operations.
//
// All renderers in this package write exclusively to os.Stderr so that
// os.Stdout remains reserved for result data (text/JSON/SBOM/PDF streams).
// Callers attach a Reporter to a context.Context via WithReporter; downstream
// code reads it back with From, which returns a no-op Reporter when none has
// been attached. This keeps tests and library use unaffected.
package progress

import (
	"context"
	"fmt"
)

// Reporter receives progress events from scanners, the resolver and report
// writers. Implementations decide how (or whether) to render them.
type Reporter interface {
	// Stage announces a new top-level phase. Implicitly closes any prior
	// open stage that did not call Done.
	Stage(name string)

	// Step describes a sub-action inside the current stage. TTY renderers
	// overwrite the previous Step on the same line; line-based renderers
	// emit one line per call (subject to throttling).
	Step(format string, args ...any)

	// Progress reports batch progress within the current stage. It is safe
	// to call on every iteration of a loop; renderers are responsible for
	// throttling redraws.
	Progress(current, total int)

	// Warn emits a user-visible warning without disrupting the active
	// stage line.
	Warn(format string, args ...any)

	// Done closes the current stage with a final summary line.
	Done(format string, args ...any)
}

// Mode selects which Reporter implementation New constructs.
type Mode int

const (
	// ModeAuto picks ttyReporter when os.Stderr is a terminal,
	// plainReporter otherwise.
	ModeAuto Mode = iota
	// ModePlain forces the line-based renderer regardless of terminal.
	ModePlain
	// ModeNone discards all progress events.
	ModeNone
)

// ParseMode maps the user-facing flag value to a Mode.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "auto", "":
		return ModeAuto, nil
	case "plain":
		return ModePlain, nil
	case "none":
		return ModeNone, nil
	default:
		return ModeAuto, fmt.Errorf("invalid progress mode %q (want auto, plain, or none)", s)
	}
}

type ctxKey struct{}

// WithReporter returns a child context carrying r.
func WithReporter(ctx context.Context, r Reporter) context.Context {
	if r == nil {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, r)
}

// From returns the Reporter attached to ctx, or a no-op Reporter if none has
// been attached. The returned value is always safe to call.
func From(ctx context.Context) Reporter {
	if ctx == nil {
		return noopReporter{}
	}
	if r, ok := ctx.Value(ctxKey{}).(Reporter); ok && r != nil {
		return r
	}
	return noopReporter{}
}
