// Package safego turns a panic in a worker goroutine into a panic on the goroutine that started the workers, where a
// recover can catch it. A recover cannot cross goroutines: without this, one panicking lookup in a fan-out ends the
// whole process, whoever called the scan.
package safego

import (
	"fmt"
	"runtime/debug"
	"sync"
)

// Panic is a recovered panic with the stack of the goroutine it happened in.
type Panic struct {
	Value any
	Stack []byte
}

// Error gives the value on the first line, then the stack.
func (p *Panic) Error() string {
	return fmt.Sprintf("panic: %v\n%s", p.Value, p.Stack)
}

// Catcher collects the first panic of a fan-out's workers. The zero value is ready to use and it is safe for concurrent
// use. A fan-out declares one, starts each worker with `defer wg.Done()` and then `defer c.Recover()`, and calls
// Repanic after Wait. Recover must be deferred after wg.Done, so that it runs first: Wait returns once the last Done
// has run, and a Recover that ran after it could record its panic too late for Repanic to see it.
type Catcher struct {
	mu    sync.Mutex
	first *Panic
}

// Recover records a panic of the calling worker. It must be deferred directly: `defer c.Recover()`. Only the first
// panic is kept. A *Panic that comes from a fan-out nested in this worker is kept as it is, so its stack still shows
// where it happened.
func (c *Catcher) Recover() {
	r := recover()
	if r == nil {
		return
	}
	p, ok := r.(*Panic)
	if !ok {
		// Taken here, inside the deferred call, the stack still includes the frames of the panic.
		p = &Panic{Value: r, Stack: debug.Stack()}
	}
	c.mu.Lock()
	if c.first == nil {
		c.first = p
	}
	c.mu.Unlock()
}

// Repanic panics with the recorded *Panic on the calling goroutine, and does nothing when no worker panicked. Call it
// after the workers are done (wg.Wait).
func (c *Catcher) Repanic() {
	c.mu.Lock()
	p := c.first
	c.mu.Unlock()
	if p != nil {
		panic(p)
	}
}
