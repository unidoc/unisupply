package scanner

import (
	"context"
	"sync"
	"time"
)

// fakeClock is a clock that only moves when something sleeps on it, so tests
// of NVD pacing and backoff take no real time.
type fakeClock struct {
	mu     sync.Mutex
	t      time.Time
	sleeps []time.Duration
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if d > 0 {
		c.t = c.t.Add(d)
		c.sleeps = append(c.sleeps, d)
	}
	return nil
}

// pacer returns an NVD pacer driven by the fake clock.
func (c *fakeClock) pacer() *nvdPacer { return newNVDPacer(c.now, c.sleep) }

// Tests must never wait on real NVD pacing or backoff: the process-wide pacer
// runs on a fake clock. Tests of the pacing itself build their own pacer.
func init() {
	processNVDPacer = newFakeClock().pacer()
}
