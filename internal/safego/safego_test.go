package safego

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// repanicked returns what Repanic panics with, or nil when it does not panic.
func repanicked(c *Catcher) (v any) {
	defer func() { v = recover() }()
	c.Repanic()
	return nil
}

func TestCatcher_NoPanicIsANoOp(t *testing.T) {
	var c Catcher
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Recover()
		}()
	}
	wg.Wait()
	if v := repanicked(&c); v != nil {
		t.Errorf("Repanic panicked with %v, want nothing", v)
	}
}

//go:noinline
func panickingWorker() { panic("boom") }

func TestCatcher_RepanicsOnTheCallersGoroutineWithTheWorkersStack(t *testing.T) {
	var c Catcher
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer c.Recover()
		panickingWorker()
	}()
	wg.Wait()

	p, ok := repanicked(&c).(*Panic)
	if !ok {
		t.Fatal("Repanic did not panic with a *Panic")
	}
	if p.Value != "boom" {
		t.Errorf("Value = %v, want boom", p.Value)
	}
	if !strings.Contains(string(p.Stack), "panickingWorker") {
		t.Errorf("Stack does not name the function that panicked:\n%s", p.Stack)
	}
	if got := p.Error(); !strings.HasPrefix(got, "panic: boom\n") || !strings.Contains(got, "panickingWorker") {
		t.Errorf("Error() = %q, want the value on the first line, then the stack", got)
	}
}

// Recover is deferred after wg.Done, so it runs first: when Wait returns, every panic is already recorded. Deferred the
// other way round, Repanic could run between Done and Recover and miss the panic (it did, one run in five, in Run).
func TestCatcher_PanicIsRecordedBeforeWaitReturns(t *testing.T) {
	for round := range 500 {
		var c Catcher
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Recover()
			panic("boom")
		}()
		wg.Wait()
		if repanicked(&c) == nil {
			t.Fatalf("round %d: Repanic after Wait missed the panic", round)
		}
	}
}

// The semaphore slot and the WaitGroup are released when a worker panics, so the fan-out finishes and does not hang.
func TestCatcher_PanickingWorkersReleaseTheirSlots(t *testing.T) {
	var c Catcher
	var wg sync.WaitGroup
	sem := make(chan struct{}, 1)
	for range 5 {
		wg.Add(1)
		sem <- struct{}{} // blocks forever if a panicking worker kept its slot
		go func() {
			defer wg.Done()
			defer c.Recover()
			defer func() { <-sem }()
			panic("boom")
		}()
	}
	wg.Wait()
	if repanicked(&c) == nil {
		t.Error("Repanic did not panic")
	}
	if len(sem) != 0 {
		t.Errorf("%d semaphore slots still held", len(sem))
	}
}

func TestCatcher_ManyPanicsKeepTheFirst(t *testing.T) {
	var c Catcher
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Recover()
			<-start
			panic(fmt.Sprintf("boom %d", i))
		}()
	}
	close(start)
	wg.Wait()

	first := repanicked(&c).(*Panic)
	for range 3 {
		if again := repanicked(&c).(*Panic); again != first {
			t.Error("Repanic must always give the same, first panic")
		}
	}
	if !strings.HasPrefix(fmt.Sprint(first.Value), "boom ") {
		t.Errorf("Value = %v", first.Value)
	}
}

// A fan-out inside a worker of another fan-out: the outer catcher keeps the inner worker's panic as it is, with the
// stack of the place it happened.
func TestCatcher_NestedFanOutsKeepTheOriginalPanic(t *testing.T) {
	var outer Catcher
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer outer.Recover()
		var inner Catcher
		var iwg sync.WaitGroup
		iwg.Add(1)
		go func() {
			defer iwg.Done()
			defer inner.Recover()
			panickingWorker()
		}()
		iwg.Wait()
		inner.Repanic()
	}()
	wg.Wait()

	p, ok := repanicked(&outer).(*Panic)
	if !ok || p.Value != "boom" || !strings.Contains(string(p.Stack), "panickingWorker") {
		t.Errorf("got %#v, want the inner worker's panic unchanged", p)
	}
	if _, wrapped := p.Value.(*Panic); wrapped {
		t.Error("the panic was wrapped a second time")
	}
}

func TestPanic_ErrorWorksAsAnError(t *testing.T) {
	var err error = &Panic{Value: errors.New("inner"), Stack: []byte("stack")}
	if got := err.Error(); got != "panic: inner\nstack" {
		t.Errorf("Error() = %q", got)
	}
}
