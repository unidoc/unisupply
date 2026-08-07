package offline_test

import (
	"bytes"
	"errors"
	"net/http"
	"testing"

	"github.com/unidoc/unisupply/pkg/netlog"
	"github.com/unidoc/unisupply/pkg/offline"
)

func TestEnableRefusesWithoutDialing(t *testing.T) {
	t.Cleanup(restoreDefaultTransport(http.DefaultTransport))

	// A transport that panics if it is ever reached: proves the refusal
	// happens above it, not that the dial merely failed.
	http.DefaultTransport = panicTransport{}

	offline.Enable()
	t.Cleanup(offline.Disable)

	if !offline.Enabled() {
		t.Fatal("Enabled() = false after Enable()")
	}

	_, err := http.Get("http://example.invalid/x")
	if !errors.Is(err, offline.ErrOffline) {
		t.Fatalf("http.Get error = %v, want ErrOffline", err)
	}
}

func TestDisableRestoresTransport(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(restoreDefaultTransport(original))

	offline.Enable()
	if http.DefaultTransport == original {
		t.Fatal("Enable() did not replace http.DefaultTransport")
	}

	offline.Disable()
	if http.DefaultTransport != original {
		t.Error("Disable() did not restore the original transport")
	}
	if offline.Enabled() {
		t.Error("Enabled() = true after Disable()")
	}
}

// TestDisableIsIdempotent guards the case where Disable runs twice (a deferred
// cleanup plus an explicit call) — the second must not clobber the transport a
// later test installed.
func TestDisableIsIdempotent(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(restoreDefaultTransport(original))

	offline.Enable()
	offline.Disable()

	sentinel := panicTransport{}
	http.DefaultTransport = sentinel
	offline.Disable()

	if http.DefaultTransport != http.RoundTripper(sentinel) {
		t.Error("second Disable() overwrote a transport it did not install")
	}
}

// TestWithNetlogLogsRefusals pins the documented install order: offline first,
// netlog second, so netlog wraps the refusal and refused requests still show up
// in the network log. Unwinding is reverse order.
func TestWithNetlogLogsRefusals(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(restoreDefaultTransport(original))

	// netlog's sink serializes its own writes; this test reads only after the
	// request has returned, so a plain buffer is safe.
	var buf bytes.Buffer

	offline.Enable()
	netlog.Enable(&buf)
	t.Cleanup(func() {
		netlog.Disable()
		offline.Disable()
	})

	_, err := http.Get("http://example.invalid/x")
	if !errors.Is(err, offline.ErrOffline) {
		t.Fatalf("http.Get error = %v, want ErrOffline", err)
	}

	if got := buf.String(); got == "" {
		t.Error("netlog recorded nothing; refusal must still be logged")
	}
}

func TestEnv(t *testing.T) {
	base := []string{"PATH=/usr/bin", "HOME=/home/x"}

	t.Run("disabled returns nil", func(t *testing.T) {
		// nil is meaningful: exec.Cmd treats it as "inherit the parent's
		// environment", which is the pre-offline behavior.
		if got := offline.Env(base); got != nil {
			t.Errorf("Env() = %v, want nil when offline is disabled", got)
		}
	})

	t.Run("enabled constrains the toolchain", func(t *testing.T) {
		t.Cleanup(restoreDefaultTransport(http.DefaultTransport))
		offline.Enable()
		t.Cleanup(offline.Disable)

		got := offline.Env(base)
		want := []string{"PATH=/usr/bin", "HOME=/home/x", "GOPROXY=off", "GOFLAGS=-mod=mod"}
		if len(got) != len(want) {
			t.Fatalf("Env() = %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("Env()[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("does not alias base", func(t *testing.T) {
		t.Cleanup(restoreDefaultTransport(http.DefaultTransport))
		offline.Enable()
		t.Cleanup(offline.Disable)

		// base has spare capacity, so a naive append would write into it and
		// corrupt a caller reusing the slice.
		shared := make([]string, 2, 8)
		copy(shared, base)

		offline.Env(shared)
		if len(shared) != 2 {
			t.Errorf("Env() mutated its argument: len = %d, want 2", len(shared))
		}
	})
}

func restoreDefaultTransport(rt http.RoundTripper) func() {
	return func() { http.DefaultTransport = rt }
}

type panicTransport struct{}

func (panicTransport) RoundTrip(*http.Request) (*http.Response, error) {
	panic("transport dialed while offline")
}
