package offline_test

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"strings"
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
		want := []string{
			"PATH=/usr/bin", "HOME=/home/x",
			"GOPROXY=off", "GOFLAGS=-mod=mod",
			"GOPRIVATE=", "GONOPROXY=", "GONOSUMDB=", "GOSUMDB=off",
		}
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

// TestEnvResolvesToNoEgress asks the real toolchain what it resolved, rather
// than asserting on the strings Env produced. It is the only check that catches
// the trap the settings exist for: GONOPROXY and GONOSUMDB fall back to
// GOPRIVATE when set to the empty string, so an Env that clears them without
// clearing GOPRIVATE reads as correct and still leaves a private module free to
// fetch directly from VCS.
//
// The parent environment deliberately carries a GOPRIVATE pattern — that is the
// configuration under which GOPROXY=off used to leak.
func TestEnvResolvesToNoEgress(t *testing.T) {
	t.Cleanup(restoreDefaultTransport(http.DefaultTransport))
	offline.Enable()
	t.Cleanup(offline.Disable)

	base := append(os.Environ(), "GOPRIVATE=example.com/private")

	// `go env` only reads configuration; it makes no network requests, so this
	// stays consistent with what the package promises.
	vars := []string{"GONOPROXY", "GONOSUMDB", "GOSUMDB", "GOPROXY"}
	cmd := exec.Command("go", append([]string{"env"}, vars...)...)
	cmd.Env = offline.Env(base)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go env: %v", err)
	}

	got := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(got) != len(vars) {
		t.Fatalf("go env printed %d lines, want %d: %q", len(got), len(vars), out)
	}

	want := map[string]string{
		// Empty: no module path can bypass GOPROXY=off for a direct VCS fetch,
		// and none can bypass the sumdb setting.
		"GONOPROXY": "",
		"GONOSUMDB": "",
		// off: useSumDB returns false, so the checksum database is never
		// contacted — not even via the direct fallback GOPROXY=off triggers.
		"GOSUMDB": "off",
		"GOPROXY": "off",
	}
	for i, name := range vars {
		if got[i] != want[name] {
			t.Errorf("go env %s = %q, want %q (egress path left open)", name, got[i], want[name])
		}
	}
}

func restoreDefaultTransport(rt http.RoundTripper) func() {
	return func() { http.DefaultTransport = rt }
}

type panicTransport struct{}

func (panicTransport) RoundTrip(*http.Request) (*http.Response, error) {
	panic("transport dialed while offline")
}
