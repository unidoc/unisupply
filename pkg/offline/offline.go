// Package offline enforces --offline mode: a scan that issues zero outbound
// network requests.
//
// Enforcement is a single global swap of http.DefaultTransport for a
// round-tripper that returns ErrOffline without dialing. That placement is
// deliberate — it is the only one that covers every egress path in the
// process:
//
//   - the hardened scanner client (pkg/scanner.Client), whose hostPinTransport
//     delegates to http.DefaultTransport when Client.Transport is nil;
//   - x/vuln, which reaches vuln.go.dev through http.DefaultClient;
//   - UniPDF, which reaches cloud.unidoc.io through http.DefaultClient.
//
// A transport installed per scanner client would reach the first only. The
// `go` subprocesses (`go mod graph`, `go list`, `go mod verify`) run outside
// this process and are covered separately by Env, which constrains the
// toolchain through its own environment.
//
// This mirrors pkg/netlog's shape on purpose: both intercept the same global,
// and callers that use both must install offline first so netlog wraps it and
// refused requests still appear in the network log.
package offline

import (
	"errors"
	"net/http"
	"sync/atomic"
)

// ErrOffline is returned by every request attempted while offline mode is
// enabled. Callers test for it with errors.Is — net/http wraps round-tripper
// errors in *url.Error, which unwraps to this.
var ErrOffline = errors.New("offline mode: network access disabled")

// installed holds the transport Enable replaced, so Disable can restore it. A
// nil pointer means offline mode is not enabled.
var installed atomic.Pointer[transport]

// Enable installs the refusing transport as http.DefaultTransport. It must be
// called during startup, before any request is issued, and before
// netlog.Enable so that netlog wraps the refusal rather than the reverse —
// otherwise refused requests never reach the log.
func Enable() {
	t := &transport{inner: http.DefaultTransport}
	installed.Store(t)
	http.DefaultTransport = t
}

// Enabled reports whether Enable has been called.
func Enabled() bool { return installed.Load() != nil }

// Disable reverses Enable, restoring the transport that was replaced.
// Production enables once at startup and never disables; this exists so tests
// can exercise offline paths without leaking global state.
//
// When netlog is also enabled it wraps this transport, so tests must unwind in
// reverse install order — netlog.Disable first, then Disable — or the restore
// is skipped and later tests inherit a refusing transport.
func Disable() {
	t := installed.Load()
	if t == nil {
		return
	}
	if http.DefaultTransport == http.RoundTripper(t) {
		http.DefaultTransport = t.inner
	}
	installed.Store(nil)
}

// goEnv is appended to the parent environment for every `go` subprocess.
//
// GOPROXY=off alone is not enough, because the toolchain checks the private-
// module patterns *before* it honors "off". In cmd/go/internal/modfetch,
// proxyList prepends a "noproxy" entry whenever GONOPROXY is non-empty, and
// lookup matches the path against GONOPROXY ahead of its `case "off"` — a match
// calls lookupDirect, a real VCS fetch. Separately, when the proxy list yields
// "off" the checksum-database client falls back to c.base = c.direct and
// contacts the sumdb host directly. Both are live egress paths out of a scan
// the user asked to make no network requests.
//
// GOPRIVATE= is load-bearing and must not be dropped: cfg.GONOPROXY and
// cfg.GONOSUMDB are declared as EnvOrAndChanged(name, GOPRIVATE), which treats
// an explicitly empty value as unset and falls back to GOPRIVATE. Clearing
// GONOPROXY without also clearing GOPRIVATE leaves the pattern in force — the
// leak stays open for exactly the users who configured private modules.
// TestEnvResolvesToNoEgress pins this against the real toolchain.
var goEnv = []string{
	"GOPROXY=off",      // the module cache is authoritative; never fetch
	"GOFLAGS=-mod=mod", // do not fail on a go.mod the toolchain would want to update
	"GOPRIVATE=",       // clears the GONOPROXY/GONOSUMDB fallback (see above)
	"GONOPROXY=",       // no path bypasses GOPROXY=off for a direct VCS fetch
	"GONOSUMDB=",       // no path bypasses the sumdb setting below
	"GOSUMDB=off",      // useSumDB returns false; never reach the checksum database
}

// Env returns the environment to use for a `go` subprocess. The global
// transport swap cannot reach a child process, so the toolchain is constrained
// through its own environment instead — see goEnv for the settings and why
// GOPROXY=off by itself leaks.
//
// The settings are appended to base rather than replacing it: exec.Cmd resolves
// duplicate keys last-wins, so an appended entry overrides whatever the parent
// inherited.
//
// It returns nil when offline mode is disabled, so callers can assign the
// result to exec.Cmd.Env unconditionally — a nil Env means "inherit the
// parent's", which is the existing behavior.
func Env(base []string) []string {
	if !Enabled() {
		return nil
	}
	return append(append([]string(nil), base...), goEnv...)
}

// SubprocessNote returns the note to pass to netlog.Subprocess for a `go`
// command. Offline replaces the caller's note because Env has already
// constrained the toolchain: a log line still warning that the proxy "may be
// contacted" would contradict the mode the user asked for, in the one output
// they are told to read to confirm it.
func SubprocessNote(online string) string {
	if !Enabled() {
		return online
	}
	return "GOPROXY=off, private-module patterns cleared, GOSUMDB=off — the go toolchain reads only the local module cache"
}

// transport refuses every request without dialing. It keeps inner only so
// Disable can put it back; it is never called.
type transport struct {
	inner http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, ErrOffline
}
