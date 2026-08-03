// Package netlog implements the --network-log diagnostic: every outbound
// HTTP request is printed to stderr so users can verify that unisupply's
// real behavior matches the network contract documented in the README.
//
// Interception happens at a single choke point — http.DefaultTransport is
// wrapped when Enable is called. The hardened scanner client delegates to
// http.DefaultTransport in production, so shared-client traffic is covered,
// and so is traffic from dependencies that use http.DefaultClient directly
// (golang.org/x/vuln reaching vuln.go.dev, UniPDF reaching cloud.unidoc.io).
//
// Requests issued through the scanner client carry a purpose label in their
// context (see WithPurpose); anything else is labeled from its host.
//
// Nothing is installed and nothing is logged unless Enable is called, so the
// flag-off path is byte-for-byte the previous behavior.
package netlog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ctxKey int

const ctxKeyPurpose ctxKey = iota

// global is the sink installed by Enable. Nil means logging is off.
var global atomic.Pointer[sink]

// WithPurpose tags ctx with a human-readable label describing why a request
// is being made (for example "maintainer:contributors"). The label is printed
// verbatim in the log line.
func WithPurpose(ctx context.Context, purpose string) context.Context {
	if purpose == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyPurpose, purpose)
}

// Enable installs the logging transport as http.DefaultTransport and turns on
// subprocess lifecycle logging. It must be called during startup, before any
// request is issued.
func Enable(w io.Writer) {
	s := &sink{w: w}
	global.Store(s)
	http.DefaultTransport = &transport{inner: http.DefaultTransport, sink: s}
}

// Enabled reports whether Enable has been called.
func Enabled() bool { return global.Load() != nil }

// Disable reverses Enable, restoring the transport that was wrapped. Production
// enables once at startup and never disables; this exists so tests can exercise
// the logging-enabled paths without leaking global state into later tests.
func Disable() {
	if t, ok := http.DefaultTransport.(*transport); ok {
		http.DefaultTransport = t.inner
	}
	global.Store(nil)
}

// Subprocess logs the lifecycle of an external command whose network traffic
// happens in a child process and therefore cannot be intercepted per-request.
// The note should state honestly what may be contacted. No-op when disabled.
func Subprocess(command, note string) {
	if s := global.Load(); s != nil {
		s.printf("NET SUBPROCESS %s (%s)", command, note)
	}
}

// NewTransport wraps inner with a logging round-tripper writing to w. Used by
// Enable, and directly by tests.
func NewTransport(inner http.RoundTripper, w io.Writer) http.RoundTripper {
	return &transport{inner: inner, sink: &sink{w: w}}
}

// Unwrap returns the round-tripper rt wraps when rt is a logging transport,
// and rt itself otherwise. Callers that need to inspect or clone the concrete
// transport underneath (for example to pin dial addresses) must go through
// this so they keep working with --network-log enabled.
func Unwrap(rt http.RoundTripper) http.RoundTripper {
	if t, ok := rt.(*transport); ok {
		return t.inner
	}
	return rt
}

// Wrap re-applies logging to a transport derived from an unwrapped one, so its
// requests still appear in the log. It shares the sink installed by Enable, so
// writes stay serialized with everything else. Returns rt unchanged when
// logging is disabled.
func Wrap(rt http.RoundTripper) http.RoundTripper {
	s := global.Load()
	if s == nil {
		return rt
	}
	return &transport{inner: rt, sink: s}
}

// sink serializes writes so concurrent scanners cannot interleave partial
// lines on stderr.
type sink struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *sink) printf(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(s.w, format+"\n", args...)
}

type transport struct {
	inner http.RoundTripper
	sink  *sink
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	purpose := purposeOf(req)

	start := time.Now()
	resp, err := t.inner.RoundTrip(req)
	elapsed := time.Since(start)

	if err != nil {
		t.sink.printf("NET %s %s %s → error: %s (%s)",
			req.Method, req.URL.Host, purpose, errorText(req.URL, err), formatDuration(elapsed))
		return resp, err
	}
	t.sink.printf("NET %s %s %s → %d (%s, %s)",
		req.Method, req.URL.Host, purpose, resp.StatusCode,
		formatBytes(resp.ContentLength), formatDuration(elapsed))
	return resp, nil
}

// purposeOf returns the context label when the request came through the
// scanner client, and a host-derived label otherwise.
func purposeOf(req *http.Request) string {
	if p, _ := req.Context().Value(ctxKeyPurpose).(string); p != "" {
		return p
	}
	switch req.URL.Hostname() {
	case "vuln.go.dev":
		return "vulndb"
	case "cloud.unidoc.io":
		return "unipdf-license"
	}
	return "unlabeled"
}

// errorText renders err for the log line without disclosing the request path or
// query. The log prints hosts and purposes only, and the README tells users to
// attach it to approval tickets, so a failed request to proxy.golang.org must
// not write a private module path into it. *url.Error stringifies the complete
// URL; net/http's own transport errors do not, but an inner round-tripper's
// might, so unwrap url.Error to its cause and then redact whatever URL text
// survives — the line cannot render a URL regardless of the error's origin.
func errorText(u *url.URL, err error) string {
	var msg string

	// Read the cause directly rather than through Error(), which would render
	// the URL — and panics on a url.Error with no cause.
	var urlErr *url.Error
	switch {
	case !errors.As(err, &urlErr):
		msg = err.Error()
	case urlErr.Err == nil:
		msg = urlErr.Op
	case urlErr.Op == "":
		msg = urlErr.Err.Error()
	default:
		msg = urlErr.Op + ": " + urlErr.Err.Error()
	}

	msg = redactURL(u, msg)
	if msg == "" {
		return "unknown error"
	}
	return msg
}

// redactURL removes the request URL and its identifying components from msg.
// Longest form first, so the full URL is replaced before its own substrings.
// Both the escaped and decoded path are listed — they differ when the path is
// percent-encoded, and an error quoting the escaped form alone would match
// neither u.Path nor u.RequestURI() (which carries the query too).
func redactURL(u *url.URL, msg string) string {
	for _, s := range []string{u.String(), u.RequestURI(), u.RawQuery, u.EscapedPath(), u.Path} {
		if s == "" || s == "/" {
			continue
		}
		msg = strings.ReplaceAll(msg, s, "<redacted>")
	}
	return msg
}

// formatBytes renders a Content-Length. A response with unknown length
// (chunked, or transparently decompressed by net/http) reports "?".
func formatBytes(n int64) string {
	if n < 0 {
		return "? bytes"
	}
	return fmt.Sprintf("%d bytes", n)
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return d.Round(time.Microsecond).String()
	}
	return d.Round(time.Millisecond).String()
}
