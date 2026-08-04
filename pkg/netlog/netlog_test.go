package netlog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// testTransport is a stub round-tripper mirroring the scanner package idiom.
type testTransport struct {
	resp *http.Response
	err  error
}

func (t *testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.err != nil {
		return nil, t.err
	}
	resp := *t.resp
	resp.Request = req
	return &resp, nil
}

func newResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode:    status,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Header:        make(http.Header),
	}
}

func doRequest(t *testing.T, rt http.RoundTripper, purpose, method, url string) {
	t.Helper()
	ctx := WithPurpose(context.Background(), purpose)
	req, err := http.NewRequestWithContext(ctx, method, url, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if _, err := rt.RoundTrip(req); err != nil && !errors.Is(err, errStub) {
		t.Fatalf("RoundTrip: %v", err)
	}
}

var errStub = errors.New("dial tcp: connection refused")

func TestTransportLogsPurposeFromContext(t *testing.T) {
	var buf bytes.Buffer
	rt := NewTransport(&testTransport{resp: newResponse(200, "hello")}, &buf)

	doRequest(t, rt, "maintainer:contributors", "GET", "https://api.github.com/repos/o/r/contributors")

	got := buf.String()
	for _, want := range []string{"NET GET", "api.github.com", "maintainer:contributors", "→ 200", "5 bytes"} {
		if !strings.Contains(got, want) {
			t.Errorf("log line %q missing %q", got, want)
		}
	}
	if strings.Count(got, "\n") != 1 {
		t.Errorf("want exactly one log line, got %q", got)
	}
}

func TestTransportLabelsUnlabeledRequestsByHost(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://vuln.go.dev/index/db.json", "vulndb"},
		{"https://cloud.unidoc.io/api/licenses", "unipdf-license"},
		{"https://example.com/whatever", "unlabeled"},
	}
	for _, tc := range tests {
		var buf bytes.Buffer
		rt := NewTransport(&testTransport{resp: newResponse(200, "")}, &buf)
		doRequest(t, rt, "", "GET", tc.url)
		if !strings.Contains(buf.String(), tc.want) {
			t.Errorf("%s: want purpose %q, got %q", tc.url, tc.want, buf.String())
		}
	}
}

func TestTransportLogsErrors(t *testing.T) {
	var buf bytes.Buffer
	rt := NewTransport(&testTransport{err: errStub}, &buf)

	doRequest(t, rt, "threatintel:kev", "GET", "https://www.cisa.gov/feed.json")

	got := buf.String()
	if !strings.Contains(got, "→ error: ") || !strings.Contains(got, "threatintel:kev") {
		t.Errorf("want error line with purpose, got %q", got)
	}
}

// The log promises hosts and purposes only, and the README tells users to attach
// it to approval tickets — a private module path or query token on the error
// line would break that.
func TestTransportRedactsURLFromErrorLine(t *testing.T) {
	const target = "https://proxy.golang.org/github.com/acme/private-module/@latest?token=SECRET"

	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "url.Error is unwrapped to its cause",
			err:  &url.Error{Op: "Get", URL: target, Err: errors.New("dial tcp: connection refused")},
			want: "Get: dial tcp: connection refused",
		},
		{
			name: "url.Error without a cause keeps only the op",
			err:  &url.Error{Op: "Post", URL: target},
			want: "Post",
		},
		{
			name: "url.Error with nothing to report",
			err:  &url.Error{},
			want: "unknown error",
		},
		{
			name: "plain error embedding the full URL",
			err:  fmt.Errorf("inner transport refused %q", target),
			want: "<redacted>",
		},
		{
			name: "plain error embedding only path and query",
			err:  errors.New("proxy fetch failed for /github.com/acme/private-module/@latest?token=SECRET"),
			want: "<redacted>",
		},
		{
			name: "error carrying no URL passes through unchanged",
			err:  errStub,
			want: "dial tcp: connection refused",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			rt := NewTransport(&testTransport{err: tc.err}, &buf)

			req, err := http.NewRequest("GET", target, http.NoBody)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if _, err := rt.RoundTrip(req); err == nil {
				t.Fatal("RoundTrip: want error from stub transport")
			}

			got := buf.String()
			for _, leak := range []string{"private-module", "SECRET", "@latest", "/github.com/acme"} {
				if strings.Contains(got, leak) {
					t.Errorf("error line leaks %q: %s", leak, got)
				}
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("want error line containing %q, got %s", tc.want, got)
			}
			// The host is logged from req.URL.Host, not from the error text.
			if !strings.Contains(got, "NET GET proxy.golang.org ") {
				t.Errorf("want host still logged, got %s", got)
			}
		})
	}
}

// An error may quote the escaped path alone — which matches neither the decoded
// u.Path nor u.RequestURI() (that one carries the query too) when the two forms
// diverge.
func TestTransportRedactsEscapedPath(t *testing.T) {
	const target = "https://proxy.golang.org/github.com/acme/private%2Dmodule/@latest?token=SECRET"

	var buf bytes.Buffer
	rt := NewTransport(&testTransport{
		err: errors.New(`fetch failed: /github.com/acme/private%2Dmodule/@latest`),
	}, &buf)

	req, err := http.NewRequest("GET", target, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("RoundTrip: want error from stub transport")
	}

	got := buf.String()
	if strings.Contains(got, "private") {
		t.Errorf("error line leaks the escaped path: %s", got)
	}
	if !strings.Contains(got, "<redacted>") {
		t.Errorf("want redacted error line, got %s", got)
	}
}

func TestTransportAgainstRealServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	rt := NewTransport(http.DefaultTransport, &buf)
	doRequest(t, rt, "", "HEAD", srv.URL+"/missing")

	if !strings.Contains(buf.String(), "NET HEAD") || !strings.Contains(buf.String(), "→ 404") {
		t.Errorf("want HEAD/404 line, got %q", buf.String())
	}
}

func TestSubprocessIsNoOpWhenDisabled(t *testing.T) {
	if Enabled() {
		t.Skip("a previous test enabled the global sink")
	}
	// Must not panic and must not write anywhere.
	Subprocess("go mod graph", "note")
}

func TestSinkSerializesConcurrentWrites(t *testing.T) {
	var buf bytes.Buffer
	rt := NewTransport(&testTransport{resp: newResponse(200, "body")}, &buf)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(
				WithPurpose(context.Background(), "resilience:governance"),
				"GET", "https://api.github.com/repos/o/r/contents/SECURITY.md", http.NoBody)
			if _, err := rt.RoundTrip(req); err != nil {
				t.Errorf("RoundTrip: %v", err)
			}
		}()
	}
	wg.Wait()

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != n {
		t.Fatalf("want %d lines, got %d", n, len(lines))
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "NET GET api.github.com resilience:governance → 200") {
			t.Errorf("interleaved or malformed line: %q", line)
		}
	}
}

func TestUnwrapReturnsInnerTransport(t *testing.T) {
	base := &testTransport{resp: newResponse(200, "x")}

	if got := Unwrap(base); got != http.RoundTripper(base) {
		t.Errorf("Unwrap of a plain transport must return it unchanged, got %T", got)
	}
	if got := Unwrap(NewTransport(base, io.Discard)); got != http.RoundTripper(base) {
		t.Errorf("Unwrap of a logging transport must return its inner, got %T", got)
	}
}

func TestWrapLogsThroughGlobalSink(t *testing.T) {
	base := &testTransport{resp: newResponse(200, "body")}

	if got := Wrap(base); got != http.RoundTripper(base) {
		t.Errorf("Wrap must be a no-op when logging is disabled, got %T", got)
	}

	var buf bytes.Buffer
	global.Store(&sink{w: &buf})
	t.Cleanup(func() { global.Store(nil) })

	doRequest(t, Wrap(base), "trustindex:lookup", "POST", "https://trust.example.com/api/v1/lookup")

	if !strings.Contains(buf.String(), "NET POST trust.example.com trustindex:lookup → 200") {
		t.Errorf("want a logged line via the global sink, got %q", buf.String())
	}
}

// TestEnableDisableRestoresGlobalState guards the inverse property scanner
// tests depend on: they enable logging to exercise the wrapped-transport paths,
// and a Disable that failed to restore would leak into every later test.
func TestEnableDisableRestoresGlobalState(t *testing.T) {
	prev := http.DefaultTransport
	var buf bytes.Buffer

	Enable(&buf)
	if !Enabled() || http.DefaultTransport == prev {
		t.Fatal("Enable did not install the logging transport")
	}

	Disable()
	if Enabled() {
		t.Error("Disable left the global sink installed")
	}
	if http.DefaultTransport != prev {
		t.Errorf("Disable did not restore http.DefaultTransport, got %T", http.DefaultTransport)
	}
}
