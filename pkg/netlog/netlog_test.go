package netlog

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
