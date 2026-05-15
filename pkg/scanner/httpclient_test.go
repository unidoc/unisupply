package scanner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPClient_BodyCappedAtMaxBytes(t *testing.T) {
	const maxBytes = 1024
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Send 10 * maxBytes worth of payload.
		w.WriteHeader(http.StatusOK)
		payload := bytes.Repeat([]byte("a"), 10*maxBytes)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	c := NewClient(ClientOptions{})
	host := mustHost(t, srv.URL)
	body, resp, err := c.Get(context.Background(), srv.URL, GetOptions{
		Host:     host,
		MaxBytes: maxBytes,
	})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if int64(len(body)) != maxBytes {
		t.Fatalf("body len = %d, want %d", len(body), maxBytes)
	}
}

func TestHTTPClient_HostPinRejectsMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(ClientOptions{})
	_, _, err := c.Get(context.Background(), srv.URL, GetOptions{
		Host: "evil.example.com",
	})
	if err == nil {
		t.Fatal("expected host pin mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "host pin mismatch") {
		t.Fatalf("expected host pin error, got: %v", err)
	}
}

func TestHTTPClient_RedirectsBlocked(t *testing.T) {
	var targetHit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	c := NewClient(ClientOptions{})
	_, resp, err := c.Get(context.Background(), redirector.URL, GetOptions{
		Host: mustHost(t, redirector.URL),
	})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected to see 302 (redirect not followed), got %d", resp.StatusCode)
	}
	if targetHit.Load() {
		t.Fatal("target server was hit — redirect was followed")
	}
}

// captureTransport records every request that reaches the inner transport.
// Used to verify hostPinTransport rejects BEFORE the inner transport runs,
// so Authorization is never sent to a mismatched host.
type captureTransport struct {
	requests []*http.Request
}

func (ct *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone to preserve headers — req is mutated downstream.
	clone := req.Clone(req.Context())
	ct.requests = append(ct.requests, clone)
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     http.Header{},
	}, nil
}

func TestHTTPClient_AuthNotSentOnHostMismatch(t *testing.T) {
	capture := &captureTransport{}
	c := NewClient(ClientOptions{})
	c.Transport = capture

	_, _, err := c.Get(context.Background(), "https://attacker.example.com/secret", GetOptions{
		Host:       "trusted.example.com",
		AuthHeader: "Bearer super-secret-token",
	})
	if err == nil {
		t.Fatal("expected host pin mismatch error, got nil")
	}
	if len(capture.requests) != 0 {
		t.Fatalf("inner transport was called %d times — auth would have leaked", len(capture.requests))
	}
}

func TestHTTPClient_AuthSentWhenHostMatches(t *testing.T) {
	capture := &captureTransport{}
	c := NewClient(ClientOptions{})
	c.Transport = capture

	_, _, err := c.Get(context.Background(), "https://trusted.example.com/data", GetOptions{
		Host:       "trusted.example.com",
		AuthHeader: "Bearer good-token",
	})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(capture.requests) != 1 {
		t.Fatalf("inner transport called %d times, want 1", len(capture.requests))
	}
	got := capture.requests[0].Header.Get("Authorization")
	if got != "Bearer good-token" {
		t.Fatalf("Authorization header = %q, want %q", got, "Bearer good-token")
	}
}

func TestHTTPClient_TimeoutEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewClient(ClientOptions{Timeout: 50 * time.Millisecond})
	_, _, err := c.Get(context.Background(), srv.URL, GetOptions{
		Host: mustHost(t, srv.URL),
	})
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	// http.Client.Timeout wraps the underlying cancel as context.DeadlineExceeded.
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "Client.Timeout") {
		t.Fatalf("expected deadline-exceeded/timeout, got: %v", err)
	}
}

func TestHTTPClient_HostMatchesIgnoresPort(t *testing.T) {
	if !hostMatches("example.com:8080", "example.com") {
		t.Error("host-with-port should match host-without-port")
	}
	if !hostMatches("Example.COM", "example.com") {
		t.Error("host match should be case-insensitive")
	}
	if hostMatches("evil.com", "good.com") {
		t.Error("different hosts must not match")
	}
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u.Host
}
