package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultMaxBytes is the default response-body byte cap used by Client.Get
// when GetOptions.MaxBytes is zero. 512 KB suits small JSON enrichment APIs;
// paginated GitHub responses should pass MaxBytes = 1 MB explicitly.
const DefaultMaxBytes int64 = 512 * 1024

// ClientOptions controls the construction of a hardened HTTP Client.
type ClientOptions struct {
	// Timeout bounds the entire request lifetime (connect + headers + body).
	// Zero falls back to 10s.
	Timeout time.Duration
}

// GetOptions controls a single Get call.
type GetOptions struct {
	// Host is required: only responses from this host are accepted. Defense
	// in depth — redirects are also disabled at the Client level, so the
	// request URL host effectively equals the response URL host.
	Host string

	// MaxBytes caps the response body. Zero falls back to DefaultMaxBytes.
	MaxBytes int64

	// AuthHeader, if non-empty, is injected as the Authorization header at
	// the RoundTripper layer — and only after the host-pin check passes.
	// This prevents accidentally leaking credentials to an unexpected host.
	AuthHeader string

	// Accept, if non-empty, is set as the request Accept header. Non-credential
	// so it's safe to attach at the request level (not the transport).
	Accept string
}

// Client is a hardened HTTP helper enforcing per-request timeout, host
// pinning, redirect rejection, and response-body size capping. Every
// scanner that issues outbound HTTP requests should use it.
type Client struct {
	httpClient *http.Client

	// Transport, if set, overrides the inner round-tripper used by the
	// host-pin transport. Intended for tests — production code should leave
	// it nil and let NewClient delegate to http.DefaultTransport.
	Transport http.RoundTripper
}

// NewClient builds a Client with the explicit safety ordering required by
// Plan 29 Task 01:
//
//  1. http.Client with CheckRedirect blocking all redirects.
//  2. Transport wrapped by hostPinTransport, which rejects mismatched hosts
//     BEFORE handing the request to the inner transport.
//  3. The inner transport (or its wrapper) injects Authorization only after
//     the host-pin check has succeeded.
func NewClient(opts ClientOptions) *Client {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	c := &Client{}
	c.httpClient = &http.Client{
		Timeout: opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &hostPinTransport{client: c},
	}
	return c
}

// Timeout returns the per-request timeout configured on the underlying
// http.Client. Used by tests that introspect scanner configuration.
func (c *Client) Timeout() time.Duration {
	return c.httpClient.Timeout
}

// hostPinTransport is the request gate: it validates the host first, then
// (if the host matches) injects any Authorization header, then delegates to
// the inner transport (Client.Transport, or http.DefaultTransport if unset).
// Auth never reaches a wrong host.
type hostPinTransport struct {
	client *Client
}

type ctxKey int

const (
	ctxKeyExpectedHost ctxKey = iota
	ctxKeyAuthHeader
)

func (t *hostPinTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	expectedHost, _ := req.Context().Value(ctxKeyExpectedHost).(string)
	if expectedHost == "" {
		return nil, errors.New("httpclient: missing expected host in request context")
	}
	if !hostMatches(req.URL.Host, expectedHost) {
		return nil, fmt.Errorf("httpclient: host pin mismatch: request host %q != expected %q", req.URL.Host, expectedHost)
	}

	if auth, _ := req.Context().Value(ctxKeyAuthHeader).(string); auth != "" {
		req.Header.Set("Authorization", auth)
	}

	inner := t.client.Transport
	if inner == nil {
		inner = http.DefaultTransport
	}
	return inner.RoundTrip(req)
}

func hostMatches(actual, expected string) bool {
	a := strings.ToLower(strings.SplitN(actual, ":", 2)[0])
	e := strings.ToLower(strings.SplitN(expected, ":", 2)[0])
	return a == e
}

// Get issues a GET request with timeout, host pinning, redirect blocking,
// and a body size cap. The returned body is already size-capped; the
// response is returned so callers can inspect StatusCode. Get closes the
// underlying response body before returning, so callers MUST NOT read it.
func (c *Client) Get(ctx context.Context, url string, opts GetOptions) ([]byte, *http.Response, error) {
	if opts.Host == "" {
		return nil, nil, errors.New("httpclient: GetOptions.Host is required")
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}

	ctx = context.WithValue(ctx, ctxKeyExpectedHost, opts.Host)
	if opts.AuthHeader != "" {
		ctx = context.WithValue(ctx, ctxKeyAuthHeader, opts.AuthHeader)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, http.NoBody)
	if err != nil {
		return nil, nil, err
	}
	if opts.Accept != "" {
		req.Header.Set("Accept", opts.Accept)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBytes))
	if err != nil {
		return nil, resp, err
	}
	return body, resp, nil
}

// Post issues a POST request with timeout, host pinning, redirect blocking,
// and a body size cap, mirroring Get's safety guarantees.
func (c *Client) Post(ctx context.Context, url, contentType string, reqBody io.Reader, opts GetOptions) ([]byte, *http.Response, error) {
	if opts.Host == "" {
		return nil, nil, errors.New("httpclient: GetOptions.Host is required")
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}

	ctx = context.WithValue(ctx, ctxKeyExpectedHost, opts.Host)
	if opts.AuthHeader != "" {
		ctx = context.WithValue(ctx, ctxKeyAuthHeader, opts.AuthHeader)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, reqBody)
	if err != nil {
		return nil, nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if opts.Accept != "" {
		req.Header.Set("Accept", opts.Accept)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBytes))
	if err != nil {
		return nil, resp, err
	}
	return body, resp, nil
}

// Head issues a HEAD request with timeout, host pinning, redirect blocking.
// No body is read. The response is returned (Body is already closed) so
// callers can inspect StatusCode.
func (c *Client) Head(ctx context.Context, url string, opts GetOptions) (*http.Response, error) {
	if opts.Host == "" {
		return nil, errors.New("httpclient: GetOptions.Host is required")
	}

	ctx = context.WithValue(ctx, ctxKeyExpectedHost, opts.Host)
	if opts.AuthHeader != "" {
		ctx = context.WithValue(ctx, ctxKeyAuthHeader, opts.AuthHeader)
	}

	req, err := http.NewRequestWithContext(ctx, "HEAD", url, http.NoBody)
	if err != nil {
		return nil, err
	}
	if opts.Accept != "" {
		req.Header.Set("Accept", opts.Accept)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	_ = resp.Body.Close()
	return resp, nil
}
