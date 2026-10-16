package scanner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// tokenProbeClient returns a Client whose inner transport answers every
// request with status (or err), and a pointer to the last request it saw.
// A canned transport is needed because the host pin rejects any host but
// api.github.com, so an httptest server on localhost cannot be used.
func tokenProbeClient(status int, err error) (*Client, *http.Request) {
	client, seen, _ := tokenProbeSequence(func(int) (int, error) { return status, err })
	return client, seen
}

// tokenProbeSequence is tokenProbeClient with a per-attempt answer: respond
// gets the zero-based attempt number. It also returns the request count.
func tokenProbeSequence(respond func(attempt int) (int, error)) (*Client, *http.Request, *int) {
	var seen http.Request
	requests := new(int)
	c := NewClient(ClientOptions{})
	c.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		seen = *req
		status, err := respond(*requests)
		*requests++
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(`{"message":"canned"}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})
	return c, &seen, requests
}

// withoutProbeBackoff removes the waits between probe retries for the test.
func withoutProbeBackoff(t *testing.T) {
	t.Helper()
	original := tokenProbeBackoff
	tokenProbeBackoff = make([]time.Duration, len(original))
	t.Cleanup(func() { tokenProbeBackoff = original })
}

func TestValidateGitHubToken(t *testing.T) {
	withoutProbeBackoff(t)
	transportErr := errors.New("connection refused")

	tests := []struct {
		name         string
		status       int
		transportErr error
		wantErr      bool
		wantRejected bool
	}{
		{name: "accepted", status: http.StatusOK},
		{name: "rejected", status: http.StatusUnauthorized, wantErr: true, wantRejected: true},
		{name: "server error", status: http.StatusInternalServerError, wantErr: true},
		{name: "forbidden is not rejection", status: http.StatusForbidden, wantErr: true},
		{name: "transport error", transportErr: transportErr, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, seen := tokenProbeClient(tc.status, tc.transportErr)

			err := ValidateGitHubToken(context.Background(), client, "secret-token")

			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got := errors.Is(err, ErrGitHubTokenRejected); got != tc.wantRejected {
				t.Errorf("errors.Is(err, ErrGitHubTokenRejected) = %v, want %v (err: %v)", got, tc.wantRejected, err)
			}
			if tc.transportErr != nil && !errors.Is(err, tc.transportErr) {
				t.Errorf("transport error not wrapped: %v", err)
			}
			if seen.URL == nil {
				t.Fatal("no request reached the transport")
			}
			if seen.URL.Host != "api.github.com" || seen.URL.Path != "/rate_limit" {
				t.Errorf("request went to %s%s, want api.github.com/rate_limit", seen.URL.Host, seen.URL.Path)
			}
			if got := seen.Header.Get("Authorization"); got != "Bearer secret-token" {
				t.Errorf("Authorization = %q, want %q", got, "Bearer secret-token")
			}
		})
	}
}

func TestValidateGitHubToken_StatusInMessage(t *testing.T) {
	withoutProbeBackoff(t)
	client, _ := tokenProbeClient(http.StatusBadGateway, nil)

	err := ValidateGitHubToken(context.Background(), client, "t")
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("err = %v, want it to name status 502", err)
	}
}

// failingBody yields an error on Read, as a connection dropped mid-body does.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (failingBody) Close() error             { return nil }

// TestValidateGitHubToken_StatusDecidesWhenBodyReadFails covers Client.Get
// returning both the response and a body-read error. Treating that as
// inconclusive would keep a rejected token in use without
// --require-github-token, so the status must still decide.
func TestValidateGitHubToken_StatusDecidesWhenBodyReadFails(t *testing.T) {
	withoutProbeBackoff(t)
	tests := []struct {
		name         string
		status       int
		wantErr      bool
		wantRejected bool
	}{
		{name: "401 is still a rejection", status: http.StatusUnauthorized, wantErr: true, wantRejected: true},
		{name: "200 is still accepted", status: http.StatusOK},
		{name: "500 is still inconclusive", status: http.StatusInternalServerError, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(ClientOptions{})
			c.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: tc.status,
					Body:       failingBody{},
					Header:     make(http.Header),
					Request:    req,
				}, nil
			})

			err := ValidateGitHubToken(context.Background(), c, "t")

			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got := errors.Is(err, ErrGitHubTokenRejected); got != tc.wantRejected {
				t.Errorf("errors.Is(err, ErrGitHubTokenRejected) = %v, want %v (err: %v)", got, tc.wantRejected, err)
			}
		})
	}
}

// TestValidateGitHubToken_Retries covers which failures are retried: only a
// transport error or a 5xx can be transient. A 401 is an answer about the
// token, and a 403 or 429 is a rate limit that a sub-second retry cannot clear.
func TestValidateGitHubToken_Retries(t *testing.T) {
	withoutProbeBackoff(t)
	attempts := len(tokenProbeBackoff) + 1
	transportErr := errors.New("connection reset by peer")

	tests := []struct {
		name         string
		respond      func(attempt int) (int, error)
		wantErr      bool
		wantRequests int
	}{
		{
			name:         "transport error is retried until attempts run out",
			respond:      func(int) (int, error) { return 0, transportErr },
			wantErr:      true,
			wantRequests: attempts,
		},
		{
			name:         "5xx is retried until attempts run out",
			respond:      func(int) (int, error) { return http.StatusBadGateway, nil },
			wantErr:      true,
			wantRequests: attempts,
		},
		{
			name: "transient failure then success is accepted",
			respond: func(attempt int) (int, error) {
				if attempt == 0 {
					return http.StatusServiceUnavailable, nil
				}
				return http.StatusOK, nil
			},
			wantRequests: 2,
		},
		{
			name: "transient failure then 401 is a rejection",
			respond: func(attempt int) (int, error) {
				if attempt == 0 {
					return 0, transportErr
				}
				return http.StatusUnauthorized, nil
			},
			wantErr:      true,
			wantRequests: 2,
		},
		{
			name:         "401 is not retried",
			respond:      func(int) (int, error) { return http.StatusUnauthorized, nil },
			wantErr:      true,
			wantRequests: 1,
		},
		{
			name:         "403 is not retried",
			respond:      func(int) (int, error) { return http.StatusForbidden, nil },
			wantErr:      true,
			wantRequests: 1,
		},
		{
			name:         "429 is not retried",
			respond:      func(int) (int, error) { return http.StatusTooManyRequests, nil },
			wantErr:      true,
			wantRequests: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, _, requests := tokenProbeSequence(tc.respond)

			err := ValidateGitHubToken(context.Background(), client, "t")

			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if *requests != tc.wantRequests {
				t.Errorf("requests = %d, want %d", *requests, tc.wantRequests)
			}
		})
	}
}

// TestValidateGitHubToken_ContextCancelled verifies that a cancelled context
// is reported as such, not as a token that could not be validated, and that
// it stops the retries.
func TestValidateGitHubToken_ContextCancelled(t *testing.T) {
	withoutProbeBackoff(t)
	ctx, cancel := context.WithCancel(context.Background())
	client, _, requests := tokenProbeSequence(func(int) (int, error) {
		cancel()
		return 0, context.Canceled
	})

	err := ValidateGitHubToken(ctx, client, "t")

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if errors.Is(err, ErrGitHubTokenRejected) {
		t.Errorf("err = %v must not claim the token was rejected", err)
	}
	if *requests > 1 {
		t.Errorf("requests = %d, want at most 1: a cancelled context must not be retried", *requests)
	}
}
