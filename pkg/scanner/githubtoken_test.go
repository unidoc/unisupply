package scanner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// tokenProbeClient returns a Client whose inner transport answers every
// request with status (or err), and a pointer to the last request it saw.
// A canned transport is needed because the host pin rejects any host but
// api.github.com, so an httptest server on localhost cannot be used.
func tokenProbeClient(status int, err error) (*Client, *http.Request) {
	var seen http.Request
	c := NewClient(ClientOptions{})
	c.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		seen = *req
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
	return c, &seen
}

func TestValidateGitHubToken(t *testing.T) {
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
	client, _ := tokenProbeClient(http.StatusBadGateway, nil)

	err := ValidateGitHubToken(context.Background(), client, "t")
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("err = %v, want it to name status 502", err)
	}
}
