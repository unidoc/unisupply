package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ErrGitHubTokenRejected is returned by ValidateGitHubToken when GitHub
// answers 401. It is distinct from every other failure because only a 401
// proves the token itself is bad; a timeout or a 5xx says nothing about it.
var ErrGitHubTokenRejected = errors.New("GitHub rejected the token (401 Bad credentials)")

// rateLimitURL is the probe target. GitHub documents that requests to
// /rate_limit do not count against the primary rate limit, so validating a
// token costs the scan nothing.
const rateLimitURL = "https://api.github.com/rate_limit"

// tokenProbeBackoff is the wait before each retry of the token probe; its
// length is the number of retries. A variable so tests can drop the waits.
var tokenProbeBackoff = []time.Duration{500 * time.Millisecond, time.Second}

// ValidateGitHubToken checks token with a GET to api.github.com/rate_limit.
//
// It exists because GitHub answers 401 to every request that carries a bad
// token rather than falling back to anonymous access. Without an up-front
// probe, each maintainer lookup fails individually as a generic API error and
// the scan reports a degraded result with no hint that the credential is the
// cause.
//
// The probe deliberately bypasses the maintainer disk cache: a cached 200 from
// an earlier, valid token would otherwise mask a token that is rejected now.
//
// A transport error or a 5xx is retried (len(tokenProbeBackoff) times, with a
// short backoff), so one dropped connection or a brief GitHub outage does not
// read as a token that cannot be validated. Client.Get does not retry itself.
//
// A nil return means GitHub accepted the token. A 401 returns an error
// wrapping ErrGitHubTokenRejected. A cancelled or expired ctx returns ctx.Err().
// Any other outcome (transport failure or 5xx after the retries, or any other
// status such as 403 or 429) returns a different error, because the token's
// validity is then unknown rather than disproved.
func ValidateGitHubToken(ctx context.Context, client *Client, token string) error {
	var err error
	for attempt := 0; ; attempt++ {
		var retryable bool
		retryable, err = probeGitHubToken(ctx, client, token)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !retryable || attempt == len(tokenProbeBackoff) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(tokenProbeBackoff[attempt]):
		}
	}
}

// probeGitHubToken makes one probe request. retryable reports whether the
// failure may be transient (a transport error or a 5xx).
func probeGitHubToken(ctx context.Context, client *Client, token string) (retryable bool, err error) {
	_, resp, err := client.Get(ctx, rateLimitURL, GetOptions{
		Host:       "api.github.com",
		MaxBytes:   64 * 1024,
		AuthHeader: "Bearer " + token,
		Accept:     "application/vnd.github.v3+json",
		Purpose:    "github:token-validation",
	})
	// Get returns the response alongside the error when only the body read
	// failed. The status line alone answers whether the token was accepted,
	// and the body is never used, so decide on the status whenever there is
	// one: a 401 with a truncated body is still a rejection.
	if resp == nil {
		return true, fmt.Errorf("probing GitHub rate limit: %w", err)
	}

	switch {
	case resp.StatusCode == http.StatusOK:
		return false, nil
	case resp.StatusCode == http.StatusUnauthorized:
		return false, ErrGitHubTokenRejected
	default:
		return resp.StatusCode >= 500, fmt.Errorf("GitHub rate limit probe returned %d", resp.StatusCode)
	}
}
