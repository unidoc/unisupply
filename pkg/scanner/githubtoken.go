package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// ErrGitHubTokenRejected is returned by ValidateGitHubToken when GitHub
// answers 401. It is distinct from every other failure because only a 401
// proves the token itself is bad; a timeout or a 5xx says nothing about it.
var ErrGitHubTokenRejected = errors.New("GitHub rejected the token (401 Bad credentials)")

// rateLimitURL is the probe target. GitHub documents that requests to
// /rate_limit do not count against the primary rate limit, so validating a
// token costs the scan nothing.
const rateLimitURL = "https://api.github.com/rate_limit"

// ValidateGitHubToken checks token with a single GET to api.github.com/rate_limit.
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
// A nil return means GitHub accepted the token. A 401 returns an error
// wrapping ErrGitHubTokenRejected. Any other outcome (transport failure, 403,
// 5xx) returns a different error, because the token's validity is then
// unknown rather than disproved.
func ValidateGitHubToken(ctx context.Context, client *Client, token string) error {
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
		return fmt.Errorf("probing GitHub rate limit: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		return ErrGitHubTokenRejected
	default:
		return fmt.Errorf("GitHub rate limit probe returned %d", resp.StatusCode)
	}
}
