package runner

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/unidoc/unisupply/pkg/progress"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// ErrGithubTokenPrecondition is returned (wrapped) by Run when
// Options.RequireGithubToken is set and the token is missing, rejected by
// GitHub, or could not be validated. The CLI maps it to exit code 3.
var ErrGithubTokenPrecondition = errors.New("github token precondition failed")

// tokenProbeTimeout caps each token probe attempt. It is separate from
// Options.Timeout (the CLI defaults to 30s; gorisk passes minutes) so an
// unreachable api.github.com delays the scan by seconds, not by the whole
// scanner timeout times the retries.
const tokenProbeTimeout = 5 * time.Second

// tokenCheck is the outcome of checkGitHubToken.
type tokenCheck struct {
	// token is what the scanners use: the caller's token, or "" after a 401.
	token string
	// rejected is true when GitHub answered 401 and token was cleared.
	rejected bool
	// warning is the report warning for the outcome, or "" when there is
	// nothing to report.
	warning string
}

// checkGitHubToken probes GitHub with token before any scanner runs.
//
// GitHub answers 401 to every request carrying a bad token instead of serving
// it anonymously, so an unchecked bad token turns every maintainer lookup and
// GHSA enrichment into a generic API error. The probe turns that into one
// explicit outcome:
//
//   - accepted: nothing changes.
//   - rejected (401): with require the run fails; without it the token is
//     cleared so the scanners really run unauthenticated, which is what the
//     warning says they are doing.
//   - undecidable (network error, or any status other than 200 and 401,
//     such as 403, 429 or 5xx): with require the run fails, since the
//     requirement exists so CI never passes a degraded scan; without it the
//     token is kept, because nothing shows it is bad.
//
// A cancelled context returns ctx.Err(), never the precondition error, so an
// interrupted run is not blamed on the token. Nothing is probed offline (the
// offline transport would refuse the request) or when no token is set.
func checkGitHubToken(ctx context.Context, token string, require, offlineMode bool, timeout time.Duration) (tokenCheck, error) {
	tc := tokenCheck{token: token}
	if token == "" || offlineMode {
		return tc, nil
	}

	probeTimeout := tokenProbeTimeout
	if timeout > 0 && timeout < probeTimeout {
		probeTimeout = timeout
	}
	client := scanner.NewClient(scanner.ClientOptions{Timeout: probeTimeout})
	err := scanner.ValidateGitHubToken(ctx, client, token)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return tc, ctxErr
	}

	rep := progress.From(ctx)
	switch {
	case err == nil:
		return tc, nil

	case errors.Is(err, scanner.ErrGitHubTokenRejected):
		if require {
			return tc, fmt.Errorf("%w: GitHub rejected the token (401 Bad credentials)", ErrGithubTokenPrecondition)
		}
		rep.Warn("GitHub token rejected (401) — continuing unauthenticated")
		tc.token = ""
		tc.rejected = true
		tc.warning = "GitHub rejected the token (401 Bad credentials); the scan ran unauthenticated, so maintainer data may be truncated by the anonymous rate limit"
		return tc, nil

	default:
		if require {
			return tc, fmt.Errorf("%w: the token could not be validated: %v", ErrGithubTokenPrecondition, err)
		}
		rep.Warn("could not validate GitHub token: %v — continuing with the token", err)
		tc.warning = fmt.Sprintf("GitHub token could not be validated (%v); the scan used it anyway", err)
		return tc, nil
	}
}
