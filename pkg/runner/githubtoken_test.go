package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/progress"
)

// stubGitHub replaces http.DefaultTransport (which the scanner client
// delegates to) with one that answers api.github.com/rate_limit with status
// and fails the test on any other request. It returns the request count.
func stubGitHub(t *testing.T, status int) *atomic.Int32 {
	t.Helper()
	var requests atomic.Int32
	original := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests.Add(1)
		if req.URL.Host != "api.github.com" || req.URL.Path != "/rate_limit" {
			t.Errorf("unexpected request %s %s: only the token probe may run", req.Method, req.URL)
			return nil, fmt.Errorf("unexpected request %s", req.URL)
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(`{"message":"canned"}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = original })
	return &requests
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// recordingReporter records Warn calls.
type recordingReporter struct {
	mu       sync.Mutex
	warnings []string
}

func (r *recordingReporter) Stage(string)        {}
func (r *recordingReporter) Step(string, ...any) {}
func (r *recordingReporter) Progress(int, int)   {}
func (r *recordingReporter) Done(string, ...any) {}
func (r *recordingReporter) Warn(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warnings = append(r.warnings, fmt.Sprintf(format, args...))
}

func TestCheckGitHubToken(t *testing.T) {
	tests := []struct {
		name          string
		token         string
		require       bool
		offline       bool
		status        int
		wantErr       bool
		wantToken     string
		wantRejected  bool
		wantWarnings  []string
		wantReportHas string
		wantRequests  int32
	}{
		{
			name:         "accepted token proceeds untouched",
			token:        "good",
			require:      true,
			status:       http.StatusOK,
			wantToken:    "good",
			wantRequests: 1,
		},
		{
			name:         "rejected with require fails",
			token:        "bad",
			require:      true,
			status:       http.StatusUnauthorized,
			wantErr:      true,
			wantToken:    "bad",
			wantRequests: 1,
		},
		{
			name:          "rejected without require warns and clears the token",
			token:         "bad",
			status:        http.StatusUnauthorized,
			wantToken:     "",
			wantRejected:  true,
			wantWarnings:  []string{"GitHub token rejected (401) — continuing unauthenticated"},
			wantReportHas: "ran unauthenticated",
			wantRequests:  1,
		},
		{
			name:         "403 with require fails as not validated",
			token:        "maybe",
			require:      true,
			status:       http.StatusForbidden,
			wantErr:      true,
			wantToken:    "maybe",
			wantRequests: 1,
		},
		{
			name:          "403 without require warns and keeps the token",
			token:         "maybe",
			status:        http.StatusForbidden,
			wantToken:     "maybe",
			wantWarnings:  []string{"could not validate GitHub token: GitHub rate limit probe returned 403 — continuing with the token"},
			wantReportHas: "returned 403",
			wantRequests:  1,
		},
		{
			name:      "no token makes no request",
			wantToken: "",
		},
		{
			name:      "offline with require makes no request and does not fail",
			token:     "tok",
			require:   true,
			offline:   true,
			wantToken: "tok",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requests := stubGitHub(t, tc.status)
			rep := &recordingReporter{}
			ctx := progress.WithReporter(context.Background(), rep)

			got, err := checkGitHubToken(ctx, tc.token, tc.require, tc.offline, 0)

			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrGithubTokenPrecondition) {
				t.Errorf("err = %v, want it to wrap ErrGithubTokenPrecondition", err)
			}
			if got.token != tc.wantToken {
				t.Errorf("token = %q, want %q", got.token, tc.wantToken)
			}
			if got.rejected != tc.wantRejected {
				t.Errorf("rejected = %v, want %v", got.rejected, tc.wantRejected)
			}
			if !reflect.DeepEqual(rep.warnings, tc.wantWarnings) {
				t.Errorf("progress warnings = %q, want %q", rep.warnings, tc.wantWarnings)
			}
			if tc.wantReportHas == "" && got.warning != "" {
				t.Errorf("report warning = %q, want none", got.warning)
			}
			if tc.wantReportHas != "" && !strings.Contains(got.warning, tc.wantReportHas) {
				t.Errorf("report warning = %q, want it to contain %q", got.warning, tc.wantReportHas)
			}
			if n := requests.Load(); n != tc.wantRequests {
				t.Errorf("requests = %d, want %d", n, tc.wantRequests)
			}
		})
	}
}

// TestCheckGitHubToken_RejectedMessage pins the two precondition messages: a
// 401 says the token was rejected, anything else must not claim that.
func TestCheckGitHubToken_RejectedMessage(t *testing.T) {
	stubGitHub(t, http.StatusUnauthorized)
	_, err := checkGitHubToken(context.Background(), "bad", true, false, 0)
	if err == nil || !strings.Contains(err.Error(), "rejected the token (401") {
		t.Errorf("err = %v, want it to name the 401 rejection", err)
	}

	stubGitHub(t, http.StatusForbidden)
	_, err = checkGitHubToken(context.Background(), "maybe", true, false, 0)
	if err == nil || !strings.Contains(err.Error(), "could not be validated") || strings.Contains(err.Error(), "rejected") {
		t.Errorf("err = %v, want \"could not be validated\" without claiming rejection", err)
	}
}

// TestCheckGitHubToken_ContextCancelled verifies that an interrupted run is
// reported as cancelled, not as a token precondition failure (which the CLI
// would turn into exit 3 and blame on the token).
func TestCheckGitHubToken_ContextCancelled(t *testing.T) {
	stubGitHub(t, http.StatusOK)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := checkGitHubToken(ctx, "tok", true, false, 0)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if errors.Is(err, ErrGithubTokenPrecondition) {
		t.Errorf("err = %v must not be a token precondition failure", err)
	}
}

// emptyModule writes a go.mod with no dependencies and returns its directory.
func emptyModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	content := "module github.com/example/empty\n\ngo 1.25\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing fixture go.mod: %v", err)
	}
	return dir
}

// TestRun_GithubTokenPrecondition covers where Run validates the token: after
// go.mod is found and the graph resolved (so a bad path reports its own
// error), and on an empty graph only when the token is required.
func TestRun_GithubTokenPrecondition(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name             string
		path             string
		token            string
		require          bool
		status           int
		wantPrecondition bool
		wantErr          bool
		wantRequests     int32
	}{
		{
			name:             "required but missing fails without a request",
			path:             "fixture",
			require:          true,
			wantPrecondition: true,
			wantErr:          true,
		},
		{
			name:         "missing go.mod reports its own error before the probe",
			path:         "missing",
			token:        "tok",
			require:      true,
			status:       http.StatusUnauthorized,
			wantErr:      true,
			wantRequests: 0,
		},
		{
			name:             "required and rejected fails on an empty graph",
			path:             "fixture",
			token:            "bad",
			require:          true,
			status:           http.StatusUnauthorized,
			wantPrecondition: true,
			wantErr:          true,
			wantRequests:     1,
		},
		{
			name:         "required and accepted passes the precondition",
			path:         "fixture",
			token:        "good",
			require:      true,
			status:       http.StatusOK,
			wantRequests: 1,
		},
		{
			name:         "not required: an empty graph uses no token, so no probe",
			path:         "fixture",
			token:        "bad",
			status:       http.StatusUnauthorized,
			wantRequests: 0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requests := stubGitHub(t, tc.status)
			path := t.TempDir() // no go.mod
			if tc.path == "fixture" {
				path = emptyModule(t)
			}

			_, err := Run(context.Background(), Options{
				Path:               path,
				GithubToken:        tc.token,
				RequireGithubToken: tc.require,
				Now:                now,
			})

			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got := errors.Is(err, ErrGithubTokenPrecondition); got != tc.wantPrecondition {
				t.Errorf("errors.Is(err, ErrGithubTokenPrecondition) = %v, want %v (err: %v)", got, tc.wantPrecondition, err)
			}
			if n := requests.Load(); n != tc.wantRequests {
				t.Errorf("requests = %d, want %d", n, tc.wantRequests)
			}
		})
	}
}
