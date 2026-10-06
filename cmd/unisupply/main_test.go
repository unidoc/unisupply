package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// buildBinary compiles the unisupply binary into a temporary directory and
// returns its path. The binary is removed when the test finishes.
func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	binName := "unisupply"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(dir, binName)

	// Resolve the module root relative to this test file's directory.
	// go test runs with cwd = package directory.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	moduleRoot := filepath.Join(cwd, "..", "..")

	cmd := exec.Command("go", "build", "-o", binPath, "./cmd/unisupply/")
	cmd.Dir = moduleRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return binPath
}

// TestRequireGithubToken_NoToken verifies that --require-github-token exits
// with code 3 when no GitHub token is present.
func TestRequireGithubToken_NoToken(t *testing.T) {
	bin := buildBinary(t)

	// Locate any go.mod to use as a scan target (the test itself lives inside
	// a Go module, so the module root will do).
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	moduleRoot := filepath.Join(cwd, "..", "..")

	cmd := exec.Command(bin, "--require-github-token", moduleRoot)
	// Remove GITHUB_TOKEN from the environment so the precondition fails.
	cmd.Env = filterEnv(os.Environ(), "GITHUB_TOKEN")

	err = cmd.Run()
	exitCode := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	}

	if exitCode != 3 {
		t.Errorf("--require-github-token without token: exit code = %d, want 3", exitCode)
	}
}

// recordingReporter captures warnings so tests can assert on what the user
// would have seen on stderr. Only Warn is of interest; the rest are no-ops.
type recordingReporter struct {
	warnings []string
}

func (r *recordingReporter) Stage(string)        {}
func (r *recordingReporter) Step(string, ...any) {}
func (r *recordingReporter) Progress(int, int)   {}
func (r *recordingReporter) Done(string, ...any) {}
func (r *recordingReporter) Warn(format string, args ...any) {
	r.warnings = append(r.warnings, fmt.Sprintf(format, args...))
}

// stubGitHub replaces http.DefaultTransport with a transport that answers
// /rate_limit with status (or transportErr when set) and fails the test on any
// other request, so a test also proves nothing else ran before validation. It
// returns a pointer to the number of requests made. The caller's cache
// directories are redirected so a warm developer cache cannot satisfy a request.
func stubGitHub(t *testing.T, status int, transportErr error) *int {
	t.Helper()

	cacheDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheDir)
	t.Setenv("HOME", cacheDir)

	requests := new(int)
	original := http.DefaultTransport
	http.DefaultTransport = stubRoundTripper(func(req *http.Request) (*http.Response, error) {
		*requests++
		if req.URL.Host != "api.github.com" || req.URL.Path != "/rate_limit" {
			t.Errorf("unexpected request %s %s: only the token probe may run before validation settles", req.Method, req.URL)
			return nil, fmt.Errorf("unexpected request %s", req.URL)
		}
		if transportErr != nil {
			return nil, transportErr
		}
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(`{"message":"canned"}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = original })
	return requests
}

type stubRoundTripper func(*http.Request) (*http.Response, error)

func (f stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// moduleRootDir returns the repository root, used as a scan target.
func moduleRootDir(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Join(cwd, "..", "..")
}

// TestRequireGithubToken_RejectedToken verifies that --require-github-token
// fails with the token precondition error when GitHub answers 401, and that it
// does so before any scanner issues a request (stubGitHub fails the test on
// any request other than the probe).
func TestRequireGithubToken_RejectedToken(t *testing.T) {
	requests := stubGitHub(t, http.StatusUnauthorized, nil)

	err := run(&runConfig{
		path:               moduleRootDir(t),
		format:             "json",
		timeout:            5 * time.Second,
		githubToken:        "invalid-token",
		requireGithubToken: true,
		progressMode:       "none",
	})

	if !errors.Is(err, errTokenPrecondition) {
		t.Fatalf("err = %v, want errTokenPrecondition", err)
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "rejected the token") {
		t.Errorf("message %q should name the 401 rejection", err)
	}
	if *requests != 1 {
		t.Errorf("requests = %d, want exactly 1 (the probe)", *requests)
	}
}

// TestRequireGithubToken_UnvalidatableToken verifies that a probe failure that
// is not a 401 also fails the precondition, but with a message that does not
// claim the token was rejected.
func TestRequireGithubToken_UnvalidatableToken(t *testing.T) {
	tests := []struct {
		name         string
		status       int
		transportErr error
		wantInErr    string
	}{
		{name: "server error", status: http.StatusInternalServerError, wantInErr: "500"},
		{name: "transport error", transportErr: errors.New("connection refused"), wantInErr: "connection refused"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stubGitHub(t, tc.status, tc.transportErr)

			err := run(&runConfig{
				path:               moduleRootDir(t),
				format:             "json",
				timeout:            5 * time.Second,
				githubToken:        "some-token",
				requireGithubToken: true,
				progressMode:       "none",
			})

			if !errors.Is(err, errTokenPrecondition) {
				t.Fatalf("err = %v, want errTokenPrecondition", err)
			}
			if !strings.Contains(err.Error(), "could not be validated") || !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("message %q should say the token could not be validated and include %q", err, tc.wantInErr)
			}
			if strings.Contains(err.Error(), "rejected") {
				t.Errorf("message %q claims rejection, but a probe failure does not show that", err)
			}
		})
	}
}

// TestValidateGitHubToken covers the outcomes that do not abort the run, which
// run() cannot show without performing a full scan.
func TestValidateGitHubToken(t *testing.T) {
	tests := []struct {
		name         string
		cfg          runConfig
		status       int
		transportErr error
		wantErr      bool
		wantToken    string
		wantRejected bool
		wantWarnings []string
		wantRequests int
	}{
		{
			name:         "accepted token proceeds untouched",
			cfg:          runConfig{githubToken: "good", requireGithubToken: true},
			status:       http.StatusOK,
			wantToken:    "good",
			wantRequests: 1,
		},
		{
			name:         "rejected without flag warns once and clears the token",
			cfg:          runConfig{githubToken: "bad"},
			status:       http.StatusUnauthorized,
			wantToken:    "",
			wantRejected: true,
			wantWarnings: []string{"GitHub token rejected (401) \u2014 continuing unauthenticated"},
			wantRequests: 1,
		},
		{
			name:         "undecidable without flag warns once and keeps the token",
			cfg:          runConfig{githubToken: "maybe"},
			status:       http.StatusServiceUnavailable,
			wantToken:    "maybe",
			wantWarnings: []string{"could not validate GitHub token: GitHub rate limit probe returned 503 \u2014 continuing with the token"},
			wantRequests: 1,
		},
		{
			name:      "no token makes no request",
			cfg:       runConfig{requireGithubToken: false},
			wantToken: "",
		},
		{
			name:      "offline with flag makes no request and does not fail",
			cfg:       runConfig{githubToken: "tok", requireGithubToken: true, offlineMode: true},
			wantToken: "tok",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requests := stubGitHub(t, tc.status, tc.transportErr)
			cfg := tc.cfg
			cfg.timeout = 5 * time.Second
			rep := &recordingReporter{}

			err := validateGitHubToken(context.Background(), &cfg, rep)

			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if cfg.githubToken != tc.wantToken {
				t.Errorf("githubToken = %q, want %q", cfg.githubToken, tc.wantToken)
			}
			if cfg.githubTokenRejected != tc.wantRejected {
				t.Errorf("githubTokenRejected = %v, want %v", cfg.githubTokenRejected, tc.wantRejected)
			}
			if !reflect.DeepEqual(rep.warnings, tc.wantWarnings) {
				t.Errorf("warnings = %q, want %q", rep.warnings, tc.wantWarnings)
			}
			if *requests != tc.wantRequests {
				t.Errorf("requests = %d, want %d", *requests, tc.wantRequests)
			}
		})
	}
}

// TestPolicyFlagConflict_Warning verifies that passing both --policy and
// --policy-preset prints a warning on stderr naming the ignored preset.
func TestPolicyFlagConflict_Warning(t *testing.T) {
	bin := buildBinary(t)

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	moduleRoot := filepath.Join(cwd, "..", "..")
	policyFile := filepath.Join(moduleRoot, "examples", "policy-custom.json")

	var stderr bytes.Buffer
	cmd := exec.Command(bin, "--policy", policyFile, "--policy-preset", "strict", moduleRoot)
	cmd.Stderr = &stderr
	_ = cmd.Run() // exit code varies with policy result; not what we're testing

	if !strings.Contains(stderr.String(), `--policy-preset "strict" ignored`) {
		t.Errorf("expected conflict warning on stderr, got:\n%s", stderr.String())
	}
}

// TestPolicyFlagConflict_NoSpuriousWarning verifies that supplying only one
// policy flag does not produce the conflict warning.
func TestPolicyFlagConflict_NoSpuriousWarning(t *testing.T) {
	bin := buildBinary(t)

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	moduleRoot := filepath.Join(cwd, "..", "..")

	for _, args := range [][]string{
		{"--policy-preset", "strict", moduleRoot},
	} {
		var stderr bytes.Buffer
		cmd := exec.Command(bin, args...)
		cmd.Stderr = &stderr
		_ = cmd.Run()

		if strings.Contains(stderr.String(), "ignored") {
			t.Errorf("unexpected conflict warning with args %v:\n%s", args, stderr.String())
		}
	}
}

// removeJSONKeys deletes every object member named in keys, at any depth. The
// generic any tree is warranted here: the test compares the shape of four
// different report schemas without modeling any of them.
func removeJSONKeys(v any, keys map[string]struct{}) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if _, drop := keys[k]; drop {
				delete(x, k)
				continue
			}
			removeJSONKeys(child, keys)
		}
	case []any:
		for _, child := range x {
			removeJSONKeys(child, keys)
		}
	}
}

// normalizeJSONReport drops the intentionally per-run fields from a JSON
// report and re-encodes it. Array order is preserved, so an ordering
// difference still shows up in the result.
func normalizeJSONReport(volatile ...string) func([]byte) ([]byte, error) {
	keys := make(map[string]struct{}, len(volatile))
	for _, k := range volatile {
		keys[k] = struct{}{}
	}
	return func(raw []byte) ([]byte, error) {
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("decoding report: %w", err)
		}
		removeJSONKeys(doc, keys)
		return json.MarshalIndent(doc, "", "  ")
	}
}

var textGeneratedLine = regexp.MustCompile(`(?m)^Report generated:.*$`)

// normalizeTextReport blanks the per-run timestamp line in the text report.
func normalizeTextReport(raw []byte) ([]byte, error) {
	return textGeneratedLine.ReplaceAll(raw, []byte("Report generated:")), nil
}

// TestReportOutputDeterministic runs the binary repeatedly on the same target
// and asserts that every output format is identical across runs once the
// intentionally per-run fields are normalized. Several runs are needed: two
// runs can match by luck when a map holds only a few entries.
//
// Offline runs have no maintainer data, so takeover ordering is covered by a
// unit test in pkg/scanner instead.
func TestReportOutputDeterministic(t *testing.T) {
	bin := buildBinary(t)

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	moduleRoot := filepath.Join(cwd, "..", "..")

	// The repo's own workflows yield too few CI findings to expose job-order
	// bugs, so point the CI scan at a multi-job fixture.
	workflowDir, err := filepath.Abs(filepath.Join(moduleRoot, "test", "integration", "testdata", "workflows-multijob"))
	if err != nil {
		t.Fatalf("resolving workflow fixture: %v", err)
	}

	const runs = 5

	// Add a row here to cover a new output format.
	tests := []struct {
		name      string
		format    string
		normalize func([]byte) ([]byte, error)
	}{
		{"json", "json", normalizeJSONReport("generated_at")},
		{"text", "text", normalizeTextReport},
		{"sbom-cyclonedx", "sbom-cyclonedx", normalizeJSONReport("serialNumber", "timestamp")},
		{"sbom-spdx", "sbom-spdx", normalizeJSONReport("documentNamespace", "created", "annotationDate")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outDir := t.TempDir()
			var first []byte
			for i := 0; i < runs; i++ {
				outFile := filepath.Join(outDir, fmt.Sprintf("run-%d.out", i))
				cmd := exec.Command(bin,
					"--offline", "--scan-ci", "--progress", "none", "--no-color", "-v",
					"--workflow-path", workflowDir,
					"-f", tt.format, "-o", outFile, moduleRoot)
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				if err := cmd.Run(); err != nil {
					t.Fatalf("run %d: %v\n%s", i+1, err, stderr.String())
				}

				raw, err := os.ReadFile(outFile)
				if err != nil {
					t.Fatalf("run %d: reading output: %v", i+1, err)
				}
				got, err := tt.normalize(raw)
				if err != nil {
					t.Fatalf("run %d: normalizing output: %v", i+1, err)
				}
				if i == 0 {
					first = got
					continue
				}
				if !bytes.Equal(first, got) {
					// Keep both normalized outputs so the difference can be inspected.
					a := filepath.Join(outDir, "run-1.normalized")
					b := filepath.Join(outDir, fmt.Sprintf("run-%d.normalized", i+1))
					_ = os.WriteFile(a, first, 0o644)
					_ = os.WriteFile(b, got, 0o644)
					t.Fatalf("%s output of run %d differs from run 1 (normalized copies: %s, %s)", tt.format, i+1, a, b)
				}
			}
		})
	}
}

// filterEnv returns a copy of env with all KEY=... entries for key removed.
func filterEnv(env []string, key string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env))
	for _, e := range env {
		if len(e) >= len(prefix) && e[:len(prefix)] == prefix {
			continue
		}
		out = append(out, e)
	}
	return out
}
