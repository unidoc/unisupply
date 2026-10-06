package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
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

// stubGitHub replaces http.DefaultTransport with a transport that answers
// /rate_limit with status (or transportErr when set) and fails the test on any
// other request, so a test also proves nothing else ran before validation. It
// returns the number of requests made. The caller's cache directories are
// redirected so a warm developer cache cannot satisfy a request.
func stubGitHub(t *testing.T, status int, transportErr error) *atomic.Int32 {
	t.Helper()

	// The probe runs after the dependency graph is resolved, and resolving
	// runs the go command, whose module and build caches default to paths
	// under HOME. Pin them first so redirecting HOME below does not send the
	// go command to the network for modules that are already cached.
	pinGoEnv(t)

	// os.UserCacheDir reads XDG_CACHE_HOME (Linux), HOME (macOS) and
	// LocalAppData (Windows).
	cacheDir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheDir)
	t.Setenv("HOME", cacheDir)
	t.Setenv("LocalAppData", cacheDir)

	// Atomic: if validation ever stopped blocking the scan, the concurrent
	// scanners would reach this transport, and a plain counter would turn the
	// real failure into a data race report under -race.
	var requests atomic.Int32
	original := http.DefaultTransport
	http.DefaultTransport = stubRoundTripper(func(req *http.Request) (*http.Response, error) {
		requests.Add(1)
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
	return &requests
}

// pinGoEnv sets the go command's cache, module and config locations to their
// current values, so they survive a later change to HOME.
func pinGoEnv(t *testing.T) {
	t.Helper()
	vars := []string{"GOPATH", "GOMODCACHE", "GOCACHE", "GOENV"}
	out, err := exec.Command("go", append([]string{"env"}, vars...)...).Output()
	if err != nil {
		t.Fatalf("go env: %v", err)
	}
	values := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(values) != len(vars) {
		t.Fatalf("go env returned %d values for %d variables: %q", len(values), len(vars), out)
	}
	for i, v := range vars {
		t.Setenv(v, strings.TrimSpace(values[i]))
	}
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
	if n := requests.Load(); n != 1 {
		t.Errorf("requests = %d, want exactly 1 (the probe)", n)
	}
}

// TestRequireGithubToken_AcceptedToken verifies that run() gets past the
// precondition when GitHub accepts the token. The fixture module has no
// dependencies, so the run ends at "No dependencies found." with no error,
// after exactly one request: the probe.
func TestRequireGithubToken_AcceptedToken(t *testing.T) {
	requests := stubGitHub(t, http.StatusOK, nil)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/empty\n\ngo 1.25\n"), 0o644); err != nil {
		t.Fatalf("writing fixture go.mod: %v", err)
	}

	err := run(&runConfig{
		path:               dir,
		format:             "json",
		timeout:            5 * time.Second,
		githubToken:        "good-token",
		requireGithubToken: true,
		progressMode:       "none",
	})

	if err != nil {
		t.Fatalf("err = %v, want nil (errors.Is(err, errTokenPrecondition) = %v)", err, errors.Is(err, errTokenPrecondition))
	}
	if n := requests.Load(); n != 1 {
		t.Errorf("requests = %d, want exactly 1 (the probe)", n)
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
