package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
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

// TestRequireGithubToken_WithToken verifies that --require-github-token exits
// with code 0 (not 3) when a GitHub token is present, even a fake one. The
// flag only checks presence, not API validity.
func TestRequireGithubToken_WithToken(t *testing.T) {
	bin := buildBinary(t)

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	moduleRoot := filepath.Join(cwd, "..", "..")

	cmd := exec.Command(bin, "--require-github-token", "--github-token", "fake-token-for-test", moduleRoot)
	// Remove GITHUB_TOKEN from env so the flag value is the only source.
	cmd.Env = filterEnv(os.Environ(), "GITHUB_TOKEN")

	err = cmd.Run()
	exitCode := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	}

	// Exit code 0 = clean scan (or policy violation 2 / runtime error 1 is
	// acceptable here — the key invariant is that it is NOT 3).
	if exitCode == 3 {
		t.Errorf("--require-github-token with --github-token present: exit code = 3, want != 3 (token precondition should pass)")
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
