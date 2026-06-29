package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
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
