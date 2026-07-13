package integration_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unidoc/unisupply/pkg/scanner"
)

// writeGoSumFixture generates a real, minimal Go module in a temp dir with a
// single tiny dependency and a toolchain-generated go.sum. `go mod tidy`
// resolves from the local module cache when warm (gopkg.in/yaml.v3 is one of
// unisupply's own dependencies) and falls back to the network otherwise —
// the caller skips the test when neither is available.
func writeGoSumFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	gomod := "module example.com/gosumfixture\n\ngo 1.21\n\nrequire gopkg.in/yaml.v3 v3.0.1\n"
	main := "package main\n\nimport \"gopkg.in/yaml.v3\"\n\nfunc main() {\n\t_, _ = yaml.Marshal(map[string]string{\"k\": \"v\"})\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(main), 0o600); err != nil {
		t.Fatalf("writing main.go: %v", err)
	}

	tidy := exec.Command("go", "mod", "tidy")
	tidy.Dir = dir
	if out, err := tidy.CombinedOutput(); err != nil {
		t.Skipf("go mod tidy failed (module cache cold and network/proxy unavailable): %v\n%s", err, out)
	}
	return dir
}

// TestVerifyGoSum_ValidGoSum exercises the real `go mod verify` shell-out on a
// freshly generated module — the happy path must report "true".
func TestVerifyGoSum_ValidGoSum(t *testing.T) {
	dir := writeGoSumFixture(t)

	report := &scanner.IntegrityReport{}
	scanner.NewIntegrityScanner().VerifyGoSum(context.Background(), filepath.Join(dir, "go.mod"), report)

	if report.GoSumVerified != scanner.GoSumVerifiedTrue {
		t.Fatalf("GoSumVerified = %q, want %q (findings: %+v)", report.GoSumVerified, scanner.GoSumVerifiedTrue, report.Findings)
	}
	if len(report.Findings) != 0 {
		t.Errorf("Findings length = %d, want 0", len(report.Findings))
	}
}

// TestVerifyGoSum_CorruptedGoSum flips a byte in a go.sum hash and verifies
// the scan degrades gracefully: `go mod verify` exits non-zero (the go
// command refuses to load a module whose go.mod hash mismatches go.sum), no
// panic, and a CRITICAL gosum_mismatch finding is produced.
func TestVerifyGoSum_CorruptedGoSum(t *testing.T) {
	dir := writeGoSumFixture(t)
	gosumPath := filepath.Join(dir, "go.sum")

	data, err := os.ReadFile(gosumPath)
	if err != nil {
		t.Fatalf("reading go.sum: %v", err)
	}
	// Flip one character inside the first "/go.mod h1:" hash. "A" and "B" are
	// both valid base64 alphabet characters, so the line stays parseable and
	// the corruption surfaces as a checksum mismatch, not a syntax error.
	// The /go.mod hash is targeted deliberately: `go mod verify` re-checks
	// go.mod hashes against go.sum when loading the build list, but verifies
	// module zips against the cache's own ziphash records — a corrupted zip
	// h1: line would go unnoticed.
	corrupted := string(data)
	idx := strings.Index(corrupted, "/go.mod h1:")
	if idx < 0 {
		t.Fatalf("no /go.mod h1: hash found in go.sum:\n%s", corrupted)
	}
	idx += len("/go.mod ")
	pos := idx + 3
	flip := "A"
	if corrupted[pos] == 'A' {
		flip = "B"
	}
	corrupted = corrupted[:pos] + flip + corrupted[pos+1:]
	if err := os.WriteFile(gosumPath, []byte(corrupted), 0o600); err != nil {
		t.Fatalf("writing corrupted go.sum: %v", err)
	}

	report := &scanner.IntegrityReport{}
	scanner.NewIntegrityScanner().VerifyGoSum(context.Background(), filepath.Join(dir, "go.mod"), report)

	if report.GoSumVerified != scanner.GoSumVerifiedFalse {
		t.Fatalf("GoSumVerified = %q, want %q (findings: %+v)", report.GoSumVerified, scanner.GoSumVerifiedFalse, report.Findings)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("Findings length = %d, want 1: %+v", len(report.Findings), report.Findings)
	}
	f := report.Findings[0]
	if f.Category != "gosum_mismatch" {
		t.Errorf("Category = %q, want gosum_mismatch", f.Category)
	}
	if f.Severity != scanner.IntegrityCritical {
		t.Errorf("Severity = %q, want %q", f.Severity, scanner.IntegrityCritical)
	}
	if f.Detail == "go mod verify failed: " {
		t.Errorf("Detail should carry the go mod verify output, got %q", f.Detail)
	}
}
