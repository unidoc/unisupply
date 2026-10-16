package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckToolchain(t *testing.T) {
	const sentence = "this unisupply was built with go1.26.9 and cannot scan code that needs go1.27; rebuild unisupply with go1.27 or newer"
	if err := checkToolchain("go1.26.9", "go1.27.2"); err == nil || err.Error() != sentence {
		t.Errorf("got %v", err)
	}
	for _, c := range []struct {
		built, scan string
		fail        bool
	}{
		{"go1.26.9", "go1.27.2", true},
		{"go1.26.9", "1.27.2", true},
		{"go1.26.9", "go1.27", true},      // the language version of the next release
		{"go1.26.9", "go1.27rc1", true},   // a release candidate of the next release
		{"go1.26.9", "go1.27beta1", true}, // so is a beta
		{"go1.26.9", "go1.26.10", false},  // a newer patch of the same minor version loads fine
		{"go1.27.1", "go1.27.2", false},
		{"go1.27", "go1.26.9", false},
		{"go1.26.9", "go1.27.1", true},
		{"go1.26.9", "go1.28.0", true},
		{"go1.26.9", "go1.26.9", false},
		{"go1.26.9", "go1.26.8", false},
		{"go1.26.9", "go1.26", false},
		{"go1.26.9", "go1.25.1", false},
		{"go1.27rc1", "go1.27rc1", false},
		{"go1.27rc1", "go1.27rc2", false},
		{"go1.27rc1", "go1.26.9", false},
		{"go1.26.9 X:nocoverageredesign", "go1.26.9", false},
		{"devel go1.28-abc Mon", "go1.27", false}, // not a release: cannot tell, scan goes on
		{"go1.26.9", "", false},
		{"go1.26.9", "garbage", false},
	} {
		if err := checkToolchain(c.built, c.scan); (err != nil) != c.fail {
			t.Errorf("built %q scan %q: err = %v, want failure %v", c.built, c.scan, err, c.fail)
		}
	}
}

func TestCheckToolchain_UsesTheRunningGo(t *testing.T) {
	prev := builtWithGo
	t.Cleanup(func() { builtWithGo = prev })
	builtWithGo = func() string { return "go1.26.9" }
	if err := CheckToolchain("go1.27.2"); err == nil || !strings.Contains(err.Error(), "built with go1.26.9") {
		t.Errorf("%v", err)
	}
	if err := CheckToolchain("go1.26.9"); err != nil {
		t.Errorf("%v", err)
	}
}

func TestToolchainErrorFrom(t *testing.T) {
	prev := builtWithGo
	t.Cleanup(func() { builtWithGo = prev })
	builtWithGo = func() string { return "go1.26.9" }
	err := toolchainErrorFrom("govulncheck: loading packages: p.go:1: file requires newer Go version go1.27 (application built with go1.26)")
	if err == nil || err.Error() != "this unisupply was built with go1.26.9 and cannot scan code that needs go1.27; rebuild unisupply with go1.27 or newer" {
		t.Errorf("%v", err)
	}
	if toolchainErrorFrom("govulncheck: something else") != nil {
		t.Error("only the newer-Go error is translated")
	}
}

// The scan stops before govulncheck starts when the Go the project resolves is newer than the Go unisupply was built with.
func TestScanVulns_ToolchainTooOld(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\necho '{\"GOVERSION\":\"go1.99.1\",\"GOROOT\":\"/nonexistent\"}'\n"
	if err := os.WriteFile(filepath.Join(dir, "go"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	prev := builtWithGo
	t.Cleanup(func() { builtWithGo = prev })
	builtWithGo = func() string { return "go1.26.9" }

	vulns, _, scanned, err := ScanVulnsWithOptions(context.Background(), t.TempDir(), VulnScanOptions{})
	want := "this unisupply was built with go1.26.9 and cannot scan code that needs go1.99; rebuild unisupply with go1.99 or newer"
	if err == nil || err.Error() != want || scanned || vulns != nil {
		t.Errorf("err = %v scanned = %v", err, scanned)
	}
}
