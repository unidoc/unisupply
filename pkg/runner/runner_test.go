package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/scanner"
)

// TestRun_NoDependencies exercises Run's zero-dependency fast path (no
// scanner network calls at all) end to end against a real temp module —
// deterministic and network-free, unlike the rest of the pipeline (which
// calls the Go Module Proxy / GitHub API and is instead covered by
// cmd/unisupply's own black-box CLI tests, run against this same
// refactored pkg/runner.Run underneath).
func TestRun_NoDependencies(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")
	content := "module github.com/example/empty\n\ngo 1.25\n"
	if err := os.WriteFile(gomodPath, []byte(content), 0o644); err != nil {
		t.Fatalf("writing fixture go.mod: %v", err)
	}

	result, err := Run(context.Background(), Options{
		Path: tmpDir,
		Now:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.GoMod == nil {
		t.Fatal("result.GoMod is nil")
	}
	if result.Graph == nil {
		t.Fatal("result.Graph is nil")
	}
	if len(result.Graph.Dependencies) != 0 {
		t.Errorf("len(Graph.Dependencies) = %d, want 0", len(result.Graph.Dependencies))
	}
	if result.ProjectScore == nil {
		t.Fatal("result.ProjectScore is nil — even a zero-dependency project must get a scored (if empty) ProjectScore, callers rely on it being non-nil")
	}
	if len(result.ProjectScore.Dependencies) != 0 {
		t.Errorf("len(ProjectScore.Dependencies) = %d, want 0", len(result.ProjectScore.Dependencies))
	}
	// The zero-dependency path must skip every network-calling scanner
	// entirely — Maintainers/Typosquats/CIReport/Takeovers/StdlibVulns
	// should all be at their zero value, not partially populated.
	if result.CIReport != nil {
		t.Errorf("result.CIReport = %+v, want nil (ScanWorkflows/ScanCI were not requested)", result.CIReport)
	}
	if len(result.Takeovers) != 0 {
		t.Errorf("result.Takeovers = %v, want empty", result.Takeovers)
	}
}

// TestRun_MissingGoMod confirms Run surfaces parser.FindGoMod's error
// directly rather than swallowing it — a caller (like gorisk, scanning an
// arbitrary cloned repo) needs a clear, typed-enough failure here.
func TestRun_MissingGoMod(t *testing.T) {
	tmpDir := t.TempDir() // no go.mod written
	_, err := Run(context.Background(), Options{Path: tmpDir})
	if err == nil {
		t.Fatal("Run with no go.mod present: want an error, got nil")
	}
}

func TestVulnScanFailure(t *testing.T) {
	if vulnScanFailure(nil, true, []string{"GitHub API unauthenticated"}) != nil {
		t.Error("a completed vulnerability scan is not a failure, whatever else it warned about")
	}
	if err := vulnScanFailure(nil, false, []string{"govulncheck: no go.mod file\n\nonly works with Go modules"}); err == nil || err.Error() != "govulncheck: no go.mod file" {
		t.Errorf("a scan that did not run must report its warning (first line only), got %v", err)
	}
	if err := vulnScanFailure(nil, false, nil); err == nil {
		t.Error("a scan that did not run and said nothing must still be a failure")
	}
	if vulnScanFailure(errors.New("starting govulncheck: boom"), true, nil) == nil {
		t.Error("a ScanVulns error must be reported")
	}
}

// TestTakeStdlibVulns verifies the stdlib entry is removed from the map and
// returned sorted by ID, and that its absence yields nil.
func TestTakeStdlibVulns(t *testing.T) {
	t.Run("sorted and removed", func(t *testing.T) {
		vulns := map[string][]scanner.Vulnerability{
			"stdlib":          {{ID: "GO-2026-0030"}, {ID: "GO-2026-0010"}, {ID: "GO-2026-0020"}},
			"example.com/dep": {{ID: "GO-2026-0001"}},
		}
		got := takeStdlibVulns(vulns)

		var ids []string
		for _, v := range got {
			ids = append(ids, v.ID)
		}
		if want := "GO-2026-0010,GO-2026-0020,GO-2026-0030"; strings.Join(ids, ",") != want {
			t.Errorf("ids = %v, want %s", ids, want)
		}
		if _, ok := vulns["stdlib"]; ok {
			t.Error("stdlib key still in the map")
		}
		if len(vulns["example.com/dep"]) != 1 {
			t.Error("dependency entries must be untouched")
		}
	})

	t.Run("absent", func(t *testing.T) {
		vulns := map[string][]scanner.Vulnerability{"example.com/dep": {{ID: "GO-2026-0001"}}}
		if got := takeStdlibVulns(vulns); got != nil {
			t.Errorf("takeStdlibVulns() = %v, want nil", got)
		}
	})
}
