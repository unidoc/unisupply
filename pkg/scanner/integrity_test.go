package scanner

import (
	"testing"

	"github.com/unidoc/unisupply/pkg/parser"
)

// TestIntegrityScanner_ClassifyReplace tests classification of every replace
// directive class: same-path (version-pin), local-path, and redirect.
func TestIntegrityScanner_ClassifyReplace(t *testing.T) {
	tests := []struct {
		name         string
		replaces     map[string]parser.Module
		wantSeverity IntegrityRiskLevel
		wantCategory string
	}{
		{
			name: "version_pin",
			replaces: map[string]parser.Module{
				"github.com/foo/bar": {Path: "github.com/foo/bar", Version: "v1.2.3"},
			},
			wantSeverity: IntegrityLow,
			wantCategory: "replace_version_pin",
		},
		{
			name: "local_path_dot_slash",
			replaces: map[string]parser.Module{
				"github.com/foo/bar": {Path: "./local/bar"},
			},
			wantSeverity: IntegrityMedium,
			wantCategory: "replace_local_path",
		},
		{
			name: "local_path_dot_dot_slash",
			replaces: map[string]parser.Module{
				"github.com/foo/bar": {Path: "../local/bar"},
			},
			wantSeverity: IntegrityMedium,
			wantCategory: "replace_local_path",
		},
		{
			name: "local_path_absolute",
			replaces: map[string]parser.Module{
				"github.com/foo/bar": {Path: "/home/dev/bar"},
			},
			wantSeverity: IntegrityMedium,
			wantCategory: "replace_local_path",
		},
		{
			name: "major_version_new_suffix",
			replaces: map[string]parser.Module{
				"github.com/foo/bar": {Path: "github.com/foo/bar/v2", Version: "v2.0.0"},
			},
			wantSeverity: IntegrityMedium,
			wantCategory: "replace_major_version",
		},
		{
			name: "major_version_swap",
			replaces: map[string]parser.Module{
				"github.com/foo/bar/v2": {Path: "github.com/foo/bar/v3", Version: "v3.0.0"},
			},
			wantSeverity: IntegrityMedium,
			wantCategory: "replace_major_version",
		},
		{
			name: "major_version_different_module_still_high",
			replaces: map[string]parser.Module{
				"github.com/foo/bar": {Path: "github.com/attacker/bar/v2", Version: "v2.0.0"},
			},
			wantSeverity: IntegrityHigh,
			wantCategory: "replace_redirect",
		},
		{
			name: "redirect",
			replaces: map[string]parser.Module{
				"github.com/foo/bar": {Path: "github.com/attacker/bar", Version: "v1.0.0"},
			},
			wantSeverity: IntegrityHigh,
			wantCategory: "replace_redirect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := &parser.GoMod{Replaces: tt.replaces}
			report, classes := NewIntegrityScanner().ScanDirectives(gm)

			if len(report.Findings) != 1 {
				t.Fatalf("Findings length = %d, want 1", len(report.Findings))
			}
			f := report.Findings[0]
			if f.Severity != tt.wantSeverity {
				t.Errorf("Severity = %q, want %q", f.Severity, tt.wantSeverity)
			}
			if f.Category != tt.wantCategory {
				t.Errorf("Category = %q, want %q", f.Category, tt.wantCategory)
			}

			for origPath := range tt.replaces {
				if got := classes[origPath]; got != tt.wantSeverity {
					t.Errorf("classes[%q] = %q, want %q", origPath, got, tt.wantSeverity)
				}
			}
		})
	}
}

// TestIntegrityScanner_RedirectCount verifies RedirectCount only counts HIGH
// (redirect) severity replaces, not LOW or MEDIUM.
func TestIntegrityScanner_RedirectCount(t *testing.T) {
	gm := &parser.GoMod{
		Replaces: map[string]parser.Module{
			"github.com/a/pin":      {Path: "github.com/a/pin", Version: "v1.0.0"},
			"github.com/b/local":    {Path: "./vendor/b"},
			"github.com/c/redirect": {Path: "github.com/attacker/c"},
		},
	}

	report, _ := NewIntegrityScanner().ScanDirectives(gm)

	if report.ReplaceCount != 3 {
		t.Errorf("ReplaceCount = %d, want 3", report.ReplaceCount)
	}
	if report.RedirectCount != 1 {
		t.Errorf("RedirectCount = %d, want 1", report.RedirectCount)
	}
}

// TestIntegrityScanner_Exclude tests that exclude directives render as INFO findings.
func TestIntegrityScanner_Exclude(t *testing.T) {
	gm := &parser.GoMod{
		Excludes: []parser.Module{
			{Path: "github.com/foo/bar", Version: "v1.2.3"},
		},
	}

	report, classes := NewIntegrityScanner().ScanDirectives(gm)

	if report.ExcludeCount != 1 {
		t.Errorf("ExcludeCount = %d, want 1", report.ExcludeCount)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("Findings length = %d, want 1", len(report.Findings))
	}
	if report.Findings[0].Severity != IntegrityInfo {
		t.Errorf("Severity = %q, want %q", report.Findings[0].Severity, IntegrityInfo)
	}
	if report.Findings[0].Category != "exclude" {
		t.Errorf("Category = %q, want %q", report.Findings[0].Category, "exclude")
	}
	if len(classes) != 0 {
		t.Errorf("classes should be empty for exclude-only go.mod, got %d entries", len(classes))
	}
}

// TestIntegrityScanner_NoDirectives verifies an empty report for a go.mod with
// no replace or exclude directives.
func TestIntegrityScanner_NoDirectives(t *testing.T) {
	gm := &parser.GoMod{}

	report, classes := NewIntegrityScanner().ScanDirectives(gm)

	if len(report.Findings) != 0 {
		t.Errorf("Findings length = %d, want 0", len(report.Findings))
	}
	if report.ReplaceCount != 0 || report.ExcludeCount != 0 || report.RedirectCount != 0 {
		t.Errorf("counts should all be 0, got %+v", report)
	}
	if len(classes) != 0 {
		t.Errorf("classes should be empty, got %d entries", len(classes))
	}
}
