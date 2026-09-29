package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/mod/module"

	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/resolver"
)

// TestIntegrityScanner_ClassifyReplace tests classification of every replace
// directive class: same-path (version-pin), local-path, and redirect.
func TestIntegrityScanner_ClassifyReplace(t *testing.T) {
	tests := []struct {
		name         string
		replaces     map[string]parser.Replace
		wantSeverity IntegrityRiskLevel
		wantCategory string
	}{
		{
			name: "version_pin",
			replaces: map[string]parser.Replace{
				"github.com/foo/bar": {New: parser.Module{Path: "github.com/foo/bar", Version: "v1.2.3"}},
			},
			wantSeverity: IntegrityLow,
			wantCategory: "replace_version_pin",
		},
		{
			name: "local_path_dot_slash",
			replaces: map[string]parser.Replace{
				"github.com/foo/bar": {New: parser.Module{Path: "./local/bar"}},
			},
			wantSeverity: IntegrityMedium,
			wantCategory: "replace_local_path",
		},
		{
			name: "local_path_dot_dot_slash",
			replaces: map[string]parser.Replace{
				"github.com/foo/bar": {New: parser.Module{Path: "../local/bar"}},
			},
			wantSeverity: IntegrityMedium,
			wantCategory: "replace_local_path",
		},
		{
			name: "local_path_absolute",
			replaces: map[string]parser.Replace{
				"github.com/foo/bar": {New: parser.Module{Path: "/home/dev/bar"}},
			},
			wantSeverity: IntegrityMedium,
			wantCategory: "replace_local_path",
		},
		{
			name: "local_path_windows_relative",
			replaces: map[string]parser.Replace{
				"github.com/foo/bar": {New: parser.Module{Path: `.\local\bar`}},
			},
			wantSeverity: IntegrityMedium,
			wantCategory: "replace_local_path",
		},
		{
			name: "local_path_windows_parent",
			replaces: map[string]parser.Replace{
				"github.com/foo/bar": {New: parser.Module{Path: `..\local\bar`}},
			},
			wantSeverity: IntegrityMedium,
			wantCategory: "replace_local_path",
		},
		{
			name: "local_path_windows_drive",
			replaces: map[string]parser.Replace{
				"github.com/foo/bar": {New: parser.Module{Path: `C:\dev\bar`}},
			},
			wantSeverity: IntegrityMedium,
			wantCategory: "replace_local_path",
		},
		{
			name: "local_path_windows_unc",
			replaces: map[string]parser.Replace{
				"github.com/foo/bar": {New: parser.Module{Path: `\\server\share\bar`}},
			},
			wantSeverity: IntegrityMedium,
			wantCategory: "replace_local_path",
		},
		{
			name: "major_version_new_suffix",
			replaces: map[string]parser.Replace{
				"github.com/foo/bar": {New: parser.Module{Path: "github.com/foo/bar/v2", Version: "v2.0.0"}},
			},
			wantSeverity: IntegrityMedium,
			wantCategory: "replace_major_version",
		},
		{
			name: "major_version_swap",
			replaces: map[string]parser.Replace{
				"github.com/foo/bar/v2": {New: parser.Module{Path: "github.com/foo/bar/v3", Version: "v3.0.0"}},
			},
			wantSeverity: IntegrityMedium,
			wantCategory: "replace_major_version",
		},
		{
			name: "major_version_different_module_still_high",
			replaces: map[string]parser.Replace{
				"github.com/foo/bar": {New: parser.Module{Path: "github.com/attacker/bar/v2", Version: "v2.0.0"}},
			},
			wantSeverity: IntegrityHigh,
			wantCategory: "replace_redirect",
		},
		{
			name: "redirect",
			replaces: map[string]parser.Replace{
				"github.com/foo/bar": {New: parser.Module{Path: "github.com/attacker/bar", Version: "v1.0.0"}},
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
		Replaces: map[string]parser.Replace{
			"github.com/a/pin":      {New: parser.Module{Path: "github.com/a/pin", Version: "v1.0.0"}},
			"github.com/b/local":    {New: parser.Module{Path: "./vendor/b"}},
			"github.com/c/redirect": {New: parser.Module{Path: "github.com/attacker/c"}},
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

// TestIntegrityScanner_VersionScopedReplace verifies that a version-scoped
// replace directive surfaces its old version in the finding detail.
func TestIntegrityScanner_VersionScopedReplace(t *testing.T) {
	gm := &parser.GoMod{
		Replaces: map[string]parser.Replace{
			"github.com/foo/bar": {OldVersion: "v1.2.3", New: parser.Module{Path: "github.com/fork/bar", Version: "v1.2.4"}},
		},
	}

	report, _ := NewIntegrityScanner().ScanDirectives(gm)

	if len(report.Findings) != 1 {
		t.Fatalf("Findings length = %d, want 1", len(report.Findings))
	}
	f := report.Findings[0]
	if f.Category != IntegrityCategoryReplaceRedirect {
		t.Errorf("Category = %q, want %q", f.Category, IntegrityCategoryReplaceRedirect)
	}
	if want := "(applies only when version v1.2.3 is selected)"; !strings.Contains(f.Detail, want) {
		t.Errorf("Detail = %q, want it to contain %q", f.Detail, want)
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

// --- pseudo-version audit (ScanPseudoVersions) ---

// TestIsPseudoVersion_Classification is a table test over
// golang.org/x/mod/module.IsPseudoVersion, including the tricky
// "pseudo-version on top of a tag" form (v0.4.1-0.20220921...) that a naive
// regex over the numeric-prefix alone could misclassify.
func TestIsPseudoVersion_Classification(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{"zero-base pseudo-version", "v0.0.0-20220702200334-8c7cb25baa11", true},
		{"pseudo-version on top of a tag", "v0.4.1-0.20220921163831-64d0910b0f3a", true},
		{"plain pre-release (not pseudo)", "v1.2.3-beta.1", false},
		{"real tagged release", "v1.2.3", false},
		{"v2 module tagged release", "v2.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := module.IsPseudoVersion(tt.version)
			if got != tt.want {
				t.Errorf("IsPseudoVersion(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

// TestScanPseudoVersions_SeverityMapping verifies direct/indirect/test-only/
// unknown severity classification end-to-end through ScanPseudoVersions.
func TestScanPseudoVersions_SeverityMapping(t *testing.T) {
	trueVal, falseVal := true, false

	graph := &resolver.Graph{
		Dependencies: map[string]*resolver.Dependency{
			"github.com/direct/pkg": {
				Module:     parser.Module{Path: "github.com/direct/pkg", Version: "v0.0.0-20220702200334-8c7cb25baa11"},
				Direct:     true,
				IsTestOnly: &falseVal,
			},
			"github.com/indirect/pkg": {
				Module:     parser.Module{Path: "github.com/indirect/pkg", Version: "v0.0.0-20260625142307-59b4966ccb57"},
				Direct:     false,
				IsTestOnly: &falseVal,
			},
			"github.com/testonly/pkg": {
				Module:     parser.Module{Path: "github.com/testonly/pkg", Version: "v0.4.1-0.20220921163831-64d0910b0f3a"},
				Direct:     true,
				IsTestOnly: &trueVal,
			},
			"github.com/unknown/pkg": {
				Module:     parser.Module{Path: "github.com/unknown/pkg", Version: "v0.0.0-20220101000000-abc123def456"},
				Direct:     false,
				IsTestOnly: nil,
			},
			"github.com/tagged/pkg": {
				Module: parser.Module{Path: "github.com/tagged/pkg", Version: "v1.2.3"},
				Direct: true,
			},
		},
	}

	report := &IntegrityReport{}
	classes := NewIntegrityScanner().ScanPseudoVersions(graph, report)

	if got := classes["github.com/direct/pkg"]; got != IntegrityMedium {
		t.Errorf("direct: severity = %q, want MEDIUM", got)
	}
	if got := classes["github.com/indirect/pkg"]; got != IntegrityLow {
		t.Errorf("indirect: severity = %q, want LOW", got)
	}
	if got := classes["github.com/testonly/pkg"]; got != IntegrityInfo {
		t.Errorf("test-only: severity = %q, want INFO", got)
	}
	if got := classes["github.com/unknown/pkg"]; got != IntegrityLow {
		t.Errorf("unknown test-only (nil, indirect): severity = %q, want LOW (nil treated as not-test-only)", got)
	}
	if _, ok := classes["github.com/tagged/pkg"]; ok {
		t.Errorf("tagged release must not be classified as a pseudo-version pin")
	}

	if report.PseudoVersionCount != 4 {
		t.Errorf("PseudoVersionCount = %d, want 4", report.PseudoVersionCount)
	}
	for _, f := range report.Findings {
		if f.Category != IntegrityCategoryPseudoVersion {
			t.Errorf("finding category = %q, want %q", f.Category, IntegrityCategoryPseudoVersion)
		}
	}
}

// TestScanPseudoVersions_SelfScanFixture is the acceptance-criteria-1 guard:
// a fixture graph mirroring unisupply's own known pseudo-version pins
// (garabic, go-cmdtest, x/telemetry) must all be flagged.
func TestScanPseudoVersions_SelfScanFixture(t *testing.T) {
	falseVal := false

	graph := &resolver.Graph{
		Dependencies: map[string]*resolver.Dependency{
			"github.com/unidoc/garabic": {
				Module:     parser.Module{Path: "github.com/unidoc/garabic", Version: "v0.0.0-20220702200334-8c7cb25baa11"},
				Direct:     true,
				IsTestOnly: &falseVal,
			},
			"github.com/google/go-cmdtest": {
				Module:     parser.Module{Path: "github.com/google/go-cmdtest", Version: "v0.4.1-0.20220921163831-55ab3332a786"},
				Direct:     true,
				IsTestOnly: &falseVal,
			},
			"golang.org/x/telemetry": {
				Module:     parser.Module{Path: "golang.org/x/telemetry", Version: "v0.0.0-20260625142307-59b4966ccb57"},
				Direct:     false,
				IsTestOnly: &falseVal,
			},
		},
	}

	report := &IntegrityReport{}
	classes := NewIntegrityScanner().ScanPseudoVersions(graph, report)

	for _, mod := range []string{"github.com/unidoc/garabic", "github.com/google/go-cmdtest", "golang.org/x/telemetry"} {
		if _, ok := classes[mod]; !ok {
			t.Errorf("%s: not flagged as a pseudo-version pin", mod)
		}
	}
}

// --- go.sum presence/completeness (ScanGoSum) ---

// gosumFixture writes a go.mod (and optionally go.sum) into a temp dir and
// returns the go.mod path.
func gosumFixture(t *testing.T, gosum string) string {
	t.Helper()
	dir := t.TempDir()
	gomodPath := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomodPath, []byte("module example.com/fixture\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	if gosum != "" {
		if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte(gosum), 0o600); err != nil {
			t.Fatalf("writing go.sum: %v", err)
		}
	}
	return gomodPath
}

func TestScanGoSum_Missing(t *testing.T) {
	gomodPath := gosumFixture(t, "")
	gm := &parser.GoMod{
		ModulePath:   "example.com/fixture",
		Requirements: []parser.Module{{Path: "github.com/foo/bar", Version: "v1.0.0"}},
	}
	graph := &resolver.Graph{Dependencies: map[string]*resolver.Dependency{}}

	report := &IntegrityReport{}
	NewIntegrityScanner().ScanGoSum(gomodPath, gm, graph, report)

	if len(report.Findings) != 1 {
		t.Fatalf("Findings length = %d, want 1", len(report.Findings))
	}
	f := report.Findings[0]
	if f.Category != "gosum_missing" {
		t.Errorf("Category = %q, want gosum_missing", f.Category)
	}
	if f.Severity != IntegrityHigh {
		t.Errorf("Severity = %q, want %q", f.Severity, IntegrityHigh)
	}
}

func TestScanGoSum_MissingButNoRequirements(t *testing.T) {
	gomodPath := gosumFixture(t, "")
	gm := &parser.GoMod{ModulePath: "example.com/fixture"}
	graph := &resolver.Graph{Dependencies: map[string]*resolver.Dependency{}}

	report := &IntegrityReport{}
	NewIntegrityScanner().ScanGoSum(gomodPath, gm, graph, report)

	if len(report.Findings) != 0 {
		t.Errorf("Findings length = %d, want 0 (no requirements → go.sum legitimately absent)", len(report.Findings))
	}
}

func TestScanGoSum_Complete(t *testing.T) {
	gosum := "github.com/foo/bar v1.0.0 h1:abc=\ngithub.com/foo/bar v1.0.0/go.mod h1:def=\n"
	gomodPath := gosumFixture(t, gosum)
	gm := &parser.GoMod{
		ModulePath:   "example.com/fixture",
		Requirements: []parser.Module{{Path: "github.com/foo/bar", Version: "v1.0.0"}},
	}
	graph := &resolver.Graph{Dependencies: map[string]*resolver.Dependency{
		"github.com/foo/bar": {Module: parser.Module{Path: "github.com/foo/bar", Version: "v1.0.0"}, Direct: true},
	}}

	report := &IntegrityReport{}
	NewIntegrityScanner().ScanGoSum(gomodPath, gm, graph, report)

	if len(report.Findings) != 0 {
		t.Errorf("Findings length = %d, want 0 (go.sum complete), findings: %+v", len(report.Findings), report.Findings)
	}
}

func TestScanGoSum_Incomplete(t *testing.T) {
	gosum := "github.com/foo/bar v1.0.0/go.mod h1:def=\n"
	gomodPath := gosumFixture(t, gosum)
	gm := &parser.GoMod{
		ModulePath:   "example.com/fixture",
		Requirements: []parser.Module{{Path: "github.com/foo/bar", Version: "v1.0.0"}},
	}
	graph := &resolver.Graph{Dependencies: map[string]*resolver.Dependency{
		"github.com/foo/bar":     {Module: parser.Module{Path: "github.com/foo/bar", Version: "v1.0.0"}, Direct: true},
		"github.com/baz/qux":     {Module: parser.Module{Path: "github.com/baz/qux", Version: "v2.1.0"}, Direct: true},
		"github.com/rep/laced":   {Module: parser.Module{Path: "github.com/rep/laced", Version: "v0.1.0"}, Direct: true, Replaced: true},
		"github.com/tran/sitive": {Module: parser.Module{Path: "github.com/tran/sitive", Version: "v0.9.0"}},
	}}

	report := &IntegrityReport{}
	NewIntegrityScanner().ScanGoSum(gomodPath, gm, graph, report)

	if len(report.Findings) != 1 {
		t.Fatalf("Findings length = %d, want 1, findings: %+v", len(report.Findings), report.Findings)
	}
	f := report.Findings[0]
	if f.Category != "gosum_incomplete" {
		t.Errorf("Category = %q, want gosum_incomplete", f.Category)
	}
	if f.Severity != IntegrityMedium {
		t.Errorf("Severity = %q, want %q", f.Severity, IntegrityMedium)
	}
	if !strings.Contains(f.Detail, "github.com/baz/qux@v2.1.0") {
		t.Errorf("Detail should name the missing module, got %q", f.Detail)
	}
	if strings.Contains(f.Detail, "github.com/rep/laced") {
		t.Errorf("Detail must not name replaced modules, got %q", f.Detail)
	}
	if strings.Contains(f.Detail, "github.com/tran/sitive") {
		t.Errorf("Detail must not name transitive modules (graph-pruning false positives), got %q", f.Detail)
	}
}

func TestScanGoSum_VendorSkipsCompleteness(t *testing.T) {
	gosum := "github.com/foo/bar v1.0.0/go.mod h1:def=\n"
	gomodPath := gosumFixture(t, gosum)
	vendorDir := filepath.Join(filepath.Dir(gomodPath), "vendor")
	if err := os.MkdirAll(vendorDir, 0o750); err != nil {
		t.Fatalf("creating vendor dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vendorDir, "modules.txt"), []byte("# github.com/baz/qux v2.1.0\n"), 0o600); err != nil {
		t.Fatalf("writing modules.txt: %v", err)
	}
	gm := &parser.GoMod{
		ModulePath:   "example.com/fixture",
		Requirements: []parser.Module{{Path: "github.com/baz/qux", Version: "v2.1.0"}},
	}
	graph := &resolver.Graph{Dependencies: map[string]*resolver.Dependency{
		"github.com/baz/qux": {Module: parser.Module{Path: "github.com/baz/qux", Version: "v2.1.0"}, Direct: true},
	}}

	report := &IntegrityReport{}
	NewIntegrityScanner().ScanGoSum(gomodPath, gm, graph, report)

	if len(report.Findings) != 0 {
		t.Errorf("Findings length = %d, want 0 (vendor/modules.txt present → -mod=vendor semantics)", len(report.Findings))
	}
}

// --- go.sum verification (VerifyGoSum) ---

func TestVerifyGoSum_Offline(t *testing.T) {
	gomodPath := gosumFixture(t, "github.com/foo/bar v1.0.0/go.mod h1:def=\n")

	report := &IntegrityReport{}
	is := NewIntegrityScanner()
	is.Offline = true
	is.VerifyGoSum(context.Background(), gomodPath, report)

	if report.GoSumVerified != GoSumVerifiedOffline {
		t.Errorf("GoSumVerified = %q, want %q", report.GoSumVerified, GoSumVerifiedOffline)
	}
	if len(report.Findings) != 0 {
		t.Errorf("Findings length = %d, want 0 (offline must never be a failure)", len(report.Findings))
	}
}

func TestVerifyGoSum_NoGoSum(t *testing.T) {
	gomodPath := gosumFixture(t, "")

	report := &IntegrityReport{}
	NewIntegrityScanner().VerifyGoSum(context.Background(), gomodPath, report)

	if report.GoSumVerified != GoSumVerifiedSkipped {
		t.Errorf("GoSumVerified = %q, want %q", report.GoSumVerified, GoSumVerifiedSkipped)
	}
	if len(report.Findings) != 0 {
		t.Errorf("Findings length = %d, want 0 (missing go.sum is gosum_missing's job, not a mismatch)", len(report.Findings))
	}
}

func TestVerifyGoSum_ContextCancelled(t *testing.T) {
	gomodPath := gosumFixture(t, "github.com/foo/bar v1.0.0/go.mod h1:def=\n")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	report := &IntegrityReport{}
	NewIntegrityScanner().VerifyGoSum(ctx, gomodPath, report)

	if report.GoSumVerified != GoSumVerifiedSkipped {
		t.Errorf("GoSumVerified = %q, want %q (killed process is not an integrity signal)", report.GoSumVerified, GoSumVerifiedSkipped)
	}
	if len(report.Findings) != 0 {
		t.Errorf("Findings length = %d, want 0 (cancellation must never be a failure)", len(report.Findings))
	}
}

// fakeGo puts a shell script named "go" on PATH that prints output and exits
// with code, so VerifyGoSum's handling of `go mod verify` failures can be
// exercised without a real module cache or network.
func fakeGo(t *testing.T, output string, code int) {
	t.Helper()
	binDir := t.TempDir()
	outFile := filepath.Join(binDir, "output.txt")
	if err := os.WriteFile(outFile, []byte(output+"\n"), 0o600); err != nil {
		t.Fatalf("writing fake go output: %v", err)
	}
	// PATH is replaced wholesale below, so the script must not rely on it —
	// use the absolute /bin/cat.
	script := "#!/bin/sh\n/bin/cat " + outFile + "\nexit " + strconv.Itoa(code) + "\n"
	if err := os.WriteFile(filepath.Join(binDir, "go"), []byte(script), 0o700); err != nil { //nolint:gosec // test helper must be executable
		t.Fatalf("writing fake go: %v", err)
	}
	t.Setenv("PATH", binDir)
}

func TestVerifyGoSum_NonMismatchFailureSkips(t *testing.T) {
	gomodPath := gosumFixture(t, "github.com/foo/bar v1.0.0/go.mod h1:def=\n")
	fakeGo(t, "go: github.com/foo/bar@v1.0.0: Get \"https://proxy.golang.org/...\": dial tcp: no such host", 1)

	report := &IntegrityReport{}
	NewIntegrityScanner().VerifyGoSum(context.Background(), gomodPath, report)

	if report.GoSumVerified != GoSumVerifiedSkipped {
		t.Errorf("GoSumVerified = %q, want %q (cold cache / network failure is not tampering)", report.GoSumVerified, GoSumVerifiedSkipped)
	}
	if len(report.Findings) != 0 {
		t.Errorf("Findings length = %d, want 0: %+v", len(report.Findings), report.Findings)
	}
}

func TestVerifyGoSum_MismatchMarkersFail(t *testing.T) {
	outputs := map[string]string{
		"verify modified":   "github.com/foo/bar v1.0.0: dir has been modified (/cache/github.com/foo/bar@v1.0.0)",
		"checksum mismatch": "verifying github.com/foo/bar@v1.0.0/go.mod: checksum mismatch\n\tdownloaded: h1:aaa=\n\tgo.sum:     h1:bbb=\n\nSECURITY ERROR",
	}
	for name, output := range outputs {
		t.Run(name, func(t *testing.T) {
			gomodPath := gosumFixture(t, "github.com/foo/bar v1.0.0/go.mod h1:def=\n")
			fakeGo(t, output, 1)

			report := &IntegrityReport{}
			NewIntegrityScanner().VerifyGoSum(context.Background(), gomodPath, report)

			if report.GoSumVerified != GoSumVerifiedFalse {
				t.Fatalf("GoSumVerified = %q, want %q", report.GoSumVerified, GoSumVerifiedFalse)
			}
			if len(report.Findings) != 1 {
				t.Fatalf("Findings length = %d, want 1: %+v", len(report.Findings), report.Findings)
			}
			if report.Findings[0].Category != "gosum_mismatch" {
				t.Errorf("Category = %q, want gosum_mismatch", report.Findings[0].Category)
			}
			if report.Findings[0].Severity != IntegrityCritical {
				t.Errorf("Severity = %q, want %q", report.Findings[0].Severity, IntegrityCritical)
			}
		})
	}
}
