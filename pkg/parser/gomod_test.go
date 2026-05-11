package parser

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseGoMod_Complete tests parsing a full go.mod with all directives.
func TestParseGoMod_Complete(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	content := `module github.com/example/myapp

go 1.21

require (
	github.com/foo/bar v1.0.0
	github.com/baz/qux v2.1.0 // indirect
)

replace (
	github.com/old/path => github.com/new/path v1.5.0
)
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	gm, err := ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if gm.ModulePath != "github.com/example/myapp" {
		t.Errorf("ModulePath = %q, want %q", gm.ModulePath, "github.com/example/myapp")
	}

	if gm.GoVersion != "1.21" {
		t.Errorf("GoVersion = %q, want %q", gm.GoVersion, "1.21")
	}

	if len(gm.Requirements) != 2 {
		t.Fatalf("Requirements length = %d, want 2", len(gm.Requirements))
	}

	if gm.Requirements[0].Path != "github.com/foo/bar" {
		t.Errorf("Requirements[0].Path = %q, want %q", gm.Requirements[0].Path, "github.com/foo/bar")
	}
	if gm.Requirements[0].Version != "v1.0.0" {
		t.Errorf("Requirements[0].Version = %q, want %q", gm.Requirements[0].Version, "v1.0.0")
	}
	if gm.Requirements[0].Indirect {
		t.Errorf("Requirements[0].Indirect = true, want false")
	}

	if gm.Requirements[1].Path != "github.com/baz/qux" {
		t.Errorf("Requirements[1].Path = %q, want %q", gm.Requirements[1].Path, "github.com/baz/qux")
	}
	if !gm.Requirements[1].Indirect {
		t.Errorf("Requirements[1].Indirect = false, want true")
	}

	if len(gm.Replaces) != 1 {
		t.Fatalf("Replaces length = %d, want 1", len(gm.Replaces))
	}

	if rep, ok := gm.Replaces["github.com/old/path"]; !ok {
		t.Errorf("Replaces missing key %q", "github.com/old/path")
	} else {
		if rep.Path != "github.com/new/path" {
			t.Errorf("Replace path = %q, want %q", rep.Path, "github.com/new/path")
		}
		if rep.Version != "v1.5.0" {
			t.Errorf("Replace version = %q, want %q", rep.Version, "v1.5.0")
		}
	}
}

// TestParseGoMod_EmptyFile tests parsing an empty go.mod file.
func TestParseGoMod_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	if err := writeFile(gomodPath, ""); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	gm, err := ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if gm.ModulePath != "" {
		t.Errorf("ModulePath = %q, want empty", gm.ModulePath)
	}

	if gm.GoVersion != "" {
		t.Errorf("GoVersion = %q, want empty", gm.GoVersion)
	}

	if len(gm.Requirements) != 0 {
		t.Errorf("Requirements length = %d, want 0", len(gm.Requirements))
	}

	if len(gm.Replaces) != 0 {
		t.Errorf("Replaces length = %d, want 0", len(gm.Replaces))
	}
}

// TestParseGoMod_CommentsOnly tests parsing a go.mod with only comments.
func TestParseGoMod_CommentsOnly(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	content := `// This is a comment
// Another comment
	// Indented comment
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	gm, err := ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if gm.ModulePath != "" {
		t.Errorf("ModulePath = %q, want empty", gm.ModulePath)
	}

	if len(gm.Requirements) != 0 {
		t.Errorf("Requirements length = %d, want 0", len(gm.Requirements))
	}
}

// TestParseGoMod_SingleLineRequire tests parsing a single-line require directive.
func TestParseGoMod_SingleLineRequire(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	content := `module github.com/test
require github.com/foo/bar v1.0.0
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	gm, err := ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if len(gm.Requirements) != 1 {
		t.Fatalf("Requirements length = %d, want 1", len(gm.Requirements))
	}

	if gm.Requirements[0].Path != "github.com/foo/bar" {
		t.Errorf("Requirements[0].Path = %q, want %q", gm.Requirements[0].Path, "github.com/foo/bar")
	}

	if gm.Requirements[0].Version != "v1.0.0" {
		t.Errorf("Requirements[0].Version = %q, want %q", gm.Requirements[0].Version, "v1.0.0")
	}
}

// TestParseGoMod_SingleLineReplace tests parsing a single-line replace directive.
func TestParseGoMod_SingleLineReplace(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	content := `module github.com/test
replace github.com/foo/bar => github.com/baz/qux v1.2.0
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	gm, err := ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if len(gm.Replaces) != 1 {
		t.Fatalf("Replaces length = %d, want 1", len(gm.Replaces))
	}

	if rep, ok := gm.Replaces["github.com/foo/bar"]; !ok {
		t.Errorf("Replaces missing key %q", "github.com/foo/bar")
	} else {
		if rep.Path != "github.com/baz/qux" {
			t.Errorf("Replace path = %q, want %q", rep.Path, "github.com/baz/qux")
		}
		if rep.Version != "v1.2.0" {
			t.Errorf("Replace version = %q, want %q", rep.Version, "v1.2.0")
		}
	}
}

// TestParseGoMod_ReplaceLocalPath tests parsing a replace directive with a local path.
func TestParseGoMod_ReplaceLocalPath(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	content := `module github.com/test
replace github.com/foo/bar => ../local/path
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	gm, err := ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if len(gm.Replaces) != 1 {
		t.Fatalf("Replaces length = %d, want 1", len(gm.Replaces))
	}

	if rep, ok := gm.Replaces["github.com/foo/bar"]; !ok {
		t.Errorf("Replaces missing key %q", "github.com/foo/bar")
	} else {
		if rep.Path != "../local/path" {
			t.Errorf("Replace path = %q, want %q", rep.Path, "../local/path")
		}
		if rep.Version != "" {
			t.Errorf("Replace version = %q, want empty", rep.Version)
		}
	}
}

// TestParseGoMod_IndirectFlag tests that the indirect flag is properly parsed.
func TestParseGoMod_IndirectFlag(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	content := `module github.com/test

require (
	github.com/direct/dep v1.0.0
	github.com/indirect/dep v2.0.0 // indirect
)
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	gm, err := ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if len(gm.Requirements) != 2 {
		t.Fatalf("Requirements length = %d, want 2", len(gm.Requirements))
	}

	if gm.Requirements[0].Indirect {
		t.Errorf("Requirements[0] should not be indirect")
	}

	if !gm.Requirements[1].Indirect {
		t.Errorf("Requirements[1] should be indirect")
	}
}

// TestParseGoMod_FileNotFound tests that an appropriate error is returned for a non-existent file.
func TestParseGoMod_FileNotFound(t *testing.T) {
	_, err := ParseGoMod("/nonexistent/path/to/go.mod")
	if err == nil {
		t.Fatalf("ParseGoMod should return an error for non-existent file")
	}

	if err.Error() == "" {
		t.Errorf("error message is empty")
	}
}

// TestParseRequireLine_Valid tests parsing a valid require line.
func TestParseRequireLine_Valid(t *testing.T) {
	mod := parseRequireLine("github.com/foo/bar v1.0.0")

	if mod == nil {
		t.Fatalf("parseRequireLine returned nil")
	}

	if mod.Path != "github.com/foo/bar" {
		t.Errorf("Path = %q, want %q", mod.Path, "github.com/foo/bar")
	}

	if mod.Version != "v1.0.0" {
		t.Errorf("Version = %q, want %q", mod.Version, "v1.0.0")
	}

	if mod.Indirect {
		t.Errorf("Indirect = true, want false")
	}
}

// TestParseRequireLine_Indirect tests parsing a require line with indirect flag.
func TestParseRequireLine_Indirect(t *testing.T) {
	mod := parseRequireLine("github.com/foo/bar v1.0.0 // indirect")

	if mod == nil {
		t.Fatalf("parseRequireLine returned nil")
	}

	if !mod.Indirect {
		t.Errorf("Indirect = false, want true")
	}
}

// TestParseRequireLine_Empty tests parsing an empty line.
func TestParseRequireLine_Empty(t *testing.T) {
	mod := parseRequireLine("")

	if mod != nil {
		t.Errorf("parseRequireLine returned non-nil for empty line")
	}
}

// TestParseRequireLine_Comment tests parsing a line with only a comment.
func TestParseRequireLine_Comment(t *testing.T) {
	mod := parseRequireLine("// this is a comment")

	if mod != nil {
		t.Errorf("parseRequireLine returned non-nil for comment line")
	}
}

// TestParseRequireLine_SingleField tests parsing a line with only path, no version.
func TestParseRequireLine_SingleField(t *testing.T) {
	mod := parseRequireLine("github.com/foo/bar")

	if mod != nil {
		t.Errorf("parseRequireLine returned non-nil for single field (no version)")
	}
}

// TestParseReplaceLine_Valid tests parsing a valid replace line.
func TestParseReplaceLine_Valid(t *testing.T) {
	replaces := make(map[string]Module)
	parseReplaceLine("github.com/foo/bar v1 => github.com/baz/qux v2", replaces)

	if len(replaces) != 1 {
		t.Fatalf("Replaces length = %d, want 1", len(replaces))
	}

	if rep, ok := replaces["github.com/foo/bar"]; !ok {
		t.Errorf("Replaces missing key %q", "github.com/foo/bar")
	} else {
		if rep.Path != "github.com/baz/qux" {
			t.Errorf("Replace path = %q, want %q", rep.Path, "github.com/baz/qux")
		}
		if rep.Version != "v2" {
			t.Errorf("Replace version = %q, want %q", rep.Version, "v2")
		}
	}
}

// TestParseReplaceLine_NoArrow tests parsing a line without the arrow operator.
func TestParseReplaceLine_NoArrow(t *testing.T) {
	replaces := make(map[string]Module)
	parseReplaceLine("github.com/foo/bar v1 github.com/baz/qux v2", replaces)

	if len(replaces) != 0 {
		t.Errorf("Replaces length = %d, want 0 (no arrow)", len(replaces))
	}
}

// TestParseReplaceLine_Empty tests parsing an empty replace line.
func TestParseReplaceLine_Empty(t *testing.T) {
	replaces := make(map[string]Module)
	parseReplaceLine("", replaces)

	if len(replaces) != 0 {
		t.Errorf("Replaces length = %d, want 0", len(replaces))
	}
}

// TestParseGoSum_Valid tests parsing a valid go.sum file with deduplication.
func TestParseGoSum_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	gosumPath := filepath.Join(tmpDir, "go.sum")

	content := `github.com/foo/bar v1.0.0 h1:hash1
github.com/foo/bar v1.0.0/go.mod h1:hash2
github.com/baz/qux v2.1.0 h1:hash3
github.com/baz/qux v2.1.0/go.mod h1:hash4
`

	if err := writeFile(gosumPath, content); err != nil {
		t.Fatalf("failed to write test go.sum: %v", err)
	}

	entries, err := ParseGoSum(gosumPath)
	if err != nil {
		t.Fatalf("ParseGoSum failed: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("Entries length = %d, want 2 (deduplicated)", len(entries))
	}

	if entries[0].Path != "github.com/foo/bar" {
		t.Errorf("entries[0].Path = %q, want %q", entries[0].Path, "github.com/foo/bar")
	}

	if entries[0].Version != "v1.0.0" {
		t.Errorf("entries[0].Version = %q, want %q", entries[0].Version, "v1.0.0")
	}

	if entries[1].Path != "github.com/baz/qux" {
		t.Errorf("entries[1].Path = %q, want %q", entries[1].Path, "github.com/baz/qux")
	}

	if entries[1].Version != "v2.1.0" {
		t.Errorf("entries[1].Version = %q, want %q", entries[1].Version, "v2.1.0")
	}
}

// TestParseGoSum_Empty tests parsing an empty go.sum file.
func TestParseGoSum_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	gosumPath := filepath.Join(tmpDir, "go.sum")

	if err := writeFile(gosumPath, ""); err != nil {
		t.Fatalf("failed to write test go.sum: %v", err)
	}

	entries, err := ParseGoSum(gosumPath)
	if err != nil {
		t.Fatalf("ParseGoSum failed: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("Entries length = %d, want 0", len(entries))
	}
}

// TestParseGoSum_FileNotFound tests that an appropriate error is returned for a non-existent file.
func TestParseGoSum_FileNotFound(t *testing.T) {
	_, err := ParseGoSum("/nonexistent/path/to/go.sum")
	if err == nil {
		t.Fatalf("ParseGoSum should return an error for non-existent file")
	}

	if err.Error() == "" {
		t.Errorf("error message is empty")
	}
}

// TestParseGoSum_Deduplication tests that duplicate entries (with and without /go.mod suffix) are deduplicated.
func TestParseGoSum_Deduplication(t *testing.T) {
	tmpDir := t.TempDir()
	gosumPath := filepath.Join(tmpDir, "go.sum")

	content := `github.com/test/pkg v1.0.0 h1:hash1
github.com/test/pkg v1.0.0/go.mod h1:hash2
github.com/test/pkg v1.0.0 h1:hash1
`

	if err := writeFile(gosumPath, content); err != nil {
		t.Fatalf("failed to write test go.sum: %v", err)
	}

	entries, err := ParseGoSum(gosumPath)
	if err != nil {
		t.Fatalf("ParseGoSum failed: %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("Entries length = %d, want 1 (fully deduplicated)", len(entries))
	}

	if entries[0].Path != "github.com/test/pkg" {
		t.Errorf("entries[0].Path = %q, want %q", entries[0].Path, "github.com/test/pkg")
	}

	if entries[0].Version != "v1.0.0" {
		t.Errorf("entries[0].Version = %q, want %q", entries[0].Version, "v1.0.0")
	}
}

// TestFindGoMod_Directory tests finding go.mod in a directory.
func TestFindGoMod_Directory(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	if err := writeFile(gomodPath, "module github.com/test"); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	found, err := FindGoMod(tmpDir)
	if err != nil {
		t.Fatalf("FindGoMod failed: %v", err)
	}

	if found != gomodPath {
		t.Errorf("FindGoMod = %q, want %q", found, gomodPath)
	}
}

// TestFindGoMod_DirectFile tests finding when given a direct path to go.mod.
func TestFindGoMod_DirectFile(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	if err := writeFile(gomodPath, "module github.com/test"); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	found, err := FindGoMod(gomodPath)
	if err != nil {
		t.Fatalf("FindGoMod failed: %v", err)
	}

	if found != gomodPath {
		t.Errorf("FindGoMod = %q, want %q", found, gomodPath)
	}
}

// TestFindGoMod_NotGoMod tests that an error is returned when given a non-go.mod file.
func TestFindGoMod_NotGoMod(t *testing.T) {
	tmpDir := t.TempDir()
	otherFile := filepath.Join(tmpDir, "go.sum")

	if err := writeFile(otherFile, "hash data"); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := FindGoMod(otherFile)
	if err == nil {
		t.Fatalf("FindGoMod should return an error for non-go.mod file")
	}

	if err.Error() == "" {
		t.Errorf("error message is empty")
	}
}

// TestFindGoMod_NoGoMod tests that an error is returned when no go.mod exists in a directory.
func TestFindGoMod_NoGoMod(t *testing.T) {
	tmpDir := t.TempDir()

	_, err := FindGoMod(tmpDir)
	if err == nil {
		t.Fatalf("FindGoMod should return an error when no go.mod found")
	}

	if err.Error() == "" {
		t.Errorf("error message is empty")
	}
}

// writeFile is a helper to write content to a file.
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0600)
}

// Unexported helper test to verify parseReplaceLine handles version-less original paths.
func TestParseReplaceLine_NoVersionOriginal(t *testing.T) {
	replaces := make(map[string]Module)
	parseReplaceLine("github.com/foo/bar => github.com/baz/qux v1.0.0", replaces)

	if len(replaces) != 1 {
		t.Fatalf("Replaces length = %d, want 1", len(replaces))
	}

	if rep, ok := replaces["github.com/foo/bar"]; !ok {
		t.Errorf("Replaces missing key %q", "github.com/foo/bar")
	} else {
		if rep.Path != "github.com/baz/qux" {
			t.Errorf("Replace path = %q, want %q", rep.Path, "github.com/baz/qux")
		}
		if rep.Version != "v1.0.0" {
			t.Errorf("Replace version = %q, want %q", rep.Version, "v1.0.0")
		}
	}
}

// TestParseReplaceLine_NoVersionReplacement tests replace with no version in replacement.
func TestParseReplaceLine_NoVersionReplacement(t *testing.T) {
	replaces := make(map[string]Module)
	parseReplaceLine("github.com/foo/bar v1.0.0 => github.com/baz/qux", replaces)

	if len(replaces) != 1 {
		t.Fatalf("Replaces length = %d, want 1", len(replaces))
	}

	if rep, ok := replaces["github.com/foo/bar"]; !ok {
		t.Errorf("Replaces missing key %q", "github.com/foo/bar")
	} else {
		if rep.Path != "github.com/baz/qux" {
			t.Errorf("Replace path = %q, want %q", rep.Path, "github.com/baz/qux")
		}
		if rep.Version != "" {
			t.Errorf("Replace version = %q, want empty", rep.Version)
		}
	}
}

// TestParseGoSum_SkipsBlankLines tests that blank lines in go.sum are properly skipped.
func TestParseGoSum_SkipsBlankLines(t *testing.T) {
	tmpDir := t.TempDir()
	gosumPath := filepath.Join(tmpDir, "go.sum")

	content := `github.com/foo/bar v1.0.0 h1:hash1

github.com/baz/qux v2.0.0 h1:hash2

`

	if err := writeFile(gosumPath, content); err != nil {
		t.Fatalf("failed to write test go.sum: %v", err)
	}

	entries, err := ParseGoSum(gosumPath)
	if err != nil {
		t.Fatalf("ParseGoSum failed: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("Entries length = %d, want 2", len(entries))
	}
}

// TestParseGoSum_SkipsInvalidLines tests that lines with fewer than 3 fields are skipped.
func TestParseGoSum_SkipsInvalidLines(t *testing.T) {
	tmpDir := t.TempDir()
	gosumPath := filepath.Join(tmpDir, "go.sum")

	content := `github.com/foo/bar v1.0.0 h1:hash1
incomplete line
github.com/baz/qux v2.0.0 h1:hash2
`

	if err := writeFile(gosumPath, content); err != nil {
		t.Fatalf("failed to write test go.sum: %v", err)
	}

	entries, err := ParseGoSum(gosumPath)
	if err != nil {
		t.Fatalf("ParseGoSum failed: %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("Entries length = %d, want 2 (invalid line skipped)", len(entries))
	}
}

// TestParseGoMod_MultipleReplaces tests parsing multiple replace directives.
func TestParseGoMod_MultipleReplaces(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	content := `module github.com/test

replace (
	github.com/old/one => github.com/new/one v1.0.0
	github.com/old/two => github.com/new/two v2.0.0
	github.com/old/three => ../local
)
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	gm, err := ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if len(gm.Replaces) != 3 {
		t.Fatalf("Replaces length = %d, want 3", len(gm.Replaces))
	}

	if rep, ok := gm.Replaces["github.com/old/one"]; !ok {
		t.Errorf("Replaces missing key %q", "github.com/old/one")
	} else if rep.Path != "github.com/new/one" {
		t.Errorf("Replace one path = %q, want %q", rep.Path, "github.com/new/one")
	}

	if rep, ok := gm.Replaces["github.com/old/two"]; !ok {
		t.Errorf("Replaces missing key %q", "github.com/old/two")
	} else if rep.Path != "github.com/new/two" {
		t.Errorf("Replace two path = %q, want %q", rep.Path, "github.com/new/two")
	}

	if rep, ok := gm.Replaces["github.com/old/three"]; !ok {
		t.Errorf("Replaces missing key %q", "github.com/old/three")
	} else if rep.Path != "../local" {
		t.Errorf("Replace three path = %q, want %q", rep.Path, "../local")
	}
}

// TestFindGoMod_EmptyString tests FindGoMod with empty string (should default to ".").
func TestFindGoMod_EmptyString(t *testing.T) {
	// Save current directory and restore after test.
	oldCwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current directory: %v", err)
	}
	defer os.Chdir(oldCwd)

	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	if err := writeFile(gomodPath, "module github.com/test"); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	// Change to temp directory to test empty string behavior.
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change directory: %v", err)
	}

	found, err := FindGoMod("")
	if err != nil {
		t.Fatalf("FindGoMod failed: %v", err)
	}

	if filepath.Base(found) != "go.mod" {
		t.Errorf("FindGoMod returned non-go.mod file: %q", found)
	}
}

// TestParseRequireLine_WithWhitespace tests parsing require lines with extra whitespace.
func TestParseRequireLine_WithWhitespace(t *testing.T) {
	mod := parseRequireLine("  github.com/foo/bar   v1.0.0  ")

	if mod == nil {
		t.Fatalf("parseRequireLine returned nil")
	}

	if mod.Path != "github.com/foo/bar" {
		t.Errorf("Path = %q, want %q", mod.Path, "github.com/foo/bar")
	}

	if mod.Version != "v1.0.0" {
		t.Errorf("Version = %q, want %q", mod.Version, "v1.0.0")
	}
}

// TestParseGoMod_MixedBlocks tests parsing with both require and replace blocks.
func TestParseGoMod_MixedBlocks(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	content := `module github.com/test

go 1.20

require (
	github.com/pkg/a v1.0.0
	github.com/pkg/b v2.0.0 // indirect
)

replace (
	github.com/old => github.com/new v1.0.0
)

require github.com/pkg/c v3.0.0

replace github.com/foo => ../local
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	gm, err := ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if len(gm.Requirements) != 3 {
		t.Fatalf("Requirements length = %d, want 3", len(gm.Requirements))
	}

	if gm.Requirements[0].Path != "github.com/pkg/a" {
		t.Errorf("Requirements[0].Path = %q, want %q", gm.Requirements[0].Path, "github.com/pkg/a")
	}

	if gm.Requirements[2].Path != "github.com/pkg/c" {
		t.Errorf("Requirements[2].Path = %q, want %q", gm.Requirements[2].Path, "github.com/pkg/c")
	}

	if len(gm.Replaces) != 2 {
		t.Fatalf("Replaces length = %d, want 2", len(gm.Replaces))
	}
}

// TestParseGoMod_EdgecaseVersions tests parsing with various version formats.
func TestParseGoMod_EdgecaseVersions(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	content := `module github.com/test

require (
	github.com/a v0.0.0
	github.com/b v1.2.3-alpha.1+build.123
	github.com/c v1.0.0-rc1
)
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	gm, err := ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if len(gm.Requirements) != 3 {
		t.Fatalf("Requirements length = %d, want 3", len(gm.Requirements))
	}

	if gm.Requirements[0].Version != "v0.0.0" {
		t.Errorf("Requirements[0].Version = %q, want %q", gm.Requirements[0].Version, "v0.0.0")
	}

	if gm.Requirements[1].Version != "v1.2.3-alpha.1+build.123" {
		t.Errorf("Requirements[1].Version = %q, want %q", gm.Requirements[1].Version, "v1.2.3-alpha.1+build.123")
	}

	if gm.Requirements[2].Version != "v1.0.0-rc1" {
		t.Errorf("Requirements[2].Version = %q, want %q", gm.Requirements[2].Version, "v1.0.0-rc1")
	}
}

// TestParseReplaceLine_CommentLine tests that comment lines in replace blocks are skipped.
func TestParseReplaceLine_CommentLine(t *testing.T) {
	replaces := make(map[string]Module)
	parseReplaceLine("// this is a comment", replaces)

	if len(replaces) != 0 {
		t.Errorf("Replaces length = %d, want 0", len(replaces))
	}
}

// TestParseReplaceLine_InsufficientFields tests replace line with missing fields.
func TestParseReplaceLine_InsufficientFields(t *testing.T) {
	replaces := make(map[string]Module)
	parseReplaceLine("github.com/foo =>", replaces)

	if len(replaces) != 0 {
		t.Errorf("Replaces length = %d, want 0 (insufficient fields)", len(replaces))
	}
}

// TestParseReplaceLine_OnlyArrow tests replace line with only arrow.
func TestParseReplaceLine_OnlyArrow(t *testing.T) {
	replaces := make(map[string]Module)
	parseReplaceLine("=>", replaces)

	if len(replaces) != 0 {
		t.Errorf("Replaces length = %d, want 0 (only arrow)", len(replaces))
	}
}

// TestParseGoMod_NestedModuleAndGo tests parsing module and go directives.
func TestParseGoMod_NestedModuleAndGo(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	content := `module github.com/example/test
go 1.22

require github.com/test v1.0.0
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	gm, err := ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if gm.ModulePath != "github.com/example/test" {
		t.Errorf("ModulePath = %q, want %q", gm.ModulePath, "github.com/example/test")
	}

	if gm.GoVersion != "1.22" {
		t.Errorf("GoVersion = %q, want %q", gm.GoVersion, "1.22")
	}
}

// TestParseGoMod_TrailingWhitespace tests parsing with trailing whitespace.
func TestParseGoMod_TrailingWhitespace(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	content := `module github.com/test
go 1.21
require github.com/pkg v1.0.0
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	gm, err := ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if gm.ModulePath != "github.com/test" {
		t.Errorf("ModulePath = %q, want %q", gm.ModulePath, "github.com/test")
	}

	if gm.GoVersion != "1.21" {
		t.Errorf("GoVersion = %q, want %q", gm.GoVersion, "1.21")
	}

	if len(gm.Requirements) != 1 {
		t.Fatalf("Requirements length = %d, want 1", len(gm.Requirements))
	}
}

// TestParseGoMod_BlockNotClosed tests parsing when a block is not properly closed.
func TestParseGoMod_BlockNotClosed(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	content := `module github.com/test

require (
	github.com/pkg/a v1.0.0
	github.com/pkg/b v2.0.0
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	gm, err := ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if len(gm.Requirements) != 2 {
		t.Fatalf("Requirements length = %d, want 2 (block not closed)", len(gm.Requirements))
	}
}

// TestParseGoSum_LargeFile tests parsing a larger go.sum file.
func TestParseGoSum_LargeFile(t *testing.T) {
	tmpDir := t.TempDir()
	gosumPath := filepath.Join(tmpDir, "go.sum")

	content := ""
	expectedCount := 10
	for i := 0; i < expectedCount; i++ {
		content += "github.com/pkg/" + string(rune('a'+i)) + " v1.0.0 h1:hash" + string(rune('0'+i)) + "\n"
	}

	if err := writeFile(gosumPath, content); err != nil {
		t.Fatalf("failed to write test go.sum: %v", err)
	}

	entries, err := ParseGoSum(gosumPath)
	if err != nil {
		t.Fatalf("ParseGoSum failed: %v", err)
	}

	if len(entries) != expectedCount {
		t.Errorf("Entries length = %d, want %d", len(entries), expectedCount)
	}
}

// TestParseGoMod_BlankLinesInBlocks tests handling blank lines within blocks.
func TestParseGoMod_BlankLinesInBlocks(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	content := `module github.com/test

require (
	github.com/pkg/a v1.0.0

	github.com/pkg/b v2.0.0

)
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	gm, err := ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if len(gm.Requirements) != 2 {
		t.Fatalf("Requirements length = %d, want 2", len(gm.Requirements))
	}
}

// TestParseGoMod_CommentsInBlocks tests that comments are skipped in blocks.
func TestParseGoMod_CommentsInBlocks(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	content := `module github.com/test

require (
	// Comment line
	github.com/pkg/a v1.0.0
	// Another comment
	github.com/pkg/b v2.0.0 // inline comment
)
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	gm, err := ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if len(gm.Requirements) != 2 {
		t.Fatalf("Requirements length = %d, want 2", len(gm.Requirements))
	}

	if gm.Requirements[0].Path != "github.com/pkg/a" {
		t.Errorf("Requirements[0].Path = %q, want %q", gm.Requirements[0].Path, "github.com/pkg/a")
	}

	if gm.Requirements[1].Path != "github.com/pkg/b" {
		t.Errorf("Requirements[1].Path = %q, want %q", gm.Requirements[1].Path, "github.com/pkg/b")
	}
}

// TestParseRequireLine_ThreeFields tests require line with exactly 3 fields.
func TestParseRequireLine_ThreeFields(t *testing.T) {
	mod := parseRequireLine("github.com/foo/bar v1.0.0 something")

	if mod == nil {
		t.Fatalf("parseRequireLine returned nil")
	}

	if mod.Path != "github.com/foo/bar" {
		t.Errorf("Path = %q, want %q", mod.Path, "github.com/foo/bar")
	}

	if mod.Version != "v1.0.0" {
		t.Errorf("Version = %q, want %q", mod.Version, "v1.0.0")
	}

	if mod.Indirect {
		t.Errorf("Indirect = true, want false (only 4+ fields with // indirect flag)")
	}
}

// TestParseRequireLine_FourFieldsNoIndirect tests require line with 4 fields but no indirect.
func TestParseRequireLine_FourFieldsNoIndirect(t *testing.T) {
	mod := parseRequireLine("github.com/foo/bar v1.0.0 foo bar")

	if mod == nil {
		t.Fatalf("parseRequireLine returned nil")
	}

	if mod.Indirect {
		t.Errorf("Indirect = true, want false (not a // indirect comment)")
	}
}

// TestParseRequireLine_IndirectWithoutDoubleSlash tests that indirect requires double slash.
func TestParseRequireLine_IndirectWithoutDoubleSlash(t *testing.T) {
	mod := parseRequireLine("github.com/foo/bar v1.0.0 indirect")

	if mod == nil {
		t.Fatalf("parseRequireLine returned nil")
	}

	if mod.Indirect {
		t.Errorf("Indirect = true, want false (missing // before indirect)")
	}
}

// TestParseGoMod_NoReplaces tests parsing go.mod with no replaces.
func TestParseGoMod_NoReplaces(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	content := `module github.com/test

require (
	github.com/pkg/a v1.0.0
)
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	gm, err := ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if len(gm.Replaces) != 0 {
		t.Errorf("Replaces length = %d, want 0", len(gm.Replaces))
	}
}

// TestParseGoMod_ModuleWithComments tests module with file comments (inline comments are included).
func TestParseGoMod_ModuleWithComments(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	content := `// File comment
module github.com/test
// Another comment
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	gm, err := ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if gm.ModulePath != "github.com/test" {
		t.Errorf("ModulePath = %q, want %q", gm.ModulePath, "github.com/test")
	}
}

// TestParseGoSum_WithHashTails tests that go.sum entries with various hash suffixes work.
func TestParseGoSum_WithHashTails(t *testing.T) {
	tmpDir := t.TempDir()
	gosumPath := filepath.Join(tmpDir, "go.sum")

	content := `github.com/foo/bar v1.0.0 h1:very/long/hash==
github.com/baz/qux v2.0.0 h1:another+hash+==
`

	if err := writeFile(gosumPath, content); err != nil {
		t.Fatalf("failed to write test go.sum: %v", err)
	}

	entries, err := ParseGoSum(gosumPath)
	if err != nil {
		t.Fatalf("ParseGoSum failed: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("Entries length = %d, want 2", len(entries))
	}

	if entries[0].Path != "github.com/foo/bar" {
		t.Errorf("entries[0].Path = %q", entries[0].Path)
	}

	if entries[1].Path != "github.com/baz/qux" {
		t.Errorf("entries[1].Path = %q", entries[1].Path)
	}
}

// TestParseReplaceLine_EmptyArrow tests replace with empty parts around arrow.
func TestParseReplaceLine_EmptyArrow(t *testing.T) {
	replaces := make(map[string]Module)
	parseReplaceLine("  =>  ", replaces)

	if len(replaces) != 0 {
		t.Errorf("Replaces length = %d, want 0 (empty parts)", len(replaces))
	}
}

// TestParseReplaceLine_LocalPathWithVersion tests local path replace with version-like string.
func TestParseReplaceLine_LocalPathWithVersion(t *testing.T) {
	replaces := make(map[string]Module)
	parseReplaceLine("github.com/foo => ../vendor/foo v1.0.0", replaces)

	if len(replaces) != 1 {
		t.Fatalf("Replaces length = %d, want 1", len(replaces))
	}

	if rep, ok := replaces["github.com/foo"]; !ok {
		t.Errorf("Replaces missing key %q", "github.com/foo")
	} else {
		if rep.Path != "../vendor/foo" {
			t.Errorf("Replace path = %q, want %q", rep.Path, "../vendor/foo")
		}
		if rep.Version != "v1.0.0" {
			t.Errorf("Replace version = %q, want %q", rep.Version, "v1.0.0")
		}
	}
}

// TestParseGoMod_OnlyGoVersionDirective tests go.mod with only go version.
func TestParseGoMod_OnlyGoVersionDirective(t *testing.T) {
	tmpDir := t.TempDir()
	gomodPath := filepath.Join(tmpDir, "go.mod")

	content := `go 1.19
`

	if err := writeFile(gomodPath, content); err != nil {
		t.Fatalf("failed to write test go.mod: %v", err)
	}

	gm, err := ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if gm.GoVersion != "1.19" {
		t.Errorf("GoVersion = %q, want %q", gm.GoVersion, "1.19")
	}

	if gm.ModulePath != "" {
		t.Errorf("ModulePath = %q, want empty", gm.ModulePath)
	}
}

// TestFindGoMod_StatError tests FindGoMod with inaccessible path.
func TestFindGoMod_StatError(t *testing.T) {
	_, err := FindGoMod("/nonexistent/path")
	if err == nil {
		t.Fatalf("FindGoMod should return an error for nonexistent path")
	}
}

// TestParseGoSum_ConsecutiveDuplicates tests consecutive duplicate entries in go.sum.
func TestParseGoSum_ConsecutiveDuplicates(t *testing.T) {
	tmpDir := t.TempDir()
	gosumPath := filepath.Join(tmpDir, "go.sum")

	content := `github.com/test/pkg v1.0.0 h1:hash1
github.com/test/pkg v1.0.0 h1:hash1
github.com/test/pkg v1.0.0 h1:hash1
github.com/test/pkg v1.0.0/go.mod h1:hash2
`

	if err := writeFile(gosumPath, content); err != nil {
		t.Fatalf("failed to write test go.sum: %v", err)
	}

	entries, err := ParseGoSum(gosumPath)
	if err != nil {
		t.Fatalf("ParseGoSum failed: %v", err)
	}

	if len(entries) != 1 {
		t.Errorf("Entries length = %d, want 1", len(entries))
	}
}
