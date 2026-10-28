// Package parser handles parsing of go.mod and go.sum files.
package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"
)

// Module represents a Go module dependency.
type Module struct {
	Path     string `json:"path"`
	Version  string `json:"version,omitempty"`
	Indirect bool   `json:"indirect,omitempty"`
}

// Replace represents one replace directive. OldVersion is empty for a
// path-only replace (applies to all versions of the original module); when
// set, the replace applies only when that exact version is selected.
type Replace struct {
	OldVersion string `json:"old_version,omitempty"`
	New        Module `json:"new"`
}

// GoMod represents parsed go.mod content.
type GoMod struct {
	ModulePath   string             `json:"module_path"`
	GoVersion    string             `json:"go_version,omitempty"`
	Requirements []Module           `json:"requirements,omitempty"`
	Replaces     map[string]Replace `json:"replaces,omitempty"` // original path -> replacement (one entry per path; a later directive for the same path wins)
	Excludes     []Module           `json:"excludes,omitempty"` // modules excluded via the exclude directive
}

// ReplacementFor returns the replace directive that applies to the module at
// (path, version), following go.mod semantics: a version-scoped replace only
// matches when the selected version equals its old version, while a path-only
// replace matches all versions.
func (gm *GoMod) ReplacementFor(path, version string) (Replace, bool) {
	r, ok := gm.Replaces[path]
	if !ok {
		return Replace{}, false
	}
	if r.OldVersion != "" && r.OldVersion != version {
		return Replace{}, false
	}
	return r, true
}

// ParseGoMod parses a go.mod file and returns structured data.
func ParseGoMod(path string) (*GoMod, error) {
	data, err := os.ReadFile(path) //#nosec G304 -- caller-supplied go.mod path is the parser's input contract
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}

	gm := &GoMod{
		Replaces: make(map[string]Replace),
	}

	lines := strings.Split(string(data), "\n")
	inRequireBlock := false
	inReplaceBlock := false
	inExcludeBlock := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip comments and empty lines.
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		// Module declaration.
		if strings.HasPrefix(line, "module ") {
			gm.ModulePath = directiveValue(strings.TrimPrefix(line, "module "))
			continue
		}

		// Go version.
		if strings.HasPrefix(line, "go ") {
			gm.GoVersion = directiveValue(strings.TrimPrefix(line, "go "))
			continue
		}

		// Block start/end.
		if line == "require (" {
			inRequireBlock = true
			continue
		}
		if line == "replace (" {
			inReplaceBlock = true
			continue
		}
		if line == "exclude (" {
			inExcludeBlock = true
			continue
		}
		if line == ")" {
			inRequireBlock = false
			inReplaceBlock = false
			inExcludeBlock = false
			continue
		}

		// Single-line require.
		if strings.HasPrefix(line, "require ") {
			mod := parseRequireLine(strings.TrimPrefix(line, "require "))
			if mod != nil {
				gm.Requirements = append(gm.Requirements, *mod)
			}
			continue
		}

		// Single-line replace.
		if strings.HasPrefix(line, "replace ") {
			parseReplaceLine(strings.TrimPrefix(line, "replace "), gm.Replaces)
			continue
		}

		// Single-line exclude.
		if strings.HasPrefix(line, "exclude ") {
			if mod := parseRequireLine(strings.TrimPrefix(line, "exclude ")); mod != nil {
				gm.Excludes = append(gm.Excludes, *mod)
			}
			continue
		}

		// Inside require block.
		if inRequireBlock {
			mod := parseRequireLine(line)
			if mod != nil {
				gm.Requirements = append(gm.Requirements, *mod)
			}
			continue
		}

		// Inside replace block.
		if inReplaceBlock {
			parseReplaceLine(line, gm.Replaces)
			continue
		}

		// Inside exclude block.
		if inExcludeBlock {
			if mod := parseRequireLine(line); mod != nil {
				gm.Excludes = append(gm.Excludes, *mod)
			}
			continue
		}
	}

	// The module path and go version are read again by the real go.mod parser, which knows the quoting and
	// comment rules; the line scan above stays as the answer for a file it rejects.
	if mf, perr := modfile.ParseLax(path, data, nil); perr == nil {
		if mf.Module != nil {
			gm.ModulePath = mf.Module.Mod.Path
		}
		if mf.Go != nil {
			gm.GoVersion = mf.Go.Version
		}
	}

	return gm, nil
}

// directiveValue returns the argument of a module or go directive line: without a trailing "// comment" and
// without the quotes a go.mod may put around a path.
func directiveValue(arg string) string {
	arg = strings.TrimSpace(arg)
	if arg != "" && (arg[0] == '"' || arg[0] == '`') {
		if end := strings.IndexByte(arg[1:], arg[0]); end >= 0 {
			return arg[1 : 1+end]
		}
		return strings.Trim(arg, "\"`")
	}
	if i := strings.Index(arg, "//"); i >= 0 {
		arg = arg[:i]
	}
	return strings.TrimSpace(arg)
}

func parseRequireLine(line string) *Module {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "//") {
		return nil
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil
	}

	indirect := false
	if len(parts) >= 4 && parts[2] == "//" && parts[3] == "indirect" {
		indirect = true
	}

	return &Module{
		Path:     parts[0],
		Version:  parts[1],
		Indirect: indirect,
	}
}

func parseReplaceLine(line string, replaces map[string]Replace) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "//") {
		return
	}

	parts := strings.SplitN(line, "=>", 2)
	if len(parts) != 2 {
		return
	}

	original := strings.Fields(strings.TrimSpace(parts[0]))
	replacement := strings.Fields(strings.TrimSpace(parts[1]))

	if len(original) < 1 || len(replacement) < 1 {
		return
	}

	origPath := original[0]
	rep := Replace{New: Module{Path: replacement[0]}}
	if len(original) >= 2 {
		rep.OldVersion = original[1]
	}
	if len(replacement) >= 2 {
		rep.New.Version = replacement[1]
	}

	replaces[origPath] = rep
}

// GoSumEntry represents one line in go.sum.
type GoSumEntry struct {
	Path    string
	Version string
}

// ParseGoSum parses a go.sum file and extracts unique module+version pairs.
func ParseGoSum(path string) ([]GoSumEntry, error) {
	f, err := os.Open(path) //#nosec G304 -- caller-supplied go.sum path is the parser's input contract
	if err != nil {
		return nil, fmt.Errorf("reading go.sum: %w", err)
	}
	defer f.Close()

	seen := make(map[string]bool)
	var entries []GoSumEntry

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		modPath := parts[0]
		version := parts[1]
		// go.sum has entries like "v1.2.3/go.mod" — strip the suffix.
		version = strings.TrimSuffix(version, "/go.mod")

		key := modPath + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true

		entries = append(entries, GoSumEntry{
			Path:    modPath,
			Version: version,
		})
	}

	return entries, scanner.Err()
}

// FindGoMod locates a go.mod file given a path (file or directory).
func FindGoMod(path string) (string, error) {
	if path == "" {
		path = "."
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", path, err)
	}

	if !info.IsDir() {
		if filepath.Base(path) == "go.mod" {
			return path, nil
		}
		return "", fmt.Errorf("%s is not a go.mod file or directory", path)
	}

	gomodPath := filepath.Join(path, "go.mod")
	if _, err := os.Stat(gomodPath); err != nil {
		return "", fmt.Errorf("no go.mod found in %s", path)
	}

	return gomodPath, nil
}
