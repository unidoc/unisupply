// Package parser handles parsing of go.mod and go.sum files.
package parser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Module represents a Go module dependency.
type Module struct {
	Path     string
	Version  string
	Indirect bool
}

// GoMod represents parsed go.mod content.
type GoMod struct {
	ModulePath   string
	GoVersion    string
	Requirements []Module
	Replaces     map[string]Module // original path -> replacement
}

// ParseGoMod parses a go.mod file and returns structured data.
func ParseGoMod(path string) (*GoMod, error) {
	data, err := os.ReadFile(path) //#nosec G304 -- caller-supplied go.mod path is the parser's input contract
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}

	gm := &GoMod{
		Replaces: make(map[string]Module),
	}

	lines := strings.Split(string(data), "\n")
	inRequireBlock := false
	inReplaceBlock := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip comments and empty lines.
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		// Module declaration.
		if strings.HasPrefix(line, "module ") {
			gm.ModulePath = strings.TrimSpace(strings.TrimPrefix(line, "module "))
			continue
		}

		// Go version.
		if strings.HasPrefix(line, "go ") {
			gm.GoVersion = strings.TrimSpace(strings.TrimPrefix(line, "go "))
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
		if line == ")" {
			inRequireBlock = false
			inReplaceBlock = false
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
	}

	return gm, nil
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

func parseReplaceLine(line string, replaces map[string]Module) {
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
	repMod := Module{Path: replacement[0]}
	if len(replacement) >= 2 {
		repMod.Version = replacement[1]
	}

	replaces[origPath] = repMod
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
