package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseGoMod_ModuleAndGoDirectiveQuotesAndComments(t *testing.T) {
	tests := []struct {
		name, content, wantModule, wantGo string
	}{
		{"plain", "module github.com/a/b\n\ngo 1.25\n", "github.com/a/b", "1.25"},
		{"trailing comments", "module github.com/a/b // the b module\n\ngo 1.25.1 // minimum\n", "github.com/a/b", "1.25.1"},
		{"quoted module", "module \"github.com/a/b\"\n\ngo 1.25\n", "github.com/a/b", "1.25"},
		{"backquoted module with comment", "module `github.com/a/b` // x\n\ngo 1.25\n", "github.com/a/b", "1.25"},
		{"quoted go version", "module github.com/a/b\n\ngo \"1.25\"\n", "github.com/a/b", "1.25"},
		{"module block", "module (\n\tgithub.com/a/b\n)\n\ngo 1.25\n", "github.com/a/b", "1.25"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "go.mod")
			if err := os.WriteFile(p, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}
			gm, err := ParseGoMod(p)
			if err != nil {
				t.Fatal(err)
			}
			if gm.ModulePath != tt.wantModule || gm.GoVersion != tt.wantGo {
				t.Errorf("ModulePath = %q, GoVersion = %q; want %q, %q", gm.ModulePath, gm.GoVersion, tt.wantModule, tt.wantGo)
			}
		})
	}
}

// For a file the real parser rejects, the line scan still drops quotes and comments.
func TestParseGoMod_DirectiveFallbackDropsQuotesAndComments(t *testing.T) {
	p := filepath.Join(t.TempDir(), "go.mod")
	content := "module \"github.com/a/b\" // c\n\ngo 1.25 // d\n\nthis is not a directive at all (\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	gm, err := ParseGoMod(p)
	if err != nil {
		t.Fatal(err)
	}
	if gm.ModulePath != "github.com/a/b" || gm.GoVersion != "1.25" {
		t.Errorf("ModulePath = %q, GoVersion = %q; want the bare values", gm.ModulePath, gm.GoVersion)
	}
}
