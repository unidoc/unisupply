package scanner

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestGovulncheckEnv(t *testing.T) {
	tests := []struct {
		name    string
		base    []string
		version string
		want    []string
	}{
		{"appends", []string{"A=1", "B=2"}, "go1.25.0", []string{"A=1", "B=2", "GOVERSION=go1.25.0"}},
		{"empty base", nil, "go1.25.0", []string{"GOVERSION=go1.25.0"}},
		{"empty version", []string{"A=1"}, "", []string{"A=1"}},
		{"existing GOVERSION wins", []string{"A=1", "GOVERSION=go1.20.0"}, "go1.25.0", []string{"A=1", "GOVERSION=go1.20.0"}},
		{"similar prefix is not GOVERSION", []string{"GOVERSIONX=1"}, "go1.25.0", []string{"GOVERSIONX=1", "GOVERSION=go1.25.0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := govulncheckEnv(tt.base, tt.version)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("govulncheckEnv() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGovulncheckEnv_DoesNotAliasBase(t *testing.T) {
	// Spare capacity would let an in-place append write into the caller's array.
	backing := make([]string, 1, 4)
	backing[0] = "A=1"
	base := backing[:1]

	got := govulncheckEnv(base, "go1.25.0")
	if len(base) != 1 || base[0] != "A=1" {
		t.Errorf("base mutated: %v", base)
	}
	if spare := backing[:2][1]; spare != "" {
		t.Errorf("append wrote into base's backing array: %q", spare)
	}
	got[0] = "CHANGED=1"
	if base[0] != "A=1" {
		t.Errorf("result shares memory with base: %v", base)
	}

	unchanged := govulncheckEnv(base, "")
	unchanged[0] = "CHANGED=1"
	if base[0] != "A=1" {
		t.Errorf("unchanged copy shares memory with base: %v", base)
	}
}

func TestRebaseStdlibFile(t *testing.T) {
	root := t.TempDir()
	scanner := filepath.Join(root, "toolchain@go1.26.8")
	project := filepath.Join(root, "toolchain@go1.25.0")
	crossFile := "../toolchain@go1.25.0/src/sync/once.go"

	tests := []struct {
		name                      string
		filename, scannerR, projR string
		want                      string
	}{
		{"equal roots", "src/sync/once.go", scanner, scanner, "src/sync/once.go"},
		{"equal roots after clean", "src/sync/once.go", scanner, scanner + string(filepath.Separator), "src/sync/once.go"},
		{"differing roots", crossFile, scanner, project, "src/sync/once.go"},
		{"empty filename", "", scanner, project, ""},
		{"empty scanner root", crossFile, "", project, crossFile},
		{"empty project root", crossFile, scanner, "", crossFile},
		{"result leaves project root", "../../elsewhere/x.go", scanner, project, "../../elsewhere/x.go"},
		{"result is the parent of project root", "..", scanner, project, ".."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rebaseStdlibFile(tt.filename, tt.scannerR, tt.projR); got != tt.want {
				t.Errorf("rebaseStdlibFile(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}

func TestParseGovulncheckJSONWithOptions_RebasesStdlibFrames(t *testing.T) {
	root := t.TempDir()
	opts := gvcParseOptions{
		scannerGOROOT: filepath.Join(root, "toolchain@go1.26.8"),
		projectGOROOT: filepath.Join(root, "toolchain@go1.25.0"),
	}

	stream := `{"osv":{"id":"GO-STD-1","summary":"sync issue"}}` + "\n" +
		`{"SBOM":{"roots":["example.com/app"]}}` + "\n" +
		gvcTestFinding("GO-STD-1",
			gvcTestFrame("stdlib", "v1.25.0", "sync", "Do", "*Once", "../toolchain@go1.25.0/src/sync/once.go", 52, 3),
			gvcTestFrame("example.com/app", "", "example.com/app", "main", "", "../cgo/gen.go", 7, 2),
		)

	parse := func(t *testing.T, withOpts bool) Vulnerability {
		t.Helper()
		buf := bytes.NewBufferString(stream)
		var res map[string][]Vulnerability
		var err error
		if withOpts {
			res, err = parseGovulncheckJSONWithOptions(buf, opts)
		} else {
			res, err = parseGovulncheckJSON(buf)
		}
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(res["stdlib"]) != 1 {
			t.Fatalf("stdlib vulnerabilities = %d, want 1", len(res["stdlib"]))
		}
		return res["stdlib"][0]
	}

	// frameFor returns the frame whose name ends in suffix.
	frameFor := func(t *testing.T, v Vulnerability, suffix string) CallFrame {
		t.Helper()
		for _, f := range v.CallTrace {
			if strings.HasSuffix(f.Name, suffix) {
				return f
			}
		}
		t.Fatalf("no frame ending in %q in %+v", suffix, v.CallTrace)
		return CallFrame{}
	}

	t.Run("with options", func(t *testing.T) {
		v := parse(t, true)
		std := frameFor(t, v, "Once.Do")
		if std.File != "src/sync/once.go" || std.Line != 52 || std.Column != 3 {
			t.Errorf("stdlib frame = %+v, want File src/sync/once.go line 52 col 3", std)
		}
		app := frameFor(t, v, "main")
		if app.File != "" || app.Line != 7 {
			t.Errorf("non-stdlib frame = %+v, want File dropped and Line kept", app)
		}
	})

	t.Run("without options", func(t *testing.T) {
		v := parse(t, false)
		if std := frameFor(t, v, "Once.Do"); std.File != "" || std.Line != 52 {
			t.Errorf("stdlib frame = %+v, want File dropped and Line kept", std)
		}
	})
}

func TestResolveGoEnv(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH")
	}

	version, goRoot, err := resolveGoEnv(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("resolveGoEnv: %v", err)
	}
	if !strings.HasPrefix(version, "go") {
		t.Errorf("version = %q, want a go-prefixed version", version)
	}
	if !filepath.IsAbs(goRoot) {
		t.Errorf("goRoot = %q, want an absolute path", goRoot)
	}
}

func TestResolveGoEnv_EmptyDirUsesProcessDirectory(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH")
	}

	version, goRoot, err := resolveGoEnv(context.Background(), "")
	if err != nil {
		t.Fatalf("resolveGoEnv: %v", err)
	}
	if version == "" || goRoot == "" {
		t.Errorf("got empty values: %q, %q", version, goRoot)
	}
}

func TestResolveGoEnv_BadDirFails(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH")
	}

	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, _, err := resolveGoEnv(context.Background(), missing); err == nil {
		t.Error("resolveGoEnv in a missing directory returned no error")
	}
}
