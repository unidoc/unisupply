package scanner

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The messages below are what govulncheck returned for the fixtures under test/integration/testdata/scanerr (paths
// shortened), recorded with CGO_ENABLED=0 GOFLAGS=-mod=readonly GOTOOLCHAIN=local GOWORK=off. The ones marked
// constructed were not recorded: they follow the format of the source that produces them (x/tools' gocommand wraps a
// failing go command as "err: <exit>: stderr: <stderr>", net/http's errors name the host), and the unit test is all that
// pins them.
const (
	msgMultipleMains = "govulncheck: loading packages: \nThere are errors with the provided package patterns:\n\n" +
		"/p/multiple_mains/b.go:3:6: main redeclared in this block\n" +
		"/p/multiple_mains/a.go:3:6: \tother declaration of main\n\n" +
		"For details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns.\n"
	msgNeedsNewerGo = "govulncheck: loading packages: err: exit status 1: stderr: go: go.mod requires go >= 1.99 (running go 1.26.9; GOTOOLCHAIN=local)\n"
	msgMissingGoSum = "govulncheck: loading packages: \nThere are errors with the provided package patterns:\n\n" +
		"main.go:3:8: missing go.sum entry for module providing package gopkg.in/yaml.v3 (imported by example.com/scanerr/missinggosum); to add:\n" +
		"\tgo get example.com/scanerr/missinggosum\n" +
		"/p/missing_gosum/main.go:3:8: could not import gopkg.in/yaml.v3 (invalid package name: \"\")\n" +
		"/p/missing_gosum/main.go:5:22: undefined: yaml\n\n" +
		"For details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns.\n"
	msgModuleFetch = "govulncheck: loading packages: \nThere are errors with the provided package patterns:\n\n" +
		"main.go:3:8: gopkg.in/yaml.v3@v3.0.1: Get \"http://127.0.0.1:1/gopkg.in/yaml.v3/@v/v3.0.1.zip\": dial tcp 127.0.0.1:1: connect: connection refused\n" +
		"/p/module_fetch/main.go:3:8: could not import gopkg.in/yaml.v3 (invalid package name: \"\")\n\n" +
		"For details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns.\n"
	msgNoPackages = "govulncheck: no packages matched the provided patterns"
	// x/vuln's errNoGoMod, from the source (constructed).
	msgNoGoMod = "govulncheck: no go.mod file\n\ngovulncheck only works with Go modules. Try navigating to your module directory.\n"
	// x/vuln's errGoVersionMismatch followed by the loader's error, from the source (constructed).
	msgVersionMismatch = "govulncheck: Loading packages failed, possibly due to a mismatch between the Go version\n" +
		"used to build govulncheck and the Go version on PATH. Consider rebuilding\ngovulncheck with the current Go version.\n\nboom"
	// CheckToolchain's own sentence, which vuln.go substitutes for the loader's message.
	msgToolchain = "this unisupply was built with go1.26.9 and cannot scan code that needs go1.27; rebuild unisupply with go1.27 or newer"
	// A failing go command with a network cause (constructed, x/tools invoke.go shape).
	msgGoCmdDial = "govulncheck: loading packages: err: exit status 1: stderr: go: github.com/x/y@v1.2.3: " +
		"Get \"https://proxy.golang.org/github.com/x/y/@v/v1.2.3.mod\": dial tcp 142.250.1.1:443: i/o timeout\n"
	// A 429 from a module proxy (constructed).
	msgRateLimited = "govulncheck: loading packages: err: exit status 1: stderr: go: github.com/x/y@v1.2.3: reading " +
		"https://proxy.golang.org/github.com/x/y/@v/v1.2.3.mod: 429 Too Many Requests\n"
	// The vulnerability database failing to answer (constructed, x/vuln client/source.go shape).
	msgVulnDB = "govulncheck: HTTP GET https://vuln.go.dev/index/db.json.gz returned unexpected status: 503 Service Unavailable"
	// The vulnerability database refusing the connection (constructed).
	msgVulnDBDial = "govulncheck: Get \"https://vuln.go.dev/index/db.json.gz\": dial tcp 34.1.1.1:443: connect: connection refused"
)

func TestClassifyScanFailure(t *testing.T) {
	tests := []struct {
		name   string
		msg    string
		reason string
		kind   FailKind
	}{
		{"multiple mains", msgMultipleMains, ReasonMultipleMains, FailPermanent},
		{"needs newer go (recorded)", msgNeedsNewerGo, ReasonNeedsNewerGo, FailPermanent},
		{"needs newer go (CheckToolchain)", msgToolchain, ReasonNeedsNewerGo, FailPermanent},
		{"needs newer go (x/vuln mismatch)", msgVersionMismatch, ReasonNeedsNewerGo, FailPermanent},
		{"missing go.sum", msgMissingGoSum, ReasonMissingGoSum, FailPermanent},
		{"module fetch (recorded)", msgModuleFetch, ReasonModuleFetch, FailTransient},
		{"module fetch (go command)", msgGoCmdDial, ReasonModuleFetch, FailTransient},
		{"no go.mod", msgNoGoMod, ReasonNoGoMod, FailPermanent},
		{"no go.mod (runner)", "no go.mod found in /tmp/x", ReasonNoGoMod, FailPermanent},
		{"rate limited", msgRateLimited, ReasonRateLimited, FailTransient},
		{"vulndb status", msgVulnDB, ReasonVulnDBUnreachable, FailTransient},
		// the database host wins over the generic network text it also carries
		{"vulndb dial", msgVulnDBDial, ReasonVulnDBUnreachable, FailTransient},
		// a permanent cause wins over network text elsewhere in the message
		{"missing go.sum and a dial", msgMissingGoSum + "dial tcp 1.1.1.1:443: i/o timeout", ReasonMissingGoSum, FailPermanent},
		// recorded; a cgo-only module gives the same text, which ScanVulnsWithOptions tells apart by looking at the files
		{"no packages matched", msgNoPackages, ReasonNoPackages, FailPermanent},
		{"unknown", "govulncheck: something nobody planned for", ReasonUnknown, FailPermanent},
		{"empty", "", ReasonUnknown, FailPermanent},
		// a line number is not a status code
		{"429 as a line number", "main.go:429:3: undefined: x", ReasonUnknown, FailPermanent},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			se := classifyScanFailure(tc.msg, nil)
			if se.Reason != tc.reason || se.Kind != tc.kind {
				t.Errorf("Reason, Kind = %q, %v; want %q, %v", se.Reason, se.Kind, tc.reason, tc.kind)
			}
			if se.Err == nil || se.Err.Error() == "" {
				t.Errorf("Err = %v, want the text of the failure (or a placeholder when it has none)", se.Err)
			}
		})
	}
}

// Once the scan's context has ended, a timeout in the message is the scan's own limit, not a network fault.
func TestClassifyScanFailure_EndedContextIsNotANetworkFault(t *testing.T) {
	if se := classifyScanFailure(msgGoCmdDial, context.DeadlineExceeded); se.Reason != ReasonUnknown || se.Kind != FailPermanent {
		t.Errorf("Reason, Kind = %q, %v, want unknown, permanent", se.Reason, se.Kind)
	}
	if se := classifyScanFailure(msgMissingGoSum, context.Canceled); se.Reason != ReasonMissingGoSum {
		t.Errorf("Reason = %q, a permanent cause is still found", se.Reason)
	}
}

func TestFailKindString(t *testing.T) {
	for k, want := range map[FailKind]string{FailTransient: "transient", FailPermanent: "permanent", FailTooLarge: "too_large", FailKind(9): "unknown"} {
		if got := k.String(); got != want {
			t.Errorf("FailKind(%d) = %q, want %q", int(k), got, want)
		}
	}
}

func TestScanErrorSummary(t *testing.T) {
	tests := []struct {
		name string
		se   *ScanError
		want string
	}{
		// the message starts with a blank line and a header: the first line of Error() says nothing
		{"package errors", classifyScanFailure(msgMultipleMains, nil), "multiple_mains: /p/multiple_mains/b.go:3:6: main redeclared in this block"},
		{"loader message", classifyScanFailure(msgNeedsNewerGo, nil), "needs_newer_go: govulncheck: loading packages: err: exit status 1: stderr: go: go.mod requires go >= 1.99 (running go 1.26.9; GOTOOLCHAIN=local)"},
		{"cut tail", &ScanError{Reason: ReasonUnknown, Err: errors.New("...\nsecond\nthird")}, "unknown: second"},
		{"bare prefix only", &ScanError{Reason: ReasonUnknown, Err: errors.New("govulncheck: loading packages: \n\n")}, "unknown"},
		{"no Err", &ScanError{Reason: ReasonUnknown}, "unknown"},
	}
	for _, tc := range tests {
		if got := tc.se.Summary(); got != tc.want {
			t.Errorf("%s: Summary() = %q, want %q", tc.name, got, tc.want)
		}
	}
	if s := classifyScanFailure(msgMultipleMains, nil).Summary(); strings.Contains(s, "\n") {
		t.Errorf("Summary() = %q, want one line", s)
	}
}

func TestScanErrorError(t *testing.T) {
	se := &ScanError{Kind: FailPermanent, Reason: ReasonNoGoMod, Err: errors.New("no go.mod found in x")}
	if got := se.Error(); got != "no_go_mod: no go.mod found in x" {
		t.Errorf("Error() = %q", got)
	}
}

func TestStderrTail(t *testing.T) {
	numbered := func(n int) string {
		var b strings.Builder
		for i := 1; i <= n; i++ {
			if i > 1 {
				b.WriteByte('\n')
			}
			b.WriteString("line ")
			b.WriteString(strings.Repeat("x", i%7))
			b.WriteString(string(rune('A' + i%26)))
		}
		return b.String()
	}

	t.Run("short is unchanged", func(t *testing.T) {
		if got := stderrTail("a\nb\n"); got != "a\nb" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("exactly 40 lines is unchanged", func(t *testing.T) {
		in := numbered(40)
		if got := stderrTail(in); got != in {
			t.Errorf("a message of %d lines was cut", tailMaxLines)
		}
	})
	t.Run("more than 40 lines keeps the last 40", func(t *testing.T) {
		in := numbered(60)
		got := stderrTail(in)
		lines := strings.Split(in, "\n")
		want := "...\n" + strings.Join(lines[20:], "\n")
		if got != want {
			t.Errorf("got %q\nwant %q", got, want)
		}
	})
	t.Run("more than 4 KiB cuts on a line boundary", func(t *testing.T) {
		// 3 lines of 2000 bytes and a short one are 6003 bytes: the first line goes, the rest fits in 4096.
		long := strings.Repeat("f", 1999)
		got := stderrTail(long + "\n" + long + "\n" + long + "\nend")
		if want := "...\n" + long + "\n" + long + "\nend"; got != want {
			t.Errorf("got %d bytes starting %.12q, want the last three lines (%d bytes)", len(got), got, len(want))
		}
	})
	t.Run("one line over the limit is cut at a character boundary", func(t *testing.T) {
		in := strings.Repeat("é", tailMaxBytes) // 2 bytes each
		got := stderrTail(in)
		kept := strings.TrimPrefix(got, "...\n")
		if !strings.HasPrefix(got, "...\n") || len(kept) > tailMaxBytes || strings.ContainsRune(kept, '�') || strings.Trim(kept, "é") != "" {
			t.Errorf("kept %d bytes, want whole characters within %d", len(kept), tailMaxBytes)
		}
	})
}

func TestClassifyScanFailure_ErrIsTheTail(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 100; i++ {
		b.WriteString("noise line\n")
	}
	b.WriteString("main.go:3:8: missing go.sum entry for module providing package x")
	se := classifyScanFailure(b.String(), nil)
	if se.Reason != ReasonMissingGoSum {
		t.Errorf("Reason = %q: the whole message is classified, not the tail", se.Reason)
	}
	if got := strings.Count(se.Err.Error(), "\n") + 1; got != tailMaxLines+1 {
		t.Errorf("Err has %d lines, want the marker and %d lines", got, tailMaxLines)
	}
	if !strings.HasSuffix(se.Err.Error(), "missing go.sum entry for module providing package x") {
		t.Errorf("Err = %q, want the last line kept", se.Err)
	}
}

func TestWrapScanFailure_KeepsTheChain(t *testing.T) {
	long := errors.New(strings.Repeat("a long line of go output\n", 100) + "dial tcp 1.1.1.1:443: i/o timeout")
	wrapped := WrapScanFailure(errors.Join(fs.ErrNotExist, long), nil)
	if !errors.Is(wrapped, fs.ErrNotExist) || !errors.Is(wrapped, long) {
		t.Error("errors.Is must see through the ScanError and the cut")
	}
	var se *ScanError
	if !errors.As(error(wrapped), &se) || se != wrapped || se.Reason != ReasonModuleFetch {
		t.Errorf("errors.As = %v, Reason = %q", se, wrapped.Reason)
	}
	plain := &ScanError{Reason: ReasonUnknown, Err: fs.ErrPermission}
	if !errors.Is(plain, fs.ErrPermission) || errors.Unwrap(plain) != fs.ErrPermission {
		t.Error("Unwrap must return Err")
	}
}

func TestHasCgoImport(t *testing.T) {
	const cgoFile = "package p\n\n// #include <stdlib.h>\nimport \"C\"\n\nfunc F() {}\n"
	const plainFile = "package p\n\nimport \"fmt\"\n\nvar _ = fmt.Sprint\n"
	tests := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"cgo file in the module root", map[string]string{"go.mod": "module m\n", "c.go": cgoFile}, true},
		{"cgo file in a subdirectory", map[string]string{"go.mod": "module m\n", "pkg/c.go": cgoFile}, true},
		{"cgo file behind a build constraint", map[string]string{"c.go": "//go:build cgo\n\n" + cgoFile}, true},
		{"no cgo anywhere", map[string]string{"go.mod": "module m\n", "a.go": plainFile}, false},
		{"only a test file imports C", map[string]string{"c_test.go": cgoFile, "a.go": plainFile}, false},
		{"only testdata imports C", map[string]string{"testdata/c.go": cgoFile, "a.go": plainFile}, false},
		{"only vendor imports C", map[string]string{"vendor/x/c.go": cgoFile}, false},
		{"only a hidden directory imports C", map[string]string{".hidden/c.go": cgoFile}, false},
		{"only an underscore directory imports C", map[string]string{"_old/c.go": cgoFile}, false},
		{"only a nested module imports C", map[string]string{"go.mod": "module m\n", "sub/go.mod": "module m/sub\n", "sub/c.go": cgoFile}, false},
		{"a file that does not parse is skipped", map[string]string{"bad.go": "package", "c.go": cgoFile}, true},
		{"empty directory", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range tc.files {
				path := filepath.Join(dir, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := hasCgoImport(dir); got != tc.want {
				t.Errorf("hasCgoImport = %v, want %v", got, tc.want)
			}
		})
	}
}
