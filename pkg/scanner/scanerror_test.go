package scanner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
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
	msgNoPackages    = "govulncheck: no packages matched the provided patterns"
	msgMixedPackages = "govulncheck: loading packages: \nThere are errors with the provided package patterns:\n\n" +
		"-: found packages main (a.go) and other (b.go) in /p/mixed_packages\n" +
		"/p/mixed_packages/b.go:1:1: package other; expected package main\n\n" +
		"For details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns.\n"
	msgMixedPackagesMainLast = "govulncheck: loading packages: \nThere are errors with the provided package patterns:\n\n" +
		"-: found packages alpha (a.go) and main (b.go) in /p/mixed_packages_main_last\n" +
		"/p/mixed_packages_main_last/b.go:1:1: package main; expected package alpha\n\n" +
		"For details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns.\n"
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
		// two package names in one directory, whichever comes first
		{"mixed packages", msgMixedPackages, ReasonMixedPackages, FailPermanent},
		{"mixed packages, main last", msgMixedPackagesMainLast, ReasonMixedPackages, FailPermanent},
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
		// a package path that names rate limiting is a build failure, not a refused request
		{"ratelimit in a local path", "govulncheck: loading packages: \n/home/u/proj/internal/ratelimit/limiter.go:12:2: undefined: tokenBucket", ReasonUnknown, FailPermanent},
		{"ratelimit in a module path", "govulncheck: loading packages: \n/m/go.uber.org/ratelimit@v0.3.1/limiter.go:12:2: undefined: tokenBucket", ReasonUnknown, FailPermanent},
		{"rate-limit in a path", "/p/rate-limit/a.go:1:1: undefined: x", ReasonUnknown, FailPermanent},
		{"GitHub rate limit", "GET https://api.github.com/repos/x/y: 403 API rate limit exceeded for 1.2.3.4", ReasonRateLimited, FailTransient},
		{"GitHub secondary rate limit", "You have exceeded a secondary rate limit", ReasonRateLimited, FailTransient},
		{"rate limited", "request was rate limited", ReasonRateLimited, FailTransient},
		// network wording reported on the PR (constructed, go command and net/http shapes)
		{"cut download", "govulncheck: loading packages: err: exit status 1: stderr: go: github.com/x/y@v1.2.3: unexpected EOF", ReasonModuleFetch, FailTransient},
		{"TCP timeout", "go: github.com/x/y@v1.2.3: read tcp 10.0.0.2:51234->142.250.1.1:443: read: connection timed out", ReasonModuleFetch, FailTransient},
		{"HTTP/2 stream reset", "go: github.com/x/y@v1.2.3: Get \"https://proxy.golang.org/github.com/x/y/@v/v1.2.3.zip\": stream error: stream ID 3; INTERNAL_ERROR; received from peer", ReasonModuleFetch, FailTransient},
		// not a network fault: a source file that ends early (recorded; go/parser's wording, not the compiler's
		// "unexpected EOF"), and an identifier that names a stream error
		{"source file cut short", "govulncheck: loading packages: \nThere are errors with the provided package patterns:\n\na.go:3:15: expected ';', found 'EOF'\na.go:3:15: expected '}', found 'EOF'\n", ReasonUnknown, FailPermanent},
		{"streamError identifier", "/p/a.go:3:2: undefined: streamError", ReasonUnknown, FailPermanent},
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

// Once the scan's context has ended, a timeout in the message is the scan's own limit, not a network fault: a scan that
// ran out of time is scan_deadline, and one the caller canceled is unknown. A permanent cause in the message still wins.
func TestClassifyScanFailure_EndedContext(t *testing.T) {
	se := classifyScanFailure(msgGoCmdDial, context.DeadlineExceeded)
	if se.Reason != ReasonScanDeadline || se.Kind != FailTooLarge {
		t.Errorf("deadline: Reason, Kind = %q, %v, want scan_deadline, too_large", se.Reason, se.Kind)
	}
	if !errors.Is(se, context.DeadlineExceeded) {
		t.Errorf("deadline: errors.Is(%v, context.DeadlineExceeded) = false", se)
	}
	if !strings.Contains(se.Error(), "dial tcp") {
		t.Errorf("deadline: Error() = %q, want the scan's own output kept", se.Error())
	}
	// a deadline wrapped by the caller's own context is still a deadline
	if se := classifyScanFailure(msgGoCmdDial, fmt.Errorf("scan: %w", context.DeadlineExceeded)); se.Reason != ReasonScanDeadline {
		t.Errorf("wrapped deadline: Reason = %q, want scan_deadline", se.Reason)
	}
	if se := classifyScanFailure(msgGoCmdDial, context.Canceled); se.Reason != ReasonUnknown || se.Kind != FailPermanent {
		t.Errorf("canceled: Reason, Kind = %q, %v, want unknown, permanent", se.Reason, se.Kind)
	}
	if se := classifyScanFailure(msgMissingGoSum, context.Canceled); se.Reason != ReasonMissingGoSum {
		t.Errorf("canceled: Reason = %q, a permanent cause is still found", se.Reason)
	}
	if se := classifyScanFailure(msgMissingGoSum, context.DeadlineExceeded); se.Reason != ReasonMissingGoSum || se.Kind != FailPermanent {
		t.Errorf("deadline: Reason, Kind = %q, %v, a permanent cause is still found", se.Reason, se.Kind)
	}
}

func TestFailKindString(t *testing.T) {
	for k, want := range map[FailKind]string{FailTransient: "transient", FailPermanent: "permanent", FailTooLarge: "too_large", FailKind(9): "unknown"} {
		if got := k.String(); got != want {
			t.Errorf("FailKind(%d) = %q, want %q", int(k), got, want)
		}
	}
	// a ScanError built without a Kind must not be retried
	if k := (ScanError{}).Kind; k != FailPermanent {
		t.Errorf("zero Kind = %v, want permanent", k)
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
		{"loader message", classifyScanFailure(msgNeedsNewerGo, nil), "needs_newer_go: go.mod requires go >= 1.99 (running go 1.26.9; GOTOOLCHAIN=local)"},
		// a package error without a position starts with "-: "
		{"no position", classifyScanFailure(msgMixedPackagesMainLast, nil), "mixed_packages: found packages alpha (a.go) and main (b.go) in /p/mixed_packages_main_last"},
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

// The summary names the line that decided the Reason, not the first meaningful line: an unrelated error can come first
// in the package-loading list, and a cause that comes later must still be the one published.
func TestScanErrorSummary_DecidingLine(t *testing.T) {
	const msgUnrelatedFirst = "govulncheck: loading packages: \nThere are errors with the provided package patterns:\n\n" +
		"x.go:1:2: undefined: foo.Bar\n" +
		"b.go:3:6: main redeclared in this block\n" +
		"a.go:3:6: \tother declaration of main\n\n" +
		"For details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns.\n"
	se := classifyScanFailure(msgUnrelatedFirst, nil)
	if se.Reason != ReasonMultipleMains {
		t.Fatalf("Reason = %q, want %q", se.Reason, ReasonMultipleMains)
	}
	if got, want := se.Summary(), "multiple_mains: b.go:3:6: main redeclared in this block"; got != want {
		t.Errorf("Summary() = %q, want %q", got, want)
	}

	// The matching line is kept whole even when the tail cut drops it from Err.
	var b strings.Builder
	b.WriteString("b.go:3:6: main redeclared in this block\n")
	for i := range tailMaxLines + 5 {
		fmt.Fprintf(&b, "x.go:%d:1: undefined: foo.Bar\n", i)
	}
	se = classifyScanFailure(b.String(), nil)
	if se.Reason != ReasonMultipleMains {
		t.Fatalf("Reason = %q, want %q", se.Reason, ReasonMultipleMains)
	}
	if got, want := se.Summary(), "multiple_mains: b.go:3:6: main redeclared in this block"; got != want {
		t.Errorf("cut tail: Summary() = %q, want %q", got, want)
	}
}

// A single over-long line is held to tailMaxBytes, like Err is: the summary is published, and a go error line can be
// arbitrarily long.
func TestScanErrorSummary_LongDecidingLine(t *testing.T) {
	const head = "b.go:3:6: main redeclared in this block "
	tests := []struct {
		name string
		line string
	}{
		{"ascii", head + strings.Repeat("x", 100000)},
		// a three-byte rune starts one byte before the cut, so the cut falls inside it
		{"rune at the cut", head + strings.Repeat("x", tailMaxBytes-1-len(head)) + strings.Repeat("\u4e16", 1000)},
	}
	for _, tc := range tests {
		se := classifyScanFailure("header\n"+tc.line, nil)
		if se.Reason != ReasonMultipleMains {
			t.Fatalf("%s: Reason = %q, want %q", tc.name, se.Reason, ReasonMultipleMains)
		}
		got := se.Summary()
		if max := len(se.Reason) + 2 + tailMaxBytes + len("..."); len(got) > max {
			t.Errorf("%s: len(Summary()) = %d, want at most %d", tc.name, len(got), max)
		}
		if !utf8.ValidString(got) {
			t.Errorf("%s: Summary() is not valid UTF-8", tc.name)
		}
		if want := "multiple_mains: " + head; !strings.HasPrefix(got, want) {
			t.Errorf("%s: Summary() = %.80q..., want it to start with %q", tc.name, got, want)
		}
		if !strings.HasSuffix(got, "...") {
			t.Errorf("%s: Summary() does not end with an ellipsis", tc.name)
		}
	}
}

// The summary starts at the cause: the wrapper that govulncheck and the go command put in front of it is dropped.
func TestScanErrorSummary_WrapperChain(t *testing.T) {
	const wantNewerGo = "needs_newer_go: go.mod requires go >= 1.27.0 (running go 1.26.9; GOTOOLCHAIN=local)"
	tests := []struct {
		name string
		se   *ScanError
		want string
	}{
		{"needs newer go", classifyScanFailure("govulncheck: loading packages: err: exit status 1: stderr: go: go.mod requires go >= 1.27.0 (running go 1.26.9; GOTOOLCHAIN=local)\n", nil), wantNewerGo},
		{"needs newer go, exit status 2", classifyScanFailure("govulncheck: loading packages: err: exit status 2: stderr: go: go.mod requires go >= 1.27.0 (running go 1.26.9; GOTOOLCHAIN=local)", nil), wantNewerGo},
		{"header lines first", classifyScanFailure("\ngovulncheck: loading packages: \nerr: exit status 1: stderr: go: go.mod requires go >= 1.27.0 (running go 1.26.9; GOTOOLCHAIN=local)\n", nil), wantNewerGo},
		// no rule matches: the first meaningful line, with its wrapper dropped too
		{"unknown", classifyScanFailure("govulncheck: loading packages: err: exit status 1: stderr: go: something odd happened\n", nil), "unknown: something odd happened"},
		// a message that has none of the wrapper is left alone
		{"no wrapper", classifyScanFailure("b.go:3:6: main redeclared in this block", nil), "multiple_mains: b.go:3:6: main redeclared in this block"},
		// a ScanError built by hand has no remembered line and keeps the first-meaningful-line behaviour
		{"hand built", &ScanError{Reason: ReasonUnknown, Err: errors.New("first\nb.go:3:6: main redeclared in this block")}, "unknown: first"},
		{"hand built, wrapper", &ScanError{Reason: ReasonNeedsNewerGo, Err: errors.New("govulncheck: loading packages: err: exit status 1: stderr: go: go.mod requires go >= 1.27.0")}, "needs_newer_go: go.mod requires go >= 1.27.0"},
	}
	for _, tc := range tests {
		got := tc.se.Summary()
		if got != tc.want {
			t.Errorf("%s: Summary() = %q, want %q", tc.name, got, tc.want)
		}
		for _, w := range []string{"govulncheck:", "exit status", "stderr:"} {
			if strings.Contains(got, w) {
				t.Errorf("%s: Summary() = %q, still carries %q", tc.name, got, w)
			}
		}
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
	wrapped := WrapScanFailure(errors.Join(fs.ErrNotExist, long), nil, "")
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

func TestTrimProjectDir(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "proj")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	// t.TempDir can itself sit behind a symlink (/var -> /private/var on macOS): the go command reports the resolved path.
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	sep := string(filepath.Separator)
	tests := []struct {
		name, msg, dir, want string
	}{
		{"file in the project", resolved + sep + "b.go:3:6: main redeclared in this block", dir, "b.go:3:6: main redeclared in this block"},
		{"file in a subdirectory", resolved + sep + "sub" + sep + "a.go:1:1: x", dir, "sub" + sep + "a.go:1:1: x"},
		{"the directory itself", "found packages a (a.go) and b (b.go) in " + resolved + "\nnext", dir, "found packages a (a.go) and b (b.go) in .\nnext"},
		{"the directory at the end", "no Go files in " + resolved, dir, "no Go files in ."},
		{"through a symlink", resolved + sep + "b.go:1:1: x", link, "b.go:1:1: x"},
		{"a sibling is kept", resolved + "2" + sep + "b.go:1:1: x", dir, resolved + "2" + sep + "b.go:1:1: x"},
		{"no directory", resolved + sep + "b.go:1:1: x", "", resolved + sep + "b.go:1:1: x"},
	}
	for _, tc := range tests {
		if got := trimProjectDir(tc.msg, tc.dir); got != tc.want {
			t.Errorf("%s: trimProjectDir = %q, want %q", tc.name, got, tc.want)
		}
	}

	// WrapScanFailure cuts it from the text it keeps, and errors.Is still sees the original error.
	cause := errors.New(resolved + sep + "go.mod:3: unknown directive: x")
	se := WrapScanFailure(cause, nil, dir)
	if got := se.Err.Error(); got != "go.mod:3: unknown directive: x" || !errors.Is(se, cause) {
		t.Errorf("Err = %q, errors.Is = %v", got, errors.Is(se, cause))
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
