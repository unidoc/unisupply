package scanner

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// FailKind says whether a failed scan is worth retrying. The zero value is FailPermanent, so a ScanError built without
// a Kind is never retried.
type FailKind int

const (
	FailPermanent FailKind = iota // examples layout, cgo-only deps, no go.mod, needs newer Go
	FailTransient                 // network, timeout, rate limit
	FailTooLarge                  // exceeded limits
)

func (k FailKind) String() string {
	switch k {
	case FailTransient:
		return "transient"
	case FailPermanent:
		return "permanent"
	case FailTooLarge:
		return "too_large"
	}
	return "unknown"
}

// The Reason codes of a ScanError. They are a contract with callers that branch on them (gorisk): a rename is a breaking
// change.
const (
	ReasonNeedsNewerGo      = "needs_newer_go"     // the project needs a newer Go than this unisupply was built with
	ReasonNoGoMod           = "no_go_mod"          // no go.mod to scan
	ReasonMultipleMains     = "multiple_mains"     // func main declared in more than one file of a package
	ReasonMixedPackages     = "mixed_packages"     // files of two different packages in one directory
	ReasonNoPackages        = "no_packages"        // the scan found no package to load
	ReasonCgoOnly           = "cgo_only"           // no package to load: cgo is off and the module's files import "C"
	ReasonMissingGoSum      = "missing_gosum"      // a go.sum entry is missing and -mod=readonly forbids adding it
	ReasonModuleFetch       = "module_fetch"       // a module download failed
	ReasonRateLimited       = "rate_limited"       // a service refused the request for rate limiting
	ReasonVulnDBUnreachable = "vulndb_unreachable" // the vulnerability database could not be fetched
	ReasonScanDeadline      = "scan_deadline"      // the scan's context deadline passed before it finished; FailTooLarge
	ReasonInternalPanic     = "internal_panic"     // a scanner panicked
	ReasonUnknown           = "unknown"            // nothing matched; FailPermanent (a caller may still retry it a bounded number of times)
)

// ScanError is a scan that failed, with the cause and whether a retry can help.
type ScanError struct {
	Kind   FailKind
	Reason string // stable code, e.g. "multiple_mains", "needs_newer_go"
	Err    error  // the underlying govulncheck/go output

	// decidingLine is the line of the failure message that the classifying rule matched, set by WrapScanFailure. It is kept
	// apart from Err, since the tail cut can drop it from there, and Summary publishes it in place of the first line.
	decidingLine string
}

func (e *ScanError) Error() string {
	if e.Err == nil {
		return e.Reason
	}
	return e.Reason + ": " + e.Err.Error()
}

func (e *ScanError) Unwrap() error { return e.Err }

// scanErrorNoise are the lines of a package-loading failure that say nothing about the cause: the wrapper's bare
// prefix, and the header of the package error list.
var scanErrorNoise = map[string]bool{
	"govulncheck:":                   true,
	"govulncheck: loading packages:": true,
	"There are errors with the provided package patterns:": true,
}

// summaryWrapper is the chain of prefixes that govulncheck and the go command put in front of a cause ("govulncheck:
// loading packages: err: exit status 1: stderr: go: go.mod requires go >= 1.27.0"), each one optional and in this order.
var summaryWrapper = regexp.MustCompile(`^(?:govulncheck: )?(?:loading packages: )?(?:err: )?(?:exit status \d+: )?(?:stderr: )?(?:go: )?`)

// summaryLine is line as a summary shows it: trimmed, without the "-: " position of a package error that has none
// ("-: found packages main (a.go) and ..."), and without the wrapper chain, so that it starts at the cause. It is empty
// for a line that says nothing about the cause.
func summaryLine(line string) string {
	line = strings.TrimPrefix(strings.TrimSpace(line), "-: ")
	if line == "" || line == "..." || scanErrorNoise[line] {
		return ""
	}
	return summaryWrapper.ReplaceAllString(line, "")
}

// Summary is Reason and one line of Err, on one line, for places that cannot show the whole tail (the grade's pending
// reason, the progress output). That line is the one that decided the Reason when WrapScanFailure remembered it: a
// package-loading failure can list an unrelated error first. Without it (a failure no rule matched, a deadline, a
// ScanError built by hand) it is the first meaningful line, which skips the blank line and the header that a
// package-loading failure starts with. Either way the wrapper in front of the cause is dropped.
func (e *ScanError) Summary() string {
	if e.Err == nil {
		return e.Reason
	}
	if line := summaryLine(e.decidingLine); line != "" {
		return e.Reason + ": " + line
	}
	for _, line := range strings.Split(e.Err.Error(), "\n") {
		if line = summaryLine(line); line != "" {
			return e.Reason + ": " + line
		}
	}
	return e.Reason
}

const (
	tailMaxBytes = 4 << 10
	tailMaxLines = 40
)

// tailError is an error cut to the tail of its text. It keeps the chain of the error it was cut from, so errors.Is and
// errors.As still see through it.
type tailError struct {
	text string
	err  error
}

func (e *tailError) Error() string { return e.text }
func (e *tailError) Unwrap() error { return e.err }

// stderrTail keeps the end of a go command's output, where its last and usually most specific message is: at most
// tailMaxLines lines and tailMaxBytes bytes, whichever is shorter, cut on a line boundary, and "...\n" in front when
// something was cut. A single line longer than the byte limit is cut at a character boundary.
func stderrTail(msg string) string {
	msg = strings.TrimSpace(msg)
	lines := strings.Split(msg, "\n")
	cut := false
	if len(lines) > tailMaxLines {
		lines, cut = lines[len(lines)-tailMaxLines:], true
	}
	for len(lines) > 1 && len(strings.Join(lines, "\n")) > tailMaxBytes {
		lines, cut = lines[1:], true
	}
	out := strings.Join(lines, "\n")
	if len(out) > tailMaxBytes {
		out, cut = out[len(out)-tailMaxBytes:], true
		for !utf8.RuneStart(out[0]) {
			out = out[1:]
		}
	}
	if cut {
		return "...\n" + out
	}
	return out
}

// scanFailureRules classify a failure message, first match wins: the permanent causes first, since a module download can
// fail with text that also names a package, and then the network ones. A rule must name the cause itself: the
// package-loading error list also carries follow-on lines ("could not import ...", "undefined: ...") for every cause.
var scanFailureRules = []struct {
	reason string
	kind   FailKind
	match  *regexp.Regexp
}{
	// "go: go.mod requires go >= 1.99 (running go 1.26.9; GOTOOLCHAIN=local)", the loader's "requires newer Go version",
	// CheckToolchain's sentence, and x/vuln's own version-mismatch text (a newline sits inside its sentence).
	{ReasonNeedsNewerGo, FailPermanent, regexp.MustCompile(`requires go >= ?\d|requires newer Go version|cannot scan code that needs go\d|mismatch between the Go version\s+used to build govulncheck`)},
	{ReasonNoGoMod, FailPermanent, regexp.MustCompile(`no go\.mod file|go\.mod file not found|no go\.mod found in|cannot find main module`)},
	{ReasonMultipleMains, FailPermanent, regexp.MustCompile(`main redeclared in this block`)},
	// "found packages main (a.go) and other (b.go) in <dir>", in either order.
	{ReasonMixedPackages, FailPermanent, regexp.MustCompile(`found packages \S+ \([^)]*\) and \S+ \(`)},
	// x/vuln's errNoPackagesMatched, which a module with no Go files gives as well as one whose files all need cgo; the
	// caller tells them apart (ReasonCgoOnly) by looking at the files, since the message cannot.
	{ReasonNoPackages, FailPermanent, regexp.MustCompile(`no packages matched the provided patterns`)},
	{ReasonMissingGoSum, FailPermanent, regexp.MustCompile(`missing go\.sum entry`)},
	// The wording of a refused request ("API rate limit exceeded", "secondary rate limit", "429 Too Many Requests"), with
	// the space: a package path or identifier that names rate limiting ("internal/ratelimit/limiter.go:12:2: undefined:
	// ...") is a build failure.
	{ReasonRateLimited, FailTransient, regexp.MustCompile(`(?i)too many requests|\brate limit(?:ed|ing)?\b|(?:status|code|http|returned)[: ]+429\b`)},
	{ReasonVulnDBUnreachable, FailTransient, regexp.MustCompile(`vuln\.go\.dev|GOVULNDB|HTTP (?:GET|POST) \S+ returned unexpected status`)},
	// A cut download ("unexpected EOF"), a TCP timeout ("read: connection timed out") and an HTTP/2 stream reset
	// ("stream error: stream ID 3; INTERNAL_ERROR") are network faults too.
	{ReasonModuleFetch, FailTransient, regexp.MustCompile(`(?i)dial tcp|i/o timeout|TLS handshake|connection reset|connection refused|connection timed out|no such host|network is unreachable|unexpected EOF|stream error: stream ID \d+|\b50[0-4] (?:bad gateway|service unavailable|gateway timeout|internal server error)`)},
}

// classifyScanFailure types the message of a failed scan. ctxErr is the scan context's error: once the context has
// ended, a timeout in the message is the scan's own limit and not a network fault, so only the permanent causes are
// matched. Past that, a context whose deadline passed is ReasonScanDeadline, and one the caller canceled is unknown: a
// cancel is the caller's own decision, not something a retry answers.
func classifyScanFailure(msg string, ctxErr error) *ScanError {
	return WrapScanFailure(errors.New(msg), ctxErr, "")
}

// WrapScanFailure types err like classifyScanFailure does its message, and keeps err as the cause: its text is cut to the
// tail, but errors.Is and errors.As still see it. A ReasonScanDeadline error also carries ctxErr, so
// errors.Is(err, context.DeadlineExceeded) holds even when err is only the scan's output text. projectDir, when not
// empty, and the module cache (see modCacheFromEnv) are cut from the text (see trimPaths), so that the published reason
// does not carry a path of the scanning machine. The line that the classifying rule matched is kept for Summary, whatever the tail cut leaves.
func WrapScanFailure(err, ctxErr error, projectDir string) *ScanError {
	msg := trimPaths(err.Error(), projectDir, modCacheFromEnv())
	for _, r := range scanFailureRules {
		if ctxErr != nil && r.kind == FailTransient {
			continue
		}
		if loc := r.match.FindStringIndex(msg); loc != nil {
			return &ScanError{Kind: r.kind, Reason: r.reason, Err: tailOf(err, msg), decidingLine: lineAt(msg, loc[0])}
		}
	}
	if errors.Is(ctxErr, context.DeadlineExceeded) {
		return &ScanError{Kind: FailTooLarge, Reason: ReasonScanDeadline, Err: &tailError{text: tailOf(err, msg).Error(), err: errors.Join(err, ctxErr)}}
	}
	return &ScanError{Kind: FailPermanent, Reason: ReasonUnknown, Err: tailOf(err, msg)}
}

// lineAt is the line of msg that contains the byte at offset i, held to tailMaxBytes like the tail of an error is: the
// summary is published, and one go error line can be arbitrarily long. An over-long line keeps its head, which has the
// position and the start of the cause, cut at a character boundary and followed by "...".
func lineAt(msg string, i int) string {
	start := strings.LastIndex(msg[:i], "\n") + 1
	end := len(msg)
	if n := strings.Index(msg[i:], "\n"); n >= 0 {
		end = i + n
	}
	line := msg[start:end]
	if len(line) <= tailMaxBytes {
		return line
	}
	cut := tailMaxBytes
	for !utf8.RuneStart(line[cut]) {
		cut--
	}
	return line[:cut] + "..."
}

// tailOf is err with its text msg (err's own text, or that text with the project directory cut) cut to the tail; an
// error with no text gets a placeholder, so that a ScanError always says something.
func tailOf(err error, msg string) error {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return &tailError{text: "no error text", err: err}
	}
	if tail := stderrTail(msg); tail != strings.TrimSpace(err.Error()) {
		return &tailError{text: tail, err: err}
	}
	return err
}

// trimPaths cuts the paths of the scanning machine out of a go command's message. The project directory: "<dir>/b.go:3:6:
// ..." becomes "b.go:3:6: ...", and "<dir>" on its own ("found packages a (a.go) and b (b.go) in <dir>") becomes ".". The
// module cache: "<cache>/github.com/x/y@v1.2.3/a.go:1:1: ..." becomes "github.com/x/y@v1.2.3/a.go:1:1: ...", so that a
// dependency reads the same on every machine; the cache on its own is left, as "." would mean the project. Escaped module
// paths ("!burnt!sushi") stay as the go command prints them. An empty dir or modCache leaves msg as it is.
func trimPaths(msg, projectDir, modCache string) string {
	msg = trimDir(msg, projectDir, true)
	return trimDir(msg, modCache, false)
}

// trimDir cuts "<dir>/" from msg, and with bare also replaces "<dir>" on its own by ".". The directory is matched absolute
// and with its symlinks resolved, since the go command reports the resolved path (/private/tmp for /tmp on macOS); a
// sibling such as "<dir>2" is left alone.
func trimDir(msg, dir string, bare bool) string {
	if dir == "" {
		return msg
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return msg
	}
	forms := []string{abs}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil && resolved != abs {
		forms = append(forms, resolved)
	}
	// The longer form first: one can contain the other ("/tmp/x" is in "/private/tmp/x").
	slices.SortFunc(forms, func(a, b string) int { return len(b) - len(a) })
	sep := string(filepath.Separator)
	for _, d := range forms {
		if d == sep || filepath.Dir(d) == d {
			continue // a volume root would cut every path
		}
		msg = strings.ReplaceAll(msg, d+sep, "")
		if bare {
			msg = regexp.MustCompile(regexp.QuoteMeta(d)+`([\s"'):,;]|$)`).ReplaceAllString(msg, ".${1}")
		}
	}
	return msg
}

// modCacheFromEnv is the module cache of this process's environment, the way the go command finds it: GOMODCACHE, else
// the first GOPATH entry's pkg/mod, else $HOME/go/pkg/mod. It does not run `go env`: WrapScanFailure runs on the failure
// path of runner.Run, which has no go environment at hand and must not start a process to describe an error. A cache that
// `go env -w` moved is not seen here; the scan, which has run `go env`, cuts that one itself. It is empty when none of
// the three is known.
func modCacheFromEnv() string {
	if d := os.Getenv("GOMODCACHE"); d != "" {
		return d
	}
	if gopath := filepath.SplitList(os.Getenv("GOPATH")); len(gopath) > 0 && gopath[0] != "" {
		return filepath.Join(gopath[0], "pkg", "mod")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, "go", "pkg", "mod")
	}
	return ""
}

// hasCgoImport reports whether a non-test Go file of the module in dir imports "C". It reads the import clauses only, and
// skips what the go command does not build with the module: testdata, vendor, hidden and underscore-prefixed
// directories, and nested modules. It stops at the first hit. A scan calls it only after a failure that could be a
// cgo-only module, never on a normal scan.
func hasCgoImport(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // an unreadable entry is skipped
		}
		name := d.Name()
		if d.IsDir() {
			if path == dir {
				return nil
			}
			if name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil && f == nil {
			return nil
		}
		for _, imp := range f.Imports {
			if p, err := strconv.Unquote(imp.Path.Value); err == nil && p == "C" {
				found = true
				return filepath.SkipAll
			}
		}
		return nil
	})
	return found
}
