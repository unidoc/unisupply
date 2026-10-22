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

// Summary is Reason and the first meaningful line of Err, on one line, for places that cannot show the whole tail (the
// grade's pending reason, the progress output). A package-loading failure starts with a blank line and a header, so the
// first line of Error() says nothing; this is the first line that does.
func (e *ScanError) Summary() string {
	if e.Err == nil {
		return e.Reason
	}
	for _, line := range strings.Split(e.Err.Error(), "\n") {
		// "-: " is the position of a package error that has none ("-: found packages main (a.go) and ...").
		line = strings.TrimPrefix(strings.TrimSpace(line), "-: ")
		if line == "" || line == "..." || scanErrorNoise[line] {
			continue
		}
		return e.Reason + ": " + line
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
// empty, is cut from the text (see trimProjectDir), so that the published reason does not carry a path of the scanning
// machine.
func WrapScanFailure(err, ctxErr error, projectDir string) *ScanError {
	msg := trimProjectDir(err.Error(), projectDir)
	for _, r := range scanFailureRules {
		if ctxErr != nil && r.kind == FailTransient {
			continue
		}
		if r.match.MatchString(msg) {
			return &ScanError{Kind: r.kind, Reason: r.reason, Err: tailOf(err, msg)}
		}
	}
	if errors.Is(ctxErr, context.DeadlineExceeded) {
		return &ScanError{Kind: FailTooLarge, Reason: ReasonScanDeadline, Err: &tailError{text: tailOf(err, msg).Error(), err: errors.Join(err, ctxErr)}}
	}
	return &ScanError{Kind: FailPermanent, Reason: ReasonUnknown, Err: tailOf(err, msg)}
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

// trimProjectDir cuts the project directory out of a go command's message: "<dir>/b.go:3:6: ..." becomes
// "b.go:3:6: ...", and "<dir>" on its own ("found packages a (a.go) and b (b.go) in <dir>") becomes ".". The directory
// is matched absolute and with its symlinks resolved, since the go command reports the resolved path (/private/tmp for
// /tmp on macOS); a sibling such as "<dir>2" is left alone. An empty dir leaves msg as it is.
func trimProjectDir(msg, dir string) string {
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
		msg = regexp.MustCompile(regexp.QuoteMeta(d)+`([\s"'):,;]|$)`).ReplaceAllString(msg, ".${1}")
	}
	return msg
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
