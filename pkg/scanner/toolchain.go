package scanner

import (
	"fmt"
	"go/version"
	"regexp"
	"runtime"
	"strings"
)

// builtWithGo is the Go release this unisupply was built with; a variable so tests can pretend otherwise.
var builtWithGo = runtime.Version

// CheckToolchain reports whether this binary can scan code that needs the Go release scanGo ("go1.27.2", "1.27.2",
// "go1.27", "go1.27rc1"). govulncheck runs inside unisupply, compiled with unisupply's own Go, and the Go loader refuses
// code that needs a newer one with a confusing "file requires newer Go version" error. CheckToolchain turns that into a
// clear one: nil when scanGo is not newer than the Go that built unisupply, or when either version cannot be read (the
// scan is then left to try). A caller such as gorisk can call it at startup with the Go release the scan will use.
func CheckToolchain(scanGo string) error {
	return checkToolchain(builtWithGo(), scanGo)
}

func checkToolchain(built, scanGo string) error {
	b, s := normalizeGoRelease(built), normalizeGoRelease(scanGo)
	if !version.IsValid(b) || !version.IsValid(s) || version.Compare(s, b) <= 0 {
		return nil
	}
	return toolchainMismatch(b, s)
}

func toolchainMismatch(built, need string) error {
	return fmt.Errorf("this unisupply was built with %s and cannot scan code that needs %s; rebuild unisupply with %s or newer", built, need, need)
}

// normalizeGoRelease gives "go1.27.2" for "1.27.2", "go1.27.2 X:nocoverageredesign" and "go1.27.2"; anything else comes
// back unchanged (and is then not a valid version).
func normalizeGoRelease(v string) string {
	f := strings.Fields(v)
	if len(f) == 0 {
		return ""
	}
	v = f[0]
	if !strings.HasPrefix(v, "go") {
		v = "go" + strings.TrimPrefix(v, "v")
	}
	return v
}

var newerGoPattern = regexp.MustCompile(`requires newer Go version (go\d[0-9A-Za-z.]*)`)

// toolchainErrorFrom turns the loader's "file requires newer Go version go1.27 (application built with go1.26)" into the
// CheckToolchain sentence; nil when msg is not that error.
func toolchainErrorFrom(msg string) error {
	m := newerGoPattern.FindStringSubmatch(msg)
	if m == nil {
		return nil
	}
	return toolchainMismatch(normalizeGoRelease(builtWithGo()), m[1])
}
