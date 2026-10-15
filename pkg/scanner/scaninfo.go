package scanner

import (
	"encoding/json"
	"os"
	"runtime"
	"runtime/debug"
	"time"
)

// ScanInfo says what a vulnerability scan was run with, so a result can state
// the platform, the tool and database versions behind it. Every field may be
// empty: govulncheck output from before the config message carries no tool or
// database fields.
type ScanInfo struct {
	// Platform is "goos/goarch" of the scan: GOOS and GOARCH from the
	// environment when set, else those of the running binary.
	Platform string `json:"platform,omitempty"`
	// GoVersion is the Go release govulncheck analysed with ("go1.26.9").
	GoVersion string `json:"go_version,omitempty"`
	// GovulncheckVersion is the version of golang.org/x/vuln linked into this binary (govulncheck runs in-process), read
	// from the build info. Empty when the build info does not list it. It is NOT govulncheck's own scanner_version: that
	// is the version of the binary that embeds it, which is unisupply.
	GovulncheckVersion string `json:"govulncheck_version,omitempty"`
	// VulnDB is the vulnerability database govulncheck read (its URL).
	VulnDB string `json:"vuln_db,omitempty"`
	// VulnDBLastModified is the database's last-modified time as govulncheck
	// reported it (RFC 3339).
	VulnDBLastModified string `json:"vuln_db_last_modified,omitempty"`
	// KEVStaleSince is set when the CISA KEV catalog could not be refreshed
	// and the copy from this date was used.
	KEVStaleSince *time.Time `json:"kev_stale_since,omitempty"`
}

// gvcConfig is govulncheck's leading {"config": {...}} message.
type gvcConfig struct {
	GoVersion      string `json:"go_version"`
	DB             string `json:"db"`
	DBLastModified string `json:"db_last_modified"`
}

// vulnModulePath is the module that provides govulncheck.
const vulnModulePath = "golang.org/x/vuln"

// readBuildInfo is replaced in tests.
var readBuildInfo = debug.ReadBuildInfo

// govulncheckVersion is the version of golang.org/x/vuln in the build info's dependencies ("" when absent or unknown). A
// replacement with a version counts; a replacement by a local directory has none. It never falls back to the main
// module's version, which is unisupply's own.
func govulncheckVersion(read func() (*debug.BuildInfo, bool)) string {
	bi, ok := read()
	if !ok || bi == nil {
		return ""
	}
	for _, d := range bi.Deps {
		if d == nil || d.Path != vulnModulePath {
			continue
		}
		if d.Replace != nil {
			return d.Replace.Version
		}
		return d.Version
	}
	return ""
}

// apply copies the config message's fields into the info.
func (i *ScanInfo) apply(raw json.RawMessage) {
	var c gvcConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return
	}
	i.GoVersion = c.GoVersion
	i.VulnDB = c.DB
	i.VulnDBLastModified = c.DBLastModified
}

// scanPlatform is "goos/goarch" for the scan.
func scanPlatform() string {
	goos, goarch := os.Getenv("GOOS"), os.Getenv("GOARCH")
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	return goos + "/" + goarch
}
