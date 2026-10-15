package scanner

import (
	"encoding/json"
	"os"
	"runtime"
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
	// GovulncheckVersion is govulncheck's scanner_version.
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
	ScannerVersion string `json:"scanner_version"`
	DB             string `json:"db"`
	DBLastModified string `json:"db_last_modified"`
}

// apply copies the config message's fields into the info.
func (i *ScanInfo) apply(raw json.RawMessage) {
	var c gvcConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return
	}
	i.GoVersion = c.GoVersion
	i.GovulncheckVersion = c.ScannerVersion
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
