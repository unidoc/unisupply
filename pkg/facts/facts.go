// Package facts is where unisupply reads what is known about a module or an advisory that is not in the code being
// scanned: whether a module is archived or deprecated, when it last released or committed, when a fix was released, and
// what an advisory's severity is. Those facts change on their own schedule (archived status daily, fix dates and severities
// rarely, advisories when the vulnerability database changes), and the same module is a dependency of many scans, so they
// are looked up once and shared.
//
// Store is the interface. unisupply reads through it (a fresh fact is used instead of a lookup, and a lookup that had to
// be made is written back); gorisk plugs a shared, Postgres-backed implementation into it, and Memory is the small
// in-process one. A nil Store, and None, mean "no store": every fact is looked up, which is what the command-line tool does,
// with the per-request disk caches the scanners keep for the module proxy, GitHub, OSV and the CISA catalog underneath.
//
// # Where the facts come from
//
// Severities are read from OSV first (then NVD, then GitHub's advisory database) by scanner.VulnEnricher, and a module's
// release and branch activity from the module proxy, with GitHub's commits API only as a fallback when a token is set.
// What still needs GitHub is the archived flag of a repository, the default branch's name (the proxy is asked for "main"
// and "master" without it) and the maintainer analysis (contributors), which the grade does not use.
//
// TODO(engine-v2): read the archived flag from deps.dev / OpenSSF Scorecard before calling GitHub. Checked against the live
// API on 2026-10-21 and not done, because it is not a drop-in: https://api.deps.dev/v3/projects/github.com%2Fowner%2Frepo
// returns stars, forks, licence and one Scorecard run, but no archived flag. Scorecard's "Maintained" check does say
// "project is archived" in its free-text reason (read for github.com/golang/dep), and "0 commit(s) and 0 issue activity ..."
// for a quiet repository (github.com/gorilla/context). But the run read was dated 2026-08-24, two months old, so a repository
// archived since would read as not archived, which is the unproven "not archived" the grade refuses to publish (see
// grade.Upkeep.ArchivedUnread). Doing it properly needs the snapshot's age checked against the module's release dates, a
// new host (api.deps.dev) in the network contract, and a decision on a stale answer.
package facts

import (
	"context"
	"time"

	"github.com/unidoc/unisupply/pkg/scanner"
)

// Module is what is known about one module version's upkeep: the maintenance scanner's own record (archived, deprecated and
// retracted status, last release, last default-branch activity, and the flags that say what could not be read).
type Module struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	// Info is the record as the scanner produced it. Its month counts are those of the day it was read; a reader calls
	// Info.AgeAt with its own date.
	Info scanner.MaintenanceInfo `json:"info"`
	// FetchedAt is when the facts were read from their sources; Source names where from ("module_proxy+github", ...).
	FetchedAt time.Time `json:"fetched_at"`
	Source    string    `json:"source,omitempty"`
}

// Advisory is what is known about one advisory, by its ID (the Go advisory ID, GO-2026-0001).
type Advisory struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
	// Severity is CRITICAL, HIGH, MEDIUM or LOW; empty when nobody has published one (it is then an unknown severity, not a
	// low one). SeveritySource says who published it ("osv", "nvd", "ghsa") and is "unscored" when every source answered
	// and none had one.
	Severity       string     `json:"severity,omitempty"`
	SeveritySource string     `json:"severity_source,omitempty"`
	PublishedAt    *time.Time `json:"published_at,omitempty"`
	// KEVChecked is true when the CISA catalog was consulted for the advisory's CVE, InKEV that it is listed, and
	// KEVDateAdded when it was added. InKEV with KEVChecked false means nothing.
	KEVChecked   bool      `json:"kev_checked,omitempty"`
	InKEV        bool      `json:"in_kev,omitempty"`
	KEVDateAdded string    `json:"kev_date_added,omitempty"`
	FetchedAt    time.Time `json:"fetched_at"`
}

// Fix is when the first fixed version of an advisory's module was released. A released version never changes, so a known
// release time is kept for a long time; an unknown one is not stored.
type Fix struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	// ReleasedAt is the later of the advisory's publication and the time the module proxy gives the version, as
	// scanner.Vulnerability.FixReleasedAt, and Source how it was decided ("module_proxy" or "advisory").
	ReleasedAt time.Time `json:"released_at"`
	Source     string    `json:"source,omitempty"`
	// RequiresGo is the go directive of the fixed version's go.mod ("1.26"); empty when it was not read.
	RequiresGo string    `json:"requires_go,omitempty"`
	FetchedAt  time.Time `json:"fetched_at"`
}

// Store reads and writes facts. Every Get returns (nil, false, nil) for a fact it does not have, and an error only when the
// store itself failed: unisupply treats an error as a miss and goes on, so a store outage costs lookups, never a scan.
// An implementation must be safe for concurrent use. It keeps what it is given and applies no expiry of its own: the
// reader decides what is fresh enough (see Policy), because the answer differs by fact and by caller.
type Store interface {
	GetModule(ctx context.Context, path, version string) (*Module, bool, error)
	PutModule(ctx context.Context, m *Module) error

	GetAdvisory(ctx context.Context, id string) (*Advisory, bool, error)
	PutAdvisory(ctx context.Context, a *Advisory) error

	GetFix(ctx context.Context, module, version string) (*Fix, bool, error)
	PutFix(ctx context.Context, f *Fix) error
}

// Policy is how old a fact may be, by kind, before it is looked up again. The ages are measured to the date of the
// grade, not to the wall clock, so a re-grade of a given day gives the same answer whenever it runs.
type Policy struct {
	Module   time.Duration
	Advisory time.Duration
	Fix      time.Duration
}

// DefaultPolicy follows the proposal: status and activity daily, advisories (severity, known-exploited status) daily until
// a shared store refreshes them when the vulnerability database index changes, fix dates for a month.
var DefaultPolicy = Policy{Module: 24 * time.Hour, Advisory: 24 * time.Hour, Fix: 30 * 24 * time.Hour}

// Fresh reports whether a fact read at fetchedAt may still be used on date. A fact from after date (a store shared with a
// later grade) is fresh: it is newer than anything the date could ask for.
func Fresh(fetchedAt, date time.Time, maxAge time.Duration) bool {
	if fetchedAt.IsZero() {
		return false
	}
	return date.Sub(fetchedAt) <= maxAge
}

// None is the Store with nothing in it: every Get misses and every Put is dropped.
var None Store = none{}

type none struct{}

func (none) GetModule(context.Context, string, string) (*Module, bool, error) { return nil, false, nil }
func (none) PutModule(context.Context, *Module) error                         { return nil }
func (none) GetAdvisory(context.Context, string) (*Advisory, bool, error)     { return nil, false, nil }
func (none) PutAdvisory(context.Context, *Advisory) error                     { return nil }
func (none) GetFix(context.Context, string, string) (*Fix, bool, error)       { return nil, false, nil }
func (none) PutFix(context.Context, *Fix) error                               { return nil }
