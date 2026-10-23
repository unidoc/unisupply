// Package vulndb reads the Go vulnerability database's module index, so a caller can tell which modules' advisories
// changed without scanning anything. gorisk uses it to decide which stored analyses need to be redone: only the build lists
// that contain a changed module.
//
// The index is https://vuln.go.dev/index/modules.json.gz: a gzip-compressed JSON array with one object per affected module
// path ({"path": "golang.org/x/net", "vulns": [{"id": "GO-2026-0001", "modified": "2026-06-25T22:34:34Z", "fixed": "0.17.0"}]}).
// "stdlib" and "toolchain" are paths like any other. An advisory that affects a module in several version ranges is listed
// once per range, so an ID can repeat. "modified" is the time the advisory's record last changed (a new affected range, a
// corrected severity, a withdrawal); "fixed" is the first fixed version of that range and is absent when there is none. The
// whole database's last-modified time is https://vuln.go.dev/index/db.json ({"modified": "2026-10-21T00:27:29Z"}); the files
// are served with Cache-Control max-age=3600. Both were read from the live service when this package was written.
package vulndb

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/unidoc/unisupply/pkg/scanner"
)

// BaseURL is the vulnerability database.
const BaseURL = "https://vuln.go.dev"

// Paths of the two index files under the base URL.
const (
	ModulesIndexPath = "/index/modules.json.gz"
	DBIndexPath      = "/index/db.json"
)

// maxIndexBytes bounds what is read of either file. The module index is about 65 KB compressed today; this leaves room for
// many years of growth and still stops a wrong or hostile answer.
const maxIndexBytes = 32 << 20

// Entry is one advisory of one module as the index lists it.
type Entry struct {
	ID       string    `json:"id"`
	Modified time.Time `json:"modified"`
	// Fixed is the first fixed version of the range this entry stands for; empty when there is none.
	Fixed string `json:"fixed,omitempty"`
}

// Index is the module index: advisories by module path.
type Index struct {
	Modules map[string][]Entry `json:"modules"`
	// DBModified is the database's own last-modified time (index/db.json); zero when it was not read.
	DBModified time.Time `json:"db_modified,omitempty"`
}

// Client reads the index. The zero value reads the live service.
type Client struct {
	// BaseURL overrides the database URL (tests, a mirror). Empty means BaseURL.
	BaseURL string
	// HTTP is the hardened client to use; nil builds one with Timeout (default 30 seconds).
	HTTP    *scanner.Client
	Timeout time.Duration
}

func (c *Client) base() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return BaseURL
}

func (c *Client) get(ctx context.Context, path, purpose string) ([]byte, error) {
	cl := c.HTTP
	if cl == nil {
		t := c.Timeout
		if t == 0 {
			t = 30 * time.Second
		}
		cl = scanner.NewClient(scanner.ClientOptions{Timeout: t})
	}
	u, err := url.Parse(c.base() + path)
	if err != nil {
		return nil, err
	}
	body, resp, err := cl.Get(ctx, u.String(), scanner.GetOptions{Host: u.Host, MaxBytes: maxIndexBytes, Purpose: purpose})
	if err != nil {
		return nil, fmt.Errorf("vulndb: %s: %w", path, err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("vulndb: %s: HTTP %d", path, resp.StatusCode)
	}
	return body, nil
}

// DBModified reads index/db.json: when the database as a whole last changed. It is one tiny request, the cheap way to find
// out that nothing changed since the last look.
func (c *Client) DBModified(ctx context.Context) (time.Time, error) {
	body, err := c.get(ctx, DBIndexPath, "vulndb:db.json")
	if err != nil {
		return time.Time{}, err
	}
	var db struct {
		Modified time.Time `json:"modified"`
	}
	if err := json.Unmarshal(body, &db); err != nil {
		return time.Time{}, fmt.Errorf("vulndb: decoding db.json: %w", err)
	}
	if db.Modified.IsZero() {
		return time.Time{}, errors.New("vulndb: db.json has no modified time")
	}
	return db.Modified, nil
}

// FetchIndex reads index/modules.json.gz and index/db.json.
func (c *Client) FetchIndex(ctx context.Context) (*Index, error) {
	idx, err := c.fetchModules(ctx)
	if err != nil {
		return nil, err
	}
	// best effort: the module list is the index, db.json only dates it
	if t, err := c.DBModified(ctx); err == nil {
		idx.DBModified = t
	}
	return idx, nil
}

func (c *Client) fetchModules(ctx context.Context) (*Index, error) {
	body, err := c.get(ctx, ModulesIndexPath, "vulndb:modules.json.gz")
	if err != nil {
		return nil, err
	}
	return ParseIndex(body)
}

// ParseIndex decodes the module index. The file is gzip-compressed, but a server that already decompressed it (a mirror, a
// proxy) is accepted: the gzip magic number decides.
func ParseIndex(data []byte) (*Index, error) {
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("vulndb: modules index: %w", err)
		}
		data, err = io.ReadAll(io.LimitReader(zr, maxIndexBytes))
		if err != nil {
			return nil, fmt.Errorf("vulndb: modules index: %w", err)
		}
	}
	var list []struct {
		Path  string  `json:"path"`
		Vulns []Entry `json:"vulns"`
	}
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("vulndb: decoding modules index: %w", err)
	}
	idx := &Index{Modules: make(map[string][]Entry, len(list))}
	for _, m := range list {
		if m.Path == "" {
			continue
		}
		idx.Modules[m.Path] = append(idx.Modules[m.Path], m.Vulns...)
	}
	return idx, nil
}

// ChangedSince returns, sorted, the module paths that have an advisory modified after t. A new advisory, a changed one and a
// withdrawn one (a withdrawal is a modification) all count. An advisory that was removed from the index altogether leaves no
// trace in a timestamp: compare Fingerprints for that.
func (i *Index) ChangedSince(t time.Time) []string {
	var out []string
	for path, entries := range i.Modules {
		for _, e := range entries {
			if e.Modified.After(t) {
				out = append(out, path)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// Fingerprint identifies the advisory data of the given module paths: a hash of every (module, advisory ID, modified time,
// fixed version) the index lists for them, so it changes when an advisory is added, changed or removed for any of them, and
// only then. The order and duplicates of modules do not matter. Modules with no advisory contribute nothing, so adding one
// to a build list does not change the fingerprint until it has an advisory. The empty fingerprint is for "not computed".
func (i *Index) Fingerprint(modules []string) string {
	mods := slices.Clone(modules)
	sort.Strings(mods)
	mods = slices.Compact(mods)
	h := sha256.New()
	for _, m := range mods {
		entries := slices.Clone(i.Modules[m])
		if len(entries) == 0 {
			continue
		}
		slices.SortFunc(entries, func(a, b Entry) int {
			if c := strings.Compare(a.ID, b.ID); c != 0 {
				return c
			}
			if c := a.Modified.Compare(b.Modified); c != 0 {
				return c
			}
			return strings.Compare(a.Fixed, b.Fixed)
		})
		entries = slices.Compact(entries)
		fmt.Fprintf(h, "%s\n", m)
		for _, e := range entries {
			fmt.Fprintf(h, " %s %s %s\n", e.ID, e.Modified.UTC().Format(time.RFC3339), e.Fixed)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Change is a module whose advisories changed, with what changed.
type Change struct {
	Module string `json:"module"`
	// IDs are the advisories modified after the timestamp, sorted, without duplicates.
	IDs []string `json:"ids"`
}

func (i *Index) dbModified() time.Time {
	if i == nil {
		return time.Time{}
	}
	return i.DBModified
}

// ChangesSince is ChangedSince with the advisory IDs, for a caller that wants to say why a module is re-analysed.
func (i *Index) ChangesSince(t time.Time) []Change {
	var out []Change
	for _, path := range i.ChangedSince(t) {
		var ids []string
		for _, e := range i.Modules[path] {
			if e.Modified.After(t) {
				ids = append(ids, e.ID)
			}
		}
		sort.Strings(ids)
		out = append(out, Change{Module: path, IDs: slices.Compact(ids)})
	}
	return out
}

// ChangedModules fetches the index and returns the modules whose advisories changed after since, the database's own
// last-modified time (zero when it could not be read) and the fetched index, which the caller can keep to compute
// fingerprints without a second request. It first reads db.json, and when the database has not changed since the
// timestamp it returns without fetching the index: the result is then empty and Index is nil.
func (c *Client) ChangedModules(ctx context.Context, since time.Time) (changes []Change, dbModified time.Time, idx *Index, err error) {
	if m, err := c.DBModified(ctx); err == nil {
		if !m.After(since) {
			return nil, m, nil, nil
		}
		dbModified = m
	}
	if dbModified.IsZero() {
		idx, err = c.FetchIndex(ctx)
		dbModified = idx.dbModified()
	} else {
		idx, err = c.fetchModules(ctx)
		if idx != nil {
			idx.DBModified = dbModified
		}
	}
	if err != nil {
		return nil, dbModified, nil, err
	}
	return idx.ChangesSince(since), dbModified, idx, nil
}
