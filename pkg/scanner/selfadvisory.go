package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/unidoc/unisupply/pkg/offline"
)

const (
	// defaultOSVBaseURL is the OSV API root; its host is the host pin.
	defaultOSVBaseURL = "https://api.osv.dev"

	// selfAdvisoryMaxBytes caps one OSV query page. A page carries full
	// advisory records, so it is larger than the 512 KB single-record cap
	// the enricher uses.
	selfAdvisoryMaxBytes = 8 * 1024 * 1024

	// selfAdvisoryMaxPages bounds next_page_token pagination. A module with
	// more advisories than this has an answer the report cannot trust, so
	// exceeding the cap is an error, not a silent truncation.
	selfAdvisoryMaxPages = 10

	selfAdvisoryTimeout = 30 * time.Second
)

// SelfAdvisoryOptions controls ScanModuleAdvisories. The zero value queries
// api.osv.dev with the default timeout and on-disk caches.
type SelfAdvisoryOptions struct {
	// BaseURL is the OSV API root. Empty means https://api.osv.dev; tests
	// point it at an httptest server. Its host is the host pin.
	BaseURL string

	// Timeout bounds the whole lookup, all pages included. Zero falls back to 30s.
	Timeout time.Duration

	// GitHubToken and NVDAPIKey are forwarded to the severity enricher, as
	// for dependency advisories. Ignored when Enricher is set.
	GitHubToken string
	NVDAPIKey   string

	// CacheDir overrides the enricher and threat-intel cache location.
	// Intended for tests. Ignored for whichever of Enricher and ThreatIntel is set.
	CacheDir string

	// Client, Enricher and ThreatIntel override the HTTP client and the
	// shared severity and EPSS/KEV helpers. Nil builds the defaults.
	// Intended for tests.
	Client      *Client
	Enricher    *VulnEnricher
	ThreatIntel *ThreatIntelClient

	// OnWarning, if set, receives the best-effort enrichment warnings
	// (severity lookup failed, EPSS/KEV unavailable). They never fail the lookup.
	OnWarning func(string)

	// clockFn is the time source for DaysUnpatched. Defaults to time.Now.
	clockFn func() time.Time
}

// selfOSVRecord is a partial decode of one OSV advisory in a /v1/query
// response. It embeds osvResponse so the severity, published and modified
// fields resolve exactly as they do for a dependency's advisory.
type selfOSVRecord struct {
	osvResponse
	Summary   string   `json:"summary"`
	Aliases   []string `json:"aliases"`
	Withdrawn string   `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific struct {
			Imports []struct {
				Path string `json:"path"`
			} `json:"imports"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
}

// selfQueryResponse is one page of an OSV /v1/query answer.
type selfQueryResponse struct {
	Vulns         []selfOSVRecord `json:"vulns"`
	NextPageToken string          `json:"next_page_token"`
}

// ScanModuleAdvisories returns the OSV advisories that affect exactly the given
// version of module itself, as Vulnerability records on the same footing as a
// dependency's. Reachability is left empty: govulncheck does not check the
// module it starts from, so the grade assumes these advisories are called.
//
// version is required. OSV answers a versionless query with the advisories of
// every version of the module, which would grade the module on bugs it no
// longer has, so an empty or malformed version is an error before any request
// is made. Withdrawn advisories are skipped.
//
// A failed lookup is returned as an error and never as an empty list: an empty
// list means "OSV answered and nothing affects this version". Offline mode
// returns an error (wrapping offline.ErrOffline) without any network access.
// Severity, EPSS and KEV enrichment is best-effort, as for dependencies; its
// warnings go to opts.OnWarning.
func ScanModuleAdvisories(ctx context.Context, opts SelfAdvisoryOptions, module, version string) ([]Vulnerability, error) {
	if offline.Enabled() {
		return nil, fmt.Errorf("module advisory lookup skipped: %w", offline.ErrOffline)
	}
	if version == "" {
		return nil, errors.New("module advisory lookup needs a version: a versionless OSV query returns the advisories of every version")
	}
	if err := checkModuleVersion(module, version); err != nil {
		return nil, err
	}

	base := opts.BaseURL
	if base == "" {
		base = defaultOSVBaseURL
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid OSV base URL %q", base)
	}
	queryURL := strings.TrimRight(base, "/") + "/v1/query"

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = selfAdvisoryTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client := opts.Client
	if client == nil {
		client = NewClient(ClientOptions{Timeout: 10 * time.Second})
	}
	now := opts.clockFn
	if now == nil {
		now = time.Now
	}

	var (
		vulns []Vulnerability
		seen  = map[string]bool{}
		token string
	)
	for page := 0; ; page++ {
		if page >= selfAdvisoryMaxPages {
			return nil, fmt.Errorf("OSV returned more than %d pages of advisories for %s@%s", selfAdvisoryMaxPages, module, version)
		}
		resp, err := queryOSVPage(ctx, client, queryURL, u.Host, module, version, token)
		if err != nil {
			return nil, err
		}
		for i := range resp.Vulns {
			rec := &resp.Vulns[i]
			if rec.Withdrawn != "" || rec.ID == "" || seen[rec.ID] {
				continue
			}
			seen[rec.ID] = true
			vulns = append(vulns, selfVulnFromOSV(rec, module, version, now))
		}
		token = resp.NextPageToken
		if token == "" {
			break
		}
	}
	sort.Slice(vulns, func(i, j int) bool { return vulns[i].ID < vulns[j].ID })

	enrichSelfAdvisories(ctx, opts, module, vulns)
	return vulns, nil
}

// checkModuleVersion rejects a module path or version no query should be sent
// for.
func checkModuleVersion(path, version string) error {
	if err := module.CheckPath(path); err != nil {
		return fmt.Errorf("invalid module path %q: %w", path, err)
	}
	if !semver.IsValid(version) {
		return fmt.Errorf("invalid module version %q", version)
	}
	return nil
}

// queryOSVPage posts one /v1/query request and decodes the answer. Any
// transport failure, non-200 status or unparseable body is an error.
func queryOSVPage(ctx context.Context, client *Client, queryURL, host, modulePath, version, pageToken string) (*selfQueryResponse, error) {
	req := map[string]any{
		"version": version,
		"package": map[string]string{"name": modulePath, "ecosystem": "Go"},
	}
	if pageToken != "" {
		req["page_token"] = pageToken
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	body, resp, err := client.Post(ctx, queryURL, "application/json", bytes.NewReader(payload), GetOptions{
		Host:     host,
		MaxBytes: selfAdvisoryMaxBytes,
		Accept:   "application/json",
		Purpose:  "selfadvisory:osv",
	})
	if err != nil {
		return nil, fmt.Errorf("OSV query for %s@%s: %w", modulePath, version, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV query for %s@%s returned HTTP %d", modulePath, version, resp.StatusCode)
	}
	var out selfQueryResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("OSV query for %s@%s: parsing response: %w", modulePath, version, err)
	}
	return &out, nil
}

// selfVulnFromOSV maps one OSV record to a Vulnerability for modulePath.
func selfVulnFromOSV(rec *selfOSVRecord, modulePath, version string, now func() time.Time) Vulnerability {
	v := Vulnerability{
		ID:       rec.ID,
		Aliases:  rec.Aliases,
		Summary:  rec.Summary,
		Severity: "UNKNOWN",
	}
	if tier := rec.severityTier(); tier != "" {
		v.Severity = tier
		v.SeveritySource = "osv"
	}
	if rec.Published != "" {
		if t, err := time.Parse(time.RFC3339, rec.Published); err == nil {
			v.PublishedAt = &t
		}
	}

	// Affected entries for this module only: a record can name other modules
	// (forks, or the stdlib) that must not leak their fixes or packages here.
	var fixes []string
	pkgs := map[string]bool{}
	for _, aff := range rec.Affected {
		if aff.Package.Name != modulePath || !strings.EqualFold(aff.Package.Ecosystem, "Go") {
			continue
		}
		for _, imp := range aff.EcosystemSpecific.Imports {
			if imp.Path != "" {
				pkgs[imp.Path] = true
			}
		}
		for _, r := range aff.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			for _, e := range r.Events {
				if f := canonicalVersion(e.Fixed); f != "" {
					fixes = append(fixes, f)
				}
			}
		}
	}
	v.AffectedPackages = slices.Sorted(func(yield func(string) bool) {
		for p := range pkgs {
			if !yield(p) {
				return
			}
		}
	})
	v.FixedVersion = firstFixAfter(fixes, version)

	// As for a dependency (applyEnrichResult): the advisory's publication
	// date stands in for the fix date, and DaysUnpatched counts from it.
	if v.FixedVersion != "" && v.PublishedAt != nil {
		v.FixPublishedAt = v.PublishedAt
		days := int(now().Sub(*v.PublishedAt).Hours() / 24)
		if days < 0 {
			days = 0
		}
		v.DaysUnpatched = days
	}
	return v
}

// canonicalVersion returns v in the "v1.2.3" form, or "" when it is not a
// semantic version. OSV's Go database writes versions without the "v";
// govulncheck's FixedVersion carries it.
func canonicalVersion(v string) string {
	if v == "" || v == "0" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return ""
	}
	return v
}

// firstFixAfter returns the lowest of fixes that is above version: the
// fix that applies to the queried version, when a module has several
// affected ranges. Empty when no fix lies above it.
func firstFixAfter(fixes []string, version string) string {
	best := ""
	for _, f := range fixes {
		if semver.Compare(f, version) <= 0 {
			continue
		}
		if best == "" || semver.Compare(f, best) < 0 {
			best = f
		}
	}
	return best
}

// enrichSelfAdvisories applies the dependency path's severity and EPSS/KEV
// enrichment to vulns in place. Both are best-effort: a failure leaves the
// documented unknown state on the record and a warning for the caller.
func enrichSelfAdvisories(ctx context.Context, opts SelfAdvisoryOptions, modulePath string, vulns []Vulnerability) {
	if len(vulns) == 0 {
		return
	}
	warn := opts.OnWarning
	if warn == nil {
		warn = func(string) {}
	}

	enricher := opts.Enricher
	if enricher == nil {
		enricher = NewVulnEnricher(VulnEnricherOptions{GitHubToken: opts.GitHubToken, NVDAPIKey: opts.NVDAPIKey, CacheDir: opts.CacheDir})
	}
	var sevWarns []string
	for i := range vulns {
		if vulns[i].Severity == "UNKNOWN" {
			sevWarns = append(sevWarns, enricher.Enrich(ctx, &vulns[i])...)
		}
	}
	for _, w := range collapseSeverityLookupWarnings(sevWarns) {
		warn(w)
	}

	ti := opts.ThreatIntel
	if ti == nil {
		ti = NewThreatIntelClient(ThreatIntelOptions{CacheDir: opts.CacheDir})
	}
	byModule := map[string][]Vulnerability{modulePath: vulns}
	for _, w := range enrichThreatIntel(ctx, ti, byModule) {
		warn(w)
	}
}
