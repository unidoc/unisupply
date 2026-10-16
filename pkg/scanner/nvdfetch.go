package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// nvdPacer spaces requests to services.nvd.nist.gov. NVD allows 5 requests per
// rolling 30 s without a key and 50 with one; a scan of a vulnerability-heavy
// module sends one NVD request per unscored advisory, and without pacing most
// of them were answered 429/403 and graded as failed lookups.
//
// The pacer is shared by the whole process (processNVDPacer), so several
// enrichers running at once still respect one limit. The clock and the sleep
// are fields so tests can run it without waiting.
type nvdPacer struct {
	mu    sync.Mutex
	next  time.Time // earliest start of the next request
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

func newNVDPacer(now func() time.Time, sleep func(context.Context, time.Duration) error) *nvdPacer {
	if now == nil {
		now = time.Now
	}
	if sleep == nil {
		sleep = sleepCtx
	}
	return &nvdPacer{now: now, sleep: sleep}
}

// processNVDPacer is the process-wide pacer used unless an enricher is given
// its own.
var processNVDPacer = newNVDPacer(nil, nil)

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// wait blocks until a request may start, then reserves spacing for the one
// after it. ok is false, with nothing reserved and no sleep, when the start
// would fall after deadline (a zero deadline means none) or ctx ended.
func (p *nvdPacer) wait(ctx context.Context, spacing time.Duration, deadline time.Time) (ok bool) {
	p.mu.Lock()
	t := p.now()
	start := t
	if p.next.After(start) {
		start = p.next
	}
	if !deadline.IsZero() && start.After(deadline) {
		p.mu.Unlock()
		return false
	}
	p.next = start.Add(spacing)
	p.mu.Unlock()
	return p.sleep(ctx, start.Sub(t)) == nil
}

// delayUntil postpones the next request to at least t. A 429 or a Retry-After
// applies to every request in the process, not just the one that was refused.
func (p *nvdPacer) delayUntil(t time.Time) {
	p.mu.Lock()
	if t.After(p.next) {
		p.next = t
	}
	p.mu.Unlock()
}

// nvdFailure describes why an NVD lookup failed after its retries.
type nvdFailure struct {
	// rateLimited is true for HTTP 429/403 and for lookups skipped because
	// the pacing budget ran out: in both cases an NVD API key helps.
	rateLimited bool
	reason      string
}

// enrichDeadline returns the instant the enricher's pacing budget ends,
// starting the clock on first use.
func (e *VulnEnricher) enrichDeadline() time.Time {
	e.deadlineMu.Lock()
	defer e.deadlineMu.Unlock()
	if e.deadline.IsZero() {
		e.deadline = e.pacer.now().Add(e.budget)
	}
	return e.deadline
}

// parseRetryAfter reads a Retry-After header: delay in seconds or an HTTP
// date. The result is capped at nvdRetryAfterCap; ok is false when the header
// is absent or unparsable.
func parseRetryAfter(h string, now time.Time) (time.Duration, bool) {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0, false
	}
	var d time.Duration
	if secs, err := strconv.Atoi(h); err == nil {
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(h); err == nil {
		d = t.Sub(now)
	} else {
		return 0, false
	}
	if d < 0 {
		d = 0
	}
	return min(d, nvdRetryAfterCap), true
}

// nvdCVSSMetric is one entry in the NVD CVE metrics arrays. NVD lists the
// metric of its own analysts (source nvd@nist.gov, type Primary) and those of
// CNAs such as security@golang.org (type Secondary). A fresh record is often
// "Awaiting Analysis" and carries only the Secondary one.
type nvdCVSSMetric struct {
	Source   string `json:"source"`
	Type     string `json:"type"`
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

// tier returns the severity tier of the metric, "" when it carries none.
func (m nvdCVSSMetric) tier() string {
	if m.CVSSData.BaseScore > 0 {
		return cvssScoreToTier(m.CVSSData.BaseScore)
	}
	return cvssStringToTier(m.CVSSData.BaseSeverity)
}

// nvdMetrics holds the CVSS metric lists of an NVD CVE record.
type nvdMetrics struct {
	CVSSV31 []nvdCVSSMetric `json:"cvssMetricV31"`
	CVSSV30 []nvdCVSSMetric `json:"cvssMetricV30"`
	CVSSV40 []nvdCVSSMetric `json:"cvssMetricV40"`
}

// nvdResponse is a partial decode of the NVD CVE 2.0 API response.
type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			Published string     `json:"published"`
			Metrics   nvdMetrics `json:"metrics"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// severityTier picks the tier from every v3.1, v3.0 and v4.0 metric, whoever
// published it: Primary before Secondary, then v3.1 before v3.0 before v4.0,
// then list order. A metric without a usable score is skipped.
func (m nvdMetrics) pick() string {
	for _, wantPrimary := range []bool{true, false} {
		for _, list := range [][]nvdCVSSMetric{m.CVSSV31, m.CVSSV30, m.CVSSV40} {
			for _, c := range list {
				if strings.EqualFold(c.Type, "Primary") != wantPrimary {
					continue
				}
				if t := c.tier(); t != "" {
					return t
				}
			}
		}
	}
	return ""
}

// fetchNVD queries https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id>
// and returns an enrichResult. It returns (nil, failure, warnings) when the
// lookup failed, (&enrichResult{}, nil, nil) when NVD has no data for the CVE.
//
// Requests are paced by the enricher's pacer. A 429, 403, 5xx or transport
// error is retried up to nvdMaxRetries times, honouring Retry-After (capped)
// and otherwise backing off; waiting never passes the enricher's budget.
// Only the final outcome yields a warning.
func (e *VulnEnricher) fetchNVD(ctx context.Context, cveID string) (result *enrichResult, failure *nvdFailure, warnings []string) {
	url := "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cveID
	deadline := e.enrichDeadline()

	for attempt := 0; ; attempt++ {
		getOpts := GetOptions{
			Host:     nvdHost,
			MaxBytes: enrichMaxBytes,
			Accept:   "application/json",
			Purpose:  "vulnenrich:nvd",
		}
		useKey := e.opts.NVDAPIKey != "" && !e.nvdKeyRejected.Load()
		if useKey && !validHeaderValue(e.opts.NVDAPIKey) {
			// net/http would refuse the request before sending it, failing
			// every NVD lookup in the scan.
			useKey = false
			if e.nvdKeyRejected.CompareAndSwap(false, true) {
				warnings = append(warnings, "vuln enrichment: NVD API key contains characters not allowed in an HTTP header; continuing unauthenticated")
			}
		}
		spacing := nvdSpacingKeyless
		if useKey {
			getOpts.APIKeyHeader = "apiKey"
			getOpts.APIKey = e.opts.NVDAPIKey
			spacing = nvdSpacingKeyed
		}

		if !e.pacer.wait(ctx, spacing, deadline) {
			if ctx.Err() != nil {
				return nil, &nvdFailure{reason: "NVD lookup cancelled"}, append(warnings, fmt.Sprintf("vuln enrichment: NVD fetch error for %s: %v", cveID, ctx.Err()))
			}
			reason := fmt.Sprintf("NVD rate limit: lookup budget of %s used up", e.budget)
			return nil, &nvdFailure{rateLimited: true, reason: reason},
				append(warnings, fmt.Sprintf("vuln enrichment: NVD lookup for %s skipped: %s", cveID, reason))
		}

		body, resp, err := e.client.Get(ctx, url, getOpts)

		var (
			fail       *nvdFailure
			retryAfter time.Duration
			haveRA     bool
			finalWarn  string
		)
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return nil, &nvdFailure{reason: "NVD lookup cancelled"}, append(warnings, fmt.Sprintf("vuln enrichment: NVD fetch error for %s: %v", cveID, err))
			}
			fail = &nvdFailure{reason: "NVD network error"}
			finalWarn = fmt.Sprintf("vuln enrichment: NVD fetch error for %s: %v", cveID, err)
		case useKey && nvdRejectsKey(resp):
			// A bad key must not cost more than no key: retry this request
			// unauthenticated, and send no key for the rest of the scan.
			if e.nvdKeyRejected.CompareAndSwap(false, true) {
				warnings = append(warnings, fmt.Sprintf("vuln enrichment: NVD rejected the API key (HTTP %d); continuing unauthenticated", resp.StatusCode))
			}
			attempt-- // not a failed attempt; the key is dropped, so this cannot loop
			continue
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden:
			fail = &nvdFailure{rateLimited: true, reason: fmt.Sprintf("NVD rate limited (HTTP %d)", resp.StatusCode)}
			finalWarn = fmt.Sprintf("vuln enrichment: NVD returned HTTP %d for %s", resp.StatusCode, cveID)
			retryAfter, haveRA = parseRetryAfter(resp.Header.Get("Retry-After"), e.pacer.now())
		case resp.StatusCode >= 500:
			fail = &nvdFailure{reason: fmt.Sprintf("NVD HTTP %d", resp.StatusCode)}
			finalWarn = fmt.Sprintf("vuln enrichment: NVD returned HTTP %d for %s", resp.StatusCode, cveID)
			retryAfter, haveRA = parseRetryAfter(resp.Header.Get("Retry-After"), e.pacer.now())
		case resp.StatusCode != 200:
			return nil, &nvdFailure{reason: fmt.Sprintf("NVD HTTP %d", resp.StatusCode)},
				append(warnings, fmt.Sprintf("vuln enrichment: NVD returned HTTP %d for %s", resp.StatusCode, cveID))
		default:
			return e.parseNVD(body, cveID, warnings)
		}

		if attempt >= nvdMaxRetries {
			return nil, fail, append(warnings, finalWarn)
		}
		wait := nvdBackoffBase << attempt
		if haveRA {
			wait = retryAfter
		}
		wait = min(wait, nvdRetryAfterCap)
		e.pacer.delayUntil(e.pacer.now().Add(wait))
	}
}

// parseNVD decodes a 200 NVD answer.
func (e *VulnEnricher) parseNVD(body []byte, cveID string, warnings []string) (*enrichResult, *nvdFailure, []string) {
	var nvd nvdResponse
	if err := json.Unmarshal(body, &nvd); err != nil {
		return nil, &nvdFailure{reason: "NVD response unparsable"},
			append(warnings, fmt.Sprintf("vuln enrichment: NVD JSON parse error for %s: %v", cveID, err))
	}
	if nvd.TotalResults == 0 || len(nvd.Vulnerabilities) == 0 {
		return &enrichResult{}, nil, warnings
	}

	cveData := nvd.Vulnerabilities[0].CVE
	result := &enrichResult{Severity: cveData.Metrics.pick()}

	if cveData.Published != "" {
		t, err := time.Parse(time.RFC3339Nano, cveData.Published)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04:05.999", cveData.Published)
		}
		if err == nil {
			result.PublishedAt = &t
		}
	}

	result.Source = "nvd"
	return result, nil, warnings
}
