package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/unidoc/unisupply/pkg/progress"
	"github.com/unidoc/unisupply/pkg/resolver"
)

// privateCIDRs is parsed once at init to avoid repeated net.ParseCIDR calls.
var privateCIDRs []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"100.64.0.0/10", // CGNAT / shared address space (RFC 6598)
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
	} {
		_, network, _ := net.ParseCIDR(cidr)
		privateCIDRs = append(privateCIDRs, network)
	}
}

// TrustIndexEntry holds Trust Index data for a module (from unitrust API).
type TrustIndexEntry struct {
	Module             string `json:"module"`
	TrustScore         int    `json:"trust_score"`
	MaintainerTrust    int    `json:"maintainer_trust"`
	ResilienceScore    int    `json:"resilience_score"`
	SecurityScore      int    `json:"security_score"`
	CommunityScore     int    `json:"community_score"`
	MaintainerName     string `json:"maintainer_name"`
	MaintainerOrg      string `json:"maintainer_org"`
	MaintainerCountry  string `json:"maintainer_country"`
	MaintainerVerified bool   `json:"maintainer_verified"`
	StewardshipStatus  string `json:"stewardship_status"`
	SaferAlternative   string `json:"safer_alternative"`
	IsUnidocMaintained bool   `json:"is_unidoc_maintained"`
}

// TrustIndexClient queries the unitrust API for Trust Index data.
type TrustIndexClient struct {
	client  *Client
	baseURL string
	host    string
}

// NewTrustIndexClient validates baseURL for SSRF risks and creates a client.
// Returns (nil, nil) when baseURL is empty (Trust Index disabled).
// allowPrivate permits RFC1918, link-local, and IPv6 ULA/link-local hosts
// (e.g. a self-hosted unitrust on a private network); pass false in production.
func NewTrustIndexClient(baseURL string, timeout time.Duration, allowPrivate bool) (*TrustIndexClient, error) {
	if baseURL == "" {
		return nil, nil
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("trust-index: invalid URL: %w", err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("trust-index: URL must include a host: %q", baseURL)
	}

	hostname := u.Hostname()

	// Resolve the host once at startup to catch SSRF vectors early.
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return nil, fmt.Errorf("trust-index: cannot resolve %q: %w", hostname, err)
	}

	allLoopback := true
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip == nil || !ip.IsLoopback() {
			allLoopback = false
			break
		}
	}

	// http is only permitted for loopback hosts; everything else requires https.
	if u.Scheme != "https" && !allLoopback {
		return nil, fmt.Errorf("trust-index: %q requires https (http is only allowed for loopback hosts)", baseURL)
	}

	// Reject RFC1918, link-local, and IPv6 ULA/link-local ranges unless the
	// operator has explicitly opted in with --trust-index-allow-private.
	if !allowPrivate {
		for _, addr := range addrs {
			ip := net.ParseIP(addr)
			if ip != nil && isPrivateIP(ip) {
				return nil, fmt.Errorf("trust-index: %q resolves to a private/link-local address; pass --trust-index-allow-private to allow this", baseURL)
			}
		}
	}

	c := NewClient(ClientOptions{Timeout: timeout})
	// Pin the startup-validated IPs at dial time to close the DNS-rebinding window.
	// Without this, http.Client re-resolves on every dial, giving an attacker a
	// second opportunity to return a private/metadata IP after passing startup checks.
	dt, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("trust-index: unexpected http.DefaultTransport type; cannot pin dial IPs")
	}
	dialTransport := dt.Clone()
	dialTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		var (
			dialer net.Dialer
			errs   []error
		)

		for _, ip := range addrs {
			conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
			if dialErr == nil {
				return conn, nil
			}
			errs = append(errs, dialErr)
		}
		return nil, fmt.Errorf("trust-index: failed to connect to %s: %w", addr, errors.Join(errs...))
	}
	c.Transport = dialTransport
	return &TrustIndexClient{
		client:  c,
		baseURL: baseURL,
		host:    u.Host,
	}, nil
}

// isPrivateIP reports whether ip falls in an RFC1918, CGNAT, link-local, or
// IPv6 ULA/link-local range. Loopback is intentionally excluded so that
// localhost remains usable without --trust-index-allow-private.
func isPrivateIP(ip net.IP) bool {
	for _, network := range privateCIDRs {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// LookupAll fetches Trust Index data for all dependencies in one bulk request.
func (c *TrustIndexClient) LookupAll(ctx context.Context, graph *resolver.Graph) (map[string]*TrustIndexEntry, error) {
	if c == nil {
		return nil, nil
	}
	rep := progress.From(ctx)

	// Collect all module paths.
	var modules []string
	for _, dep := range graph.Dependencies {
		modules = append(modules, dep.Module.Path)
	}

	if len(modules) == 0 {
		return nil, nil
	}

	// Bulk lookup request.
	reqBody, err := json.Marshal(map[string][]string{"modules": modules})
	if err != nil {
		return nil, err
	}

	lookupURL := fmt.Sprintf("%s/api/v1/lookup", c.baseURL)
	rep.Warn("trust-index: posting %d module paths to %s", len(modules), lookupURL)
	body, resp, err := c.client.Post(ctx, lookupURL, "application/json", bytes.NewReader(reqBody), GetOptions{
		Host:     c.host,
		MaxBytes: 4 * 1024 * 1024, // 4 MB — Trust Index response may include many modules.
	})
	if err != nil {
		return nil, fmt.Errorf("trust index lookup: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trust index API returned %d", resp.StatusCode)
	}

	var response struct {
		Results map[string]*TrustIndexEntry `json:"results"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("parsing trust index response: %w", err)
	}

	return response.Results, nil
}
