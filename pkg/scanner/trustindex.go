package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/unidoc/unisupply/pkg/progress"
	"github.com/unidoc/unisupply/pkg/resolver"
)

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
	client  *http.Client
	baseURL string
}

// NewTrustIndexClient creates a client for the unitrust API.
// If baseURL is empty, Trust Index lookup is disabled.
func NewTrustIndexClient(baseURL string, timeout time.Duration) *TrustIndexClient {
	if baseURL == "" {
		return nil
	}
	return &TrustIndexClient{
		client: &http.Client{
			Timeout: timeout,
		},
		baseURL: baseURL,
	}
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

	url := fmt.Sprintf("%s/api/v1/lookup", c.baseURL)
	rep.Step("POST %s (%d modules)", url, len(modules))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("trust index lookup: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("trust index lookup: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trust index API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var response struct {
		Results map[string]*TrustIndexEntry `json:"results"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("parsing trust index response: %w", err)
	}

	return response.Results, nil
}
