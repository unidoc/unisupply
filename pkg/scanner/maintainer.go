package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/unidoc/unisupply/pkg/resolver"
)

// MaintainerInfo holds maintainer/ownership data for a module.
type MaintainerInfo struct {
	Owner            string    `json:"owner"`
	Repo             string    `json:"repo"`
	OwnerName        string    `json:"owner_name"`        // display name of owner
	OwnerLocation    string    `json:"owner_location"`    // country/city
	OwnerCompany     string    `json:"owner_company"`     // company affiliation
	OwnerBio         string    `json:"owner_bio"`         // bio/description
	OwnerURL         string    `json:"owner_url"`         // website/blog
	IsOrg            bool      `json:"is_org"`            // org vs personal
	OwnerVerified    bool      `json:"owner_verified"`
	BusinessModel    string    `json:"business_model"`    // "open_source", "company_backed", "foundation", "unknown"
	License          string    `json:"license"`           // SPDX license identifier
	Description      string    `json:"description"`       // repo description
	ContributorCount int       `json:"contributor_count"`
	TopContributors  []string  `json:"top_contributors"`  // top 5 contributor logins
	BusFactor        int       `json:"bus_factor"`
	IsArchived       bool      `json:"is_archived"`
	IsFork           bool      `json:"is_fork"`
	ActivityPattern  string    `json:"activity_pattern"`  // "active", "sporadic", "inactive"
	LastCommitDate   time.Time `json:"last_commit_date"`
	CreatedAt        time.Time `json:"created_at"`
	Stars            int       `json:"stars"`
	Forks            int       `json:"forks"`
	OpenIssues       int       `json:"open_issues"`
	SubDependencies  int       `json:"sub_dependencies"`  // how many deps this dep pulls in
	// Takeover analysis.
	TakeoverCandidate bool   `json:"takeover_candidate"`
	TakeoverReason    string `json:"takeover_reason,omitempty"`
}

// MaintainerScanner analyzes module maintainership via the GitHub API.
type MaintainerScanner struct {
	client    *http.Client
	token     string
	cache     map[string]*MaintainerInfo
	userCache map[string]*githubUser
	mu        sync.Mutex
}

// NewMaintainerScanner creates a new maintainer scanner.
func NewMaintainerScanner(timeout time.Duration, githubToken string) *MaintainerScanner {
	return &MaintainerScanner{
		client: &http.Client{
			Timeout: timeout,
		},
		token:     githubToken,
		cache:     make(map[string]*MaintainerInfo),
		userCache: make(map[string]*githubUser),
	}
}

// githubRepo represents relevant fields from the GitHub repos API.
type githubRepo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Archived    bool   `json:"archived"`
	Disabled    bool   `json:"disabled"`
	Fork        bool   `json:"fork"`
	Stars       int    `json:"stargazers_count"`
	Forks       int    `json:"forks_count"`
	OpenIssues  int    `json:"open_issues_count"`
	PushedAt    string `json:"pushed_at"`
	CreatedAt   string `json:"created_at"`
	License     *struct {
		SPDXID string `json:"spdx_id"`
		Name   string `json:"name"`
	} `json:"license"`
	Owner struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"owner"`
}

// githubUser represents a GitHub user or org profile.
type githubUser struct {
	Login    string `json:"login"`
	Name     string `json:"name"`
	Company  string `json:"company"`
	Location string `json:"location"`
	Bio      string `json:"bio"`
	Blog     string `json:"blog"`
	Type     string `json:"type"`
}

// githubContributor represents a contributor from the GitHub API.
type githubContributor struct {
	Login         string `json:"login"`
	Contributions int    `json:"contributions"`
}

// ScanAll analyzes maintainer info for all dependencies.
func (ms *MaintainerScanner) ScanAll(graph *resolver.Graph) map[string]*MaintainerInfo {
	results := make(map[string]*MaintainerInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, 5)

	for _, dep := range graph.Dependencies {
		owner, repo := parseGitHubPath(dep.Module.Path)
		if owner == "" || repo == "" {
			continue
		}

		wg.Add(1)
		go func(d *resolver.Dependency, owner, repo string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			info := ms.analyzeRepo(owner, repo)
			if info != nil {
				info.SubDependencies = d.TransitiveDeps
				mu.Lock()
				results[d.Module.Path] = info
				mu.Unlock()
			}
		}(dep, owner, repo)
	}

	wg.Wait()
	return results
}

func (ms *MaintainerScanner) analyzeRepo(owner, repo string) *MaintainerInfo {
	cacheKey := owner + "/" + repo
	ms.mu.Lock()
	if cached, ok := ms.cache[cacheKey]; ok {
		ms.mu.Unlock()
		return cached
	}
	ms.mu.Unlock()

	info := &MaintainerInfo{
		Owner: owner,
		Repo:  repo,
	}

	// Fetch repo info.
	repoData, err := ms.fetchRepo(owner, repo)
	if err != nil {
		ms.mu.Lock()
		ms.cache[cacheKey] = info
		ms.mu.Unlock()
		return info
	}

	info.Description = repoData.Description
	info.IsArchived = repoData.Archived
	info.IsFork = repoData.Fork
	info.Stars = repoData.Stars
	info.Forks = repoData.Forks
	info.OpenIssues = repoData.OpenIssues
	info.IsOrg = repoData.Owner.Type == "Organization"
	info.OwnerVerified = repoData.Owner.Type == "Organization"

	if repoData.License != nil {
		info.License = repoData.License.SPDXID
	}

	if repoData.PushedAt != "" {
		if t, err := time.Parse(time.RFC3339, repoData.PushedAt); err == nil {
			info.LastCommitDate = t
		}
	}
	if repoData.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, repoData.CreatedAt); err == nil {
			info.CreatedAt = t
		}
	}

	info.ActivityPattern = classifyActivity(info.LastCommitDate)

	// Fetch owner profile (user or org).
	user := ms.fetchUser(owner)
	if user != nil {
		info.OwnerName = user.Name
		if info.OwnerName == "" {
			info.OwnerName = user.Login
		}
		info.OwnerLocation = user.Location
		info.OwnerCompany = user.Company
		info.OwnerBio = user.Bio
		info.OwnerURL = user.Blog
	}

	// Determine business model.
	info.BusinessModel = classifyBusinessModel(info, repoData)

	// Fetch contributors for bus factor analysis.
	contributors := ms.fetchContributors(owner, repo)
	info.ContributorCount = len(contributors)
	info.BusFactor = computeBusFactor(contributors)

	// Top contributors (up to 5).
	for i, c := range contributors {
		if i >= 5 {
			break
		}
		info.TopContributors = append(info.TopContributors, c.Login)
	}

	// Takeover candidate analysis.
	assessTakeover(info)

	ms.mu.Lock()
	ms.cache[cacheKey] = info
	ms.mu.Unlock()

	return info
}

func (ms *MaintainerScanner) fetchRepo(owner, repo string) (*githubRepo, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
	body, err := ms.githubGet(url)
	if err != nil {
		return nil, err
	}
	var result githubRepo
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (ms *MaintainerScanner) fetchUser(login string) *githubUser {
	ms.mu.Lock()
	if cached, ok := ms.userCache[login]; ok {
		ms.mu.Unlock()
		return cached
	}
	ms.mu.Unlock()

	url := fmt.Sprintf("https://api.github.com/users/%s", login)
	body, err := ms.githubGet(url)
	if err != nil {
		return nil
	}
	var user githubUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil
	}

	ms.mu.Lock()
	ms.userCache[login] = &user
	ms.mu.Unlock()

	return &user
}

func (ms *MaintainerScanner) fetchContributors(owner, repo string) []githubContributor {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contributors?per_page=100", owner, repo)
	body, err := ms.githubGet(url)
	if err != nil {
		return nil
	}
	var contributors []githubContributor
	if err := json.Unmarshal(body, &contributors); err != nil {
		return nil
	}
	return contributors
}

func (ms *MaintainerScanner) githubGet(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if ms.token != "" {
		req.Header.Set("Authorization", "Bearer "+ms.token)
	}
	resp, err := ms.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d for %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}

func classifyActivity(lastCommit time.Time) string {
	if lastCommit.IsZero() {
		return "unknown"
	}
	months := monthsSince(lastCommit)
	switch {
	case months < 3:
		return "active"
	case months < 12:
		return "sporadic"
	default:
		return "inactive"
	}
}

// classifyBusinessModel guesses the business model based on available signals.
func classifyBusinessModel(info *MaintainerInfo, repo *githubRepo) string {
	ownerLower := strings.ToLower(info.Owner)
	companyLower := strings.ToLower(info.OwnerCompany)

	// Known foundations / orgs.
	foundations := []string{"golang", "kubernetes", "cncf", "apache", "linux", "mozilla"}
	for _, f := range foundations {
		if strings.Contains(ownerLower, f) || strings.Contains(companyLower, f) {
			return "foundation"
		}
	}

	// Known companies.
	companies := []string{"google", "microsoft", "amazon", "aws", "meta", "facebook",
		"hashicorp", "docker", "elastic", "datadog", "grafana", "unidoc", "stripe",
		"cloudflare", "uber", "github", "gitlab", "jetbrains", "redhat", "ibm", "oracle"}
	for _, c := range companies {
		if strings.Contains(ownerLower, c) || strings.Contains(companyLower, c) {
			return "company_backed"
		}
	}

	// Org with company name.
	if info.IsOrg && info.OwnerCompany != "" {
		return "company_backed"
	}

	// golang.org/x/ is Go team.
	if strings.HasPrefix(info.Owner, "golang") {
		return "foundation"
	}

	if info.IsOrg {
		return "organization"
	}

	return "individual"
}

func computeBusFactor(contributors []githubContributor) int {
	if len(contributors) == 0 {
		return 0
	}
	totalContribs := 0
	for _, c := range contributors {
		totalContribs += c.Contributions
	}
	if totalContribs == 0 {
		return 0
	}
	threshold := float64(totalContribs) * 0.05
	keyMaintainers := 0
	for _, c := range contributors {
		if float64(c.Contributions) >= threshold {
			keyMaintainers++
		}
	}
	return keyMaintainers
}

func assessTakeover(info *MaintainerInfo) {
	if info.Stars >= 100 && info.ActivityPattern == "inactive" {
		info.TakeoverCandidate = true
		info.TakeoverReason = "widely used but inactive"
		return
	}
	if info.BusFactor <= 1 && info.ActivityPattern == "inactive" {
		info.TakeoverCandidate = true
		info.TakeoverReason = "single maintainer, inactive"
		return
	}
	if info.IsArchived {
		info.TakeoverCandidate = true
		info.TakeoverReason = "repository archived"
		return
	}
}

func parseGitHubPath(modPath string) (string, string) {
	if !strings.HasPrefix(modPath, "github.com/") {
		return "", ""
	}
	parts := strings.Split(strings.TrimPrefix(modPath, "github.com/"), "/")
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}
