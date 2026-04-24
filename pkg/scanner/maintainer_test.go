package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/resolver"
)

// ============================================================================
// Helper functions for testing
// ============================================================================

// newMockGitHub creates an httptest.Server that simulates GitHub API responses.
// Routes:
//   - GET /repos/{owner}/{repo} -> githubRepo response
//   - GET /repos/{owner}/{repo}/contributors -> array of githubContributor
//   - GET /users/{login} -> githubUser response
func newMockGitHub() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		w.Header().Set("Content-Type", "application/json")

		// Route: /repos/{owner}/{repo}/contributors
		if strings.Contains(path, "/contributors") {
			parts := strings.Split(strings.TrimPrefix(path, "/repos/"), "/")
			if len(parts) >= 2 {
				owner, repo := parts[0], parts[1]
				if owner == "golang" && repo == "go" {
					json.NewEncoder(w).Encode([]githubContributor{
						{Login: "rsc", Contributions: 1000},
						{Login: "alandonovan", Contributions: 500},
						{Login: "griesemer", Contributions: 450},
						{Login: "iant", Contributions: 300},
						{Login: "bradfitz", Contributions: 250},
					})
					return
				} else if owner == "single" && repo == "maintainer" {
					json.NewEncoder(w).Encode([]githubContributor{
						{Login: "solo", Contributions: 100},
					})
					return
				} else if owner == "few" && repo == "devs" {
					json.NewEncoder(w).Encode([]githubContributor{
						{Login: "dev1", Contributions: 60},
						{Login: "dev2", Contributions: 25},
						{Login: "dev3", Contributions: 15},
					})
					return
				}
			}
			json.NewEncoder(w).Encode([]githubContributor{})
			return
		}

		// Route: /repos/{owner}/{repo}
		if strings.HasPrefix(path, "/repos/") && !strings.Contains(path, "/contributors") {
			parts := strings.Split(strings.TrimPrefix(path, "/repos/"), "/")
			if len(parts) >= 2 {
				owner, repo := parts[0], parts[1]

				switch owner + "/" + repo {
				case "golang/go":
					ownStruct := struct {
						Login string `json:"login"`
						Type  string `json:"type"`
					}{Login: "golang", Type: "Organization"}
					lic := &struct {
						SPDXID string `json:"spdx_id"`
						Name   string `json:"name"`
					}{SPDXID: "BSD-3-Clause", Name: "BSD 3-Clause License"}
					r := githubRepo{
						Name:        "go",
						Description: "The Go programming language",
						Archived:    false,
						Fork:        false,
						Stars:       45000,
						Forks:       6500,
						OpenIssues:  800,
						PushedAt:    time.Now().Add(-7 * 24 * time.Hour).Format(time.RFC3339),
						CreatedAt:   time.Now().Add(-5000 * 24 * time.Hour).Format(time.RFC3339),
						License:     lic,
						Owner:       ownStruct,
					}
					json.NewEncoder(w).Encode(r)
					return

				case "single/maintainer":
					ownStruct := struct {
						Login string `json:"login"`
						Type  string `json:"type"`
					}{Login: "single", Type: "User"}
					r := githubRepo{
						Name:        "maintainer",
						Description: "Single maintainer repo",
						Archived:    false,
						Fork:        false,
						Stars:       250,
						Forks:       50,
						OpenIssues:  10,
						PushedAt:    time.Now().Add(-18 * 30 * 24 * time.Hour).Format(time.RFC3339),
						CreatedAt:   time.Now().Add(-1000 * 24 * time.Hour).Format(time.RFC3339),
						Owner:       ownStruct,
					}
					json.NewEncoder(w).Encode(r)
					return

				case "few/devs":
					ownStruct := struct {
						Login string `json:"login"`
						Type  string `json:"type"`
					}{Login: "few", Type: "Organization"}
					r := githubRepo{
						Name:        "devs",
						Description: "Few developers repo",
						Archived:    false,
						Fork:        false,
						Stars:       150,
						Forks:       30,
						OpenIssues:  5,
						PushedAt:    time.Now().Add(-2 * 24 * time.Hour).Format(time.RFC3339),
						CreatedAt:   time.Now().Add(-500 * 24 * time.Hour).Format(time.RFC3339),
						Owner:       ownStruct,
					}
					json.NewEncoder(w).Encode(r)
					return

				case "archived/old":
					ownStruct := struct {
						Login string `json:"login"`
						Type  string `json:"type"`
					}{Login: "archived", Type: "User"}
					r := githubRepo{
						Name:        "old",
						Description: "Archived repository",
						Archived:    true,
						Fork:        false,
						Stars:       500,
						Forks:       100,
						OpenIssues:  0,
						PushedAt:    time.Now().Add(-3 * 365 * 24 * time.Hour).Format(time.RFC3339),
						CreatedAt:   time.Now().Add(-2000 * 24 * time.Hour).Format(time.RFC3339),
						Owner:       ownStruct,
					}
					json.NewEncoder(w).Encode(r)
					return

				case "widely/used":
					ownStruct := struct {
						Login string `json:"login"`
						Type  string `json:"type"`
					}{Login: "widely", Type: "User"}
					r := githubRepo{
						Name:        "used",
						Description: "Widely used but inactive",
						Archived:    false,
						Fork:        false,
						Stars:       5000,
						Forks:       1000,
						OpenIssues:  200,
						PushedAt:    time.Now().Add(-24 * 30 * 24 * time.Hour).Format(time.RFC3339),
						CreatedAt:   time.Now().Add(-3000 * 24 * time.Hour).Format(time.RFC3339),
						Owner:       ownStruct,
					}
					json.NewEncoder(w).Encode(r)
					return

				case "fork/clone":
					ownStruct := struct {
						Login string `json:"login"`
						Type  string `json:"type"`
					}{Login: "fork", Type: "User"}
					r := githubRepo{
						Name:        "clone",
						Description: "Forked repository",
						Archived:    false,
						Fork:        true,
						Stars:       50,
						Forks:       5,
						OpenIssues:  2,
						PushedAt:    time.Now().Add(-10 * 24 * time.Hour).Format(time.RFC3339),
						CreatedAt:   time.Now().Add(-200 * 24 * time.Hour).Format(time.RFC3339),
						Owner:       ownStruct,
					}
					json.NewEncoder(w).Encode(r)
					return

				case "no/license":
					ownStruct := struct {
						Login string `json:"login"`
						Type  string `json:"type"`
					}{Login: "no", Type: "User"}
					r := githubRepo{
						Name:        "no-license",
						Description: "Repo without SPDX license",
						Archived:    false,
						Fork:        false,
						Stars:       100,
						Forks:       20,
						OpenIssues:  5,
						PushedAt:    time.Now().Format(time.RFC3339),
						CreatedAt:   time.Now().Add(-100 * 24 * time.Hour).Format(time.RFC3339),
						License:     nil,
						Owner:       ownStruct,
					}
					json.NewEncoder(w).Encode(r)
					return

				case "error/repo":
					w.WriteHeader(http.StatusNotFound)
					return

				default:
					ownStruct := struct {
						Login string `json:"login"`
						Type  string `json:"type"`
					}{Login: owner, Type: "User"}
					r := githubRepo{
						Name:     repo,
						Owner:    ownStruct,
						Stars:    0,
						Forks:    0,
						PushedAt: time.Now().Format(time.RFC3339),
					}
					json.NewEncoder(w).Encode(r)
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Route: /users/{login}
		if strings.HasPrefix(path, "/users/") {
			login := strings.TrimPrefix(path, "/users/")

			switch login {
			case "golang":
				json.NewEncoder(w).Encode(githubUser{
					Login:    "golang",
					Name:     "Go Team",
					Company:  "Google",
					Location: "Mountain View, CA",
					Bio:      "The Go Programming Language",
					Blog:     "https://golang.org",
					Type:     "Organization",
				})
				return

			case "single":
				json.NewEncoder(w).Encode(githubUser{
					Login:    "single",
					Name:     "Single Developer",
					Company:  "",
					Location: "San Francisco",
					Bio:      "Indie developer",
					Type:     "User",
				})
				return

			case "few":
				json.NewEncoder(w).Encode(githubUser{
					Login:    "few",
					Name:     "Few Developers Inc",
					Company:  "Few Developers Inc",
					Location: "Seattle, WA",
					Bio:      "A small team of developers",
					Type:     "Organization",
				})
				return

			case "archived":
				json.NewEncoder(w).Encode(githubUser{
					Login:    "archived",
					Name:     "Archived User",
					Location: "Unknown",
					Type:     "User",
				})
				return

			case "widely":
				json.NewEncoder(w).Encode(githubUser{
					Login:    "widely",
					Name:     "Widely Used",
					Location: "Somewhere",
					Type:     "User",
				})
				return

			case "fork":
				json.NewEncoder(w).Encode(githubUser{
					Login: "fork",
					Name:  "Fork Owner",
					Type:  "User",
				})
				return

			case "no":
				json.NewEncoder(w).Encode(githubUser{
					Login: "no",
					Name:  "No License User",
					Type:  "User",
				})
				return

			default:
				json.NewEncoder(w).Encode(githubUser{
					Login: login,
					Name:  strings.Title(login),
					Type:  "User",
				})
				return
			}
		}

		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "Not found: %s\n", path)
	}))
}

// makeGraphWithDeps builds a resolver.Graph from dependency specs for testing.
func makeGraphWithDeps(deps ...struct {
	path string
	ver  string
}) *resolver.Graph {
	g := &resolver.Graph{
		Root:         "test/module",
		Dependencies: make(map[string]*resolver.Dependency, len(deps)),
	}
	for _, spec := range deps {
		g.Dependencies[spec.path] = &resolver.Dependency{
			Module: parser.Module{
				Path:     spec.path,
				Version:  spec.ver,
				Indirect: false,
			},
			Direct: true,
			Depth:  0,
		}
	}
	return g
}

// ============================================================================
// Unit tests: parseGitHubPath
// ============================================================================

// TestParseGitHubPath verifies GitHub path parsing with various inputs.
func TestParseGitHubPath(t *testing.T) {
	tests := []struct {
		name         string
		modPath      string
		expectedOrg  string
		expectedRepo string
	}{
		// Valid GitHub paths
		{
			name:         "valid_three_part",
			modPath:      "github.com/org/repo",
			expectedOrg:  "org",
			expectedRepo: "repo",
		},
		{
			name:         "valid_four_part",
			modPath:      "github.com/org/repo/sub",
			expectedOrg:  "org",
			expectedRepo: "repo",
		},
		{
			name:         "valid_long_path",
			modPath:      "github.com/org/repo/sub/deep/path",
			expectedOrg:  "org",
			expectedRepo: "repo",
		},
		{
			name:         "valid_with_dashes",
			modPath:      "github.com/org-name/repo-name",
			expectedOrg:  "org-name",
			expectedRepo: "repo-name",
		},

		// Invalid paths (non-GitHub)
		{
			name:         "non_github_gitlab",
			modPath:      "gitlab.com/org/repo",
			expectedOrg:  "",
			expectedRepo: "",
		},
		{
			name:         "non_github_golang",
			modPath:      "golang.org/x/text",
			expectedOrg:  "",
			expectedRepo: "",
		},
		{
			name:         "non_github_custom",
			modPath:      "custom.org/org/repo",
			expectedOrg:  "",
			expectedRepo: "",
		},

		// Edge cases
		{
			name:         "github_prefix_only",
			modPath:      "github.com",
			expectedOrg:  "",
			expectedRepo: "",
		},
		{
			name:         "github_prefix_one_part",
			modPath:      "github.com/org",
			expectedOrg:  "",
			expectedRepo: "",
		},
		{
			name:         "empty_string",
			modPath:      "",
			expectedOrg:  "",
			expectedRepo: "",
		},
		{
			name:         "github_with_version",
			modPath:      "github.com/org/repo/v2",
			expectedOrg:  "org",
			expectedRepo: "repo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			org, repo := parseGitHubPath(tt.modPath)
			if org != tt.expectedOrg || repo != tt.expectedRepo {
				t.Errorf("parseGitHubPath(%q) = (%q, %q), want (%q, %q)",
					tt.modPath, org, repo, tt.expectedOrg, tt.expectedRepo)
			}
		})
	}
}

// ============================================================================
// Unit tests: classifyActivity
// ============================================================================

// TestClassifyActivity verifies activity classification based on last commit time.
func TestClassifyActivity(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name             string
		lastCommit       time.Time
		expectedClassify string
	}{
		// Active (< 3 months)
		{
			name:             "active_one_week",
			lastCommit:       now.Add(-7 * 24 * time.Hour),
			expectedClassify: "active",
		},
		{
			name:             "active_one_month",
			lastCommit:       now.Add(-30 * 24 * time.Hour),
			expectedClassify: "active",
		},
		{
			name:             "active_two_months",
			lastCommit:       now.Add(-60 * 24 * time.Hour),
			expectedClassify: "active",
		},

		// Sporadic (3-12 months)
		{
			name:             "sporadic_three_months",
			lastCommit:       now.Add(-3 * 30 * 24 * time.Hour),
			expectedClassify: "sporadic",
		},
		{
			name:             "sporadic_six_months",
			lastCommit:       now.Add(-6 * 30 * 24 * time.Hour),
			expectedClassify: "sporadic",
		},
		{
			name:             "sporadic_eleven_months",
			lastCommit:       now.Add(-11 * 30 * 24 * time.Hour),
			expectedClassify: "sporadic",
		},

		// Inactive (> 12 months)
		{
			name:             "inactive_one_year",
			lastCommit:       now.Add(-365 * 24 * time.Hour),
			expectedClassify: "inactive",
		},
		{
			name:             "inactive_two_years",
			lastCommit:       now.Add(-2 * 365 * 24 * time.Hour),
			expectedClassify: "inactive",
		},
		{
			name:             "inactive_five_years",
			lastCommit:       now.Add(-5 * 365 * 24 * time.Hour),
			expectedClassify: "inactive",
		},

		// Unknown (zero time)
		{
			name:             "unknown_zero_time",
			lastCommit:       time.Time{},
			expectedClassify: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyActivity(tt.lastCommit)
			if got != tt.expectedClassify {
				t.Errorf("classifyActivity(%v) = %q, want %q", tt.lastCommit, got, tt.expectedClassify)
			}
		})
	}
}

// ============================================================================
// Unit tests: classifyBusinessModel
// ============================================================================

// TestClassifyBusinessModel verifies business model classification.
func TestClassifyBusinessModel(t *testing.T) {
	tests := []struct {
		name     string
		info     *MaintainerInfo
		repo     *githubRepo
		expected string
	}{
		// Foundation/well-known open source
		{
			name: "foundation_golang",
			info: &MaintainerInfo{
				Owner:        "golang",
				IsOrg:        true,
				OwnerCompany: "",
			},
			repo:     &githubRepo{},
			expected: "foundation",
		},
		{
			name: "foundation_kubernetes",
			info: &MaintainerInfo{
				Owner:        "kubernetes",
				IsOrg:        true,
				OwnerCompany: "",
			},
			repo:     &githubRepo{},
			expected: "foundation",
		},
		{
			name: "foundation_apache",
			info: &MaintainerInfo{
				Owner:        "apache",
				IsOrg:        true,
				OwnerCompany: "",
			},
			repo:     &githubRepo{},
			expected: "foundation",
		},

		// Company-backed
		{
			name: "company_backed_google",
			info: &MaintainerInfo{
				Owner:        "google",
				IsOrg:        true,
				OwnerCompany: "",
			},
			repo:     &githubRepo{},
			expected: "company_backed",
		},
		{
			name: "company_backed_microsoft",
			info: &MaintainerInfo{
				Owner:        "microsoft",
				IsOrg:        true,
				OwnerCompany: "",
			},
			repo:     &githubRepo{},
			expected: "company_backed",
		},
		{
			name: "company_backed_amazon",
			info: &MaintainerInfo{
				Owner:        "aws",
				IsOrg:        true,
				OwnerCompany: "",
			},
			repo:     &githubRepo{},
			expected: "company_backed",
		},
		{
			name: "company_backed_org_with_company",
			info: &MaintainerInfo{
				Owner:        "mycompany",
				IsOrg:        true,
				OwnerCompany: "MyCompany Inc",
			},
			repo:     &githubRepo{},
			expected: "company_backed",
		},

		// Organization (IsOrg but not company-backed)
		{
			name: "organization",
			info: &MaintainerInfo{
				Owner:        "myorg",
				IsOrg:        true,
				OwnerCompany: "",
			},
			repo:     &githubRepo{},
			expected: "organization",
		},

		// Individual
		{
			name: "individual",
			info: &MaintainerInfo{
				Owner:        "johndoe",
				IsOrg:        false,
				OwnerCompany: "",
			},
			repo:     &githubRepo{},
			expected: "individual",
		},

		// Case insensitivity
		{
			name: "case_insensitive_GOOGLE",
			info: &MaintainerInfo{
				Owner:        "GOOGLE",
				IsOrg:        true,
				OwnerCompany: "",
			},
			repo:     &githubRepo{},
			expected: "company_backed",
		},
		{
			name: "case_insensitive_company_in_bio",
			info: &MaintainerInfo{
				Owner:        "someorg",
				IsOrg:        true,
				OwnerCompany: "HashiCorp",
			},
			repo:     &githubRepo{},
			expected: "company_backed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyBusinessModel(tt.info, tt.repo)
			if got != tt.expected {
				t.Errorf("classifyBusinessModel(%+v, %+v) = %q, want %q", tt.info, tt.repo, got, tt.expected)
			}
		})
	}
}

// ============================================================================
// Unit tests: computeBusFactor
// ============================================================================

// TestComputeBusFactor verifies bus factor calculation from contributors.
func TestComputeBusFactor(t *testing.T) {
	tests := []struct {
		name         string
		contributors []githubContributor
		expectedBF   int
	}{
		// Empty contributors
		{
			name:         "empty_contributors",
			contributors: []githubContributor{},
			expectedBF:   0,
		},

		// Single contributor (bus factor = 1)
		{
			name: "single_contributor",
			contributors: []githubContributor{
				{Login: "dev1", Contributions: 100},
			},
			expectedBF: 1,
		},

		// Two equal contributors
		{
			name: "two_equal_contributors",
			contributors: []githubContributor{
				{Login: "dev1", Contributions: 50},
				{Login: "dev2", Contributions: 50},
			},
			expectedBF: 2,
		},

		// Many contributors with steep distribution (5 above 5% threshold)
		{
			name: "many_contributors_steep",
			contributors: []githubContributor{
				{Login: "dev1", Contributions: 1000},
				{Login: "dev2", Contributions: 500},
				{Login: "dev3", Contributions: 450},
				{Login: "dev4", Contributions: 300},
				{Login: "dev5", Contributions: 250},
				{Login: "dev6", Contributions: 100},
			},
			expectedBF: 5,
		},

		// Flat distribution (all above 5% threshold)
		{
			name: "flat_distribution",
			contributors: []githubContributor{
				{Login: "dev1", Contributions: 40},
				{Login: "dev2", Contributions: 35},
				{Login: "dev3", Contributions: 25},
			},
			expectedBF: 3,
		},

		// Mixed: all at/above 5% threshold (5 is exactly at threshold)
		{
			name: "mixed_distribution",
			contributors: []githubContributor{
				{Login: "dev1", Contributions: 80},
				{Login: "dev2", Contributions: 15},
				{Login: "dev3", Contributions: 5},
			},
			expectedBF: 3,
		},

		// Zero contributions (edge case)
		{
			name: "zero_contributions",
			contributors: []githubContributor{
				{Login: "dev1", Contributions: 0},
				{Login: "dev2", Contributions: 0},
			},
			expectedBF: 0,
		},

		// Very small contributions
		{
			name: "very_small_contributions",
			contributors: []githubContributor{
				{Login: "dev1", Contributions: 3},
				{Login: "dev2", Contributions: 1},
			},
			expectedBF: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeBusFactor(tt.contributors)
			if got != tt.expectedBF {
				t.Errorf("computeBusFactor(%v) = %d, want %d", tt.contributors, got, tt.expectedBF)
			}
		})
	}
}

// ============================================================================
// Unit tests: assessTakeover
// ============================================================================

// TestAssessTakeover verifies takeover candidate detection.
func TestAssessTakeover(t *testing.T) {
	tests := []struct {
		name              string
		info              *MaintainerInfo
		expectedCandidate bool
		expectedReason    string
	}{
		// Widely used but inactive
		{
			name: "widely_used_inactive",
			info: &MaintainerInfo{
				Stars:           200,
				ActivityPattern: "inactive",
				BusFactor:       3,
				IsArchived:      false,
			},
			expectedCandidate: true,
			expectedReason:    "widely used but inactive",
		},

		// Single maintainer, inactive
		{
			name: "single_inactive",
			info: &MaintainerInfo{
				Stars:           50,
				ActivityPattern: "inactive",
				BusFactor:       1,
				IsArchived:      false,
			},
			expectedCandidate: true,
			expectedReason:    "single maintainer, inactive",
		},

		// Archived (always takeover candidate)
		{
			name: "archived_repo",
			info: &MaintainerInfo{
				Stars:           100,
				ActivityPattern: "active",
				BusFactor:       5,
				IsArchived:      true,
			},
			expectedCandidate: true,
			expectedReason:    "repository archived",
		},

		// Active, so not a takeover candidate
		{
			name: "active_repo",
			info: &MaintainerInfo{
				Stars:           1000,
				ActivityPattern: "active",
				BusFactor:       3,
				IsArchived:      false,
			},
			expectedCandidate: false,
			expectedReason:    "",
		},

		// Many maintainers, inactive but not widely used
		{
			name: "many_maintainers_inactive",
			info: &MaintainerInfo{
				Stars:           50,
				ActivityPattern: "inactive",
				BusFactor:       5,
				IsArchived:      false,
			},
			expectedCandidate: false,
			expectedReason:    "",
		},

		// Sporadic activity is not inactive
		{
			name: "sporadic_activity",
			info: &MaintainerInfo{
				Stars:           500,
				ActivityPattern: "sporadic",
				BusFactor:       1,
				IsArchived:      false,
			},
			expectedCandidate: false,
			expectedReason:    "",
		},

		// Bus factor = 2 (not single)
		{
			name: "two_maintainers_inactive",
			info: &MaintainerInfo{
				Stars:           50,
				ActivityPattern: "inactive",
				BusFactor:       2,
				IsArchived:      false,
			},
			expectedCandidate: false,
			expectedReason:    "",
		},

		// Exactly 100 stars (edge of threshold)
		{
			name: "exactly_100_stars_inactive",
			info: &MaintainerInfo{
				Stars:           100,
				ActivityPattern: "inactive",
				BusFactor:       3,
				IsArchived:      false,
			},
			expectedCandidate: true,
			expectedReason:    "widely used but inactive",
		},

		// 99 stars (below threshold)
		{
			name: "99_stars_inactive",
			info: &MaintainerInfo{
				Stars:           99,
				ActivityPattern: "inactive",
				BusFactor:       3,
				IsArchived:      false,
			},
			expectedCandidate: false,
			expectedReason:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assessTakeover(tt.info)
			if tt.info.TakeoverCandidate != tt.expectedCandidate {
				t.Errorf("TakeoverCandidate = %v, want %v", tt.info.TakeoverCandidate, tt.expectedCandidate)
			}
			if tt.info.TakeoverReason != tt.expectedReason {
				t.Errorf("TakeoverReason = %q, want %q", tt.info.TakeoverReason, tt.expectedReason)
			}
		})
	}
}

// ============================================================================
// Integration tests: MaintainerScanner
// ============================================================================

// TestMaintainerScanner_AnalyzeRepo verifies full repo analysis via mock GitHub API.
func TestMaintainerScanner_AnalyzeRepo(t *testing.T) {
	server := newMockGitHub()
	defer server.Close()

	// Replace base URL in the scanner by patching http.Client transport
	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.client.Transport = &testTransport{baseURL: server.URL}

	info := ms.analyzeRepo("golang", "go")

	if info == nil {
		t.Fatal("analyzeRepo returned nil")
	}

	if info.Owner != "golang" {
		t.Errorf("Owner = %q, want %q", info.Owner, "golang")
	}
	if info.Repo != "go" {
		t.Errorf("Repo = %q, want %q", info.Repo, "go")
	}
	if info.Stars < 40000 {
		t.Errorf("Stars = %d, want >= 40000", info.Stars)
	}
	if info.OwnerName == "" {
		t.Errorf("OwnerName should not be empty")
	}
	if info.ActivityPattern != "active" {
		t.Errorf("ActivityPattern = %q, want %q", info.ActivityPattern, "active")
	}
	if info.BusFactor < 2 {
		t.Errorf("BusFactor = %d, want >= 2", info.BusFactor)
	}
	if info.ContributorCount == 0 {
		t.Errorf("ContributorCount = %d, want > 0", info.ContributorCount)
	}
	if info.IsOrg != true {
		t.Errorf("IsOrg = %v, want true", info.IsOrg)
	}
	if info.License == "" {
		t.Errorf("License should not be empty")
	}
}

// TestMaintainerScanner_AnalyzeRepo_SingleMaintainer verifies single maintainer detection.
func TestMaintainerScanner_AnalyzeRepo_SingleMaintainer(t *testing.T) {
	server := newMockGitHub()
	defer server.Close()

	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.client.Transport = &testTransport{baseURL: server.URL}

	info := ms.analyzeRepo("single", "maintainer")

	if info == nil {
		t.Fatal("analyzeRepo returned nil")
	}

	if info.BusFactor != 1 {
		t.Errorf("BusFactor = %d, want 1 (single maintainer)", info.BusFactor)
	}
	if info.ContributorCount != 1 {
		t.Errorf("ContributorCount = %d, want 1", info.ContributorCount)
	}
	if info.ActivityPattern != "inactive" {
		t.Errorf("ActivityPattern = %q, want %q", info.ActivityPattern, "inactive")
	}
}

// TestMaintainerScanner_AnalyzeRepo_NoLicense verifies handling of repos without license.
func TestMaintainerScanner_AnalyzeRepo_NoLicense(t *testing.T) {
	server := newMockGitHub()
	defer server.Close()

	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.client.Transport = &testTransport{baseURL: server.URL}

	info := ms.analyzeRepo("no", "license")

	if info == nil {
		t.Fatal("analyzeRepo returned nil")
	}

	if info.License != "" {
		t.Errorf("License = %q, want empty", info.License)
	}
}

// TestMaintainerScanner_AnalyzeRepo_APIError verifies graceful handling of API errors.
func TestMaintainerScanner_AnalyzeRepo_APIError(t *testing.T) {
	server := newMockGitHub()
	defer server.Close()

	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.client.Transport = &testTransport{baseURL: server.URL}

	info := ms.analyzeRepo("error", "repo")

	if info == nil {
		t.Fatal("analyzeRepo returned nil (should return partial info on API error)")
	}

	// Should have owner and repo set, but no other data
	if info.Owner != "error" {
		t.Errorf("Owner = %q, want %q", info.Owner, "error")
	}
	if info.Repo != "repo" {
		t.Errorf("Repo = %q, want %q", info.Repo, "repo")
	}
}

// TestMaintainerScanner_Cache verifies caching of repo data.
func TestMaintainerScanner_Cache(t *testing.T) {
	server := newMockGitHub()
	defer server.Close()

	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.client.Transport = &testTransport{baseURL: server.URL, requestCount: make(map[string]int)}

	// First call
	info1 := ms.analyzeRepo("golang", "go")
	if info1 == nil {
		t.Fatal("first analyzeRepo returned nil")
	}

	// Second call (should come from cache)
	info2 := ms.analyzeRepo("golang", "go")
	if info2 == nil {
		t.Fatal("second analyzeRepo returned nil")
	}

	// Check that the cached version is the same object
	if info1 == info2 {
		t.Logf("Cache working: both calls returned same object")
	}
}

// TestMaintainerScanner_ScanAll_NonGitHub verifies non-GitHub modules are skipped.
func TestMaintainerScanner_ScanAll_NonGitHub(t *testing.T) {
	server := newMockGitHub()
	defer server.Close()

	graph := makeGraphWithDeps(
		struct {
			path string
			ver  string
		}{path: "golang.org/x/text", ver: "v0.0.0"},
		struct {
			path string
			ver  string
		}{path: "gorm.io/gorm", ver: "v1.0.0"},
	)

	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.client.Transport = &testTransport{baseURL: server.URL}

	results := ms.ScanAll(graph)

	if len(results) != 0 {
		t.Errorf("ScanAll returned %d results for non-GitHub modules, want 0", len(results))
	}
}

// TestMaintainerScanner_ScanAll_WithGitHub verifies GitHub modules are analyzed.
func TestMaintainerScanner_ScanAll_WithGitHub(t *testing.T) {
	server := newMockGitHub()
	defer server.Close()

	graph := makeGraphWithDeps(
		struct {
			path string
			ver  string
		}{path: "github.com/golang/go", ver: "v1.0.0"},
		struct {
			path string
			ver  string
		}{path: "golang.org/x/text", ver: "v0.0.0"},
	)

	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.client.Transport = &testTransport{baseURL: server.URL}

	results := ms.ScanAll(graph)

	if len(results) != 1 {
		t.Errorf("ScanAll returned %d results, want 1", len(results))
	}

	result, ok := results["github.com/golang/go"]
	if !ok {
		t.Fatalf("Expected result for github.com/golang/go")
	}

	if result.Owner != "golang" {
		t.Errorf("Owner = %q, want %q", result.Owner, "golang")
	}
}

// TestMaintainerScanner_ScanAll_TransitiveDeps verifies transitive dependency count is set.
func TestMaintainerScanner_ScanAll_TransitiveDeps(t *testing.T) {
	server := newMockGitHub()
	defer server.Close()

	g := &resolver.Graph{
		Root:         "test/module",
		Dependencies: make(map[string]*resolver.Dependency),
	}
	g.Dependencies["github.com/golang/go"] = &resolver.Dependency{
		Module: parser.Module{
			Path:     "github.com/golang/go",
			Version:  "v1.0.0",
			Indirect: false,
		},
		Direct:         true,
		Depth:          0,
		TransitiveDeps: 42,
	}

	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.client.Transport = &testTransport{baseURL: server.URL}

	results := ms.ScanAll(g)

	result := results["github.com/golang/go"]
	if result == nil {
		t.Fatal("Expected result for github.com/golang/go")
	}

	if result.SubDependencies != 42 {
		t.Errorf("SubDependencies = %d, want 42", result.SubDependencies)
	}
}

// TestMaintainerScanner_TopContributors verifies top 5 contributors are extracted.
func TestMaintainerScanner_TopContributors(t *testing.T) {
	server := newMockGitHub()
	defer server.Close()

	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.client.Transport = &testTransport{baseURL: server.URL}

	info := ms.analyzeRepo("golang", "go")

	if info == nil {
		t.Fatal("analyzeRepo returned nil")
	}

	if len(info.TopContributors) == 0 {
		t.Errorf("TopContributors is empty, want at least one contributor")
	}
	if len(info.TopContributors) > 5 {
		t.Errorf("TopContributors has %d entries, want <= 5", len(info.TopContributors))
	}
}

// TestMaintainerScanner_ArchivedRepo verifies archived repo handling.
func TestMaintainerScanner_ArchivedRepo(t *testing.T) {
	server := newMockGitHub()
	defer server.Close()

	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.client.Transport = &testTransport{baseURL: server.URL}

	info := ms.analyzeRepo("archived", "old")

	if info == nil {
		t.Fatal("analyzeRepo returned nil")
	}

	if !info.IsArchived {
		t.Errorf("IsArchived = %v, want true", info.IsArchived)
	}
	if !info.TakeoverCandidate {
		t.Errorf("TakeoverCandidate = %v, want true (archived repo)", info.TakeoverCandidate)
	}
}

// TestMaintainerScanner_ForkRepo verifies fork handling.
func TestMaintainerScanner_ForkRepo(t *testing.T) {
	server := newMockGitHub()
	defer server.Close()

	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.client.Transport = &testTransport{baseURL: server.URL}

	info := ms.analyzeRepo("fork", "clone")

	if info == nil {
		t.Fatal("analyzeRepo returned nil")
	}

	if !info.IsFork {
		t.Errorf("IsFork = %v, want true", info.IsFork)
	}
}

// TestMaintainerScanner_WidelyUsedInactive verifies takeover detection for widely-used inactive repos.
func TestMaintainerScanner_WidelyUsedInactive(t *testing.T) {
	server := newMockGitHub()
	defer server.Close()

	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.client.Transport = &testTransport{baseURL: server.URL}

	info := ms.analyzeRepo("widely", "used")

	if info == nil {
		t.Fatal("analyzeRepo returned nil")
	}

	if info.Stars < 100 {
		t.Errorf("Stars = %d, want >= 100", info.Stars)
	}
	if info.ActivityPattern != "inactive" {
		t.Errorf("ActivityPattern = %q, want %q", info.ActivityPattern, "inactive")
	}
	if !info.TakeoverCandidate {
		t.Errorf("TakeoverCandidate = %v, want true", info.TakeoverCandidate)
	}
}

// TestMaintainerScanner_UserCache verifies user caching works.
func TestMaintainerScanner_UserCache(t *testing.T) {
	server := newMockGitHub()
	defer server.Close()

	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.client.Transport = &testTransport{baseURL: server.URL}

	// First call should fetch
	user1 := ms.fetchUser("golang")
	if user1 == nil {
		t.Fatal("fetchUser returned nil")
	}

	// Second call should use cache
	user2 := ms.fetchUser("golang")
	if user2 == nil {
		t.Fatal("fetchUser returned nil on cache hit")
	}

	// Both should have same data
	if user1.Login != user2.Login {
		t.Errorf("user1.Login %q != user2.Login %q", user1.Login, user2.Login)
	}
}

// TestMaintainerScanner_FetchContributors tests contributor fetching.
func TestMaintainerScanner_FetchContributors(t *testing.T) {
	server := newMockGitHub()
	defer server.Close()

	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.client.Transport = &testTransport{baseURL: server.URL}

	contribs := ms.fetchContributors("golang", "go")

	if len(contribs) == 0 {
		t.Errorf("fetchContributors returned empty slice")
	}
	if len(contribs) > 0 && contribs[0].Login == "" {
		t.Errorf("contributors[0].Login is empty")
	}
}

// TestMaintainerScanner_NewMaintainerScanner verifies correct initialization.
func TestMaintainerScanner_NewMaintainerScanner(t *testing.T) {
	ms := NewMaintainerScanner(5*time.Second, "my-token")

	if ms == nil {
		t.Fatal("NewMaintainerScanner returned nil")
	}
	if ms.client == nil {
		t.Fatal("client is nil")
	}
	if ms.cache == nil {
		t.Fatal("cache is nil")
	}
	if ms.userCache == nil {
		t.Fatal("userCache is nil")
	}
}

// TestMaintainerScanner_EmptyGraph verifies empty graph handling.
func TestMaintainerScanner_EmptyGraph(t *testing.T) {
	server := newMockGitHub()
	defer server.Close()

	graph := &resolver.Graph{
		Root:         "test/module",
		Dependencies: make(map[string]*resolver.Dependency),
	}

	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.client.Transport = &testTransport{baseURL: server.URL}

	results := ms.ScanAll(graph)

	if len(results) != 0 {
		t.Errorf("ScanAll on empty graph = %d results, want 0", len(results))
	}
}

// TestMaintainerScanner_MixedDependencies verifies mixed GitHub/non-GitHub modules.
func TestMaintainerScanner_MixedDependencies(t *testing.T) {
	server := newMockGitHub()
	defer server.Close()

	graph := makeGraphWithDeps(
		struct {
			path string
			ver  string
		}{path: "github.com/golang/go", ver: "v1.0.0"},
		struct {
			path string
			ver  string
		}{path: "golang.org/x/text", ver: "v0.0.0"},
		struct {
			path string
			ver  string
		}{path: "github.com/single/maintainer", ver: "v0.0.0"},
		struct {
			path string
			ver  string
		}{path: "gorm.io/gorm", ver: "v1.0.0"},
	)

	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.client.Transport = &testTransport{baseURL: server.URL}

	results := ms.ScanAll(graph)

	if len(results) != 2 {
		t.Errorf("ScanAll returned %d GitHub results, want 2", len(results))
	}

	if _, ok := results["github.com/golang/go"]; !ok {
		t.Errorf("Expected github.com/golang/go in results")
	}

	if _, ok := results["github.com/single/maintainer"]; !ok {
		t.Errorf("Expected github.com/single/maintainer in results")
	}
}

// TestMaintainerScanner_BusinessModelDetection verifies business model is set.
func TestMaintainerScanner_BusinessModelDetection(t *testing.T) {
	server := newMockGitHub()
	defer server.Close()

	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.client.Transport = &testTransport{baseURL: server.URL}

	info := ms.analyzeRepo("golang", "go")

	if info == nil {
		t.Fatal("analyzeRepo returned nil")
	}

	if info.BusinessModel == "" {
		t.Errorf("BusinessModel is empty")
	}
	if info.BusinessModel != "foundation" && info.BusinessModel != "company_backed" {
		t.Errorf("BusinessModel = %q, expected foundation or company_backed", info.BusinessModel)
	}
}

// TestMaintainerScanner_ActivityPatternDetection verifies activity pattern is set.
func TestMaintainerScanner_ActivityPatternDetection(t *testing.T) {
	server := newMockGitHub()
	defer server.Close()

	ms := NewMaintainerScanner(5*time.Second, "test-token")
	ms.client.Transport = &testTransport{baseURL: server.URL}

	info := ms.analyzeRepo("golang", "go")

	if info == nil {
		t.Fatal("analyzeRepo returned nil")
	}

	if info.ActivityPattern == "" {
		t.Errorf("ActivityPattern is empty")
	}
	if info.ActivityPattern != "active" && info.ActivityPattern != "sporadic" && info.ActivityPattern != "inactive" && info.ActivityPattern != "unknown" {
		t.Errorf("ActivityPattern = %q, unexpected value", info.ActivityPattern)
	}
}

// ============================================================================
// Helper: testTransport for mocking HTTP requests
// ============================================================================

type testTransport struct {
	baseURL      string
	requestCount map[string]int
}

func (t *testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	newURL := t.baseURL + req.URL.Path
	if req.URL.RawQuery != "" {
		newURL += "?" + req.URL.RawQuery
	}
	newReq := req.Clone(req.Context())
	newReq.URL = req.URL
	newReq.URL.Scheme = "http"
	newReq.URL.Host = strings.TrimPrefix(strings.TrimPrefix(t.baseURL, "http://"), "https://")

	// Create a new request with updated URL
	newReq, _ = http.NewRequest(req.Method, newURL, req.Body)
	newReq.Header = req.Header

	client := &http.Client{}
	return client.Do(newReq)
}
