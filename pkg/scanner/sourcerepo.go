package scanner

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/unidoc/unisupply/pkg/resolver"
)

// Values of MaintainerInfo.SourceRepoVia: how a module's GitHub repository
// was determined.
const (
	// SourceViaModulePath means the module path itself starts with github.com/.
	SourceViaModulePath = "module_path"

	// SourceViaProxyOrigin means the module proxy's .info Origin.URL names a
	// github.com repository.
	SourceViaProxyOrigin = "proxy_origin"

	// SourceViaGopkgIn means the module is a gopkg.in path, which maps to
	// GitHub by a fixed rule.
	SourceViaGopkgIn = "gopkg_in_rule"
)

// gopkgInPath matches a gopkg.in module path: gopkg.in/pkg.vN or
// gopkg.in/user/pkg.vN, with an optional -unstable suffix. Anything else
// under gopkg.in (extra segments, a missing version) does not match.
var gopkgInPath = regexp.MustCompile(
	`^gopkg\.in/(?:([A-Za-z0-9][A-Za-z0-9-]*)/)?([A-Za-z0-9][A-Za-z0-9_.-]*?)\.v(?:0|[1-9][0-9]*)(?:-unstable)?$`)

// ownerNamePattern and repoNamePattern are GitHub's own name alphabets. They
// are enforced for names that do not come from a github.com module path so a
// hostile or garbled Origin cannot inject path segments or query strings into
// the GitHub API URLs built from them.
var (
	ownerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*$`)
	repoNamePattern  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
)

// ResolveSourceRepo returns the GitHub owner and repository behind a module
// and how it was determined, or empty strings when the module cannot be mapped
// without contacting a new host. originURL is the module proxy's Origin.URL
// for the module and may be empty.
//
// The order matters: a github.com module path always wins, so modules that
// resolved before this resolver existed resolve exactly as they did. Only
// modules that previously had no GitHub data fall through to the proxy Origin
// and the static gopkg.in rule. No step performs I/O.
func ResolveSourceRepo(modPath, originURL string) (owner, repo, via string) {
	if owner, repo = parseGitHubPath(modPath); owner != "" && repo != "" {
		return owner, repo, SourceViaModulePath
	}
	if owner, repo = githubRepoFromOrigin(originURL); owner != "" {
		return owner, repo, SourceViaProxyOrigin
	}
	if owner, repo = gopkgInRepo(modPath); owner != "" {
		return owner, repo, SourceViaGopkgIn
	}
	return "", "", ""
}

// githubRepoFromOrigin extracts owner and repo from a module proxy Origin.URL
// such as https://github.com/yaml/go-yaml. It returns empty strings for any
// other host (for example go.googlesource.com), for a path that is not exactly
// owner/repo, and for malformed input. A trailing .git is removed.
func githubRepoFromOrigin(originURL string) (owner, repo string) {
	if originURL == "" {
		return "", ""
	}
	u, err := url.Parse(originURL)
	if err != nil {
		return "", ""
	}
	switch u.Scheme {
	case "https", "http", "git":
	default:
		return "", ""
	}
	if !strings.EqualFold(u.Hostname(), "github.com") {
		return "", ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 {
		return "", ""
	}
	owner, repo = parts[0], strings.TrimSuffix(parts[1], ".git")
	if !ownerNamePattern.MatchString(owner) || !repoNamePattern.MatchString(repo) {
		return "", ""
	}
	return owner, repo
}

// gopkgInRepo maps a gopkg.in module path to its GitHub repository:
// gopkg.in/pkg.vN is github.com/go-pkg/pkg and gopkg.in/user/pkg.vN is
// github.com/user/pkg. It is the rule gopkg.in itself documents, and works
// offline.
func gopkgInRepo(modPath string) (owner, repo string) {
	m := gopkgInPath.FindStringSubmatch(modPath)
	if m == nil {
		return "", ""
	}
	owner, repo = m[1], m[2]
	if owner == "" {
		owner = "go-" + repo
	}
	if !ownerNamePattern.MatchString(owner) || !repoNamePattern.MatchString(repo) {
		return "", ""
	}
	return owner, repo
}

// sourceRepo is a resolved GitHub repository for one module.
type sourceRepo struct {
	owner, repo, via string
}

// resolveSourceRepos resolves every dependency in graph, keyed by module path.
// Modules that cannot be mapped to GitHub are omitted. originURLs maps module
// path to proxy Origin.URL and may be nil.
func resolveSourceRepos(graph *resolver.Graph, originURLs map[string]string) map[string]sourceRepo {
	out := make(map[string]sourceRepo, len(graph.Dependencies))
	for _, dep := range graph.Dependencies {
		path := dep.Module.Path
		if owner, repo, via := ResolveSourceRepo(path, originURLs[path]); owner != "" {
			out[path] = sourceRepo{owner: owner, repo: repo, via: via}
		}
	}
	return out
}
