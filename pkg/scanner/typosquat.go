package scanner

import (
	"context"
	"strings"

	"github.com/unidoc/unisupply/pkg/progress"
	"github.com/unidoc/unisupply/pkg/resolver"
)

// TyposquatResult holds typosquatting analysis for a module.
type TyposquatResult struct {
	Module         string            `json:"module"`
	SimilarTo      string            `json:"similar_to"`
	Distance       int               `json:"distance"`
	Confidence     float64           `json:"confidence"` // 0.0-1.0, higher = more suspicious
	Indicators     []string          `json:"indicators"`
	SuspectMatches []TyposquatResult `json:"suspect_matches,omitempty"` // Low-confidence matches for debuggability
}

// wellKnownModules is a list of popular Go modules that typosquatters target.
var wellKnownModules = []string{
	"github.com/gin-gonic/gin",
	"github.com/gorilla/mux",
	"github.com/gorilla/websocket",
	"github.com/go-chi/chi",
	"github.com/labstack/echo",
	"github.com/stretchr/testify",
	"github.com/sirupsen/logrus",
	"github.com/uber-go/zap",
	"go.uber.org/zap",
	"github.com/spf13/cobra",
	"github.com/spf13/viper",
	"github.com/spf13/pflag",
	"github.com/go-sql-driver/mysql",
	"github.com/lib/pq",
	"github.com/jackc/pgx",
	"github.com/redis/go-redis",
	"github.com/go-redis/redis",
	"github.com/aws/aws-sdk-go",
	"github.com/aws/aws-sdk-go-v2",
	"google.golang.org/grpc",
	"google.golang.org/protobuf",
	"github.com/golang/protobuf",
	"github.com/prometheus/client_golang",
	"github.com/hashicorp/consul",
	"github.com/hashicorp/vault",
	"github.com/hashicorp/terraform",
	"github.com/docker/docker",
	"github.com/kubernetes/kubernetes",
	"k8s.io/client-go",
	"k8s.io/api",
	"github.com/go-gorm/gorm",
	"gorm.io/gorm",
	"github.com/jmoiron/sqlx",
	"github.com/mattn/go-sqlite3",
	"github.com/dgrijalva/jwt-go",
	"github.com/golang-jwt/jwt",
	"github.com/google/uuid",
	"github.com/google/go-cmp",
	"github.com/mitchellh/mapstructure",
	"github.com/fatih/color",
	"github.com/pkg/errors",
	"github.com/go-playground/validator",
	"github.com/shopspring/decimal",
	"github.com/tidwall/gjson",
	"github.com/valyala/fasthttp",
	"github.com/gofiber/fiber",
	"github.com/unidoc/unipdf",
	"github.com/unidoc/unioffice",
	"golang.org/x/crypto",
	"golang.org/x/net",
	"golang.org/x/sys",
	"golang.org/x/text",
	"golang.org/x/sync",
	"golang.org/x/tools",
	"golang.org/x/oauth2",
}

// TyposquatScanner detects potential typosquatting in module names.
type TyposquatScanner struct{}

// NewTyposquatScanner creates a new typosquatting scanner.
func NewTyposquatScanner() *TyposquatScanner {
	return &TyposquatScanner{}
}

// ScanAll checks all dependencies for typosquatting indicators.
func (ts *TyposquatScanner) ScanAll(ctx context.Context, graph *resolver.Graph) map[string]*TyposquatResult {
	rep := progress.From(ctx)
	total := len(graph.Dependencies)
	results := make(map[string]*TyposquatResult)

	i := 0
	for _, dep := range graph.Dependencies {
		i++
		if result := ts.checkModule(dep.Module.Path); result != nil {
			results[dep.Module.Path] = result
		}
		rep.Progress(i, total)
	}

	return results
}

func (ts *TyposquatScanner) checkModule(modPath string) *TyposquatResult {
	// Skip well-known modules themselves.
	for _, known := range wellKnownModules {
		if modPath == known {
			return nil
		}
	}

	var bestMatch *TyposquatResult
	var suspectMatches []TyposquatResult

	for _, known := range wellKnownModules {
		result := compareModules(modPath, known)
		if result == nil {
			continue
		}

		// Collect low-confidence matches as suspects.
		if result.Confidence < 0.7 {
			suspectMatches = append(suspectMatches, *result)
			continue
		}

		// Track the best high-confidence match.
		if bestMatch == nil || result.Confidence > bestMatch.Confidence {
			bestMatch = result
		}
	}

	// If we have a high-confidence match, attach suspect matches for debuggability.
	if bestMatch != nil {
		bestMatch.SuspectMatches = suspectMatches
		return bestMatch
	}

	// No high-confidence match found.
	return nil
}

func compareModules(candidate, known string) *TyposquatResult {
	// Extract the last path component (package name) for comparison.
	candidateName := lastPathComponent(candidate)
	knownName := lastPathComponent(known)

	// Also compare full paths for org-level typosquatting.
	candidateOrg := orgComponent(candidate)
	knownOrg := orgComponent(known)

	var indicators []string
	confidence := 0.0

	// 1. Check package name similarity via Levenshtein distance.
	nameDist := levenshtein(candidateName, knownName)
	if nameDist > 0 && nameDist <= 2 && len(knownName) > 3 {
		confidence += 0.5
		indicators = append(indicators, "similar_package_name")
	}

	// 2. Check org/user similarity.
	if candidateOrg != knownOrg {
		orgDist := levenshtein(candidateOrg, knownOrg)
		if orgDist > 0 && orgDist <= 2 && len(knownOrg) > 3 {
			confidence += 0.3
			indicators = append(indicators, "similar_org_name")
		}
	}

	// 3. Check for common typosquatting patterns.
	if checkSwappedChars(candidateName, knownName) {
		confidence += 0.2
		indicators = append(indicators, "swapped_characters")
	}
	if checkMissingDash(candidateName, knownName) {
		confidence += 0.2
		indicators = append(indicators, "missing_separator")
	}
	if checkExtraChar(candidateName, knownName) {
		confidence += 0.15
		indicators = append(indicators, "extra_character")
	}
	if checkHomoglyph(candidateName, knownName) {
		confidence += 0.3
		indicators = append(indicators, "homoglyph_substitution")
	}

	// 4. Check if same package name under different org.
	if candidateName == knownName && candidateOrg != knownOrg {
		confidence += 0.4
		indicators = append(indicators, "same_name_different_org")
	}

	if confidence < 0.3 || len(indicators) == 0 {
		return nil
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	totalDist := levenshtein(candidate, known)

	return &TyposquatResult{
		Module:     candidate,
		SimilarTo:  known,
		Distance:   totalDist,
		Confidence: confidence,
		Indicators: indicators,
	}
}

func lastPathComponent(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return path
	}
	return parts[len(parts)-1]
}

func orgComponent(path string) string {
	// For "github.com/org/repo" return "org".
	parts := strings.Split(path, "/")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

// levenshtein computes the Levenshtein distance between two strings.
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	// Use two rows for space efficiency.
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)

	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min3(
				prev[j]+1,
				curr[j-1]+1,
				prev[j-1]+cost,
			)
		}
		prev, curr = curr, prev
	}

	return prev[lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// checkSwappedChars detects adjacent character transpositions.
func checkSwappedChars(a, b string) bool {
	if len(a) != len(b) || len(a) < 2 {
		return false
	}
	diffs := 0
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			diffs++
		}
	}
	if diffs != 2 {
		return false
	}
	// Check if it's an adjacent swap.
	for i := 0; i < len(a)-1; i++ {
		if a[i] == b[i+1] && a[i+1] == b[i] {
			return true
		}
	}
	return false
}

// checkMissingDash detects missing hyphens/underscores.
func checkMissingDash(a, b string) bool {
	stripped := strings.ReplaceAll(strings.ReplaceAll(b, "-", ""), "_", "")
	candidateStripped := strings.ReplaceAll(strings.ReplaceAll(a, "-", ""), "_", "")
	return candidateStripped == stripped && a != b
}

// checkExtraChar detects one extra character added.
func checkExtraChar(a, b string) bool {
	if len(a) != len(b)+1 {
		return false
	}
	j := 0
	skipped := false
	for i := 0; i < len(a) && j < len(b); i++ {
		switch {
		case a[i] == b[j]:
			j++
		case !skipped:
			skipped = true
		default:
			return false
		}
	}
	return true
}

// checkHomoglyph detects common character substitutions that look similar.
func checkHomoglyph(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	homoglyphs := map[byte][]byte{
		'l': {'1', 'I', 'i'},
		'1': {'l', 'I', 'i'},
		'0': {'O', 'o'},
		'O': {'0', 'o'},
		'o': {'0', 'O'},
		'I': {'l', '1'},
		'i': {'l', '1'},
		'n': {'m'},
		'm': {'n'},
	}

	diffs := 0
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			diffs++
			if subs, ok := homoglyphs[b[i]]; ok {
				found := false
				for _, s := range subs {
					if a[i] == s {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			} else {
				return false
			}
		}
	}

	return diffs > 0 && diffs <= 2
}
