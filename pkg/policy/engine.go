// Package policy implements organizational policy evaluation for supply chain risk.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// Policy defines organizational rules for acceptable supply chain risk.
//
// The JSON shape of this struct is the public schema users author at the
// command line via --policy. Reference policy files live under examples/
// (policy-strict.json, policy-moderate.json, policy-custom.json)
// keep them in sync when fields change here. DefaultStrictPolicy and
// DefaultModeratePolicy below define the values mirrored by the first two.
type Policy struct {
	// MaxRiskScore fails if any dependency exceeds this score (0-100).
	MaxRiskScore *int `json:"max_risk_score,omitempty"`

	// MaxOverallScore fails if the overall project score exceeds this.
	MaxOverallScore *int `json:"max_overall_score,omitempty"`

	// NoKnownVulns fails if any dependency has known vulnerabilities.
	NoKnownVulns bool `json:"no_known_vulns,omitempty"`

	// NoCriticalVulns fails only on critical/high severity vulns.
	NoCriticalVulns bool `json:"no_critical_vulns,omitempty"`

	// NoSingleMaintainer fails if any direct dependency has bus factor <= 1.
	NoSingleMaintainer bool `json:"no_single_maintainer,omitempty"`

	// NoUnmaintained fails if any dependency hasn't been released in this many months.
	NoUnmaintainedMonths *int `json:"no_unmaintained_months,omitempty"`

	// NoArchived fails if any dependency is archived.
	NoArchived bool `json:"no_archived,omitempty"`

	// NoDeprecated fails if any dependency is deprecated.
	NoDeprecated bool `json:"no_deprecated,omitempty"`

	// NoTyposquatting fails if any dependency has a typosquatting indicator.
	NoTyposquatting bool `json:"no_typosquatting,omitempty"`

	// MaxDepth fails if any dependency is deeper than this level of transitivity.
	MaxDepth *int `json:"max_depth,omitempty"`

	// AllowedModules is a whitelist — if set, only these modules are allowed.
	AllowedModules []string `json:"allowed_modules,omitempty"`

	// BlockedModules is a blacklist — these modules are never allowed.
	BlockedModules []string `json:"blocked_modules,omitempty"`

	// MaxCIScore fails if the CI/CD risk score exceeds this.
	MaxCIScore *int `json:"max_ci_score,omitempty"`
}

// Violation represents a single policy violation.
type Violation struct {
	Rule     string `json:"rule"`
	Module   string `json:"module,omitempty"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"` // "error" or "warning"
}

// Result holds the outcome of policy evaluation.
type Result struct {
	Pass       bool        `json:"pass"`
	Violations []Violation `json:"violations"`
}

// LoadPolicy reads a policy from a JSON file.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path) //#nosec G304 -- caller-supplied policy file path is the CLI's input contract
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}

	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy file: %w", err)
	}

	return &p, nil
}

// EvalInput bundles all data needed for policy evaluation.
type EvalInput struct {
	ProjectScore *scorer.ProjectScore
	Maintainers  map[string]*scanner.MaintainerInfo
	Typosquats   map[string]*scanner.TyposquatResult
	CIReport     *scanner.CIReport
}

// Evaluate checks all dependencies against the policy and returns violations.
func (p *Policy) Evaluate(input EvalInput) *Result {
	result := &Result{Pass: true}
	ps := input.ProjectScore

	// Overall project score.
	if p.MaxOverallScore != nil && ps.OverallScore > *p.MaxOverallScore {
		result.addError("max_overall_score", "",
			fmt.Sprintf("overall risk score %d exceeds maximum %d", ps.OverallScore, *p.MaxOverallScore))
	}

	// Per-dependency checks.
	for _, ds := range ps.Dependencies {
		// Max risk score.
		if p.MaxRiskScore != nil && ds.RiskScore > *p.MaxRiskScore {
			result.addError("max_risk_score", ds.Module,
				fmt.Sprintf("risk score %d exceeds maximum %d", ds.RiskScore, *p.MaxRiskScore))
		}

		// No known vulns.
		if p.NoKnownVulns && len(ds.Vulns) > 0 {
			ids := make([]string, 0, len(ds.Vulns))
			for _, v := range ds.Vulns {
				ids = append(ids, v.ID)
			}
			result.addError("no_known_vulns", ds.Module,
				fmt.Sprintf("has %d known vulnerabilities: %s", len(ds.Vulns), strings.Join(ids, ", ")))
		}

		// No critical vulns.
		if p.NoCriticalVulns {
			for _, v := range ds.Vulns {
				sev := strings.ToUpper(v.Severity)
				if sev == "CRITICAL" || sev == "HIGH" {
					result.addError("no_critical_vulns", ds.Module,
						fmt.Sprintf("has %s severity vulnerability: %s", v.Severity, v.ID))
				}
			}
		}

		// No single maintainer (direct deps only).
		if p.NoSingleMaintainer && ds.Direct {
			if mi, ok := input.Maintainers[ds.Module]; ok {
				if mi.BusFactor <= 1 && mi.ContributorCount > 0 {
					result.addError("no_single_maintainer", ds.Module,
						fmt.Sprintf("bus factor is %d (single maintainer risk)", mi.BusFactor))
				}
			}
		}

		// No unmaintained.
		if p.NoUnmaintainedMonths != nil && ds.Maintenance != nil {
			if ds.Maintenance.MonthsSinceRelease > *p.NoUnmaintainedMonths {
				result.addError("no_unmaintained", ds.Module,
					fmt.Sprintf("last release %d months ago (max: %d)", ds.Maintenance.MonthsSinceRelease, *p.NoUnmaintainedMonths))
			}
		}

		// No archived.
		if p.NoArchived && ds.Maintenance != nil && ds.Maintenance.Archived {
			result.addError("no_archived", ds.Module, "repository is archived")
		}

		// No deprecated.
		if p.NoDeprecated && ds.Maintenance != nil && ds.Maintenance.Deprecated {
			result.addError("no_deprecated", ds.Module, "module is deprecated")
		}

		// No typosquatting.
		if p.NoTyposquatting {
			if ts, ok := input.Typosquats[ds.Module]; ok {
				result.addError("no_typosquatting", ds.Module,
					fmt.Sprintf("similar to %s (confidence: %.0f%%)", ts.SimilarTo, ts.Confidence*100))
			}
		}

		// Blocked modules.
		for _, blocked := range p.BlockedModules {
			if ds.Module == blocked || strings.HasPrefix(ds.Module, blocked+"/") {
				result.addError("blocked_module", ds.Module,
					fmt.Sprintf("module is on the blocklist"))
			}
		}

		// Allowed modules (whitelist).
		if len(p.AllowedModules) > 0 && ds.Direct {
			allowed := false
			for _, a := range p.AllowedModules {
				if ds.Module == a || strings.HasPrefix(ds.Module, a+"/") {
					allowed = true
					break
				}
			}
			if !allowed {
				result.addError("allowed_modules", ds.Module,
					"module is not on the allowlist")
			}
		}
	}

	// CI/CD score.
	if p.MaxCIScore != nil && input.CIReport != nil {
		if input.CIReport.OverallScore > *p.MaxCIScore {
			result.addError("max_ci_score", "",
				fmt.Sprintf("CI/CD risk score %d exceeds maximum %d", input.CIReport.OverallScore, *p.MaxCIScore))
		}
	}

	return result
}

func (r *Result) addError(rule, module, detail string) {
	r.Pass = false
	r.Violations = append(r.Violations, Violation{
		Rule:     rule,
		Module:   module,
		Detail:   detail,
		Severity: "error",
	})
}

// FormatText returns a human-readable summary of violations.
func (r *Result) FormatText(noColor bool) string {
	if r.Pass {
		if noColor {
			return "PASS: All policies satisfied.\n"
		}
		return "\033[32mPASS: All policies satisfied.\033[0m\n"
	}

	var b strings.Builder
	if noColor {
		fmt.Fprintf(&b, "FAIL: %d policy violation(s) found.\n\n", len(r.Violations))
	} else {
		fmt.Fprintf(&b, "\033[31mFAIL: %d policy violation(s) found.\033[0m\n\n", len(r.Violations))
	}

	for i, v := range r.Violations {
		prefix := fmt.Sprintf("  %d. [%s]", i+1, v.Rule)
		if v.Module != "" {
			fmt.Fprintf(&b, "%s %s: %s\n", prefix, v.Module, v.Detail)
		} else {
			fmt.Fprintf(&b, "%s %s\n", prefix, v.Detail)
		}
	}

	return b.String()
}

// FormatJSON returns the result as JSON.
func (r *Result) FormatJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// DefaultStrictPolicy returns a strict policy suitable for production use.
func DefaultStrictPolicy() *Policy {
	maxRisk := 70
	maxOverall := 50
	maxUnmaintained := 24
	maxCI := 50

	return &Policy{
		MaxRiskScore:         &maxRisk,
		MaxOverallScore:      &maxOverall,
		NoCriticalVulns:      true,
		NoSingleMaintainer:   true,
		NoUnmaintainedMonths: &maxUnmaintained,
		NoArchived:           true,
		NoTyposquatting:      true,
		MaxCIScore:           &maxCI,
	}
}

// DefaultModeratePolicy returns a moderate policy for general use.
func DefaultModeratePolicy() *Policy {
	maxRisk := 85
	maxOverall := 70

	return &Policy{
		MaxRiskScore:    &maxRisk,
		MaxOverallScore: &maxOverall,
		NoCriticalVulns: true,
		NoArchived:      true,
	}
}
