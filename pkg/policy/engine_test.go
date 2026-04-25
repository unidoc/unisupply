package policy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/policy"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// Helper function to create EvalInput with dependencies and overall score.
func makeEvalInput(deps []*scorer.DependencyScore, overallScore int) policy.EvalInput {
	ps := &scorer.ProjectScore{
		OverallScore: overallScore,
		Dependencies: deps,
	}
	return policy.EvalInput{
		ProjectScore: ps,
		Maintainers:  make(map[string]*scanner.MaintainerInfo),
		Typosquats:   make(map[string]*scanner.TyposquatResult),
		CIReport:     nil,
	}
}

// Tests for LoadPolicy
func TestLoadPolicy_ValidJSON(t *testing.T) {
	tempDir := t.TempDir()
	policyPath := filepath.Join(tempDir, "policy.json")

	policyData := map[string]interface{}{
		"max_risk_score":         75,
		"max_overall_score":      60,
		"no_known_vulns":         true,
		"no_critical_vulns":      true,
		"no_single_maintainer":   true,
		"no_unmaintained_months": 24,
		"no_archived":            true,
		"no_deprecated":          true,
		"no_typosquatting":       true,
		"max_depth":              5,
		"max_ci_score":           50,
		"allowed_modules":        []string{"github.com/allowed/*"},
		"blocked_modules":        []string{"github.com/blocked/*"},
	}

	data, err := json.Marshal(policyData)
	if err != nil {
		t.Fatalf("failed to marshal policy data: %v", err)
	}

	if err := os.WriteFile(policyPath, data, 0o644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	p, err := policy.LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("LoadPolicy failed: %v", err)
	}

	if p == nil {
		t.Fatal("policy is nil")
	}
	if p.MaxRiskScore == nil || *p.MaxRiskScore != 75 {
		t.Errorf("MaxRiskScore: expected 75, got %v", p.MaxRiskScore)
	}
	if p.MaxOverallScore == nil || *p.MaxOverallScore != 60 {
		t.Errorf("MaxOverallScore: expected 60, got %v", p.MaxOverallScore)
	}
	if !p.NoKnownVulns {
		t.Errorf("NoKnownVulns: expected true, got %v", p.NoKnownVulns)
	}
	if !p.NoCriticalVulns {
		t.Errorf("NoCriticalVulns: expected true, got %v", p.NoCriticalVulns)
	}
	if !p.NoSingleMaintainer {
		t.Errorf("NoSingleMaintainer: expected true, got %v", p.NoSingleMaintainer)
	}
	if p.NoUnmaintainedMonths == nil || *p.NoUnmaintainedMonths != 24 {
		t.Errorf("NoUnmaintainedMonths: expected 24, got %v", p.NoUnmaintainedMonths)
	}
	if !p.NoArchived {
		t.Errorf("NoArchived: expected true, got %v", p.NoArchived)
	}
	if !p.NoDeprecated {
		t.Errorf("NoDeprecated: expected true, got %v", p.NoDeprecated)
	}
	if !p.NoTyposquatting {
		t.Errorf("NoTyposquatting: expected true, got %v", p.NoTyposquatting)
	}
	if p.MaxDepth == nil || *p.MaxDepth != 5 {
		t.Errorf("MaxDepth: expected 5, got %v", p.MaxDepth)
	}
	if p.MaxCIScore == nil || *p.MaxCIScore != 50 {
		t.Errorf("MaxCIScore: expected 50, got %v", p.MaxCIScore)
	}
	if len(p.AllowedModules) != 1 || p.AllowedModules[0] != "github.com/allowed/*" {
		t.Errorf("AllowedModules: expected [github.com/allowed/*], got %v", p.AllowedModules)
	}
	if len(p.BlockedModules) != 1 || p.BlockedModules[0] != "github.com/blocked/*" {
		t.Errorf("BlockedModules: expected [github.com/blocked/*], got %v", p.BlockedModules)
	}
}

func TestLoadPolicy_InvalidJSON(t *testing.T) {
	tempDir := t.TempDir()
	policyPath := filepath.Join(tempDir, "invalid_policy.json")

	if err := os.WriteFile(policyPath, []byte("{invalid json}"), 0o644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	_, err := policy.LoadPolicy(policyPath)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parsing policy") {
		t.Errorf("expected error to contain 'parsing policy', got: %v", err)
	}
}

func TestLoadPolicy_FileNotFound(t *testing.T) {
	_, err := policy.LoadPolicy("/nonexistent/path/to/policy.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
	if !strings.Contains(err.Error(), "reading policy") {
		t.Errorf("expected error to contain 'reading policy', got: %v", err)
	}
}

// Tests for Default Policies
func TestDefaultStrictPolicy(t *testing.T) {
	p := policy.DefaultStrictPolicy()

	if p.MaxRiskScore == nil || *p.MaxRiskScore != 70 {
		t.Errorf("MaxRiskScore: expected 70, got %v", p.MaxRiskScore)
	}
	if p.MaxOverallScore == nil || *p.MaxOverallScore != 50 {
		t.Errorf("MaxOverallScore: expected 50, got %v", p.MaxOverallScore)
	}
	if !p.NoCriticalVulns {
		t.Errorf("NoCriticalVulns: expected true")
	}
	if !p.NoSingleMaintainer {
		t.Errorf("NoSingleMaintainer: expected true")
	}
	if p.NoUnmaintainedMonths == nil || *p.NoUnmaintainedMonths != 24 {
		t.Errorf("NoUnmaintainedMonths: expected 24, got %v", p.NoUnmaintainedMonths)
	}
	if !p.NoArchived {
		t.Errorf("NoArchived: expected true")
	}
	if !p.NoTyposquatting {
		t.Errorf("NoTyposquatting: expected true")
	}
	if p.MaxCIScore == nil || *p.MaxCIScore != 50 {
		t.Errorf("MaxCIScore: expected 50, got %v", p.MaxCIScore)
	}
}

func TestDefaultModeratePolicy(t *testing.T) {
	p := policy.DefaultModeratePolicy()

	if p.MaxRiskScore == nil || *p.MaxRiskScore != 85 {
		t.Errorf("MaxRiskScore: expected 85, got %v", p.MaxRiskScore)
	}
	if p.MaxOverallScore == nil || *p.MaxOverallScore != 70 {
		t.Errorf("MaxOverallScore: expected 70, got %v", p.MaxOverallScore)
	}
	if !p.NoCriticalVulns {
		t.Errorf("NoCriticalVulns: expected true")
	}
	if !p.NoArchived {
		t.Errorf("NoArchived: expected true")
	}
}

// Tests for Evaluate - AllPass
func TestEvaluate_AllPass(t *testing.T) {
	p := policy.DefaultStrictPolicy()

	// Create a clean dependency with low scores
	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/example/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   20,
			Vulns:       []scanner.Vulnerability{},
			Maintenance: &scanner.MaintenanceInfo{MonthsSinceRelease: 1, Archived: false, Deprecated: false},
		},
	}

	input := makeEvalInput(deps, 20)
	input.Maintainers["github.com/example/pkg"] = &scanner.MaintainerInfo{
		BusFactor:        2,
		ContributorCount: 5,
	}

	result := p.Evaluate(input)

	if !result.Pass {
		t.Errorf("expected Pass=true, got %v. Violations: %v", result.Pass, result.Violations)
	}
	if len(result.Violations) != 0 {
		t.Errorf("expected no violations, got %d: %v", len(result.Violations), result.Violations)
	}
}

// Tests for Evaluate - MaxRiskScore
func TestEvaluate_MaxRiskScore(t *testing.T) {
	maxScore := 70
	p := &policy.Policy{MaxRiskScore: &maxScore}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/high-risk/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   80,
			Vulns:       []scanner.Vulnerability{},
			Maintenance: &scanner.MaintenanceInfo{},
		},
	}

	input := makeEvalInput(deps, 80)
	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	if len(result.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Rule != "max_risk_score" {
		t.Errorf("expected rule 'max_risk_score', got %s", result.Violations[0].Rule)
	}
	if result.Violations[0].Module != "github.com/high-risk/pkg" {
		t.Errorf("expected module 'github.com/high-risk/pkg', got %s", result.Violations[0].Module)
	}
	if !strings.Contains(result.Violations[0].Detail, "80") || !strings.Contains(result.Violations[0].Detail, "70") {
		t.Errorf("expected detail to contain scores 80 and 70, got: %s", result.Violations[0].Detail)
	}
}

// Tests for Evaluate - MaxOverallScore
func TestEvaluate_MaxOverallScore(t *testing.T) {
	maxScore := 50
	p := &policy.Policy{MaxOverallScore: &maxScore}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/example/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   30,
			Maintenance: &scanner.MaintenanceInfo{},
		},
	}

	input := makeEvalInput(deps, 60)
	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	if len(result.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Rule != "max_overall_score" {
		t.Errorf("expected rule 'max_overall_score', got %s", result.Violations[0].Rule)
	}
	if !strings.Contains(result.Violations[0].Detail, "60") || !strings.Contains(result.Violations[0].Detail, "50") {
		t.Errorf("expected detail to contain scores 60 and 50, got: %s", result.Violations[0].Detail)
	}
}

// Tests for Evaluate - NoKnownVulns
func TestEvaluate_NoKnownVulns(t *testing.T) {
	p := &policy.Policy{NoKnownVulns: true}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/vuln/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   50,
			Maintenance: &scanner.MaintenanceInfo{},
			Vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-1001", "MEDIUM", "v1.1.0"),
				testutil.MakeVuln("CVE-2024-1002", "LOW", "v1.2.0"),
			},
		},
	}

	input := makeEvalInput(deps, 50)
	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	if len(result.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Rule != "no_known_vulns" {
		t.Errorf("expected rule 'no_known_vulns', got %s", result.Violations[0].Rule)
	}
	detail := result.Violations[0].Detail
	if !strings.Contains(detail, "2") || !strings.Contains(detail, "CVE-2024-1001") || !strings.Contains(detail, "CVE-2024-1002") {
		t.Errorf("expected detail to list both CVE IDs, got: %s", detail)
	}
}

// Tests for Evaluate - NoCriticalVulns with CRITICAL severity
func TestEvaluate_NoCriticalVulns_Critical(t *testing.T) {
	p := &policy.Policy{NoCriticalVulns: true}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/critical/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   80,
			Maintenance: &scanner.MaintenanceInfo{},
			Vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-9999", "CRITICAL", "v1.1.0"),
			},
		},
	}

	input := makeEvalInput(deps, 80)
	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	if len(result.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Rule != "no_critical_vulns" {
		t.Errorf("expected rule 'no_critical_vulns', got %s", result.Violations[0].Rule)
	}
	if !strings.Contains(result.Violations[0].Detail, "CRITICAL") || !strings.Contains(result.Violations[0].Detail, "CVE-2024-9999") {
		t.Errorf("expected detail to contain CRITICAL and CVE ID, got: %s", result.Violations[0].Detail)
	}
}

// Tests for Evaluate - NoCriticalVulns with HIGH severity
func TestEvaluate_NoCriticalVulns_High(t *testing.T) {
	p := &policy.Policy{NoCriticalVulns: true}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/high/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   70,
			Maintenance: &scanner.MaintenanceInfo{},
			Vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-8888", "HIGH", "v1.1.0"),
			},
		},
	}

	input := makeEvalInput(deps, 70)
	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	if len(result.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Rule != "no_critical_vulns" {
		t.Errorf("expected rule 'no_critical_vulns', got %s", result.Violations[0].Rule)
	}
}

// Tests for Evaluate - NoCriticalVulns with MEDIUM severity (should pass)
func TestEvaluate_NoCriticalVulns_Medium(t *testing.T) {
	p := &policy.Policy{NoCriticalVulns: true}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/medium/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   50,
			Maintenance: &scanner.MaintenanceInfo{},
			Vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-5555", "MEDIUM", "v1.1.0"),
			},
		},
	}

	input := makeEvalInput(deps, 50)
	result := p.Evaluate(input)

	if !result.Pass {
		t.Errorf("expected Pass=true for MEDIUM vuln, got false. Violations: %v", result.Violations)
	}
	if len(result.Violations) != 0 {
		t.Errorf("expected no violations for MEDIUM severity, got %d", len(result.Violations))
	}
}

// Tests for Evaluate - NoSingleMaintainer (direct dep)
func TestEvaluate_NoSingleMaintainer_Direct(t *testing.T) {
	p := &policy.Policy{NoSingleMaintainer: true}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/single/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   30,
			Maintenance: &scanner.MaintenanceInfo{},
		},
	}

	input := makeEvalInput(deps, 30)
	input.Maintainers["github.com/single/pkg"] = &scanner.MaintainerInfo{
		BusFactor:        1,
		ContributorCount: 1,
	}

	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	if len(result.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Rule != "no_single_maintainer" {
		t.Errorf("expected rule 'no_single_maintainer', got %s", result.Violations[0].Rule)
	}
	if !strings.Contains(result.Violations[0].Detail, "1") {
		t.Errorf("expected detail to mention bus factor 1, got: %s", result.Violations[0].Detail)
	}
}

// Tests for Evaluate - NoSingleMaintainer (indirect dep - should not trigger)
func TestEvaluate_NoSingleMaintainer_Indirect(t *testing.T) {
	p := &policy.Policy{NoSingleMaintainer: true}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/single/pkg",
			Version:     "v1.0.0",
			Direct:      false,
			RiskScore:   30,
			Maintenance: &scanner.MaintenanceInfo{},
		},
	}

	input := makeEvalInput(deps, 30)
	input.Maintainers["github.com/single/pkg"] = &scanner.MaintainerInfo{
		BusFactor:        1,
		ContributorCount: 1,
	}

	result := p.Evaluate(input)

	if !result.Pass {
		t.Errorf("expected Pass=true for indirect dep, got false. Violations: %v", result.Violations)
	}
	if len(result.Violations) != 0 {
		t.Errorf("expected no violations for indirect dep, got %d", len(result.Violations))
	}
}

// Tests for Evaluate - NoUnmaintained
func TestEvaluate_NoUnmaintained(t *testing.T) {
	max := 24
	p := &policy.Policy{NoUnmaintainedMonths: &max}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/old/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   50,
			Maintenance: testutil.MakeMaintenanceInfo(30, false, false),
		},
	}

	input := makeEvalInput(deps, 50)
	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	if len(result.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Rule != "no_unmaintained" {
		t.Errorf("expected rule 'no_unmaintained', got %s", result.Violations[0].Rule)
	}
	if !strings.Contains(result.Violations[0].Detail, "30") || !strings.Contains(result.Violations[0].Detail, "24") {
		t.Errorf("expected detail to contain months 30 and 24, got: %s", result.Violations[0].Detail)
	}
}

// Tests for Evaluate - NoArchived
func TestEvaluate_NoArchived(t *testing.T) {
	p := &policy.Policy{NoArchived: true}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/archived/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   50,
			Maintenance: testutil.MakeMaintenanceInfo(10, true, false),
		},
	}

	input := makeEvalInput(deps, 50)
	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	if len(result.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Rule != "no_archived" {
		t.Errorf("expected rule 'no_archived', got %s", result.Violations[0].Rule)
	}
	if !strings.Contains(result.Violations[0].Detail, "archived") {
		t.Errorf("expected detail to mention 'archived', got: %s", result.Violations[0].Detail)
	}
}

// Tests for Evaluate - NoDeprecated
func TestEvaluate_NoDeprecated(t *testing.T) {
	p := &policy.Policy{NoDeprecated: true}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/deprecated/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   50,
			Maintenance: testutil.MakeMaintenanceInfo(10, false, true),
		},
	}

	input := makeEvalInput(deps, 50)
	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	if len(result.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Rule != "no_deprecated" {
		t.Errorf("expected rule 'no_deprecated', got %s", result.Violations[0].Rule)
	}
	if !strings.Contains(result.Violations[0].Detail, "deprecated") {
		t.Errorf("expected detail to mention 'deprecated', got: %s", result.Violations[0].Detail)
	}
}

// Tests for Evaluate - NoTyposquatting
func TestEvaluate_NoTyposquatting(t *testing.T) {
	p := &policy.Policy{NoTyposquatting: true}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/example/gin",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   30,
			Maintenance: &scanner.MaintenanceInfo{},
		},
	}

	input := makeEvalInput(deps, 30)
	input.Typosquats["github.com/example/gin"] = &scanner.TyposquatResult{
		Module:     "github.com/example/gin",
		SimilarTo:  "github.com/gin-gonic/gin",
		Confidence: 0.75,
	}

	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	if len(result.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Rule != "no_typosquatting" {
		t.Errorf("expected rule 'no_typosquatting', got %s", result.Violations[0].Rule)
	}
	detail := result.Violations[0].Detail
	if !strings.Contains(detail, "gin-gonic/gin") || !strings.Contains(detail, "75%") {
		t.Errorf("expected detail to contain similar module and confidence, got: %s", detail)
	}
}

// Tests for Evaluate - BlockedModules (exact match)
func TestEvaluate_BlockedModules_Exact(t *testing.T) {
	p := &policy.Policy{
		BlockedModules: []string{"github.com/evil/pkg"},
	}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/evil/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   30,
			Maintenance: &scanner.MaintenanceInfo{},
		},
	}

	input := makeEvalInput(deps, 30)
	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	if len(result.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Rule != "blocked_module" {
		t.Errorf("expected rule 'blocked_module', got %s", result.Violations[0].Rule)
	}
	if result.Violations[0].Module != "github.com/evil/pkg" {
		t.Errorf("expected module 'github.com/evil/pkg', got %s", result.Violations[0].Module)
	}
}

// Tests for Evaluate - BlockedModules (prefix match)
func TestEvaluate_BlockedModules_Prefix(t *testing.T) {
	p := &policy.Policy{
		BlockedModules: []string{"github.com/blocked"},
	}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/blocked/pkg/sub",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   30,
			Maintenance: &scanner.MaintenanceInfo{},
		},
	}

	input := makeEvalInput(deps, 30)
	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	if len(result.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Rule != "blocked_module" {
		t.Errorf("expected rule 'blocked_module', got %s", result.Violations[0].Rule)
	}
}

// Tests for Evaluate - AllowedModules (direct dep not in allowlist)
func TestEvaluate_AllowedModules_NotListed(t *testing.T) {
	p := &policy.Policy{
		AllowedModules: []string{"github.com/allowed"},
	}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/notallowed/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   30,
			Maintenance: &scanner.MaintenanceInfo{},
		},
	}

	input := makeEvalInput(deps, 30)
	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	if len(result.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Rule != "allowed_modules" {
		t.Errorf("expected rule 'allowed_modules', got %s", result.Violations[0].Rule)
	}
}

// Tests for Evaluate - AllowedModules (indirect dep allowed regardless)
func TestEvaluate_AllowedModules_IndirectPass(t *testing.T) {
	p := &policy.Policy{
		AllowedModules: []string{"github.com/allowed"},
	}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/notallowed/pkg",
			Version:     "v1.0.0",
			Direct:      false,
			RiskScore:   30,
			Maintenance: &scanner.MaintenanceInfo{},
		},
	}

	input := makeEvalInput(deps, 30)
	result := p.Evaluate(input)

	if !result.Pass {
		t.Errorf("expected Pass=true for indirect dep, got false. Violations: %v", result.Violations)
	}
}

// Tests for Evaluate - AllowedModules (exact match)
func TestEvaluate_AllowedModules_ExactMatch(t *testing.T) {
	p := &policy.Policy{
		AllowedModules: []string{"github.com/allowed/pkg"},
	}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/allowed/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   30,
			Maintenance: &scanner.MaintenanceInfo{},
		},
	}

	input := makeEvalInput(deps, 30)
	result := p.Evaluate(input)

	if !result.Pass {
		t.Errorf("expected Pass=true for allowed module, got false. Violations: %v", result.Violations)
	}
}

// Tests for Evaluate - AllowedModules (prefix match)
func TestEvaluate_AllowedModules_PrefixMatch(t *testing.T) {
	p := &policy.Policy{
		AllowedModules: []string{"github.com/allowed"},
	}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/allowed/pkg/sub",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   30,
			Maintenance: &scanner.MaintenanceInfo{},
		},
	}

	input := makeEvalInput(deps, 30)
	result := p.Evaluate(input)

	if !result.Pass {
		t.Errorf("expected Pass=true for allowed prefix, got false. Violations: %v", result.Violations)
	}
}

// Tests for Evaluate - MaxCIScore
func TestEvaluate_MaxCIScore(t *testing.T) {
	maxCI := 50
	p := &policy.Policy{MaxCIScore: &maxCI}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/example/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   30,
			Maintenance: &scanner.MaintenanceInfo{},
		},
	}

	input := makeEvalInput(deps, 30)
	input.CIReport = &scanner.CIReport{
		OverallScore: 60,
		OverallLevel: scanner.CIRiskHigh,
	}

	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	if len(result.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Rule != "max_ci_score" {
		t.Errorf("expected rule 'max_ci_score', got %s", result.Violations[0].Rule)
	}
	if !strings.Contains(result.Violations[0].Detail, "60") || !strings.Contains(result.Violations[0].Detail, "50") {
		t.Errorf("expected detail to contain scores 60 and 50, got: %s", result.Violations[0].Detail)
	}
}

// Tests for Evaluate - MaxCIScore with nil CIReport
func TestEvaluate_MaxCIScore_NilReport(t *testing.T) {
	maxCI := 50
	p := &policy.Policy{MaxCIScore: &maxCI}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/example/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   30,
			Maintenance: &scanner.MaintenanceInfo{},
		},
	}

	input := makeEvalInput(deps, 30)
	// CIReport is nil

	result := p.Evaluate(input)

	if !result.Pass {
		t.Errorf("expected Pass=true when CIReport is nil, got false. Violations: %v", result.Violations)
	}
	if len(result.Violations) != 0 {
		t.Errorf("expected no violations when CIReport is nil, got %d", len(result.Violations))
	}
}

// Tests for Evaluate - Multiple Violations
func TestEvaluate_MultipleViolations(t *testing.T) {
	maxRisk := 70
	maxOverall := 50
	p := &policy.Policy{
		MaxRiskScore:       &maxRisk,
		MaxOverallScore:    &maxOverall,
		NoKnownVulns:       true,
		NoCriticalVulns:    true,
		NoSingleMaintainer: true,
	}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/bad/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   80,
			Maintenance: &scanner.MaintenanceInfo{},
			Vulns: []scanner.Vulnerability{
				testutil.MakeVuln("CVE-2024-1111", "CRITICAL", "v1.1.0"),
				testutil.MakeVuln("CVE-2024-2222", "MEDIUM", "v1.2.0"),
			},
		},
	}

	input := makeEvalInput(deps, 60)
	input.Maintainers["github.com/bad/pkg"] = &scanner.MaintainerInfo{
		BusFactor:        1,
		ContributorCount: 1,
	}

	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	// Should have violations for: MaxOverallScore, MaxRiskScore, NoKnownVulns, NoCriticalVulns (CRITICAL), NoSingleMaintainer
	// At least 5 violations
	if len(result.Violations) < 5 {
		t.Errorf("expected at least 5 violations, got %d", len(result.Violations))
	}

	rules := make(map[string]int)
	for _, v := range result.Violations {
		rules[v.Rule]++
	}

	if rules["max_overall_score"] == 0 {
		t.Error("expected max_overall_score violation")
	}
	if rules["max_risk_score"] == 0 {
		t.Error("expected max_risk_score violation")
	}
	if rules["no_known_vulns"] == 0 {
		t.Error("expected no_known_vulns violation")
	}
	if rules["no_critical_vulns"] == 0 {
		t.Error("expected no_critical_vulns violation (for CRITICAL)")
	}
	if rules["no_single_maintainer"] == 0 {
		t.Error("expected no_single_maintainer violation")
	}
}

// Tests for FormatText - Pass
func TestResult_FormatText_Pass(t *testing.T) {
	result := &policy.Result{Pass: true, Violations: []policy.Violation{}}

	text := result.FormatText(true)
	if !strings.Contains(text, "PASS") {
		t.Errorf("expected 'PASS' in output, got: %s", text)
	}
	if !strings.Contains(text, "All policies satisfied") {
		t.Errorf("expected 'All policies satisfied' in output, got: %s", text)
	}
}

// Tests for FormatText - Fail
func TestResult_FormatText_Fail(t *testing.T) {
	result := &policy.Result{
		Pass: false,
		Violations: []policy.Violation{
			{
				Rule:     "max_risk_score",
				Module:   "github.com/example/pkg",
				Detail:   "risk score 80 exceeds maximum 70",
				Severity: "error",
			},
			{
				Rule:     "no_archived",
				Module:   "github.com/other/pkg",
				Detail:   "repository is archived",
				Severity: "error",
			},
		},
	}

	text := result.FormatText(true)
	if !strings.Contains(text, "FAIL") {
		t.Errorf("expected 'FAIL' in output, got: %s", text)
	}
	if !strings.Contains(text, "2") || !strings.Contains(text, "violation") {
		t.Errorf("expected '2 violations' in output, got: %s", text)
	}
	if !strings.Contains(text, "max_risk_score") {
		t.Errorf("expected 'max_risk_score' in output, got: %s", text)
	}
	if !strings.Contains(text, "github.com/example/pkg") {
		t.Errorf("expected module name in output, got: %s", text)
	}
	if !strings.Contains(text, "no_archived") {
		t.Errorf("expected 'no_archived' in output, got: %s", text)
	}
}

// Tests for FormatText - With color
func TestResult_FormatText_Color(t *testing.T) {
	result := &policy.Result{Pass: true, Violations: []policy.Violation{}}

	text := result.FormatText(false)
	if !strings.Contains(text, "\033[32m") && !strings.Contains(text, "PASS") {
		t.Errorf("expected ANSI color codes or PASS in output, got: %s", text)
	}
}

// Tests for FormatJSON
func TestResult_FormatJSON(t *testing.T) {
	result := &policy.Result{
		Pass: false,
		Violations: []policy.Violation{
			{
				Rule:     "max_risk_score",
				Module:   "github.com/example/pkg",
				Detail:   "risk score 80 exceeds maximum 70",
				Severity: "error",
			},
		},
	}

	jsonStr, err := result.FormatJSON()
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}

	var parsed map[string]interface{}
	err = json.Unmarshal([]byte(jsonStr), &parsed)
	if err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if pass, ok := parsed["pass"].(bool); !ok || pass {
		t.Errorf("expected pass=false in JSON, got: %v", parsed["pass"])
	}

	violations, ok := parsed["violations"].([]interface{})
	if !ok || len(violations) != 1 {
		t.Errorf("expected 1 violation in JSON, got: %v", parsed["violations"])
	}

	if v, ok := violations[0].(map[string]interface{}); ok {
		if rule, ok := v["rule"].(string); !ok || rule != "max_risk_score" {
			t.Errorf("expected rule='max_risk_score', got: %v", v["rule"])
		}
		if module, ok := v["module"].(string); !ok || module != "github.com/example/pkg" {
			t.Errorf("expected module='github.com/example/pkg', got: %v", v["module"])
		}
	}
}

// Tests for Evaluate - SingleMaintainerWithZeroContributors (should not trigger)
func TestEvaluate_NoSingleMaintainer_ZeroContributors(t *testing.T) {
	p := &policy.Policy{NoSingleMaintainer: true}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/unknown/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   30,
			Maintenance: &scanner.MaintenanceInfo{},
		},
	}

	input := makeEvalInput(deps, 30)
	input.Maintainers["github.com/unknown/pkg"] = &scanner.MaintainerInfo{
		BusFactor:        1,
		ContributorCount: 0, // Zero contributors, should not trigger
	}

	result := p.Evaluate(input)

	if !result.Pass {
		t.Errorf("expected Pass=true for zero contributors, got false. Violations: %v", result.Violations)
	}
}

// Tests for Evaluate - BlockedModules (no partial match)
func TestEvaluate_BlockedModules_NoPartialMatch(t *testing.T) {
	p := &policy.Policy{
		BlockedModules: []string{"github.com/blocked/lib"},
	}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/blockedx/lib",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   30,
			Maintenance: &scanner.MaintenanceInfo{},
		},
	}

	input := makeEvalInput(deps, 30)
	result := p.Evaluate(input)

	if !result.Pass {
		t.Errorf("expected Pass=true (no blocked match), got false. Violations: %v", result.Violations)
	}
}

// Tests for Evaluate - EmptyDependencies
func TestEvaluate_EmptyDependencies(t *testing.T) {
	p := policy.DefaultStrictPolicy()

	input := makeEvalInput([]*scorer.DependencyScore{}, 0)
	result := p.Evaluate(input)

	if !result.Pass {
		t.Errorf("expected Pass=true for empty deps, got false. Violations: %v", result.Violations)
	}
	if len(result.Violations) != 0 {
		t.Errorf("expected no violations for empty deps, got %d", len(result.Violations))
	}
}

// Tests for Evaluate - NilMaintenance
func TestEvaluate_NilMaintenance(t *testing.T) {
	p := &policy.Policy{NoUnmaintainedMonths: testutil.IntPtr(24)}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/example/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   30,
			Maintenance: nil,
		},
	}

	input := makeEvalInput(deps, 30)
	result := p.Evaluate(input)

	if !result.Pass {
		t.Errorf("expected Pass=true for nil maintenance, got false. Violations: %v", result.Violations)
	}
	if len(result.Violations) != 0 {
		t.Errorf("expected no violations for nil maintenance, got %d", len(result.Violations))
	}
}

// Tests for Evaluate - NilMaintainerInfo
func TestEvaluate_NilMaintainerInfo(t *testing.T) {
	p := &policy.Policy{NoSingleMaintainer: true}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/example/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   30,
			Maintenance: &scanner.MaintenanceInfo{},
		},
	}

	input := makeEvalInput(deps, 30)
	// No maintainer info registered for the module

	result := p.Evaluate(input)

	if !result.Pass {
		t.Errorf("expected Pass=true for nil maintainer info, got false. Violations: %v", result.Violations)
	}
	if len(result.Violations) != 0 {
		t.Errorf("expected no violations for nil maintainer info, got %d", len(result.Violations))
	}
}
