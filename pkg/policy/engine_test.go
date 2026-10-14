package policy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/grade"
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
		Grade:        &grade.Result{RuleVersion: grade.RuleVersion, Letter: grade.LetterA},
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
		"max_grade":               "C",
		"allow_pending":           true,
		"no_known_vulns":          true,
		"no_critical_vulns":       true,
		"no_single_maintainer":    true,
		"no_unmaintained_months":  24,
		"no_archived":             true,
		"no_deprecated":           true,
		"no_typosquatting":        true,
		"max_depth":               5,
		"max_ci_score":            50,
		"allowed_modules":         []string{"github.com/allowed/*"},
		"blocked_modules":         []string{"github.com/blocked/*"},
		"forbid_replace_redirect": true,
		"require_gosum_verified":  true,
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
	if p.MaxGrade != "C" || !p.AllowPending {
		t.Errorf("MaxGrade/AllowPending: expected C/true, got %q/%v", p.MaxGrade, p.AllowPending)
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
	if !p.ForbidReplaceRedirect {
		t.Errorf("ForbidReplaceRedirect: expected true, got %v", p.ForbidReplaceRedirect)
	}
	if !p.RequireGoSumVerified {
		t.Errorf("RequireGoSumVerified: expected true, got %v", p.RequireGoSumVerified)
	}
}

func TestLoadPolicy_UnknownFieldRejected(t *testing.T) {
	tempDir := t.TempDir()
	policyPath := filepath.Join(tempDir, "typo_policy.json")

	if err := os.WriteFile(policyPath, []byte(`{"require_gosum_verifed": true}`), 0o644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	_, err := policy.LoadPolicy(policyPath)
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
	if !strings.Contains(err.Error(), "require_gosum_verifed") {
		t.Errorf("expected error to name the offending key 'require_gosum_verifed', got: %v", err)
	}
}

func TestLoadPolicy_ShippedExamplesAreValid(t *testing.T) {
	for _, name := range []string{"policy-strict.json", "policy-custom.json"} {
		path := filepath.Join("..", "..", "examples", name)
		if _, err := policy.LoadPolicy(path); err != nil {
			t.Errorf("LoadPolicy(%s) failed: %v", name, err)
		}
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

	if p.MaxGrade != "B" {
		t.Errorf("MaxGrade: expected B, got %q", p.MaxGrade)
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
	if !p.ForbidReplaceRedirect {
		t.Errorf("ForbidReplaceRedirect: expected true")
	}
	if !p.RequireGoSumVerified {
		t.Errorf("RequireGoSumVerified: expected true")
	}
	if !p.ForbidPseudoVersions {
		t.Errorf("ForbidPseudoVersions: expected true")
	}
}

func TestDefaultModeratePolicy(t *testing.T) {
	p := policy.DefaultModeratePolicy()

	if p.MaxGrade != "C" {
		t.Errorf("MaxGrade: expected C, got %q", p.MaxGrade)
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

// Tests for Evaluate - MaxGrade
func gradeOf(l grade.Letter, module, reason string) *grade.Result {
	r := &grade.Result{RuleVersion: grade.RuleVersion, Letter: l}
	if module != "" {
		r.Deciding = &grade.Deciding{Module: module, Reason: reason}
	}
	return r
}

func TestEvaluate_MaxGrade(t *testing.T) {
	p := &policy.Policy{MaxGrade: "C"}
	for _, c := range []struct {
		l    grade.Letter
		pass bool
	}{{grade.LetterA, true}, {grade.LetterB, true}, {grade.LetterC, true}, {grade.LetterD, false}, {grade.LetterF, false}} {
		input := makeEvalInput(nil, 0)
		input.Grade = gradeOf(c.l, "github.com/x/y", "called high GO-2026-1 (70)")
		result := p.Evaluate(input)
		if result.Pass != c.pass {
			t.Errorf("grade %s against max C: Pass=%v, want %v", c.l, result.Pass, c.pass)
		}
		if !c.pass {
			v := result.Violations[0]
			if v.Rule != "max_grade" || v.Module != "github.com/x/y" || !strings.Contains(v.Detail, "worse than the maximum C") || !strings.Contains(v.Detail, "called high GO-2026-1 (70)") {
				t.Errorf("violation %+v: it must name the rule, the deciding row and why", v)
			}
		}
	}
}

func TestEvaluate_MaxGrade_PendingFailsUnlessAllowed(t *testing.T) {
	pending := &grade.Result{RuleVersion: grade.RuleVersion, Pending: &grade.Pending{Check: "vulnerability_scan", Reason: "govulncheck did not run"}}
	input := makeEvalInput(nil, 0)
	input.Grade = pending

	result := (&policy.Policy{MaxGrade: "F"}).Evaluate(input)
	if result.Pass || len(result.Violations) != 1 || result.Violations[0].Severity != "error" || !strings.Contains(result.Violations[0].Detail, "Pending") {
		t.Errorf("a Pending grade must fail even the most lenient maximum: %+v", result)
	}
	result = (&policy.Policy{MaxGrade: "A", AllowPending: true}).Evaluate(input)
	if !result.Pass || len(result.Violations) != 1 || result.Violations[0].Severity != "warning" {
		t.Errorf("allow_pending turns it into a warning: %+v", result)
	}
	// no grade at all is the same as Pending
	input.Grade = nil
	if result := (&policy.Policy{MaxGrade: "F"}).Evaluate(input); result.Pass {
		t.Error("a missing grade passed the gate")
	}
}

func TestEvaluate_MaxGrade_InvalidLetter(t *testing.T) {
	input := makeEvalInput(nil, 0)
	input.Grade = gradeOf(grade.LetterA, "", "")
	if result := (&policy.Policy{MaxGrade: "Z"}).Evaluate(input); result.Pass {
		t.Error("an unknown letter must fail, not pass silently")
	}
	path := filepath.Join(t.TempDir(), "p.json")
	if err := os.WriteFile(path, []byte(`{"max_grade":"E"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.LoadPolicy(path); err == nil || !strings.Contains(err.Error(), "max_grade") {
		t.Errorf("LoadPolicy accepted max_grade E: %v", err)
	}
	// the old score rules are gone: an old policy file fails loudly instead of being ignored
	if err := os.WriteFile(path, []byte(`{"max_overall_score":60}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.LoadPolicy(path); err == nil {
		t.Error("a policy with max_overall_score was accepted")
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

// Tests for Evaluate - ForbidReplaceRedirect
func TestEvaluate_ForbidReplaceRedirect_Redirect(t *testing.T) {
	p := &policy.Policy{ForbidReplaceRedirect: true}

	input := makeEvalInput(nil, 0)
	input.IntegrityReport = &scanner.IntegrityReport{
		Findings: []scanner.IntegrityFinding{
			{
				Category: "replace_redirect",
				Severity: scanner.IntegrityHigh,
				Module:   "github.com/foo/bar",
				Detail:   "github.com/foo/bar is redirected to a different module: github.com/attacker/bar",
			},
		},
	}

	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	if len(result.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Rule != "forbid_replace_redirect" {
		t.Errorf("expected rule 'forbid_replace_redirect', got %s", result.Violations[0].Rule)
	}
	if result.Violations[0].Module != "github.com/foo/bar" {
		t.Errorf("expected module 'github.com/foo/bar', got %s", result.Violations[0].Module)
	}
}

// TestEvaluate_ForbidReplaceRedirect_OtherHighFindingPasses verifies the rule
// matches by finding category, not severity: a HIGH-severity finding of a
// different kind (e.g. a future go.sum integrity check) must not trigger it.
func TestEvaluate_ForbidReplaceRedirect_OtherHighFindingPasses(t *testing.T) {
	p := &policy.Policy{ForbidReplaceRedirect: true}

	input := makeEvalInput(nil, 0)
	input.IntegrityReport = &scanner.IntegrityReport{
		Findings: []scanner.IntegrityFinding{
			{
				Category: "gosum_mismatch",
				Severity: scanner.IntegrityHigh,
				Module:   "github.com/foo/bar",
				Detail:   "go.sum entry does not match module content",
			},
		},
	}

	result := p.Evaluate(input)

	if !result.Pass {
		t.Errorf("expected Pass=true (non-redirect HIGH finding must not trigger forbid_replace_redirect), got false: %+v", result.Violations)
	}
}

// TestEvaluate_ForbidReplaceRedirect_VersionPinPasses verifies that a
// version-pin (LOW) replace does not trigger the policy — only redirect
// replaces are rejected.
func TestEvaluate_ForbidReplaceRedirect_VersionPinPasses(t *testing.T) {
	p := &policy.Policy{ForbidReplaceRedirect: true}

	input := makeEvalInput(nil, 0)
	input.IntegrityReport = &scanner.IntegrityReport{
		Findings: []scanner.IntegrityFinding{
			{
				Category: "replace_version_pin",
				Severity: scanner.IntegrityLow,
				Module:   "github.com/foo/bar",
				Detail:   "github.com/foo/bar is version-pinned to v1.0.1",
			},
		},
	}

	result := p.Evaluate(input)

	if !result.Pass {
		t.Errorf("expected Pass=true (version-pin replace must not trigger forbid_replace_redirect), got false: %+v", result.Violations)
	}
}

// TestEvaluate_ForbidPseudoVersions_NonTestOnly verifies that a non-test-only
// dependency pinned to a pseudo-version fails the policy.
func TestEvaluate_ForbidPseudoVersions_NonTestOnly(t *testing.T) {
	p := &policy.Policy{ForbidPseudoVersions: true}

	isTestOnly := false
	deps := []*scorer.DependencyScore{
		{
			Module:        "github.com/unidoc/garabic",
			Version:       "v0.0.0-20220101000000-abc123def456",
			Direct:        true,
			PseudoVersion: true,
			IsTestOnly:    &isTestOnly,
		},
	}

	result := p.Evaluate(makeEvalInput(deps, 30))

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	if len(result.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Rule != "forbid_pseudo_versions" {
		t.Errorf("expected rule 'forbid_pseudo_versions', got %s", result.Violations[0].Rule)
	}
	if result.Violations[0].Module != "github.com/unidoc/garabic" {
		t.Errorf("expected module 'github.com/unidoc/garabic', got %s", result.Violations[0].Module)
	}
}

// TestEvaluate_ForbidPseudoVersions_ConfirmedTestOnlyPasses verifies that a
// confirmed test-only (IsTestOnly == &true) pseudo-version pin is exempted.
func TestEvaluate_ForbidPseudoVersions_ConfirmedTestOnlyPasses(t *testing.T) {
	p := &policy.Policy{ForbidPseudoVersions: true}

	isTestOnly := true
	deps := []*scorer.DependencyScore{
		{
			Module:        "github.com/google/go-cmdtest",
			Version:       "v0.4.1-0.20220921163831-64d0910b0f3a",
			Direct:        true,
			PseudoVersion: true,
			IsTestOnly:    &isTestOnly,
		},
	}

	result := p.Evaluate(makeEvalInput(deps, 30))

	if !result.Pass {
		t.Errorf("expected Pass=true (confirmed test-only pseudo-version must be exempted), got false: %+v", result.Violations)
	}
}

// TestEvaluate_ForbidPseudoVersions_UnknownTestOnlyDenies verifies that a
// nil (unknown) IsTestOnly classification is treated as not-test-only and
// denied, matching the scorer's under-discount-when-unverified convention.
func TestEvaluate_ForbidPseudoVersions_UnknownTestOnlyDenies(t *testing.T) {
	p := &policy.Policy{ForbidPseudoVersions: true}

	deps := []*scorer.DependencyScore{
		{
			Module:        "golang.org/x/telemetry",
			Version:       "v0.0.0-20260101000000-abc123def456",
			Direct:        false,
			PseudoVersion: true,
			IsTestOnly:    nil,
		},
	}

	result := p.Evaluate(makeEvalInput(deps, 30))

	if result.Pass {
		t.Errorf("expected Pass=false (unknown test-only must be denied, not exempted), got true")
	}
}

// TestEvaluate_ForbidPseudoVersions_NoPin verifies that a dependency without
// a pseudo-version pin never triggers the policy.
func TestEvaluate_ForbidPseudoVersions_NoPin(t *testing.T) {
	p := &policy.Policy{ForbidPseudoVersions: true}

	deps := []*scorer.DependencyScore{
		{
			Module:  "golang.org/x/text",
			Version: "v1.0.0",
			Direct:  true,
		},
	}

	result := p.Evaluate(makeEvalInput(deps, 30))

	if !result.Pass {
		t.Errorf("expected Pass=true, got false: %+v", result.Violations)
	}
}

// TestEvaluate_RequireGoSumVerified_Mismatch verifies that a confirmed
// `go mod verify` mismatch fails the require_gosum_verified rule and the
// violation carries the gosum_mismatch finding detail.
func TestEvaluate_RequireGoSumVerified_Mismatch(t *testing.T) {
	p := &policy.Policy{RequireGoSumVerified: true}

	input := makeEvalInput(nil, 0)
	input.IntegrityReport = &scanner.IntegrityReport{
		GoSumVerified: scanner.GoSumVerifiedFalse,
		Findings: []scanner.IntegrityFinding{
			{
				Category: "gosum_mismatch",
				Severity: scanner.IntegrityCritical,
				Module:   "go.sum",
				Detail:   "go mod verify failed: verifying gopkg.in/yaml.v3@v3.0.1/go.mod: checksum mismatch",
			},
		},
	}

	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	if len(result.Violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(result.Violations))
	}
	if result.Violations[0].Rule != "require_gosum_verified" {
		t.Errorf("expected rule 'require_gosum_verified', got %s", result.Violations[0].Rule)
	}
	if result.Violations[0].Detail != input.IntegrityReport.Findings[0].Detail {
		t.Errorf("expected violation to carry the gosum_mismatch detail, got %q", result.Violations[0].Detail)
	}
}

// TestEvaluate_RequireGoSumVerified_UnknownStatesPass verifies the
// honest-UNKNOWN contract: "true", "offline", "skipped", and never-attempted
// verification all pass — only a confirmed mismatch fails.
func TestEvaluate_RequireGoSumVerified_UnknownStatesPass(t *testing.T) {
	p := &policy.Policy{RequireGoSumVerified: true}

	for _, state := range []string{
		scanner.GoSumVerifiedTrue,
		scanner.GoSumVerifiedOffline,
		scanner.GoSumVerifiedSkipped,
		"", // verification never attempted
	} {
		input := makeEvalInput(nil, 0)
		input.IntegrityReport = &scanner.IntegrityReport{GoSumVerified: state}

		result := p.Evaluate(input)

		if !result.Pass {
			t.Errorf("state %q: expected Pass=true (only a confirmed mismatch fails), got false: %+v", state, result.Violations)
		}
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

// Tests for Evaluate - AllowedModules (prefix entry with trailing slash)
func TestEvaluate_AllowedModules_PrefixTrailingSlash(t *testing.T) {
	p := &policy.Policy{
		AllowedModules: []string{"github.com/allowed/"},
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
		t.Errorf("expected Pass=true for trailing-slash prefix, got false. Violations: %v", result.Violations)
	}
}

// Tests for Evaluate - BlockedModules (prefix entry with trailing slash)
func TestEvaluate_BlockedModules_PrefixTrailingSlash(t *testing.T) {
	p := &policy.Policy{
		BlockedModules: []string{"github.com/blocked/"},
	}

	deps := []*scorer.DependencyScore{
		{
			Module:      "github.com/blocked/pkg",
			Version:     "v1.0.0",
			Direct:      true,
			RiskScore:   30,
			Maintenance: &scanner.MaintenanceInfo{},
		},
	}

	input := makeEvalInput(deps, 30)
	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false for trailing-slash blocked prefix, got true")
	}
	if len(result.Violations) != 1 || result.Violations[0].Rule != "blocked_module" {
		t.Errorf("expected one blocked_module violation, got %v", result.Violations)
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
	p := &policy.Policy{
		MaxGrade:           "C",
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
	input.Grade = gradeOf(grade.LetterF, "github.com/bad/pkg", "called critical (90)")
	input.Maintainers["github.com/bad/pkg"] = &scanner.MaintainerInfo{
		BusFactor:        1,
		ContributorCount: 1,
	}

	result := p.Evaluate(input)

	if result.Pass {
		t.Errorf("expected Pass=false, got true")
	}
	// Should have violations for: MaxGrade, NoKnownVulns, NoCriticalVulns (CRITICAL), NoSingleMaintainer
	if len(result.Violations) < 4 {
		t.Errorf("expected at least 4 violations, got %d", len(result.Violations))
	}

	rules := make(map[string]int)
	for _, v := range result.Violations {
		rules[v.Rule]++
	}

	if rules["max_grade"] == 0 {
		t.Error("expected max_grade violation")
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

// TestEvaluate_ForbidPseudoVersions_InBuild verifies that a confirmed
// outside-the-build (InBuild == &false) pseudo-version pin is exempted, while a
// nil (unknown) or &true InBuild is still denied.
func TestEvaluate_ForbidPseudoVersions_InBuild(t *testing.T) {
	p := &policy.Policy{ForbidPseudoVersions: true}
	inBuild, outside := true, false

	tests := []struct {
		name     string
		inBuild  *bool
		wantPass bool
	}{
		{"outside the build is exempt", &outside, true},
		{"in build is denied", &inBuild, false},
		{"unknown InBuild is denied", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := []*scorer.DependencyScore{{
				Module:        "github.com/kr/pty",
				Version:       "v0.0.0-20220101000000-abc123def456",
				PseudoVersion: true,
				InBuild:       tt.inBuild,
			}}
			result := p.Evaluate(makeEvalInput(deps, 30))
			if result.Pass != tt.wantPass {
				t.Errorf("Pass = %v, want %v: %+v", result.Pass, tt.wantPass, result.Violations)
			}
		})
	}
}

// TestEvaluate_MaintenanceRules_InBuild verifies that no_unmaintained,
// no_archived and no_deprecated exempt confirmed outside-the-build deps
// (InBuild == &false) and still fail an in-build (&true) or unknown (nil) dep.
func TestEvaluate_MaintenanceRules_InBuild(t *testing.T) {
	unmaintainedMonths := 24
	rules := []struct {
		rule   string
		policy *policy.Policy
		maint  *scanner.MaintenanceInfo
	}{
		{
			rule:   "no_unmaintained",
			policy: &policy.Policy{NoUnmaintainedMonths: &unmaintainedMonths},
			maint:  &scanner.MaintenanceInfo{MonthsSinceRelease: 60},
		},
		{
			rule:   "no_archived",
			policy: &policy.Policy{NoArchived: true},
			maint:  &scanner.MaintenanceInfo{Archived: true},
		},
		{
			rule:   "no_deprecated",
			policy: &policy.Policy{NoDeprecated: true},
			maint:  &scanner.MaintenanceInfo{Deprecated: true},
		},
	}
	inBuild, outside := true, false
	states := []struct {
		name     string
		inBuild  *bool
		wantPass bool
	}{
		{"outside the build is exempt", &outside, true},
		{"in build fails", &inBuild, false},
		{"unknown InBuild fails", nil, false},
	}

	for _, r := range rules {
		for _, s := range states {
			t.Run(r.rule+"/"+s.name, func(t *testing.T) {
				deps := []*scorer.DependencyScore{{
					Module:      "github.com/kr/pty",
					Maintenance: r.maint,
					InBuild:     s.inBuild,
				}}
				result := r.policy.Evaluate(makeEvalInput(deps, 30))
				if result.Pass != s.wantPass {
					t.Fatalf("Pass = %v, want %v: %+v", result.Pass, s.wantPass, result.Violations)
				}
				if !s.wantPass && (len(result.Violations) != 1 || result.Violations[0].Rule != r.rule) {
					t.Errorf("violations = %+v, want exactly one %s", result.Violations, r.rule)
				}
			})
		}
	}
}

// TestEvaluate_MaintenanceRules_TestOnlyNotExempt pins that the maintenance
// rules have no test-only exemption: a confirmed test-only dep that is in the
// build still fails them.
func TestEvaluate_MaintenanceRules_TestOnlyNotExempt(t *testing.T) {
	p := &policy.Policy{NoArchived: true}
	testOnly, inBuild := true, true
	deps := []*scorer.DependencyScore{{
		Module:      "github.com/stretchr/objx",
		Maintenance: &scanner.MaintenanceInfo{Archived: true},
		IsTestOnly:  &testOnly,
		InBuild:     &inBuild,
	}}
	if result := p.Evaluate(makeEvalInput(deps, 30)); result.Pass {
		t.Errorf("Pass = true, want a no_archived violation for a test-only dep")
	}
}
