// Package integration_test provides offline integration smoke tests for the unisupply pipeline.
package integration_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

func testdataPath(t testing.TB, parts ...string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("could not determine test file path")
	}
	pathParts := append([]string{filepath.Dir(thisFile), "testdata"}, parts...)
	return filepath.Join(pathParts...)
}

// TestFullPipeline_Simple exercises the offline pipeline end-to-end:
// parse -> resolve -> scan (typosquat, AI-gen) -> score.
func TestFullPipeline_Simple(t *testing.T) {
	gomodPath := testdataPath(t, "gomod", "simple.mod")

	// Resolve dependency graph (direct only to avoid network calls).
	graph, warnings, err := resolver.Resolve(gomodPath, true)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(graph.Dependencies) == 0 {
		t.Errorf("Expected at least 1 direct dependency, got %d", len(graph.Dependencies))
	}
	t.Logf("Resolved %d dependencies with %d warnings", len(graph.Dependencies), len(warnings))

	// Run offline scanners: typosquat and AI-gen.
	typosquatScanner := scanner.NewTyposquatScanner()
	typosquatResults := typosquatScanner.ScanAll(graph)
	t.Logf("Typosquat scanner found %d suspicious modules", len(typosquatResults))

	// For AI-gen scanner, we need empty maps for maintainers and resilience.
	aiGenScanner := scanner.NewAIGenScanner()
	aiGenResults := aiGenScanner.ScanAll(graph, make(map[string]*scanner.MaintainerInfo), make(map[string]*scanner.ResilienceInfo))
	t.Logf("AI-gen scanner found %d risky modules", len(aiGenResults))

	// Run scorer on the offline results.
	scoreInput := scorer.ScoreInput{
		Graph:       graph,
		Vulns:       make(map[string][]scanner.Vulnerability),
		Maintenance: make(map[string]*scanner.MaintenanceInfo),
		Maintainers: make(map[string]*scanner.MaintainerInfo),
		Typosquats:  typosquatResults,
		Resilience:  make(map[string]*scanner.ResilienceInfo),
		AIGenRisks:  aiGenResults,
		TrustIndex:  make(map[string]*scanner.TrustIndexEntry),
	}

	projectScore := scorer.ScoreAll(scoreInput)
	if projectScore == nil {
		t.Fatal("ScoreAll returned nil")
	}

	// Assertions.
	if len(projectScore.Dependencies) == 0 {
		t.Errorf("Expected scored dependencies, got none")
	}

	// Verify all risk scores are in valid range [0, 100].
	for _, dep := range projectScore.Dependencies {
		if dep.RiskScore < 0 || dep.RiskScore > 100 {
			t.Errorf("Invalid risk score %d for %s (expected [0, 100])", dep.RiskScore, dep.Module)
		}
	}

	// Verify overall score is in valid range.
	if projectScore.OverallScore < 0 || projectScore.OverallScore > 100 {
		t.Errorf("Invalid overall score %d (expected [0, 100])", projectScore.OverallScore)
	}

	t.Logf("Overall project score: %d (%s)", projectScore.OverallScore, projectScore.OverallLevel)
}

// TestFullPipeline_Empty parses an empty go.mod and ensures the pipeline
// handles zero dependencies gracefully.
func TestFullPipeline_Empty(t *testing.T) {
	gomodPath := testdataPath(t, "gomod", "empty.mod")
	gomod, err := parser.ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}

	if len(gomod.Requirements) != 0 {
		t.Errorf("Expected empty.mod to have no requirements, got %d", len(gomod.Requirements))
	}

	// Resolve dependency graph.
	graph, _, err := resolver.Resolve(gomodPath, true)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if len(graph.Dependencies) != 0 {
		t.Errorf("Expected empty graph, got %d dependencies", len(graph.Dependencies))
	}

	// Run scorer on empty graph.
	scoreInput := scorer.ScoreInput{
		Graph:       graph,
		Vulns:       make(map[string][]scanner.Vulnerability),
		Maintenance: make(map[string]*scanner.MaintenanceInfo),
		Maintainers: make(map[string]*scanner.MaintainerInfo),
		Typosquats:  make(map[string]*scanner.TyposquatResult),
		Resilience:  make(map[string]*scanner.ResilienceInfo),
		AIGenRisks:  make(map[string]*scanner.AIGenRisk),
		TrustIndex:  make(map[string]*scanner.TrustIndexEntry),
	}

	projectScore := scorer.ScoreAll(scoreInput)
	if projectScore == nil {
		t.Fatal("ScoreAll returned nil on empty graph")
	}

	if len(projectScore.Dependencies) != 0 {
		t.Errorf("Expected zero scored dependencies, got %d", len(projectScore.Dependencies))
	}

	if projectScore.OverallScore != 0 {
		t.Errorf("Expected overall score 0 for empty graph, got %d", projectScore.OverallScore)
	}

	t.Log("Empty pipeline completed successfully")
}

// TestFullPipeline_ScoreStability runs the offline pipeline twice against
// simple.mod and verifies risk scores are deterministic.
func TestFullPipeline_ScoreStability(t *testing.T) {
	gomodPath := testdataPath(t, "gomod", "simple.mod")

	// Run 1.
	graph1, _, err := resolver.Resolve(gomodPath, true)
	if err != nil {
		t.Fatalf("First resolve failed: %v", err)
	}

	typosquat1 := scanner.NewTyposquatScanner().ScanAll(graph1)
	aiGen1 := scanner.NewAIGenScanner().ScanAll(graph1, make(map[string]*scanner.MaintainerInfo), make(map[string]*scanner.ResilienceInfo))

	input1 := scorer.ScoreInput{
		Graph:       graph1,
		Vulns:       make(map[string][]scanner.Vulnerability),
		Maintenance: make(map[string]*scanner.MaintenanceInfo),
		Maintainers: make(map[string]*scanner.MaintainerInfo),
		Typosquats:  typosquat1,
		Resilience:  make(map[string]*scanner.ResilienceInfo),
		AIGenRisks:  aiGen1,
		TrustIndex:  make(map[string]*scanner.TrustIndexEntry),
	}
	scores1 := scorer.ScoreAll(input1)

	// Run 2 (identical).
	graph2, _, err := resolver.Resolve(gomodPath, true)
	if err != nil {
		t.Fatalf("Second resolve failed: %v", err)
	}

	typosquat2 := scanner.NewTyposquatScanner().ScanAll(graph2)
	aiGen2 := scanner.NewAIGenScanner().ScanAll(graph2, make(map[string]*scanner.MaintainerInfo), make(map[string]*scanner.ResilienceInfo))

	input2 := scorer.ScoreInput{
		Graph:       graph2,
		Vulns:       make(map[string][]scanner.Vulnerability),
		Maintenance: make(map[string]*scanner.MaintenanceInfo),
		Maintainers: make(map[string]*scanner.MaintainerInfo),
		Typosquats:  typosquat2,
		Resilience:  make(map[string]*scanner.ResilienceInfo),
		AIGenRisks:  aiGen2,
		TrustIndex:  make(map[string]*scanner.TrustIndexEntry),
	}
	scores2 := scorer.ScoreAll(input2)

	// Verify determinism: overall scores must match.
	if scores1.OverallScore != scores2.OverallScore {
		t.Errorf("Overall scores differ: %d vs %d", scores1.OverallScore, scores2.OverallScore)
	}

	// Verify per-dependency scores match.
	if len(scores1.Dependencies) != len(scores2.Dependencies) {
		t.Errorf("Dependency counts differ: %d vs %d", len(scores1.Dependencies), len(scores2.Dependencies))
	}

	scoresByModule := make(map[string]int, len(scores2.Dependencies))
	for _, d := range scores2.Dependencies {
		scoresByModule[d.Module] = d.RiskScore
	}

	for _, dep1 := range scores1.Dependencies {
		score2, ok := scoresByModule[dep1.Module]
		if !ok {
			t.Errorf("Module %s missing in second run", dep1.Module)
			continue
		}
		if dep1.RiskScore != score2 {
			t.Errorf("Risk score differs for %s: %d vs %d", dep1.Module, dep1.RiskScore, score2)
		}
	}

	t.Logf("Score stability verified: %d runs produced identical scores", 2)
}

// TestCIScanner_PinnedFixture loads pinned.yml and verifies no unpinned action warnings.
func TestCIScanner_PinnedFixture(t *testing.T) {
	workflowDir := testdataPath(t, "workflows")
	ciScanner := scanner.NewCIScanner()

	report, err := ciScanner.ScanWorkflows(workflowDir)
	if err != nil {
		t.Fatalf("ScanWorkflows failed: %v", err)
	}

	if report == nil {
		t.Fatal("ScanWorkflows returned nil report")
	}

	// Verify pinned.yml has no findings (all actions are pinned to SHA).
	var pinnedWF *scanner.WorkflowRisk
	for _, wr := range report.Workflows {
		if wr.Name == "CI" {
			pinnedWF = wr
			break
		}
	}

	if pinnedWF == nil {
		t.Fatalf("CI workflow not found in report")
	}

	if len(pinnedWF.Findings) > 0 {
		t.Errorf("Expected zero findings for pinned workflow, got %d:", len(pinnedWF.Findings))
		for _, f := range pinnedWF.Findings {
			t.Logf("  - %s: %s", f.Category, f.Description)
		}
	}

	t.Logf("Pinned workflow scan passed: %d findings (expected 0)", len(pinnedWF.Findings))
}

// TestCIScanner_UnsafeFixture loads unsafe.yml and verifies findings for unpinned actions
// and dangerous expression injection patterns.
func TestCIScanner_UnsafeFixture(t *testing.T) {
	workflowDir := testdataPath(t, "workflows")
	ciScanner := scanner.NewCIScanner()

	report, err := ciScanner.ScanWorkflows(workflowDir)
	if err != nil {
		t.Fatalf("ScanWorkflows failed: %v", err)
	}

	if report == nil {
		t.Fatal("ScanWorkflows returned nil report")
	}

	// Verify unsafe.yml has findings.
	var unsafeWF *scanner.WorkflowRisk
	for _, wr := range report.Workflows {
		if wr.Name == "Unsafe" {
			unsafeWF = wr
			break
		}
	}

	if unsafeWF == nil {
		t.Fatalf("Unsafe workflow not found in report")
	}

	if len(unsafeWF.Findings) == 0 {
		t.Errorf("Expected findings in unsafe workflow, got none")
	}

	// Verify we found unpinned action or expression injection.
	hasUnpinned := false
	hasExprInjection := false
	for _, f := range unsafeWF.Findings {
		if f.Category == "unpinned_action" {
			hasUnpinned = true
		}
		if f.Category == "expression_injection" {
			hasExprInjection = true
		}
	}

	if !hasUnpinned && !hasExprInjection {
		t.Errorf("Expected unpinned_action or expression_injection finding, got: %v", unsafeWF.Findings)
	}

	t.Logf("Unsafe workflow scan found %d findings (expected >= 1)", len(unsafeWF.Findings))
	for _, f := range unsafeWF.Findings {
		t.Logf("  - %s (%s): %s", f.Category, f.Severity, f.Description)
	}
}

// BenchmarkPipeline_Simple measures the performance of a full offline pipeline run.
func BenchmarkPipeline_Simple(b *testing.B) {
	gomodPath := testdataPath(b, "gomod", "simple.mod")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		graph, _, err := resolver.Resolve(gomodPath, true)
		if err != nil {
			b.Fatalf("Resolve failed: %v", err)
		}

		typosquatScanner := scanner.NewTyposquatScanner()
		typosquatResults := typosquatScanner.ScanAll(graph)

		aiGenScanner := scanner.NewAIGenScanner()
		aiGenResults := aiGenScanner.ScanAll(graph, make(map[string]*scanner.MaintainerInfo), make(map[string]*scanner.ResilienceInfo))

		scoreInput := scorer.ScoreInput{
			Graph:       graph,
			Vulns:       make(map[string][]scanner.Vulnerability),
			Maintenance: make(map[string]*scanner.MaintenanceInfo),
			Maintainers: make(map[string]*scanner.MaintainerInfo),
			Typosquats:  typosquatResults,
			Resilience:  make(map[string]*scanner.ResilienceInfo),
			AIGenRisks:  aiGenResults,
			TrustIndex:  make(map[string]*scanner.TrustIndexEntry),
		}

		_ = scorer.ScoreAll(scoreInput)
	}
}
