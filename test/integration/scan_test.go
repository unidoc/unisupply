// Package integration_test provides offline integration smoke tests for the unisupply pipeline.
package integration_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

const (
	stabilityRuns = 5

	// directOnly mirrors resolver.Resolve's second argument and keeps the
	// integration suite offline by skipping `go mod graph` (which would touch
	// the network for transitive resolution).
	directOnly = true

	// Workflow names match the `name:` field in the corresponding fixture
	// files under testdata/workflows/. Centralized here so a fixture rename
	// breaks compilation rather than producing a confusing nil-lookup failure.
	pinnedWorkflowName = "CI"
	unsafeWorkflowName = "Unsafe"
)

func testdataPath(parts ...string) string {
	return filepath.Join(append([]string{"testdata"}, parts...)...)
}

// ciReportOnce caches the CI scan of testdata/workflows/ across all CI tests
// in this package. Each individual test was previously re-parsing every
// fixture file in the directory; with this helper the scan happens once.
var (
	ciReportOnce sync.Once
	ciReport     *scanner.CIReport
	ciReportErr  error
)

func loadCIReport(t *testing.T) *scanner.CIReport {
	t.Helper()
	ciReportOnce.Do(func() {
		ciReport, ciReportErr = scanner.NewCIScanner().ScanWorkflows(context.Background(), testdataPath("workflows"))
	})
	if ciReportErr != nil {
		t.Fatalf("ScanWorkflows failed: %v", ciReportErr)
	}
	if ciReport == nil {
		t.Fatal("ScanWorkflows returned nil report")
	}
	return ciReport
}

func findWorkflow(t *testing.T, report *scanner.CIReport, name string) *scanner.WorkflowRisk {
	t.Helper()
	for _, wr := range report.Workflows {
		if wr.Name == name {
			return wr
		}
	}
	t.Fatalf("%q workflow not found in report", name)
	return nil
}

func emptyScoreInput(g *resolver.Graph) scorer.ScoreInput {
	return scorer.ScoreInput{
		Graph:       g,
		Vulns:       map[string][]scanner.Vulnerability{},
		Maintenance: map[string]*scanner.MaintenanceInfo{},
		Maintainers: map[string]*scanner.MaintainerInfo{},
		Typosquats:  map[string]*scanner.TyposquatResult{},
		Resilience:  map[string]*scanner.ResilienceInfo{},
		AIGenRisks:  map[string]*scanner.AIGenRisk{},
		TrustIndex:  map[string]*scanner.TrustIndexEntry{},
	}
}

func TestFullPipeline_Simple(t *testing.T) {
	gomodPath := testdataPath("gomod", "simple.mod")

	graph, _, err := resolver.Resolve(context.Background(), gomodPath, directOnly)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(graph.Dependencies) == 0 {
		t.Fatalf("expected at least 1 direct dependency, got 0")
	}

	typosquatResults := scanner.NewTyposquatScanner().ScanAll(context.Background(), graph)

	// pflag and testify are themselves in the well-known module list — the
	// scanner must not flag them as typosquats.
	for _, mod := range []string{"github.com/spf13/pflag", "github.com/stretchr/testify"} {
		if _, flagged := typosquatResults[mod]; flagged {
			t.Errorf("%s should not be flagged as typosquat (it is the canonical well-known module)", mod)
		}
	}

	aiGenResults := scanner.NewAIGenScanner().ScanAll(
		context.Background(),
		graph,
		map[string]*scanner.MaintainerInfo{},
		map[string]*scanner.ResilienceInfo{},
	)

	input := emptyScoreInput(graph)
	input.Typosquats = typosquatResults
	input.AIGenRisks = aiGenResults

	projectScore := scorer.ScoreAll(input)
	if projectScore == nil {
		t.Fatal("ScoreAll returned nil")
	}
	if len(projectScore.Dependencies) == 0 {
		t.Errorf("expected scored dependencies, got none")
	}
	for _, dep := range projectScore.Dependencies {
		if dep.RiskScore < 0 || dep.RiskScore > 100 {
			t.Errorf("invalid risk score %d for %s (expected [0, 100])", dep.RiskScore, dep.Module)
		}
	}
	if projectScore.OverallScore < 0 || projectScore.OverallScore > 100 {
		t.Errorf("invalid overall score %d (expected [0, 100])", projectScore.OverallScore)
	}
}

func TestFullPipeline_Empty(t *testing.T) {
	gomodPath := testdataPath("gomod", "empty.mod")

	gomod, err := parser.ParseGoMod(gomodPath)
	if err != nil {
		t.Fatalf("ParseGoMod failed: %v", err)
	}
	if len(gomod.Requirements) != 0 {
		t.Errorf("expected empty.mod to have no requirements, got %d", len(gomod.Requirements))
	}

	graph, _, err := resolver.Resolve(context.Background(), gomodPath, directOnly)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if len(graph.Dependencies) != 0 {
		t.Errorf("expected empty graph, got %d dependencies", len(graph.Dependencies))
	}

	projectScore := scorer.ScoreAll(emptyScoreInput(graph))
	if projectScore == nil {
		t.Fatal("ScoreAll returned nil on empty graph")
	}
	if len(projectScore.Dependencies) != 0 {
		t.Errorf("expected zero scored dependencies, got %d", len(projectScore.Dependencies))
	}
	if projectScore.OverallScore != 0 {
		t.Errorf("expected overall score 0 for empty graph, got %d", projectScore.OverallScore)
	}
}

// TestFullPipeline_ScoreStability verifies the offline pipeline is deterministic
// across repeated runs against the same input.
func TestFullPipeline_ScoreStability(t *testing.T) {
	gomodPath := testdataPath("gomod", "simple.mod")

	runOnce := func(t *testing.T) *scorer.ProjectScore {
		t.Helper()
		graph, _, err := resolver.Resolve(context.Background(), gomodPath, directOnly)
		if err != nil {
			t.Fatalf("Resolve failed: %v", err)
		}
		input := emptyScoreInput(graph)
		input.Typosquats = scanner.NewTyposquatScanner().ScanAll(context.Background(), graph)
		input.AIGenRisks = scanner.NewAIGenScanner().ScanAll(
			context.Background(),
			graph,
			map[string]*scanner.MaintainerInfo{},
			map[string]*scanner.ResilienceInfo{},
		)
		return scorer.ScoreAll(input)
	}

	baseline := runOnce(t)
	baselineByModule := make(map[string]int, len(baseline.Dependencies))
	for _, d := range baseline.Dependencies {
		baselineByModule[d.Module] = d.RiskScore
	}

	for i := 2; i <= stabilityRuns; i++ {
		got := runOnce(t)
		if got.OverallScore != baseline.OverallScore {
			t.Errorf("run %d: overall score %d differs from baseline %d", i, got.OverallScore, baseline.OverallScore)
		}
		if len(got.Dependencies) != len(baseline.Dependencies) {
			t.Errorf("run %d: dependency count %d differs from baseline %d", i, len(got.Dependencies), len(baseline.Dependencies))
		}
		for _, dep := range got.Dependencies {
			want, ok := baselineByModule[dep.Module]
			if !ok {
				t.Errorf("run %d: module %s missing from baseline", i, dep.Module)
				continue
			}
			if dep.RiskScore != want {
				t.Errorf("run %d: risk score for %s is %d, baseline %d", i, dep.Module, dep.RiskScore, want)
			}
		}
	}
}

func TestCIScanner_PinnedFixture(t *testing.T) {
	pinnedWF := findWorkflow(t, loadCIReport(t), pinnedWorkflowName)

	// The contract for pinned.yml is that it must not produce findings in the
	// two categories the fixture is built to avoid. Total finding count is left
	// loose so unrelated heuristics can grow without breaking this test.
	for _, f := range pinnedWF.Findings {
		switch f.Category {
		case "unpinned_action", "expression_injection":
			t.Errorf("pinned workflow should not produce %s finding: %s", f.Category, f.Description)
		}
	}
}

func TestCIScanner_UnsafeFixture(t *testing.T) {
	unsafeWF := findWorkflow(t, loadCIReport(t), unsafeWorkflowName)

	if len(unsafeWF.Findings) == 0 {
		t.Fatalf("expected findings in unsafe workflow, got none")
	}

	hasUnpinned, hasExprInjection := false, false
	for _, f := range unsafeWF.Findings {
		switch f.Category {
		case "unpinned_action":
			hasUnpinned = true
		case "expression_injection":
			hasExprInjection = true
		}
	}
	if !hasUnpinned && !hasExprInjection {
		t.Errorf("expected unpinned_action or expression_injection finding, got: %v", unsafeWF.Findings)
	}
}

// BenchmarkPipeline_Simple measures the offline pipeline. Scanners and the
// shared empty-map scaffolding are hoisted so the benchmark reflects pipeline
// work, not per-iteration allocator noise.
func BenchmarkPipeline_Simple(b *testing.B) {
	gomodPath := testdataPath("gomod", "simple.mod")

	typosquatScanner := scanner.NewTyposquatScanner()
	aiGenScanner := scanner.NewAIGenScanner()

	emptyVulns := map[string][]scanner.Vulnerability{}
	emptyMaintenance := map[string]*scanner.MaintenanceInfo{}
	emptyMaintainers := map[string]*scanner.MaintainerInfo{}
	emptyResilience := map[string]*scanner.ResilienceInfo{}
	emptyTrustIndex := map[string]*scanner.TrustIndexEntry{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		graph, _, err := resolver.Resolve(context.Background(), gomodPath, directOnly)
		if err != nil {
			b.Fatalf("Resolve failed: %v", err)
		}
		input := scorer.ScoreInput{
			Graph:       graph,
			Vulns:       emptyVulns,
			Maintenance: emptyMaintenance,
			Maintainers: emptyMaintainers,
			Typosquats:  typosquatScanner.ScanAll(context.Background(), graph),
			Resilience:  emptyResilience,
			AIGenRisks:  aiGenScanner.ScanAll(context.Background(), graph, emptyMaintainers, emptyResilience),
			TrustIndex:  emptyTrustIndex,
		}
		_ = scorer.ScoreAll(input)
	}
}
