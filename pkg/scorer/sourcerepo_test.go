package scorer

import (
	"slices"
	"testing"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// TestScoreAll_ArchivedVanityDirectDependency verifies that a direct, in-build
// gopkg.in module whose repository the maintainer scanner found archived (via
// the gopkg.in rule) gets the archived factor and the archived floor, the same
// as a github.com module would.
func TestScoreAll_ArchivedVanityDirectDependency(t *testing.T) {
	const mod = "gopkg.in/yaml.v3"
	input := twoAxisEmptyInput(testutil.MakeGraph(
		testutil.DepSpec{Path: mod, Version: "v3.0.1", Direct: true, Depth: 0, InBuild: testutil.BoolPtr(true)},
	))
	input.Maintenance[mod] = &scanner.MaintenanceInfo{MonthsSinceRelease: 40}
	input.Maintainers[mod] = &scanner.MaintainerInfo{
		DataAvailable: true, Owner: "go-yaml", Repo: "yaml", IsArchived: true,
		SourceRepo: "github.com/go-yaml/yaml", SourceRepoVia: scanner.SourceViaGopkgIn,
	}

	ps := ScoreAll(input)

	var ds *DependencyScore
	for _, d := range ps.Dependencies {
		if d.Module == mod {
			ds = d
		}
	}
	if ds == nil {
		t.Fatal("dependency missing from the score")
	}
	if !slices.Contains(ds.RiskFactors, "archived") {
		t.Errorf("RiskFactors = %v, want archived", ds.RiskFactors)
	}
	if ps.HeadlineDriver != "archived_floor" || ps.OverallScore < 60 {
		t.Errorf("headline = %s at %v, want archived_floor at >= 60", ps.HeadlineDriver, ps.OverallScore)
	}
	if ps.OverallLevel != RiskHigh {
		t.Errorf("OverallLevel = %s, want HIGH", ps.OverallLevel)
	}
}
