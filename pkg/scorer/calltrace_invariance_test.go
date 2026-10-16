package scorer

import (
	"reflect"
	"testing"
	"time"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// TestScoreAll_IgnoresCallTrace pins the contract that the call trace evidence
// (CallTrace, CalledSymbols) is display data only: scoring a project whose
// called vulnerabilities carry it must give the same result as scoring the same
// project without it. Everything in the ProjectScore is compared, apart from
// the trace fields themselves, which the scorer copies through untouched.
func TestScoreAll_IgnoresCallTrace(t *testing.T) {
	const module = "golang.org/x/crypto"

	traced := func() []scanner.Vulnerability {
		return []scanner.Vulnerability{
			{
				ID: "GO-2026-5005", Severity: "CRITICAL", Reachability: "called",
				CallPath: []string{"example.com/u1repro.main", "golang.org/x/crypto/ssh/agent.keyring.Add"},
				CallTrace: []scanner.CallFrame{
					{Name: "example.com/u1repro.main", Module: "example.com/u1repro", File: "main.go", Line: 13, Column: 12, Project: true},
					{Name: "golang.org/x/crypto/ssh/agent.keyring.Add", Module: module, Version: "v0.48.0", File: "ssh/agent/keyring.go", Line: 149, Column: 19},
				},
				CalledSymbols: []string{"golang.org/x/crypto/ssh/agent.keyring.Add", "golang.org/x/crypto/ssh/agent.keyring.Lock"},
			},
			{ID: "GO-2026-0001", Severity: "HIGH", Reachability: "imported"},
		}
	}
	untraced := func() []scanner.Vulnerability {
		vulns := traced()
		for i := range vulns {
			vulns[i].CallTrace, vulns[i].CalledSymbols = nil, nil
		}
		return vulns
	}

	score := func(vulns []scanner.Vulnerability) *ProjectScore {
		input := twoAxisEmptyInput(testutil.MakeGraph(
			testutil.DepSpec{Path: module, Version: "v0.48.0", Direct: true, Depth: 0, InBuild: testutil.BoolPtr(true)},
		))
		input.Vulns[module] = vulns
		input.Now = time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
		return ScoreAll(input)
	}

	withTrace, without := score(traced()), score(untraced())

	if withTrace.OverallScore != without.OverallScore || withTrace.OverallLevel != without.OverallLevel {
		t.Errorf("overall = %d/%s with trace, %d/%s without; want identical",
			withTrace.OverallScore, withTrace.OverallLevel, without.OverallScore, without.OverallLevel)
	}
	if len(withTrace.Dependencies) != 1 || len(without.Dependencies) != 1 {
		t.Fatalf("want 1 dependency, got %d and %d", len(withTrace.Dependencies), len(without.Dependencies))
	}
	a, b := withTrace.Dependencies[0], without.Dependencies[0]
	if a.RiskScore != b.RiskScore || a.RiskLevel != b.RiskLevel {
		t.Errorf("dependency = %d/%s with trace, %d/%s without; want identical",
			a.RiskScore, a.RiskLevel, b.RiskScore, b.RiskLevel)
	}
	if a.RiskScore == 0 {
		t.Fatal("RiskScore = 0, want a scored called vulnerability (test setup)")
	}

	// Strip the trace fields the scorer passes through, then require the whole
	// result to match, so a field added to ProjectScore later is covered too.
	for _, ds := range withTrace.Dependencies {
		for i := range ds.Vulns {
			ds.Vulns[i].CallTrace, ds.Vulns[i].CalledSymbols = nil, nil
		}
	}
	if !reflect.DeepEqual(withTrace, without) {
		t.Errorf("ProjectScore differs once only the trace fields are removed:\nwith:    %+v\nwithout: %+v", withTrace, without)
	}
}
