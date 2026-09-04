package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/scanner"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// aliasReport builds a one-dependency report carrying the given advisories.
func aliasReport(vulns ...scanner.Vulnerability) *scorer.ProjectScore {
	return &scorer.ProjectScore{
		OverallScore: 60,
		OverallLevel: scorer.RiskHigh,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "example.com/vulnerable",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 60,
				RiskLevel: scorer.RiskHigh,
				Vulns:     vulns,
			},
		},
		HighRiskCount: 1,
		TotalVulns:    len(vulns),
	}
}

func renderAliasReport(t *testing.T, ps *scorer.ProjectScore, stdlib []scanner.Vulnerability) string {
	t.Helper()

	graph := testutil.MakeGraph(testutil.DepSpec{
		Path:    "example.com/vulnerable",
		Version: "v1.0.0",
		Direct:  true,
	})
	opts := TextOptions{
		NoColor:     true,
		Verbose:     true,
		Writer:      &bytes.Buffer{},
		StdlibVulns: stdlib,
	}
	if err := WriteText(graph, ps, &opts); err != nil {
		t.Fatalf("WriteText failed: %v", err)
	}
	return opts.Writer.(*bytes.Buffer).String()
}

// TestWriteText_VulnLineOmitsInlineAliases pins the canonical-ID contract: the
// advisory line carries the Go advisory ID and nothing else identifying, with
// the CVE reachable from the glossary instead.
func TestWriteText_VulnLineOmitsInlineAliases(t *testing.T) {
	ps := aliasReport(scanner.Vulnerability{
		ID:           "GO-2026-5026",
		Aliases:      []string{"CVE-2026-39821", "GHSA-aaaa-bbbb-cccc"},
		Summary:      "Denial of service",
		Severity:     "CRITICAL",
		Reachability: "required",
		FixedVersion: "v1.1.0",
	})

	out := renderAliasReport(t, ps, nil)

	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "⚠ GO-2026-5026") {
			continue
		}
		if strings.Contains(line, "CVE-2026-39821") || strings.Contains(line, "GHSA-") {
			t.Errorf("advisory line still carries an inline alias:\n%s", line)
		}
	}

	if !strings.Contains(out, "GO-2026-5026 = CVE-2026-39821, GHSA-aaaa-bbbb-cccc") {
		t.Errorf("glossary entry missing or malformed; output:\n%s", out)
	}
}

// TestWriteText_NoSelfAlias covers the tautology the old fallback produced:
// an advisory with no aliases used to render "GO-… — GO-…".
func TestWriteText_NoSelfAlias(t *testing.T) {
	ps := aliasReport(scanner.Vulnerability{
		ID:           "GO-2026-5932",
		Summary:      "Unspecified",
		Severity:     "UNKNOWN",
		Reachability: "required",
	})

	out := renderAliasReport(t, ps, nil)

	if strings.Contains(out, "GO-2026-5932 — GO-2026-5932") {
		t.Error("advisory rendered as its own alias")
	}
	if strings.Contains(out, "VULNERABILITY ID ALIASES") {
		t.Errorf("glossary rendered with no aliases to list; output:\n%s", out)
	}
}

// TestWriteText_AliasEqualToIDIsNotListed guards the same tautology arriving
// from the other direction: govulncheck reporting the ID as its own alias.
func TestWriteText_AliasEqualToIDIsNotListed(t *testing.T) {
	ps := aliasReport(scanner.Vulnerability{
		ID:       "GO-2026-5932",
		Aliases:  []string{"GO-2026-5932"},
		Severity: "UNKNOWN",
	})

	out := renderAliasReport(t, ps, nil)

	if strings.Contains(out, "GO-2026-5932 = GO-2026-5932") {
		t.Error("glossary lists an advisory as its own alias")
	}
	if strings.Contains(out, "VULNERABILITY ID ALIASES") {
		t.Errorf("glossary rendered with no real aliases; output:\n%s", out)
	}
}

// TestWriteText_StdlibVulnUsesCanonicalID checks the stdlib section follows
// the same convention as the per-dependency lines — it used to render
// "ID Summary (CVE-…)", a second ID convention in the same report.
func TestWriteText_StdlibVulnUsesCanonicalID(t *testing.T) {
	ps := aliasReport()
	stdlib := []scanner.Vulnerability{{
		ID:           "GO-2026-4970",
		Aliases:      []string{"CVE-2026-39822"},
		Summary:      "Root escape via symlink",
		Severity:     "HIGH",
		FixedVersion: "v1.25.12",
	}}

	out := renderAliasReport(t, ps, stdlib)

	if !strings.Contains(out, "GO-2026-4970 Root escape via symlink") {
		t.Errorf("stdlib line missing or reformatted; output:\n%s", out)
	}
	if strings.Contains(out, "Root escape via symlink (CVE-2026-39822)") {
		t.Error("stdlib line still carries the inline CVE parenthetical")
	}
	if !strings.Contains(out, "GO-2026-4970 = CVE-2026-39822") {
		t.Errorf("stdlib advisory missing from the glossary; output:\n%s", out)
	}
}

// TestCollectVulnAliases_DeduplicatesAndSorts covers the mapping itself: one
// entry per advisory however many dependencies carry it, aliases sorted, IDs
// sorted, alias-less advisories absent.
func TestCollectVulnAliases_DeduplicatesAndSorts(t *testing.T) {
	shared := scanner.Vulnerability{
		ID:      "GO-2026-0002",
		Aliases: []string{"GHSA-zzzz", "CVE-2026-2"},
	}
	ps := &scorer.ProjectScore{
		Dependencies: []*scorer.DependencyScore{
			{Module: "a", Vulns: []scanner.Vulnerability{
				{ID: "GO-2026-0003", Aliases: []string{"CVE-2026-3"}},
				shared,
			}},
			{Module: "b", Vulns: []scanner.Vulnerability{
				shared,
				{ID: "GO-2026-0004"}, // no aliases
			}},
		},
	}
	stdlib := []scanner.Vulnerability{{ID: "GO-2026-0001", Aliases: []string{"CVE-2026-1"}}}

	got := collectVulnAliases(ps, stdlib)

	want := []vulnAliasEntry{
		{ID: "GO-2026-0001", Aliases: []string{"CVE-2026-1"}},
		{ID: "GO-2026-0002", Aliases: []string{"CVE-2026-2", "GHSA-zzzz"}},
		{ID: "GO-2026-0003", Aliases: []string{"CVE-2026-3"}},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].ID != want[i].ID {
			t.Errorf("entry %d: ID = %q, want %q", i, got[i].ID, want[i].ID)
		}
		if strings.Join(got[i].Aliases, ",") != strings.Join(want[i].Aliases, ",") {
			t.Errorf("entry %d (%s): aliases = %v, want %v", i, got[i].ID, got[i].Aliases, want[i].Aliases)
		}
	}
}
