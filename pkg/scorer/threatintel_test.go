package scorer

import (
	"strings"
	"testing"
	"time"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// makeVulnTI builds a vulnerability with threat-intel fields for the
// composition tests. epss may be nil (no EPSS data).
func makeVulnTI(id, severity, reachability string, epss *float64, inKEV bool) scanner.Vulnerability {
	return scanner.Vulnerability{
		ID:           id,
		Severity:     severity,
		Reachability: reachability,
		EPSSScore:    epss,
		EPSSDate:     "2026-07-10",
		InKEV:        inKEV,
		KEVChecked:   true,
	}
}

func floatPtr(f float64) *float64 { return &f }

// ---------------------------------------------------------------------------
// Step-function composition: EPSS amplifier and KEV override vs downgrades
// ---------------------------------------------------------------------------

// TestThreatIntel_EPSSZeroOnHigh_Unchanged verifies EPSS below the 0.5
// threshold leaves the tier untouched: called HIGH → step 70.
func TestThreatIntel_EPSSZeroOnHigh_Unchanged(t *testing.T) {
	input := reachabilityScoreInput(
		"github.com/risky/pkg",
		testutil.BoolPtr(false),
		[]scanner.Vulnerability{
			makeVulnTI("CVE-2024-1001", "HIGH", "called", floatPtr(0.0), false),
		},
	)
	ps := ScoreAll(input)
	if ps.SeverityAdjustedVulnScore != 70 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 70 (EPSS 0.0 < 0.5 → HIGH unchanged → 70)",
			ps.SeverityAdjustedVulnScore)
	}
}

// TestThreatIntel_EPSSHighOnHigh_PromotesToCritical verifies the EPSS
// amplifier: called HIGH with EPSS 0.6 promotes one tier → CRITICAL → 95.
func TestThreatIntel_EPSSHighOnHigh_PromotesToCritical(t *testing.T) {
	input := reachabilityScoreInput(
		"github.com/risky/pkg",
		testutil.BoolPtr(false),
		[]scanner.Vulnerability{
			makeVulnTI("CVE-2024-1002", "HIGH", "called", floatPtr(0.6), false),
		},
	)
	ps := ScoreAll(input)
	if ps.SeverityAdjustedVulnScore != 95 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 95 (EPSS 0.6 → HIGH promotes to CRITICAL → 95)",
			ps.SeverityAdjustedVulnScore)
	}
}

// TestThreatIntel_EPSSHighOnTestOnlyHigh_Becomes70 verifies composition with
// the test-only downgrade: HIGH → MEDIUM (test-only) first, then EPSS 0.6
// promotes MEDIUM → HIGH → step 70.
func TestThreatIntel_EPSSHighOnTestOnlyHigh_Becomes70(t *testing.T) {
	input := reachabilityScoreInput(
		"github.com/risky/pkg",
		testutil.BoolPtr(true), // confirmed test-only dep
		[]scanner.Vulnerability{
			makeVulnTI("CVE-2024-1003", "HIGH", "called", floatPtr(0.6), false),
		},
	)
	ps := ScoreAll(input)
	if ps.SeverityAdjustedVulnScore != 70 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 70 (test-only HIGH → MEDIUM, EPSS promotes → HIGH → 70)",
			ps.SeverityAdjustedVulnScore)
	}
}

// TestThreatIntel_KEVOnMedium_ForcesCritical verifies the KEV override:
// called MEDIUM in KEV → CRITICAL → 95.
func TestThreatIntel_KEVOnMedium_ForcesCritical(t *testing.T) {
	input := reachabilityScoreInput(
		"github.com/risky/pkg",
		testutil.BoolPtr(false),
		[]scanner.Vulnerability{
			makeVulnTI("CVE-2024-1004", "MEDIUM", "called", nil, true),
		},
	)
	ps := ScoreAll(input)
	if ps.SeverityAdjustedVulnScore != 95 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 95 (KEV override forces CRITICAL → 95)",
			ps.SeverityAdjustedVulnScore)
	}
}

// TestThreatIntel_KEVOnTestOnlyMedium_ForcesCritical verifies that a test-only
// MEDIUM downgrades to LOW — which is still in the step function, not dropped —
// so the KEV override applies and forces CRITICAL → 95. Only a dropped tier
// escapes the override.
func TestThreatIntel_KEVOnTestOnlyMedium_ForcesCritical(t *testing.T) {
	input := reachabilityScoreInput(
		"github.com/risky/pkg",
		testutil.BoolPtr(true), // confirmed test-only dep
		[]scanner.Vulnerability{
			makeVulnTI("CVE-2024-1005", "MEDIUM", "called", nil, true),
		},
	)
	ps := ScoreAll(input)
	if ps.SeverityAdjustedVulnScore != 95 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 95 (test-only MEDIUM → LOW, KEV overrides non-dropped tier → 95)",
			ps.SeverityAdjustedVulnScore)
	}
}

// TestThreatIntel_KEVAndEPSS_KEVWins verifies that when both signals are
// present, KEV wins: the tier is CRITICAL regardless of the EPSS promotion.
func TestThreatIntel_KEVAndEPSS_KEVWins(t *testing.T) {
	input := reachabilityScoreInput(
		"github.com/risky/pkg",
		testutil.BoolPtr(false),
		[]scanner.Vulnerability{
			makeVulnTI("CVE-2024-1006", "HIGH", "called", floatPtr(0.8), true),
		},
	)
	ps := ScoreAll(input)
	if ps.SeverityAdjustedVulnScore != 95 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 95 (KEV + EPSS 0.8 → CRITICAL → 95)",
			ps.SeverityAdjustedVulnScore)
	}
}

// TestThreatIntel_DroppedCVENotResurrected verifies the no-resurrection rule:
// a test-only LOW drops out of the step function entirely, and neither KEV nor
// EPSS brings it back — severity_adjusted stays 0.
func TestThreatIntel_DroppedCVENotResurrected(t *testing.T) {
	input := reachabilityScoreInput(
		"github.com/risky/pkg",
		testutil.BoolPtr(true), // confirmed test-only dep
		[]scanner.Vulnerability{
			makeVulnTI("CVE-2024-1007", "LOW", "called", floatPtr(0.95), true),
		},
	)
	ps := ScoreAll(input)
	if ps.SeverityAdjustedVulnScore != 0 {
		t.Errorf("SeverityAdjustedVulnScore = %d, want 0 (test-only LOW → dropped; KEV/EPSS must not resurrect)",
			ps.SeverityAdjustedVulnScore)
	}
}

// ---------------------------------------------------------------------------
// Per-dep axis: vulnScore EPSS bonus and KEV floor
// ---------------------------------------------------------------------------

// TestVulnScore_EPSSBonus verifies the additive per-dep bonus:
// called HIGH (80) + EPSS 0.8 × 15 = 92.
func TestVulnScore_EPSSBonus(t *testing.T) {
	got := vulnScore([]scanner.Vulnerability{
		makeVulnTI("CVE-2024-1008", "HIGH", "called", floatPtr(0.8), false),
	})
	if got != 92 {
		t.Errorf("vulnScore = %v, want 92 (HIGH 80 + EPSS 0.8×15 = 92)", got)
	}
}

// TestVulnScore_EPSSBonusCappedAt100 verifies the 100 ceiling holds.
func TestVulnScore_EPSSBonusCappedAt100(t *testing.T) {
	got := vulnScore([]scanner.Vulnerability{
		makeVulnTI("CVE-2024-1009", "CRITICAL", "called", floatPtr(1.0), false),
	})
	if got != 100 {
		t.Errorf("vulnScore = %v, want 100 (CRITICAL 100 + EPSS bonus capped at 100)", got)
	}
}

// TestSeverityFloor_KEVForcesCriticalFloor verifies that any KEV-listed CVE
// floors the dep at 76/CRITICAL regardless of severity and reachability.
func TestSeverityFloor_KEVForcesCriticalFloor(t *testing.T) {
	floor, promoted := severityFloor(time.Time{}, []scanner.Vulnerability{
		makeVulnTI("CVE-2024-1010", "MEDIUM", "required", nil, true),
	})
	if floor != 76 || promoted != RiskCritical {
		t.Errorf("severityFloor = (%d, %s), want (76, CRITICAL) for KEV-listed CVE", floor, promoted)
	}
}

// TestDepRiskLevel_KEVForcesCritical verifies end-to-end that a dep carrying a
// KEV MEDIUM surfaces as CRITICAL with score >= 76.
func TestDepRiskLevel_KEVForcesCritical(t *testing.T) {
	input := reachabilityScoreInput(
		"github.com/risky/pkg",
		testutil.BoolPtr(false),
		[]scanner.Vulnerability{
			makeVulnTI("CVE-2024-1011", "MEDIUM", "called", nil, true),
		},
	)
	ps := ScoreAll(input)
	var ds *DependencyScore
	for _, d := range ps.Dependencies {
		if d.Module == "github.com/risky/pkg" {
			ds = d
		}
	}
	if ds == nil {
		t.Fatal("dep github.com/risky/pkg not found in ProjectScore")
	}
	if ds.RiskLevel != RiskCritical || ds.RiskScore < 76 {
		t.Errorf("dep risk = %d/%s, want >=76/CRITICAL (KEV floor)", ds.RiskScore, ds.RiskLevel)
	}
}

// ---------------------------------------------------------------------------
// Hidden-risk warnings and time-bombs
// ---------------------------------------------------------------------------

// TestThreatIntel_KEVOnTestOnly_EmitsWarning verifies the hidden-risk warning:
// static analysis downgraded a KEV CVE, so a manual-review notice is emitted.
func TestThreatIntel_KEVOnTestOnly_EmitsWarning(t *testing.T) {
	input := reachabilityScoreInput(
		"github.com/risky/pkg",
		testutil.BoolPtr(true),
		[]scanner.Vulnerability{
			makeVulnTI("CVE-2024-1012", "MEDIUM", "called", nil, true),
		},
	)
	ps := ScoreAll(input)
	found := false
	for _, w := range ps.Warnings {
		if strings.Contains(w, "KEV CVE CVE-2024-1012") && strings.Contains(w, "verify reachability manually") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected KEV hidden-risk warning, got %v", ps.Warnings)
	}
}

// TestThreatIntel_HighEPSSOnImported_EmitsWarning verifies the EPSS >= 0.9
// variant of the hidden-risk warning on a reachability-downgraded CVE.
func TestThreatIntel_HighEPSSOnImported_EmitsWarning(t *testing.T) {
	input := reachabilityScoreInput(
		"github.com/risky/pkg",
		testutil.BoolPtr(false),
		[]scanner.Vulnerability{
			makeVulnTI("CVE-2024-1013", "HIGH", "imported", floatPtr(0.92), false),
		},
	)
	ps := ScoreAll(input)
	found := false
	for _, w := range ps.Warnings {
		if strings.Contains(w, "CVE-2024-1013") && strings.Contains(w, "verify reachability manually") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected high-EPSS hidden-risk warning, got %v", ps.Warnings)
	}
}

// TestCollectTimeBombs_KEV verifies that a KEV-listed CVE produces a "kev"
// time-bomb and is not duplicated as a critical_cve entry.
func TestCollectTimeBombs_KEV(t *testing.T) {
	input := reachabilityScoreInput(
		"github.com/risky/pkg",
		testutil.BoolPtr(false),
		[]scanner.Vulnerability{
			makeVulnTI("CVE-2024-1014", "CRITICAL", "called", nil, true),
		},
	)
	ps := ScoreAll(input)
	bombs := CollectTimeBombs(ps)

	var kevCount, critCount int
	for _, b := range bombs {
		switch b.Kind {
		case "kev":
			kevCount++
			if !strings.Contains(b.Detail, "CVE-2024-1014") || !strings.Contains(b.Detail, "exploited in the wild") {
				t.Errorf("kev bomb detail = %q, want CVE ID and exploitation wording", b.Detail)
			}
		case "critical_cve":
			critCount++
		}
	}
	if kevCount != 1 || critCount != 0 {
		t.Errorf("time-bombs kev=%d critical_cve=%d, want 1 kev and 0 critical_cve (KEV wins the dedup)", kevCount, critCount)
	}
}

// TestCollectTimeBombs_DedupeByCVEAlias verifies that the same CVE surfaced
// under different advisory IDs (GO-* and GHSA-*) produces one time-bomb, not
// one per advisory.
func TestCollectTimeBombs_DedupeByCVEAlias(t *testing.T) {
	goVuln := makeVulnTI("GO-2024-0001", "CRITICAL", "called", nil, true)
	goVuln.Aliases = []string{"CVE-2024-1015"}
	ghsaVuln := makeVulnTI("GHSA-aaaa-bbbb-cccc", "CRITICAL", "called", nil, true)
	ghsaVuln.Aliases = []string{"CVE-2024-1015"}

	input := reachabilityScoreInput(
		"github.com/risky/pkg",
		testutil.BoolPtr(false),
		[]scanner.Vulnerability{goVuln, ghsaVuln},
	)
	ps := ScoreAll(input)
	bombs := CollectTimeBombs(ps)

	var kevCount int
	for _, b := range bombs {
		if b.Kind == "kev" {
			kevCount++
		}
	}
	if kevCount != 1 {
		t.Errorf("time-bombs kev=%d, want 1 (GO-* and GHSA-* advisories share CVE-2024-1015)", kevCount)
	}
}
