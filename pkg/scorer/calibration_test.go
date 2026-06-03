package scorer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/scanner"
)

// Calibration corpus regression gate.
//
// Each fixture under testdata/calibration/<project>.json is a recorded
// `unisupply --format json` output (plus a leading `_meta` block) at a pinned
// upstream SHA. The fixture is treated as frozen scanner output; the test
// rebuilds the per-dep score list from the recorded `dependencies[]` and
// re-runs only the Task-10 headline aggregators (computeOverallScore +
// severityAdjustedVulnScore). Those two functions are the regression gate
// this corpus is designed to catch — per-dep scoring (Task 8) is already
// covered by risk_test.go on synthetic inputs.
//
// We deliberately do NOT re-run the full ScoreAll pipeline. The JSON report
// drops `resilience`, `ai_gen_risk`, and `trust_index` from each dep, so a
// scanner-input-level re-run would diverge from the recorded per-dep
// `risk_score`. Instead the harness re-aggregates the headline directly from
// the recorded per-dep `risk_score` + `vulnerabilities` + `is_test_only` —
// those are exactly the inputs of two aggregators read, and the
// per-dep `risk_score` already absorbs every bonus the JSON dropped. The
// regression this corpus catches is therefore a change to the aggregation
// step (computeOverallScore / severityAdjustedVulnScore / headline tiebreak)
// or to the recorded fixture itself (via the sha256 ratchet). Changes inside
// per-dep `scoreDependency` are not gated here — they are covered by
// risk_test.go on synthetic inputs, and surface in this corpus only when a
// fixture is re-recorded.
//
// Re-recording protocol:
//
//   1. Run `unisupply --format json --debug-scoring -o /tmp/<project>-raw.json <path>`.
//   2. Run `go run ./tools/calibration-record --in /tmp/<project>-raw.json
//      --out pkg/scorer/testdata/calibration/<project>.json --upstream-pin <pin>
//      --scanner-sha $(git rev-parse HEAD) --version <version> --reason "<why>"`.
//   3. The tool recomputes `_meta.content_sha256` and writes the
//      `_meta.rerecord_reason` you passed; both must change on every commit
//      that modifies the body.
//
// Until a fixture is recorded the corresponding subtest skips with t.Skip.

const calibrationDir = "testdata/calibration"

// calibrationCase declares one fixture and the expected headline envelope.
type calibrationCase struct {
	fixture        string    // file under testdata/calibration/
	expectedLevel  RiskLevel // hard assertion
	scoreMin       int       // soft assertion (t.Logf on miss)
	scoreMax       int       // soft assertion (t.Logf on miss)
	expectedDriver string    // hard assertion: "mean" or "severity_adjusted"
	// worstCVEAliases lists acceptable aliases of `worst_cve_id`. The test
	// looks up the dep that carries the recorded worst CVE and asserts its
	// alias list intersects this set. Empty = skip the check.
	worstCVEAliases []string
}

var calibrationCases = []calibrationCase{
	{
		fixture:         "gitea-v1.20.json",
		expectedLevel:   RiskCritical,
		scoreMin:        85,
		scoreMax:        100,
		expectedDriver:  "severity_adjusted",
		worstCVEAliases: []string{"CVE-2023-49569", "CVE-2024-45337", "CVE-2025-21613"},
	},
	{
		// Source body anchored Traefik master as MEDIUM 35–55 with
		// docker/docker classified as test-only. Task 09's honest package-level
		// `go list` comparison reports docker/docker as production-path because
		// Traefik's non-test code transitively imports it, which promotes the
		// severity-adjusted axis to HIGH 70 (`--debug-scoring` confirms
		// test_only:false). INDEX.md line 33 ratifies the revised anchor.
		fixture:        "traefik-master.json",
		expectedLevel:  RiskHigh,
		scoreMin:       60,
		scoreMax:       80,
		expectedDriver: "severity_adjusted",
		// CVE-2026-34040 / GHSA-x744-4wpc-v9h2 — the load-bearing HIGH on
		// google.golang.org/grpc at the time of recording.
		worstCVEAliases: []string{"CVE-2026-34040", "GHSA-x744-4wpc-v9h2"},
	},
	{
		fixture:        "gitea-master.json",
		expectedLevel:  RiskMedium,
		scoreMin:       30,
		scoreMax:       40,
		expectedDriver: "p95_dep_risk",
	},
	{
		fixture:        "unisupply-self.json",
		expectedLevel:  RiskMedium,
		scoreMin:       35,
		scoreMax:       45,
		expectedDriver: "severity_adjusted",
	},
}

// fixtureMeta mirrors the `_meta` block produced by the recording tool.
type fixtureMeta struct {
	RecordedAt       string `json:"recorded_at"`
	UnisupplyVersion string `json:"unisupply_version"`
	ScannerGitSHA    string `json:"scanner_git_sha"`
	UpstreamPin      string `json:"upstream_pin"`
	RerecordReason   string `json:"rerecord_reason"`
	ContentSHA256    string `json:"content_sha256"`
}

// fixtureVuln is the minimal subset of pkg/report.JSONVuln the test needs.
// We can't import pkg/report here (that package depends on scorer), so we
// declare the local shape inline.
type fixtureVuln struct {
	ID           string   `json:"id"`
	Aliases      []string `json:"aliases"`
	Severity     string   `json:"severity"`
	Reachability string   `json:"reachability,omitempty"`
}

type fixtureDep struct {
	Module      string        `json:"module"`
	Version     string        `json:"version"`
	Direct      bool          `json:"direct"`
	TestOnly    *bool         `json:"test_only"`
	RiskScore   int           `json:"risk_score"`
	RiskLevel   string        `json:"risk_level"`
	Vulns       []fixtureVuln `json:"vulnerabilities"`
	Maintenance struct {
		Archived bool `json:"archived"`
	} `json:"maintenance"`
}

// fixtureBody is the subset of the report JSON that the test reads. Other
// top-level keys (project, summary, ci_findings, debug_scoring, …) are
// preserved in the fixture but unused here.
type fixtureBody struct {
	OverallRiskScore          int          `json:"overall_risk_score"`
	OverallRiskLevel          string       `json:"overall_risk_level"`
	HeadlineDriver            string       `json:"headline_driver"`
	MeanDepRiskScore          int          `json:"mean_dep_risk_score"`
	SeverityAdjustedVulnScore int          `json:"severity_adjusted_vuln_score"`
	WorstCVEID                string       `json:"worst_cve_id"`
	WorstCVESeverity          string       `json:"worst_cve_severity"`
	Dependencies              []fixtureDep `json:"dependencies"`
}

// loadFixture reads a calibration fixture, validates content_sha256, and
// returns the parsed envelope. Returns nil + skip-reason if the fixture
// is missing on disk (used to skip unrecorded cases via t.Skip).
func loadFixture(t *testing.T, name string) (fixtureMeta, fixtureBody, []fixtureDep, bool) {
	t.Helper()

	path := filepath.Join(calibrationDir, name)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return fixtureMeta{}, fixtureBody{}, nil, true
	}
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}

	// Parse generically first so we can separate _meta from body for hashing.
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("parse fixture %s: %v", path, err)
	}

	metaRaw, ok := generic["_meta"]
	if !ok {
		t.Fatalf("%s: missing _meta block", path)
	}
	metaBytes, err := json.Marshal(metaRaw)
	if err != nil {
		t.Fatalf("%s: re-encode _meta: %v", path, err)
	}
	var meta fixtureMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		t.Fatalf("%s: parse _meta: %v", path, err)
	}

	// Required _meta fields. ContentSHA256 is verified separately below.
	switch {
	case meta.RecordedAt == "":
		t.Fatalf("%s: _meta.recorded_at is empty", path)
	case meta.UnisupplyVersion == "":
		t.Fatalf("%s: _meta.unisupply_version is empty", path)
	case meta.ScannerGitSHA == "":
		t.Fatalf("%s: _meta.scanner_git_sha is empty", path)
	case meta.UpstreamPin == "":
		t.Fatalf("%s: _meta.upstream_pin is empty", path)
	case meta.RerecordReason == "":
		t.Fatalf("%s: _meta.rerecord_reason is empty (every commit modifying a fixture must update this)", path)
	case meta.ContentSHA256 == "":
		t.Fatalf("%s: _meta.content_sha256 is empty", path)
	}

	// Hash the body with _meta stripped, using the same canonicalization the
	// recording tool used: json.MarshalIndent(map, "", "  ") with Go's default
	// alphabetical key ordering.
	delete(generic, "_meta")
	canon, err := json.MarshalIndent(generic, "", "  ")
	if err != nil {
		t.Fatalf("%s: canonicalize body: %v", path, err)
	}
	sum := sha256.Sum256(canon)
	gotHash := hex.EncodeToString(sum[:])
	if gotHash != meta.ContentSHA256 {
		t.Fatalf("%s: content_sha256 mismatch — _meta says %s, body hashes to %s. Re-record the fixture with the prep tool (which recomputes the hash) and update _meta.rerecord_reason.", path, meta.ContentSHA256, gotHash)
	}

	// Now parse the body into the typed envelope.
	var body fixtureBody
	if err := json.Unmarshal(canon, &body); err != nil {
		t.Fatalf("%s: parse body: %v", path, err)
	}

	// Also parse dependencies (already in body, but duplicated here to keep
	// the call signature simple).
	return meta, body, body.Dependencies, false
}

// buildDeps reconstructs the per-dep score list needed by the Task-10
// headline aggregators. Only fields touched by computeOverallScore and
// severityAdjustedVulnScore are populated — the rest (Maintainer, AIGenRisk,
// Resilience, TrustIndex, …) are left zero because the headline math does not
// read them. Maintenance.Archived is populated for archivedFloor.
func buildDeps(in []fixtureDep) []*DependencyScore {
	out := make([]*DependencyScore, 0, len(in))
	for _, d := range in {
		var maint *scanner.MaintenanceInfo
		if d.Maintenance.Archived {
			maint = &scanner.MaintenanceInfo{Archived: true}
		}
		ds := &DependencyScore{
			Module:      d.Module,
			Version:     d.Version,
			Direct:      d.Direct,
			RiskScore:   d.RiskScore,
			RiskLevel:   RiskLevel(d.RiskLevel),
			IsTestOnly:  d.TestOnly,
			Maintenance: maint,
		}
		for _, v := range d.Vulns {
			ds.Vulns = append(ds.Vulns, scanner.Vulnerability{
				ID:           v.ID,
				Aliases:      v.Aliases,
				Severity:     v.Severity,
				Reachability: v.Reachability,
			})
		}
		out = append(out, ds)
	}
	return out
}

// rerunHeadline computes the same headline ScoreAll would have produced from
// the recorded per-dep RiskScore + Vulns + IsTestOnly + Maintenance.
// Mirrors the four-candidate logic in ScoreAll.
func rerunHeadline(deps []*DependencyScore) (mean, sevAdj, overall int, level RiskLevel, driver, worstID, worstSev string) {
	mean = computeOverallScore(deps)
	sev := severityAdjustedVulnScore(time.Now(), deps)
	sevAdj = sev.score
	worstID = sev.worstID
	worstSev = sev.worstSeverity

	// Build the four candidates.
	candidates := []HeadlineCandidate{
		{Name: "severity_adjusted", Score: float64(sevAdj)},
		p95DepRiskCandidate(deps),
		archivedFloor(deps),
		cveFloor(deps),
	}
	winner := selectHeadline(candidates)
	overall = int(math.Round(winner.Score))
	driver = winner.Name

	// Clear driver when no deps (mirrors ScoreAll behavior).
	if len(deps) == 0 {
		driver = ""
	}

	level = levelFromScore(overall)
	return
}

func TestCalibrationCorpus(t *testing.T) {
	for _, tc := range calibrationCases {
		tc := tc
		t.Run(tc.fixture, func(t *testing.T) {
			_, body, deps, missing := loadFixture(t, tc.fixture)
			if missing {
				t.Skipf("%s not yet recorded — see calibration_test.go header for re-recording protocol", tc.fixture)
			}
			// Cases with no expectations declared (placeholders) are also
			// skipped so the test fails only on real regressions.
			if tc.expectedLevel == "" {
				t.Skipf("%s: expected envelope not yet declared in calibrationCases", tc.fixture)
			}

			built := buildDeps(deps)
			mean, sevAdj, overall, level, driver, worstID, _ := rerunHeadline(built)

			// 1) Re-run must agree with the recorded headline. This is what
			//    catches a scoring-formula change that the author forgot to
			//    re-record fixtures for.
			if level != RiskLevel(body.OverallRiskLevel) {
				t.Fatalf("re-run level %s != recorded level %s — scoring formula changed; re-record fixture", level, body.OverallRiskLevel)
			}
			if driver != body.HeadlineDriver {
				t.Fatalf("re-run driver %q != recorded driver %q", driver, body.HeadlineDriver)
			}
			if worstID != body.WorstCVEID {
				t.Fatalf("re-run worst_cve_id %q != recorded %q", worstID, body.WorstCVEID)
			}
			if mean != body.MeanDepRiskScore {
				t.Errorf("re-run mean_dep_risk_score %d != recorded %d", mean, body.MeanDepRiskScore)
			}
			if sevAdj != body.SeverityAdjustedVulnScore {
				t.Errorf("re-run severity_adjusted_vuln_score %d != recorded %d", sevAdj, body.SeverityAdjustedVulnScore)
			}
			if overall != body.OverallRiskScore {
				t.Errorf("re-run overall_risk_score %d != recorded %d", overall, body.OverallRiskScore)
			}

			// 2) Recorded headline must fall in the expected envelope. This is
			//    the calibration assertion — even after a fixture is re-recorded,
			//    the recorded level must stay in band.
			if RiskLevel(body.OverallRiskLevel) != tc.expectedLevel {
				t.Fatalf("calibration anchor regressed: %s recorded as %s, expected %s", tc.fixture, body.OverallRiskLevel, tc.expectedLevel)
			}
			if body.HeadlineDriver != tc.expectedDriver {
				t.Fatalf("calibration driver regressed: %s recorded driver=%q, expected %q", tc.fixture, body.HeadlineDriver, tc.expectedDriver)
			}
			if body.OverallRiskScore < tc.scoreMin || body.OverallRiskScore > tc.scoreMax {
				t.Logf("calibration soft warning: %s score %d outside expected band [%d, %d] (level %s still matches)",
					tc.fixture, body.OverallRiskScore, tc.scoreMin, tc.scoreMax, body.OverallRiskLevel)
			}

			// 3) Worst-CVE alias check. The recorded worst_cve_id is the canonical
			//    govulncheck ID (e.g. GO-2024-2456); we look up that dep and assert
			//    its alias list intersects the expected CVE set.
			if len(tc.worstCVEAliases) > 0 {
				if !worstCVEAliasMatch(deps, body.WorstCVEID, tc.worstCVEAliases) {
					t.Fatalf("calibration worst-CVE regressed: %s worst_cve_id=%q has no alias in %v",
						tc.fixture, body.WorstCVEID, tc.worstCVEAliases)
				}
			}
		})
	}
}

// worstCVEAliasMatch returns true when at least one dep has a vuln whose ID
// equals worstID and whose aliases overlap with want.
func worstCVEAliasMatch(deps []fixtureDep, worstID string, want []string) bool {
	wantSet := make(map[string]struct{}, len(want))
	for _, a := range want {
		wantSet[a] = struct{}{}
	}
	for _, d := range deps {
		for _, v := range d.Vulns {
			if v.ID != worstID {
				continue
			}
			for _, a := range v.Aliases {
				if _, ok := wantSet[a]; ok {
					return true
				}
			}
		}
	}
	return false
}

// TestCalibrationHashRatchet asserts that tampering with a fixture body fails
// loadFixture's hash check. Uses gitea-v1.20.json as the canary; if that
// fixture is ever removed the test skips.
func TestCalibrationHashRatchet(t *testing.T) {
	path := filepath.Join(calibrationDir, "gitea-v1.20.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("gitea-v1.20.json not recorded; cannot exercise ratchet")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	// Tamper: bump the recorded overall_risk_score by 1. Hash should no
	// longer match _meta.content_sha256.
	if v, ok := m["overall_risk_score"].(float64); ok {
		m["overall_risk_score"] = v + 1
	} else {
		t.Fatalf("overall_risk_score not a number")
	}

	tampered, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}

	tmp := filepath.Join(t.TempDir(), "tampered.json")
	if err := os.WriteFile(tmp, tampered, 0o644); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	// Re-parse and run the hash check inline (loadFixture would call t.Fatal
	// which we'd have to recover from).
	var generic map[string]any
	if err := json.Unmarshal(tampered, &generic); err != nil {
		t.Fatalf("parse tampered: %v", err)
	}
	metaRaw := generic["_meta"]
	metaBytes, _ := json.Marshal(metaRaw)
	var meta fixtureMeta
	_ = json.Unmarshal(metaBytes, &meta)
	delete(generic, "_meta")
	canon, _ := json.MarshalIndent(generic, "", "  ")
	sum := sha256.Sum256(canon)
	gotHash := hex.EncodeToString(sum[:])
	if gotHash == meta.ContentSHA256 {
		t.Fatalf("tampered fixture still hashes to %s — ratchet not catching changes", gotHash)
	}
}
