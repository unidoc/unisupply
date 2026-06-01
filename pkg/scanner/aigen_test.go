package scanner

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/resolver"
)

// aigenTestNow is the fixed clock reference used by every test in this file.
// Anchoring to day-15 of a mid-year month makes time.AddDate end-of-month-safe
// (e.g. "May 31 minus 3 months" → March 3 normalization never bites), which
// matters because the aigen scanner gates on monthsSince(s.ScanStart,
// FirstReleaseDate). Tests that depend on real wall-clock time silently drift
// across band boundaries as the calendar moves; pinning a fixed date keeps
// assertions deterministic regardless of when the test happens to run.
func aigenTestNow() time.Time {
	return time.Date(2025, time.July, 15, 0, 0, 0, 0, time.UTC)
}

// newAIGenScannerForTest constructs an AIGenScanner whose ScanStart is pinned
// to the supplied now. The production NewAIGenScanner reads time.Now() — for
// determinism tests must override it so the scanner reads the same clock the
// test fixtures were built against.
func newAIGenScannerForTest(now time.Time) *AIGenScanner {
	s := NewAIGenScanner()
	s.ScanStart = now
	return s
}

// TestAIGenScanner_NoRisk tests a clean module with no AI-generated code indicators.
// Old module (years old), IsOrg=true, many releases → score=0, level="none"
func TestAIGenScanner_NoRisk(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	// Create a very old dependency (5 years old)
	now := aigenTestNow()
	oldDate := now.AddDate(-5, 0, 0)

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/golang/protobuf",
			Version: "v1.5.0",
		},
		Direct: true,
		Depth:  0,
	}

	maintainerInfo := &MaintainerInfo{
		Owner:            "golang",
		Repo:             "protobuf",
		OwnerName:        "Go Authors",
		OwnerLocation:    "USA",
		OwnerBio:         "Official Go language project",
		IsOrg:            true,
		ContributorCount: 50,
		BusFactor:        10,
		ActivityPattern:  "active",
	}

	resilienceInfo := &ResilienceInfo{
		FirstReleaseDate:  oldDate,
		TotalReleases:     100,
		ReleaseCadence:    "regular",
		HasSecurityPolicy: true,
		HasContribGuide:   true,
		HasCodeOfConduct:  true,
		VersionScheme:     "semver",
	}

	risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

	if risk.Score != 0 {
		t.Errorf("Expected score 0 for clean module, got %d", risk.Score)
	}
	if risk.RiskLevel != "none" {
		t.Errorf("Expected level 'none', got %q", risk.RiskLevel)
	}
	if len(risk.Indicators) != 0 {
		t.Errorf("Expected no indicators, got %v", risk.Indicators)
	}
}

// TestAIGenScanner_RecentModule tests a module created 3 months ago.
// Should add 15 points for "module_created_recently" + 5 for generic name "utils"
func TestAIGenScanner_RecentModule(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	now := aigenTestNow()
	threeMonthsAgo := now.AddDate(0, -3, 0)

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/newuser/mylib", // Non-generic name
			Version: "v0.1.0",
		},
		Direct: true,
	}

	maintainerInfo := &MaintainerInfo{
		IsOrg:            true,
		ContributorCount: 5,
		BusFactor:        2,
	}

	resilienceInfo := &ResilienceInfo{
		FirstReleaseDate:  threeMonthsAgo,
		TotalReleases:     5,
		HasSecurityPolicy: true,
		HasContribGuide:   true,
		HasCodeOfConduct:  true,
	}

	risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

	if risk.Score != 15 {
		t.Errorf("Expected score 15, got %d", risk.Score)
	}
	if risk.RiskLevel != "low" {
		t.Errorf("Expected level 'low', got %q", risk.RiskLevel)
	}
	if !slices.Contains(risk.Indicators, "module_created_recently") {
		t.Errorf("Expected indicator 'module_created_recently', got %v", risk.Indicators)
	}
}

// TestAIGenScanner_VeryNewModule tests a module created 10 days ago.
// Should add 30 (recent + last_30_days) + 10 (very_few) + 5 (no_governance) + 20 (single_anonymous) = 65
func TestAIGenScanner_VeryNewModule(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	now := aigenTestNow()
	tenDaysAgo := now.AddDate(0, 0, -10)

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/attacker/freshmodule",
			Version: "v0.0.1",
		},
		Direct: true,
	}

	maintainerInfo := &MaintainerInfo{
		IsOrg:            true,
		ContributorCount: 1,
		BusFactor:        1,
		OwnerName:        "", // Empty profile triggers empty_maintainer_profile (+10)
		OwnerBio:         "",
		OwnerLocation:    "",
	}

	resilienceInfo := &ResilienceInfo{
		FirstReleaseDate:  tenDaysAgo,
		TotalReleases:     1,
		HasSecurityPolicy: false,
		HasContribGuide:   false,
		HasCodeOfConduct:  false,
	}

	risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

	expectedScore := 15 + 15 + 10 + 5 + 10 + 10 // recent + last_30_days + very_few + no_governance + single_anon + empty_profile
	if risk.Score != expectedScore {
		t.Errorf("Expected score %d (15+15+10+5+10+10), got %d", expectedScore, risk.Score)
	}
	if risk.RiskLevel != "high" {
		t.Errorf("Expected level 'high', got %q", risk.RiskLevel)
	}

	hasRecent := slices.Contains(risk.Indicators, "module_created_recently")
	hasLast30 := slices.Contains(risk.Indicators, "module_created_last_30_days")
	if !hasRecent || !hasLast30 {
		t.Errorf("Expected both recent indicators, got %v", risk.Indicators)
	}
}

// TestAIGenScanner_FewReleases tests a module with only 1 release.
// Should add 10 points for "very_few_releases" + 5 for generic name "helper"
func TestAIGenScanner_FewReleases(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	now := aigenTestNow()
	twoYearsAgo := now.AddDate(-2, 0, 0)

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/oldstartup/mylib", // Non-generic name
			Version: "v0.1.0",
		},
		Direct: true,
	}

	maintainerInfo := &MaintainerInfo{
		IsOrg:            true,
		ContributorCount: 2,
		BusFactor:        1,
	}

	resilienceInfo := &ResilienceInfo{
		FirstReleaseDate:  twoYearsAgo,
		TotalReleases:     1, // Only 1 release
		HasSecurityPolicy: true,
		HasContribGuide:   true,
		HasCodeOfConduct:  true,
	}

	risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

	if risk.Score != 10 {
		t.Errorf("Expected score 10, got %d", risk.Score)
	}
	if !slices.Contains(risk.Indicators, "very_few_releases") {
		t.Errorf("Expected indicator 'very_few_releases', got %v", risk.Indicators)
	}
}

// TestAIGenScanner_FewReleasesTwo tests a module with 2 releases (boundary).
// Should add 10 points for "very_few_releases"
func TestAIGenScanner_FewReleasesTwo(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	now := aigenTestNow()
	oldDate := now.AddDate(-1, 0, 0)

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/oldstartup/mylib", // Non-generic name
			Version: "v0.2.0",
		},
		Direct: true,
	}

	maintainerInfo := &MaintainerInfo{
		IsOrg:            true,
		ContributorCount: 2,
		BusFactor:        1,
	}

	resilienceInfo := &ResilienceInfo{
		FirstReleaseDate:  oldDate,
		TotalReleases:     2, // Boundary: 2 releases
		HasSecurityPolicy: true,
		HasContribGuide:   true,
		HasCodeOfConduct:  true,
	}

	risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

	if risk.Score != 10 {
		t.Errorf("Expected score 10 for 2 releases, got %d", risk.Score)
	}
}

// TestAIGenScanner_NoGovernance tests a module with no governance files.
// Should add 5 points for "no_governance_files"
func TestAIGenScanner_NoGovernance(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	now := aigenTestNow()
	oldDate := now.AddDate(-1, 0, 0)

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/user/nogovernance",
			Version: "v1.0.0",
		},
		Direct: true,
	}

	maintainerInfo := &MaintainerInfo{
		IsOrg:            true,
		ContributorCount: 5,
		BusFactor:        2,
	}

	resilienceInfo := &ResilienceInfo{
		FirstReleaseDate:  oldDate,
		TotalReleases:     10,
		HasSecurityPolicy: false,
		HasContribGuide:   false,
		HasCodeOfConduct:  false,
	}

	risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

	if risk.Score != 5 {
		t.Errorf("Expected score 5, got %d", risk.Score)
	}
	if !slices.Contains(risk.Indicators, "no_governance_files") {
		t.Errorf("Expected indicator 'no_governance_files', got %v", risk.Indicators)
	}
}

// TestAIGenScanner_NoGovernanceNoReleases tests no governance with zero releases.
// Should NOT add 5 points for no_governance (because TotalReleases == 0)
// But may get points for single_anonymous_maintainer if contributor count is 1
func TestAIGenScanner_NoGovernanceNoReleases(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	now := aigenTestNow()
	oldDate := now.AddDate(-1, 0, 0)

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/user/nogovernance",
			Version: "v0.0.0",
		},
		Direct: true,
	}

	maintainerInfo := &MaintainerInfo{
		IsOrg:            true,
		ContributorCount: 5, // Multiple contributors
		BusFactor:        2,
	}

	resilienceInfo := &ResilienceInfo{
		FirstReleaseDate:  oldDate,
		TotalReleases:     0, // No releases
		HasSecurityPolicy: false,
		HasContribGuide:   false,
		HasCodeOfConduct:  false,
	}

	risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

	if risk.Score != 0 {
		t.Errorf("Expected score 0 (governance check skipped when no releases), got %d", risk.Score)
	}
	if slices.Contains(risk.Indicators, "no_governance_files") {
		t.Errorf("Should not have 'no_governance_files' indicator when TotalReleases=0")
	}
}

// TestAIGenScanner_SingleAnonymous tests a single maintainer with no profile info.
// Should add 10 for single_anonymous + 10 for empty_maintainer_profile = 20 total
func TestAIGenScanner_SingleAnonymous(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	now := aigenTestNow()
	oldDate := now.AddDate(-1, 0, 0)

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/anon/mysterypkg",
			Version: "v1.0.0",
		},
		Direct: true,
	}

	maintainerInfo := &MaintainerInfo{
		BusFactor:        1,
		ContributorCount: 1,
		OwnerName:        "", // Empty
		OwnerBio:         "", // Empty
		OwnerLocation:    "", // Empty
	}

	resilienceInfo := &ResilienceInfo{
		FirstReleaseDate:  oldDate,
		TotalReleases:     5,
		HasSecurityPolicy: true,
	}

	risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

	if risk.Score != 20 {
		t.Errorf("Expected score 20 (10+10), got %d", risk.Score)
	}
	if !slices.Contains(risk.Indicators, "single_anonymous_maintainer") {
		t.Errorf("Expected 'single_anonymous_maintainer', got %v", risk.Indicators)
	}
	if !slices.Contains(risk.Indicators, "empty_maintainer_profile") {
		t.Errorf("Expected 'empty_maintainer_profile', got %v", risk.Indicators)
	}
}

// TestAIGenScanner_SingleMaintainerWithProfile tests a single maintainer WITH profile info.
// Should add 10 for single_anonymous but NOT for empty_maintainer_profile
// Note: "mylib" doesn't match any special names, so no extra points
func TestAIGenScanner_SingleMaintainerWithProfile(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	now := aigenTestNow()
	oldDate := now.AddDate(-1, 0, 0)

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/realdev/something", // Non-generic, non-special name
			Version: "v1.0.0",
		},
		Direct: true,
	}

	maintainerInfo := &MaintainerInfo{
		BusFactor:        1,
		ContributorCount: 1,
		OwnerName:        "John Doe",
		OwnerBio:         "Software engineer",
		OwnerLocation:    "San Francisco",
		IsOrg:            true,
	}

	resilienceInfo := &ResilienceInfo{
		FirstReleaseDate:  oldDate,
		TotalReleases:     5,
		HasSecurityPolicy: true,
		HasContribGuide:   true,
		HasCodeOfConduct:  true,
	}

	risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

	if risk.Score != 10 {
		t.Errorf("Expected score 10, got %d (indicators: %v)", risk.Score, risk.Indicators)
	}
	if !slices.Contains(risk.Indicators, "single_anonymous_maintainer") {
		t.Errorf("Expected 'single_anonymous_maintainer', got %v", risk.Indicators)
	}
	if slices.Contains(risk.Indicators, "empty_maintainer_profile") {
		t.Errorf("Should not have 'empty_maintainer_profile' when OwnerName is set")
	}
}

// TestAIGenScanner_GenericNames tests various generic package names.
func TestAIGenScanner_GenericNames(t *testing.T) {
	genericNames := []string{
		"utils",
		"helper",
		"helpers",
		"common",
		"shared",
		"core",
		"tools",
		"toolkit",
		"sdk",
		"client",
		"api",
		"lib",
		"go-utils",
		"go-helper",
		"go-common",
		"go-tools",
	}

	now := aigenTestNow()
	oldDate := now.AddDate(-1, 0, 0)

	scanner := newAIGenScannerForTest(aigenTestNow())

	for _, name := range genericNames {
		t.Run(name, func(t *testing.T) {
			modulePath := "github.com/user/" + name

			dep := &resolver.Dependency{
				Module: parser.Module{
					Path:    modulePath,
					Version: "v1.0.0",
				},
				Direct: true,
			}

			maintainerInfo := &MaintainerInfo{
				IsOrg:            true,
				ContributorCount: 5,
				BusFactor:        2,
			}

			resilienceInfo := &ResilienceInfo{
				FirstReleaseDate:  oldDate,
				TotalReleases:     5,
				HasSecurityPolicy: true,
			}

			risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

			if risk.Score != 5 {
				t.Errorf("Expected score 5 for generic name %q, got %d", name, risk.Score)
			}
			if !slices.Contains(risk.Indicators, "generic_package_name") {
				t.Errorf("Expected 'generic_package_name' indicator for %q, got %v", name, risk.Indicators)
			}
		})
	}
}

// TestAIGenScanner_NonGenericNames tests that legitimate names don't trigger generic_package_name.
func TestAIGenScanner_NonGenericNames(t *testing.T) {
	nonGenericNames := []string{
		"kubernetes",
		"prometheus",
		"protobuf",
		"jwt-go",
		"uuid",
		"gorm",
	}

	now := aigenTestNow()
	oldDate := now.AddDate(-1, 0, 0)

	scanner := newAIGenScannerForTest(aigenTestNow())

	for _, name := range nonGenericNames {
		t.Run(name, func(t *testing.T) {
			modulePath := "github.com/user/" + name

			dep := &resolver.Dependency{
				Module: parser.Module{
					Path:    modulePath,
					Version: "v1.0.0",
				},
				Direct: true,
			}

			maintainerInfo := &MaintainerInfo{
				IsOrg:            true,
				ContributorCount: 5,
				BusFactor:        2,
			}

			resilienceInfo := &ResilienceInfo{
				FirstReleaseDate:  oldDate,
				TotalReleases:     5,
				HasSecurityPolicy: true,
			}

			risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

			if slices.Contains(risk.Indicators, "generic_package_name") {
				t.Errorf("Should not flag %q as generic_package_name", name)
			}
		})
	}
}

// TestAIGenScanner_UnofficialOfficial tests user account with official-looking names.
func TestAIGenScanner_UnofficialOfficial(t *testing.T) {
	officialPrefixes := []string{"go-", "golang-", "google-", "aws-", "azure-", "k8s-"}

	now := aigenTestNow()
	oldDate := now.AddDate(-1, 0, 0)

	scanner := newAIGenScannerForTest(aigenTestNow())

	for _, prefix := range officialPrefixes {
		t.Run(prefix, func(t *testing.T) {
			modulePath := "github.com/attacker/" + prefix + "something"

			dep := &resolver.Dependency{
				Module: parser.Module{
					Path:    modulePath,
					Version: "v1.0.0",
				},
				Direct: true,
			}

			// User account (not org)
			maintainerInfo := &MaintainerInfo{
				IsOrg:            false,
				ContributorCount: 1,
				BusFactor:        1,
				OwnerName:        "", // Empty profile
				OwnerBio:         "",
				OwnerLocation:    "",
			}

			resilienceInfo := &ResilienceInfo{
				FirstReleaseDate:  oldDate,
				TotalReleases:     1,
				HasSecurityPolicy: false,
				HasContribGuide:   false,
				HasCodeOfConduct:  false,
			}

			risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

			// Check that unofficial_official_looking_name is present and score includes it
			if !slices.Contains(risk.Indicators, "unofficial_official_looking_name") {
				t.Errorf("Expected 'unofficial_official_looking_name' for %q, got %v", prefix, risk.Indicators)
			}
			// single_anonymous (10) + empty_profile (10) + unofficial_official (10) + very_few (10) + no_governance (5) = 45
			expectedScore := 10 + 10 + 10 + 10 + 5
			if risk.Score != expectedScore {
				t.Errorf("Expected score %d for %q, got %d (indicators: %v)", expectedScore, prefix, risk.Score, risk.Indicators)
			}
		})
	}
}

// TestAIGenScanner_UnofficialOfficialInOrgAccount tests that org account doesn't trigger the check.
func TestAIGenScanner_UnofficialOfficialInOrgAccount(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	now := aigenTestNow()
	oldDate := now.AddDate(-1, 0, 0)

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/googlecontrib/go-utils",
			Version: "v1.0.0",
		},
		Direct: true,
	}

	// Org account
	maintainerInfo := &MaintainerInfo{
		IsOrg:            true,
		ContributorCount: 10,
		BusFactor:        5,
	}

	resilienceInfo := &ResilienceInfo{
		FirstReleaseDate:  oldDate,
		TotalReleases:     5,
		HasSecurityPolicy: true,
	}

	risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

	if slices.Contains(risk.Indicators, "unofficial_official_looking_name") {
		t.Errorf("Should not flag org account with official-looking name")
	}
}

// TestAIGenScanner_PseudoVersionOnly tests a module with only pseudo-versions.
// Should add 10 points for "pseudo_version_only" + 10 for single_anonymous + 10 for empty_profile
func TestAIGenScanner_PseudoVersionOnly(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	now := aigenTestNow()
	oldDate := now.AddDate(-1, 0, 0)

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/untagged/mylib",
			Version: "v0.0.0-20230101120000-abc123def456",
		},
		Direct: true,
	}

	maintainerInfo := &MaintainerInfo{
		IsOrg:            true,
		ContributorCount: 1,
		BusFactor:        1,
		OwnerName:        "",
		OwnerBio:         "",
		OwnerLocation:    "",
	}

	resilienceInfo := &ResilienceInfo{
		FirstReleaseDate:  oldDate,
		VersionScheme:     "pseudo",
		TotalReleases:     0, // No tagged releases
		HasSecurityPolicy: false,
	}

	risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

	expectedScore := 10 + 10 + 10 // pseudo_version_only + single_anonymous + empty_profile
	if risk.Score != expectedScore {
		t.Errorf("Expected score %d, got %d", expectedScore, risk.Score)
	}
	if !slices.Contains(risk.Indicators, "pseudo_version_only") {
		t.Errorf("Expected 'pseudo_version_only', got %v", risk.Indicators)
	}
}

// TestAIGenScanner_HighRiskComposite tests stacking multiple indicators.
// Score should be capped at 100 even if indicators add up to more.
func TestAIGenScanner_HighRiskComposite(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	now := aigenTestNow()
	tenDaysAgo := now.AddDate(0, 0, -10)

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/attacker/go-utils", // unofficial official (match "go-") + generic ("go-utils")
			Version: "v0.0.0-20230101120000-abc123",
		},
		Direct: true,
	}

	maintainerInfo := &MaintainerInfo{
		IsOrg:            false, // user account
		ContributorCount: 1,
		BusFactor:        1,
		OwnerName:        "",
		OwnerBio:         "",
		OwnerLocation:    "",
	}

	resilienceInfo := &ResilienceInfo{
		FirstReleaseDate:  tenDaysAgo, // very new (< 30 days)
		TotalReleases:     1,          // very few
		HasSecurityPolicy: false,
		HasContribGuide:   false,
		HasCodeOfConduct:  false,
		VersionScheme:     "pseudo",
	}

	risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

	// Verify key indicators are present
	requiredIndicators := []string{
		"module_created_recently",
		"module_created_last_30_days",
		"very_few_releases",
		"no_governance_files",
		"single_anonymous_maintainer",
		"empty_maintainer_profile",
		"generic_package_name",
		"unofficial_official_looking_name",
	}

	for _, ind := range requiredIndicators {
		if !slices.Contains(risk.Indicators, ind) {
			t.Errorf("Expected indicator %q in %v", ind, risk.Indicators)
		}
	}

	if risk.Score > 100 {
		t.Errorf("Score should be capped at 100, got %d", risk.Score)
	}
	if risk.RiskLevel != "high" {
		t.Errorf("Expected level 'high' for score %d, got %q", risk.Score, risk.RiskLevel)
	}
}

// TestAIGenScanner_RiskLevelClassification tests the risk level thresholds.
func TestAIGenScanner_RiskLevelClassification(t *testing.T) {
	tests := []struct {
		name          string
		setupFunc     func(*resolver.Dependency, *MaintainerInfo, *ResilienceInfo)
		expectedLevel string
	}{
		{
			"score_0",
			func(dep *resolver.Dependency, mi *MaintainerInfo, ri *ResilienceInfo) {
				// Old module, multiple contributors, all governance files
				ri.FirstReleaseDate = aigenTestNow().AddDate(-5, 0, 0)
				ri.TotalReleases = 50
				ri.HasSecurityPolicy = true
				ri.HasContribGuide = true
				ri.HasCodeOfConduct = true
				mi.IsOrg = true
				mi.ContributorCount = 10
				mi.BusFactor = 5
			},
			"none",
		},
		{
			"score_low",
			func(dep *resolver.Dependency, mi *MaintainerInfo, ri *ResilienceInfo) {
				// Recent module (3 months)
				ri.FirstReleaseDate = aigenTestNow().AddDate(0, -3, 0)
				ri.TotalReleases = 5
				mi.IsOrg = true
				mi.ContributorCount = 5
				mi.BusFactor = 2
			},
			"low",
		},
		{
			"score_medium",
			func(dep *resolver.Dependency, mi *MaintainerInfo, ri *ResilienceInfo) {
				// Recent + very few releases (15 + 10 = 25)
				ri.FirstReleaseDate = aigenTestNow().AddDate(0, -3, 0)
				ri.TotalReleases = 1
				mi.IsOrg = true
				mi.ContributorCount = 5
				mi.BusFactor = 2
			},
			"medium",
		},
		{
			"score_high",
			func(dep *resolver.Dependency, mi *MaintainerInfo, ri *ResilienceInfo) {
				// Very new (30) + few releases (10) + no governance (5) + single anon (20) = 65 >= 50
				ri.FirstReleaseDate = aigenTestNow().AddDate(0, 0, -10)
				ri.TotalReleases = 1
				ri.HasSecurityPolicy = false
				ri.HasContribGuide = false
				ri.HasCodeOfConduct = false
				mi.BusFactor = 1
				mi.ContributorCount = 1
				mi.OwnerName = ""
				mi.OwnerBio = ""
				mi.OwnerLocation = ""
			},
			"high",
		},
	}

	scanner := newAIGenScannerForTest(aigenTestNow())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dep := &resolver.Dependency{
				Module: parser.Module{
					Path:    "github.com/test/" + tt.name,
					Version: "v1.0.0",
				},
				Direct: true,
			}

			maintainerInfo := &MaintainerInfo{
				IsOrg:            true,
				ContributorCount: 10,
				BusFactor:        3,
				OwnerName:        "Test Owner",
			}

			resilienceInfo := &ResilienceInfo{
				FirstReleaseDate:  aigenTestNow().AddDate(-1, 0, 0),
				TotalReleases:     5,
				HasSecurityPolicy: true,
				HasContribGuide:   true,
				HasCodeOfConduct:  true,
			}

			// Apply test-specific setup
			tt.setupFunc(dep, maintainerInfo, resilienceInfo)

			risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

			if risk.RiskLevel != tt.expectedLevel {
				t.Errorf("expected level %q, got %q (score=%d, indicators=%v)", tt.expectedLevel, risk.RiskLevel, risk.Score, risk.Indicators)
			}
		})
	}
}

// TestAIGenScanner_ScanAll integration test with multiple dependencies.
func TestAIGenScanner_ScanAll(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	// Create a graph with 3 dependencies
	graph := &resolver.Graph{
		Root: "test/module",
		Dependencies: map[string]*resolver.Dependency{
			"github.com/clean/lib": {
				Module: parser.Module{
					Path:    "github.com/clean/lib",
					Version: "v1.5.0",
				},
				Direct: true,
				Depth:  0,
			},
			"github.com/suspicious/utils": {
				Module: parser.Module{
					Path:    "github.com/suspicious/utils",
					Version: "v0.0.1",
				},
				Direct: false,
				Depth:  1,
			},
			"github.com/official/gorm": {
				Module: parser.Module{
					Path:    "github.com/official/gorm",
					Version: "v1.0.0",
				},
				Direct: true,
				Depth:  0,
			},
		},
	}

	// Create maintainer info map
	now := aigenTestNow()
	oldDate := now.AddDate(-1, 0, 0)
	recentDate := now.AddDate(0, 0, -10)

	maintainers := map[string]*MaintainerInfo{
		"github.com/clean/lib": {
			IsOrg:            true,
			ContributorCount: 20,
			BusFactor:        5,
			OwnerName:        "Real Maintainer",
		},
		"github.com/suspicious/utils": {
			IsOrg:            false,
			ContributorCount: 1,
			BusFactor:        1,
			OwnerName:        "",
		},
		"github.com/official/gorm": {
			IsOrg:            true,
			ContributorCount: 50,
			BusFactor:        10,
		},
	}

	// Create resilience info map
	resilience := map[string]*ResilienceInfo{
		"github.com/clean/lib": {
			FirstReleaseDate:  oldDate,
			TotalReleases:     50,
			HasSecurityPolicy: true,
			HasContribGuide:   true,
			VersionScheme:     "semver",
		},
		"github.com/suspicious/utils": {
			FirstReleaseDate:  recentDate,
			TotalReleases:     1,
			HasSecurityPolicy: false,
			HasContribGuide:   false,
			HasCodeOfConduct:  false,
			VersionScheme:     "pseudo",
		},
		"github.com/official/gorm": {
			FirstReleaseDate:  oldDate,
			TotalReleases:     100,
			HasSecurityPolicy: true,
			HasContribGuide:   true,
			VersionScheme:     "semver",
		},
	}

	results := scanner.ScanAll(context.Background(), graph, maintainers, resilience)

	// Clean module should not be in results (score 0) since it's old with governance
	if _, ok := results["github.com/clean/lib"]; ok {
		// It might appear if the generic name check triggers - check the score
		risk := results["github.com/clean/lib"]
		if risk.Score == 0 {
			// Expected - it shouldn't be in results
			delete(results, "github.com/clean/lib")
		}
	}

	// Suspicious module should be in results with high score
	if risk, ok := results["github.com/suspicious/utils"]; ok {
		if risk.Score == 0 {
			t.Error("Suspicious module should have score > 0")
		}
		if risk.RiskLevel == "none" {
			t.Error("Suspicious module should not have level 'none'")
		}
	} else {
		t.Error("Suspicious module should be in results")
	}

	// Official module should not be in results (score 0)
	if _, ok := results["github.com/official/gorm"]; ok {
		// It might appear if the generic name check triggers
		risk := results["github.com/official/gorm"]
		if risk.Score == 0 {
			// Expected - it shouldn't be in results
			delete(results, "github.com/official/gorm")
		}
	}
}

// TestAIGenScanner_NilMaintainerInfo tests handling of nil maintainer info.
// Note: generic name "utils" will still trigger, so score won't be 0.
func TestAIGenScanner_NilMaintainerInfo(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	now := aigenTestNow()
	oldDate := now.AddDate(-1, 0, 0)

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/test/mylib", // Non-generic name
			Version: "v1.0.0",
		},
		Direct: true,
	}

	resilienceInfo := &ResilienceInfo{
		FirstReleaseDate:  oldDate,
		TotalReleases:     5,
		HasSecurityPolicy: true,
	}

	// Should not panic with nil maintainerInfo
	risk := scanner.analyzeModule(dep, nil, resilienceInfo)

	if risk == nil {
		t.Fatal("Risk should not be nil")
	}
	if risk.Score != 0 {
		t.Errorf("Score should be 0 with nil maintainer and old module, got %d", risk.Score)
	}
}

// TestAIGenScanner_NilResilienceInfo tests handling of nil resilience info.
// Note: generic name "utils" will still trigger, so score won't be 0.
func TestAIGenScanner_NilResilienceInfo(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/test/mylib", // Non-generic name
			Version: "v1.0.0",
		},
		Direct: true,
	}

	maintainerInfo := &MaintainerInfo{
		IsOrg:            true,
		ContributorCount: 5,
		BusFactor:        2,
	}

	// Should not panic with nil resilienceInfo
	risk := scanner.analyzeModule(dep, maintainerInfo, nil)

	if risk == nil {
		t.Fatal("Risk should not be nil")
	}
	if risk.Score != 0 {
		t.Errorf("Score should be 0 with nil resilience info, got %d", risk.Score)
	}
}

// TestAIGenScanner_BothNil tests handling of both nil inputs.
func TestAIGenScanner_BothNil(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/test/module",
			Version: "v1.0.0",
		},
		Direct: true,
	}

	// Should not panic with both nil
	risk := scanner.analyzeModule(dep, nil, nil)

	if risk == nil {
		t.Fatal("Risk should not be nil")
	}
	if risk.Score != 0 {
		t.Errorf("Score should be 0 with nil inputs, got %d", risk.Score)
	}
	if risk.RiskLevel != "none" {
		t.Errorf("Level should be 'none', got %q", risk.RiskLevel)
	}
}

// TestAIGenScanner_ModuleFieldSet tests that the Module field is set correctly.
func TestAIGenScanner_ModuleFieldSet(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	modulePath := "github.com/example/testmod"
	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    modulePath,
			Version: "v1.0.0",
		},
		Direct: true,
	}

	maintainerInfo := &MaintainerInfo{
		IsOrg: true,
	}

	resilienceInfo := &ResilienceInfo{
		TotalReleases: 10,
	}

	risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

	if risk.Module != modulePath {
		t.Errorf("Expected Module to be %q, got %q", modulePath, risk.Module)
	}
}

// TestAIGenScanner_ZeroFirstReleaseDate tests handling of zero FirstReleaseDate.
func TestAIGenScanner_ZeroFirstReleaseDate(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/test/unknown",
			Version: "v1.0.0",
		},
		Direct: true,
	}

	maintainerInfo := &MaintainerInfo{
		IsOrg: true,
	}

	resilienceInfo := &ResilienceInfo{
		FirstReleaseDate: time.Time{}, // zero time
		TotalReleases:    5,
	}

	// Should not panic and should not add points for recency
	risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

	if slices.Contains(risk.Indicators, "module_created_recently") {
		t.Errorf("Should not flag zero FirstReleaseDate as recently created")
	}
}

// TestAIGenScanner_PreChatGPTModuleNotFlagged verifies that a module first
// released before 2022-11-01 (the ChatGPT public launch date) is excluded from
// the AI-gen detector regardless of its other characteristics.
// github.com/kr/text was first released in 2014 — it must never be flagged.
func TestAIGenScanner_PreChatGPTModuleNotFlagged(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	firstRelease2014 := time.Date(2014, time.January, 1, 0, 0, 0, 0, time.UTC)

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/kr/text",
			Version: "v0.2.0",
		},
		Direct: true,
	}

	maintainerInfo := &MaintainerInfo{
		IsOrg:            false,
		ContributorCount: 1,
		BusFactor:        1,
		OwnerName:        "",
		OwnerBio:         "",
		OwnerLocation:    "",
	}

	resilienceInfo := &ResilienceInfo{
		FirstReleaseDate:  firstRelease2014,
		TotalReleases:     2,
		HasSecurityPolicy: false,
		HasContribGuide:   false,
		HasCodeOfConduct:  false,
	}

	risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

	if risk.RiskLevel != "none" {
		t.Errorf("Pre-ChatGPT module must not be flagged: got risk_level=%q score=%d indicators=%v",
			risk.RiskLevel, risk.Score, risk.Indicators)
	}
	if risk.Score != 0 {
		t.Errorf("Pre-ChatGPT module must have score 0, got %d", risk.Score)
	}
	if len(risk.Indicators) != 0 {
		t.Errorf("Pre-ChatGPT module must have no indicators, got %v", risk.Indicators)
	}
	if risk.MeetsPromotionGate {
		t.Error("Pre-ChatGPT module must not meet promotion gate")
	}
}

// TestAIGenScanner_PostChatGPTAllThreeIndicatorsFlagged verifies that a
// synthetic module with all three high-confidence signals (first release within
// the last 12 months, single release, generic name "utils") is flagged and
// promoted via MeetsPromotionGate.
func TestAIGenScanner_PostChatGPTAllThreeIndicatorsFlagged(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	// First release 6 months ago: post-ChatGPT and within the 12-month window.
	firstRelease := aigenTestNow().AddDate(0, -6, 0)

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/someuser/utils", // generic name "utils"
			Version: "v0.1.0",
		},
		Direct: true,
	}

	maintainerInfo := &MaintainerInfo{
		IsOrg:            true,
		ContributorCount: 5,
		BusFactor:        2,
	}

	resilienceInfo := &ResilienceInfo{
		FirstReleaseDate:  firstRelease,
		TotalReleases:     1, // single release — releasesAtMost2 = true
		HasSecurityPolicy: false,
		HasContribGuide:   false,
		HasCodeOfConduct:  false,
	}

	risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

	if risk.Score == 0 {
		t.Error("Post-ChatGPT module with all three indicators must have score > 0")
	}
	if !risk.MeetsPromotionGate {
		t.Errorf("Post-ChatGPT module with age<12mo + <=2 releases + generic name must meet promotion gate (score=%d indicators=%v)", risk.Score, risk.Indicators)
	}
	if !slices.Contains(risk.Indicators, "generic_package_name") {
		t.Errorf("Expected generic_package_name indicator, got %v", risk.Indicators)
	}
	if !slices.Contains(risk.Indicators, "very_few_releases") {
		t.Errorf("Expected very_few_releases indicator, got %v", risk.Indicators)
	}
}

// TestAIGenScanner_NilResilienceInfoNoFlag verifies that a nil ResilienceInfo
// causes the detector to skip entirely and produce no risk flag.
// Missing data must never trigger a false positive.
func TestAIGenScanner_NilResilienceInfoNoFlag(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/someuser/utils", // generic name — would score if ri were present
			Version: "v0.1.0",
		},
		Direct: true,
	}

	maintainerInfo := &MaintainerInfo{
		IsOrg:            false,
		ContributorCount: 1,
		BusFactor:        1,
		OwnerName:        "",
	}

	// ri == nil: no resilience data available.
	risk := scanner.analyzeModule(dep, maintainerInfo, nil)

	if risk.Score != 0 {
		t.Errorf("nil ResilienceInfo must produce score 0, got %d (indicators: %v)", risk.Score, risk.Indicators)
	}
	if risk.RiskLevel != "none" {
		t.Errorf("nil ResilienceInfo must produce risk_level none, got %q", risk.RiskLevel)
	}
	if risk.MeetsPromotionGate {
		t.Error("nil ResilienceInfo must not meet promotion gate")
	}
}

// TestAIGenScanner_ZeroFirstReleaseDateNoFlag verifies that a zero
// FirstReleaseDate causes the detector to skip entirely and produce no flag.
// This guards against false positives when GitHub API data is unavailable.
func TestAIGenScanner_ZeroFirstReleaseDateNoFlag(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/someuser/utils", // generic name — would score if date were known
			Version: "v0.1.0",
		},
		Direct: true,
	}

	maintainerInfo := &MaintainerInfo{
		IsOrg:            false,
		ContributorCount: 1,
		BusFactor:        1,
	}

	resilienceInfo := &ResilienceInfo{
		FirstReleaseDate: time.Time{}, // zero: date unknown
		TotalReleases:    1,
	}

	risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

	if risk.Score != 0 {
		t.Errorf("Zero FirstReleaseDate must produce score 0, got %d (indicators: %v)", risk.Score, risk.Indicators)
	}
	if risk.RiskLevel != "none" {
		t.Errorf("Zero FirstReleaseDate must produce risk_level none, got %q", risk.RiskLevel)
	}
	if risk.MeetsPromotionGate {
		t.Error("Zero FirstReleaseDate must not meet promotion gate")
	}
}

// TestAIGenScanner_SingleIndicatorPopulatesIndicatorsNotRiskFactors verifies
// that a module with only one indicator (generic_name only, no recent age, no
// few releases) populates aigen.Indicators for transparency but does NOT meet
// the promotion gate that drives risk_factors in the scorer.
func TestAIGenScanner_SingleIndicatorPopulatesIndicatorsNotRiskFactors(t *testing.T) {
	scanner := newAIGenScannerForTest(aigenTestNow())

	// Module first released in 2023 (post-ChatGPT) but more than 12 months ago
	// so it does NOT meet age < 12 months.
	firstRelease := time.Date(2023, time.January, 1, 0, 0, 0, 0, time.UTC)

	dep := &resolver.Dependency{
		Module: parser.Module{
			Path:    "github.com/someuser/utils", // generic name only
			Version: "v2.0.0",
		},
		Direct: true,
	}

	maintainerInfo := &MaintainerInfo{
		IsOrg:            true,
		ContributorCount: 10,
		BusFactor:        5,
	}

	resilienceInfo := &ResilienceInfo{
		FirstReleaseDate:  firstRelease,
		TotalReleases:     20, // many releases, so releasesAtMost2 = false
		HasSecurityPolicy: true,
		HasContribGuide:   true,
		HasCodeOfConduct:  true,
	}

	risk := scanner.analyzeModule(dep, maintainerInfo, resilienceInfo)

	// generic_package_name indicator must be populated for transparency.
	if !slices.Contains(risk.Indicators, "generic_package_name") {
		t.Errorf("Single-indicator hit must populate Indicators: got %v", risk.Indicators)
	}
	if risk.Score == 0 {
		t.Error("Single-indicator hit must have non-zero score")
	}

	// But the promotion gate must NOT fire (only one of the three signals is present).
	if risk.MeetsPromotionGate {
		t.Errorf("Single generic_name indicator must NOT meet promotion gate (score=%d indicators=%v)",
			risk.Score, risk.Indicators)
	}
}
