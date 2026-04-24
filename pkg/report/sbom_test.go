package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/unidoc/unisupply/pkg/scorer"
	"github.com/unidoc/unisupply/pkg/testutil"
)

// TestWriteCycloneDX_ValidJSON tests that WriteCycloneDX produces valid JSON.
func TestWriteCycloneDX_ValidJSON(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/example/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 20,
		OverallLevel: scorer.RiskLow,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "github.com/example/pkg",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 20,
				RiskLevel: scorer.RiskLow,
			},
		},
		LowRiskCount: 1,
	}

	opts := SBOMOptions{
		GoVersion: "1.21",
	}

	var buf bytes.Buffer
	err := WriteCycloneDX(graph, ps, opts, &buf)
	if err != nil {
		t.Fatalf("WriteCycloneDX() failed: %v", err)
	}

	// Parse as JSON
	var bom cdxBOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("Failed to unmarshal CycloneDX JSON: %v", err)
	}

	// Verify top-level structure
	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("BOMFormat = %q, want %q", bom.BOMFormat, "CycloneDX")
	}

	if bom.SpecVersion != "1.5" {
		t.Errorf("SpecVersion = %q, want %q", bom.SpecVersion, "1.5")
	}

	if bom.SerialNumber == "" {
		t.Error("SerialNumber should not be empty")
	}

	if bom.Version != 1 {
		t.Errorf("Version = %d, want 1", bom.Version)
	}
}

// TestWriteCycloneDX_Components tests that components are populated correctly.
func TestWriteCycloneDX_Components(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/pkg1",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
		testutil.DepSpec{
			Path:    "github.com/pkg2",
			Version: "v2.0.0",
			Direct:  false,
			Depth:   1,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 30,
		OverallLevel: scorer.RiskLow,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "github.com/pkg1",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 20,
				RiskLevel: scorer.RiskLow,
			},
			{
				Module:    "github.com/pkg2",
				Version:   "v2.0.0",
				Direct:    false,
				RiskScore: 30,
				RiskLevel: scorer.RiskLow,
			},
		},
		LowRiskCount: 2,
	}

	opts := SBOMOptions{
		GoVersion: "1.21",
	}

	var buf bytes.Buffer
	err := WriteCycloneDX(graph, ps, opts, &buf)
	if err != nil {
		t.Fatalf("WriteCycloneDX() failed: %v", err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("Failed to unmarshal CycloneDX JSON: %v", err)
	}

	// Should have 2 components (one for each dependency)
	if len(bom.Components) != 2 {
		t.Fatalf("Components length = %d, want 2", len(bom.Components))
	}

	// Check first component
	comp1 := bom.Components[0]
	if comp1.Name != "github.com/pkg1" {
		t.Errorf("Components[0].Name = %q, want %q", comp1.Name, "github.com/pkg1")
	}
	if comp1.Version != "v1.0.0" {
		t.Errorf("Components[0].Version = %q, want %q", comp1.Version, "v1.0.0")
	}
	if comp1.Scope != "required" {
		t.Errorf("Components[0].Scope = %q, want %q", comp1.Scope, "required")
	}

	// Check second component
	comp2 := bom.Components[1]
	if comp2.Name != "github.com/pkg2" {
		t.Errorf("Components[1].Name = %q, want %q", comp2.Name, "github.com/pkg2")
	}
	if comp2.Version != "v2.0.0" {
		t.Errorf("Components[1].Version = %q, want %q", comp2.Version, "v2.0.0")
	}
	if comp2.Scope != "optional" {
		t.Errorf("Components[1].Scope = %q, want %q", comp2.Scope, "optional")
	}
}

// TestWriteCycloneDX_RiskScoreProperty tests that risk score is added as a property.
func TestWriteCycloneDX_RiskScoreProperty(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "risky-pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 60,
		OverallLevel: scorer.RiskHigh,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "risky-pkg",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 60,
				RiskLevel: scorer.RiskHigh,
			},
		},
		HighRiskCount: 1,
	}

	opts := SBOMOptions{
		GoVersion: "1.21",
	}

	var buf bytes.Buffer
	err := WriteCycloneDX(graph, ps, opts, &buf)
	if err != nil {
		t.Fatalf("WriteCycloneDX() failed: %v", err)
	}

	var bom cdxBOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("Failed to unmarshal CycloneDX JSON: %v", err)
	}

	if len(bom.Components) != 1 {
		t.Fatalf("Components length = %d, want 1", len(bom.Components))
	}

	comp := bom.Components[0]

	// Find risk score property
	found := false
	for _, prop := range comp.Properties {
		if prop.Name == "unisupply:risk_score" {
			if prop.Value != "60" {
				t.Errorf("risk_score property = %q, want %q", prop.Value, "60")
			}
			found = true
			break
		}
	}

	if !found {
		t.Error("unisupply:risk_score property not found")
	}

	// Find risk level property
	found = false
	for _, prop := range comp.Properties {
		if prop.Name == "unisupply:risk_level" {
			if prop.Value != "HIGH" {
				t.Errorf("risk_level property = %q, want %q", prop.Value, "HIGH")
			}
			found = true
			break
		}
	}

	if !found {
		t.Error("unisupply:risk_level property not found")
	}
}

// TestWriteSPDX_ValidJSON tests that WriteSPDX produces valid JSON.
func TestWriteSPDX_ValidJSON(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/example/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 20,
		OverallLevel: scorer.RiskLow,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "github.com/example/pkg",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 20,
				RiskLevel: scorer.RiskLow,
			},
		},
		LowRiskCount: 1,
	}

	opts := SBOMOptions{
		GoVersion: "1.21",
	}

	var buf bytes.Buffer
	err := WriteSPDX(graph, ps, opts, &buf)
	if err != nil {
		t.Fatalf("WriteSPDX() failed: %v", err)
	}

	// Parse as JSON
	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to unmarshal SPDX JSON: %v", err)
	}

	// Verify top-level structure
	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("SPDXVersion = %q, want %q", doc.SPDXVersion, "SPDX-2.3")
	}

	if doc.DataLicense != "CC0-1.0" {
		t.Errorf("DataLicense = %q, want %q", doc.DataLicense, "CC0-1.0")
	}

	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID = %q, want %q", doc.SPDXID, "SPDXRef-DOCUMENT")
	}

	if doc.Name != "test/module" {
		t.Errorf("Name = %q, want %q", doc.Name, "test/module")
	}
}

// TestWriteSPDX_Packages tests that packages are populated correctly.
func TestWriteSPDX_Packages(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/pkg1",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
		testutil.DepSpec{
			Path:    "github.com/pkg2",
			Version: "v2.0.0",
			Direct:  false,
			Depth:   1,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 30,
		OverallLevel: scorer.RiskLow,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "github.com/pkg1",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 20,
				RiskLevel: scorer.RiskLow,
			},
			{
				Module:    "github.com/pkg2",
				Version:   "v2.0.0",
				Direct:    false,
				RiskScore: 30,
				RiskLevel: scorer.RiskLow,
			},
		},
		LowRiskCount: 2,
	}

	opts := SBOMOptions{
		GoVersion: "1.21",
	}

	var buf bytes.Buffer
	err := WriteSPDX(graph, ps, opts, &buf)
	if err != nil {
		t.Fatalf("WriteSPDX() failed: %v", err)
	}

	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to unmarshal SPDX JSON: %v", err)
	}

	// Should have 3 packages: root + 2 dependencies
	if len(doc.Packages) != 3 {
		t.Fatalf("Packages length = %d, want 3", len(doc.Packages))
	}

	// First package should be root
	rootPkg := doc.Packages[0]
	if rootPkg.Name != "test/module" {
		t.Errorf("Root package Name = %q, want %q", rootPkg.Name, "test/module")
	}
	if rootPkg.SPDXID != "SPDXRef-RootPackage" {
		t.Errorf("Root package SPDXID = %q, want %q", rootPkg.SPDXID, "SPDXRef-RootPackage")
	}

	// Find the two dependency packages (order is not guaranteed in map iteration)
	var pkg1, pkg2 *spdxPackage
	for i := 1; i < len(doc.Packages); i++ {
		if doc.Packages[i].Name == "github.com/pkg1" {
			pkg1 = &doc.Packages[i]
		} else if doc.Packages[i].Name == "github.com/pkg2" {
			pkg2 = &doc.Packages[i]
		}
	}

	if pkg1 == nil {
		t.Fatal("Package github.com/pkg1 not found")
	}
	if pkg2 == nil {
		t.Fatal("Package github.com/pkg2 not found")
	}

	if pkg1.VersionInfo != "v1.0.0" {
		t.Errorf("Package pkg1 VersionInfo = %q, want %q", pkg1.VersionInfo, "v1.0.0")
	}

	if pkg2.VersionInfo != "v2.0.0" {
		t.Errorf("Package pkg2 VersionInfo = %q, want %q", pkg2.VersionInfo, "v2.0.0")
	}
}

// TestWriteSPDX_Relationships tests that relationships are created correctly.
func TestWriteSPDX_Relationships(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "github.com/example/pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 20,
		OverallLevel: scorer.RiskLow,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "github.com/example/pkg",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 20,
				RiskLevel: scorer.RiskLow,
			},
		},
		LowRiskCount: 1,
	}

	opts := SBOMOptions{
		GoVersion: "1.21",
	}

	var buf bytes.Buffer
	err := WriteSPDX(graph, ps, opts, &buf)
	if err != nil {
		t.Fatalf("WriteSPDX() failed: %v", err)
	}

	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to unmarshal SPDX JSON: %v", err)
	}

	// Should have at least 2 relationships:
	// 1. DOCUMENT DESCRIBES RootPackage
	// 2. RootPackage DEPENDS_ON dependency
	if len(doc.Relationships) < 2 {
		t.Fatalf("Relationships length = %d, want at least 2", len(doc.Relationships))
	}

	// Check DESCRIBES relationship
	found := false
	for _, rel := range doc.Relationships {
		if rel.SPDXElementID == "SPDXRef-DOCUMENT" && rel.RelationshipType == "DESCRIBES" {
			if rel.RelatedSPDXElement != "SPDXRef-RootPackage" {
				t.Errorf("DESCRIBES relationship target = %q, want %q", rel.RelatedSPDXElement, "SPDXRef-RootPackage")
			}
			found = true
			break
		}
	}

	if !found {
		t.Error("DESCRIBES relationship not found")
	}

	// Check DEPENDS_ON relationship
	found = false
	for _, rel := range doc.Relationships {
		if rel.SPDXElementID == "SPDXRef-RootPackage" && rel.RelationshipType == "DEPENDS_ON" {
			found = true
			break
		}
	}

	if !found {
		t.Error("DEPENDS_ON relationship not found")
	}
}

// TestWriteSPDX_RiskAnnotation tests that risk scores are added as annotations.
func TestWriteSPDX_RiskAnnotation(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{
			Path:    "risky-pkg",
			Version: "v1.0.0",
			Direct:  true,
			Depth:   0,
		},
	)

	ps := &scorer.ProjectScore{
		OverallScore: 60,
		OverallLevel: scorer.RiskHigh,
		Dependencies: []*scorer.DependencyScore{
			{
				Module:    "risky-pkg",
				Version:   "v1.0.0",
				Direct:    true,
				RiskScore: 60,
				RiskLevel: scorer.RiskHigh,
			},
		},
		HighRiskCount: 1,
	}

	opts := SBOMOptions{
		GoVersion: "1.21",
	}

	var buf bytes.Buffer
	err := WriteSPDX(graph, ps, opts, &buf)
	if err != nil {
		t.Fatalf("WriteSPDX() failed: %v", err)
	}

	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("Failed to unmarshal SPDX JSON: %v", err)
	}

	// Should have 2 packages: root + 1 dependency
	if len(doc.Packages) != 2 {
		t.Fatalf("Packages length = %d, want 2", len(doc.Packages))
	}

	// Check the dependency package for annotations
	depPkg := doc.Packages[1]
	if depPkg.Name != "risky-pkg" {
		t.Fatalf("Package name = %q, want %q", depPkg.Name, "risky-pkg")
	}

	// Should have at least one annotation
	if len(depPkg.Annotations) == 0 {
		t.Fatal("Package should have annotations")
	}

	// Check the annotation contains risk score
	ann := depPkg.Annotations[0]
	if ann.AnnotationType != "REVIEW" {
		t.Errorf("AnnotationType = %q, want %q", ann.AnnotationType, "REVIEW")
	}

	if !containsSubstring(ann.Comment, "risk_score=60") {
		t.Errorf("Annotation comment should contain risk_score=60, got: %q", ann.Comment)
	}

	if !containsSubstring(ann.Comment, "risk_level=HIGH") {
		t.Errorf("Annotation comment should contain risk_level=HIGH, got: %q", ann.Comment)
	}
}

// Helper function
func containsSubstring(str, substr string) bool {
	return bytes.Contains([]byte(str), []byte(substr))
}
