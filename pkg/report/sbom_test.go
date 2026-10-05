package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scorer"
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

	// Build a lookup map so the test is independent of component order.
	byName := make(map[string]cdxComponent, len(bom.Components))
	for _, c := range bom.Components {
		byName[c.Name] = c
	}

	comp1, ok := byName["github.com/pkg1"]
	if !ok {
		t.Fatal("component github.com/pkg1 not found")
	}
	if comp1.Version != "v1.0.0" {
		t.Errorf("pkg1 Version = %q, want %q", comp1.Version, "v1.0.0")
	}
	if comp1.Scope != "required" {
		t.Errorf("pkg1 Scope = %q, want %q", comp1.Scope, "required")
	}

	comp2, ok := byName["github.com/pkg2"]
	if !ok {
		t.Fatal("component github.com/pkg2 not found")
	}
	if comp2.Version != "v2.0.0" {
		t.Errorf("pkg2 Version = %q, want %q", comp2.Version, "v2.0.0")
	}
	if comp2.Scope != "optional" {
		t.Errorf("pkg2 Scope = %q, want %q", comp2.Scope, "optional")
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

// TestWriteCycloneDX_RootComponentVersion checks that the go directive is not
// reported as the scanned project's own version. A go.mod carries no version
// for the main module, so the root component has none; the go directive is
// kept as a labelled property instead.
func TestWriteCycloneDX_RootComponentVersion(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{Path: "github.com/example/pkg", Version: "v1.0.0", Direct: true},
	)

	var buf bytes.Buffer
	if err := WriteCycloneDX(graph, nil, SBOMOptions{GoVersion: "1.26.8"}, &buf); err != nil {
		t.Fatalf("WriteCycloneDX() failed: %v", err)
	}

	var raw struct {
		Metadata struct {
			Component map[string]json.RawMessage `json:"component"`
		} `json:"metadata"`
		Components []map[string]json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("Failed to unmarshal CycloneDX JSON: %v", err)
	}
	if v, ok := raw.Metadata.Component["version"]; ok {
		t.Errorf("root component version = %s, want the field omitted", v)
	}
	if len(raw.Components) != 1 {
		t.Fatalf("components = %d, want 1", len(raw.Components))
	}
	if got := string(raw.Components[0]["version"]); got != `"v1.0.0"` {
		t.Errorf("dependency version = %s, want \"v1.0.0\"", got)
	}

	var bom cdxBOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("Failed to unmarshal CycloneDX JSON: %v", err)
	}
	var goVersion string
	for _, p := range bom.Metadata.Component.Properties {
		if p.Name == "unisupply:go_version" {
			goVersion = p.Value
		}
	}
	if goVersion != "1.26.8" {
		t.Errorf("root property unisupply:go_version = %q, want %q", goVersion, "1.26.8")
	}
}

// TestWriteSPDX_RootPackageVersion checks that the root package omits
// versionInfo and has a NOASSERTION downloadLocation, while dependencies
// keep both.
func TestWriteSPDX_RootPackageVersion(t *testing.T) {
	graph := testutil.MakeGraph(
		testutil.DepSpec{Path: "github.com/example/pkg", Version: "v1.0.0", Direct: true},
	)

	var buf bytes.Buffer
	if err := WriteSPDX(graph, nil, SBOMOptions{GoVersion: "1.26.8"}, &buf); err != nil {
		t.Fatalf("WriteSPDX() failed: %v", err)
	}

	var raw struct {
		Packages []map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("Failed to unmarshal SPDX JSON: %v", err)
	}
	if len(raw.Packages) != 2 {
		t.Fatalf("packages = %d, want 2 (root + 1 dependency)", len(raw.Packages))
	}

	root, dep := raw.Packages[0], raw.Packages[1]
	if v, ok := root["versionInfo"]; ok {
		t.Errorf("root versionInfo = %s, want the field omitted", v)
	}
	if got := string(root["downloadLocation"]); got != `"NOASSERTION"` {
		t.Errorf("root downloadLocation = %s, want \"NOASSERTION\"", got)
	}
	if got := string(dep["versionInfo"]); got != `"v1.0.0"` {
		t.Errorf("dependency versionInfo = %s, want \"v1.0.0\"", got)
	}
	if got, want := string(dep["downloadLocation"]), `"https://proxy.golang.org/github.com/example/pkg/@v/v1.0.0.zip"`; got != want {
		t.Errorf("dependency downloadLocation = %s, want %s", got, want)
	}
}

// determinismGraph builds a graph with enough modules and parent edges that
// ranging its maps in iteration order would almost surely reorder the output
// between runs.
func determinismGraph() (*resolver.Graph, *scorer.ProjectScore) {
	names := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet"}
	specs := make([]testutil.DepSpec, 0, len(names))
	ps := &scorer.ProjectScore{}
	for i, n := range names {
		path := "example.com/" + n
		spec := testutil.DepSpec{Path: path, Version: "v1.0.0", Direct: i%2 == 0}
		if spec.Direct {
			spec.UsedBy = []string{"test/module"}
		} else {
			// Every transitive module is used by several earlier modules.
			for _, p := range names[:i] {
				spec.UsedBy = append(spec.UsedBy, "example.com/"+p)
			}
			spec.Depth = 1
		}
		specs = append(specs, spec)
		ps.Dependencies = append(ps.Dependencies, &scorer.DependencyScore{
			Module: path, Version: "v1.0.0", RiskScore: i, RiskLevel: scorer.RiskLow,
		})
	}
	return testutil.MakeGraph(specs...), ps
}

// TestWriteCycloneDX_DeterministicOrder verifies that repeated generation
// yields identical output once the per-run timestamp and serial number are
// zeroed, and that the dependency lists are sorted.
func TestWriteCycloneDX_DeterministicOrder(t *testing.T) {
	graph, ps := determinismGraph()

	generate := func() cdxBOM {
		t.Helper()
		var buf bytes.Buffer
		if err := WriteCycloneDX(graph, ps, SBOMOptions{}, &buf); err != nil {
			t.Fatalf("WriteCycloneDX() failed: %v", err)
		}
		var bom cdxBOM
		if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		bom.SerialNumber = ""
		bom.Metadata.Timestamp = ""
		return bom
	}

	want := generate()
	for i := 0; i < 20; i++ {
		if got := generate(); !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d: CycloneDX output differs from first run", i+1)
		}
	}

	for _, dep := range want.Dependencies {
		if !sort.StringsAreSorted(dep.DependsOn) {
			t.Errorf("dependsOn of %s is not sorted: %v", dep.Ref, dep.DependsOn)
		}
	}
	refs := make([]string, 0, len(want.Dependencies))
	for _, dep := range want.Dependencies[1:] { // the root entry comes first
		refs = append(refs, dep.Ref)
	}
	if !sort.StringsAreSorted(refs) {
		t.Errorf("dependency entries are not sorted by parent: %v", refs)
	}
}

// TestWriteSPDX_DeterministicOrder verifies that repeated generation yields
// identical output once per-run timestamps are zeroed, and that package IDs
// are assigned in sorted module order so SPDXRef-Package-N always names the
// same module.
func TestWriteSPDX_DeterministicOrder(t *testing.T) {
	graph, ps := determinismGraph()

	generate := func() spdxDocument {
		t.Helper()
		var buf bytes.Buffer
		if err := WriteSPDX(graph, ps, SBOMOptions{}, &buf); err != nil {
			t.Fatalf("WriteSPDX() failed: %v", err)
		}
		var doc spdxDocument
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		doc.DocumentNamespace = ""
		doc.CreationInfo.Created = ""
		for i := range doc.Packages {
			for j := range doc.Packages[i].Annotations {
				doc.Packages[i].Annotations[j].AnnotationDate = ""
			}
		}
		return doc
	}

	want := generate()
	for i := 0; i < 20; i++ {
		if got := generate(); !reflect.DeepEqual(got, want) {
			t.Fatalf("run %d: SPDX output differs from first run", i+1)
		}
	}

	// Package 0 is the root; dependencies follow in sorted module order.
	for i, path := range graph.SortedPaths() {
		pkg := want.Packages[i+1]
		wantID := fmt.Sprintf("SPDXRef-Package-%d", i+1)
		if pkg.SPDXID != wantID || pkg.Name != path {
			t.Errorf("package %d = %s (%s), want %s (%s)", i+1, pkg.SPDXID, pkg.Name, wantID, path)
		}
	}
}
