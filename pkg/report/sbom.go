package report

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"time"

	"github.com/unidoc/unisupply/internal/version"
	"github.com/unidoc/unisupply/pkg/grade"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// SBOMOptions configures SBOM generation.
type SBOMOptions struct {
	// GoVersion is the scanned module's go directive. CycloneDX records it as
	// the root component's unisupply:go_version property; SPDX omits it.
	GoVersion string

	// Grade supplies each component's letter (Grading v2) and the overall letter on the root; nil leaves the grade
	// properties out. A row with no letter (its upkeep could not be read) gets no property or annotation.
	Grade *grade.Result
}

// ---- CycloneDX 1.5 ----

// CDX* types model the CycloneDX 1.5 JSON schema (subset relevant to Go modules).

type cdxBOM struct {
	BOMFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	SerialNumber string          `json:"serialNumber"`
	Version      int             `json:"version"`
	Metadata     cdxMetadata     `json:"metadata"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies,omitempty"`
}

type cdxMetadata struct {
	Timestamp string        `json:"timestamp"`
	Tools     []cdxTool     `json:"tools"`
	Component *cdxComponent `json:"component,omitempty"`
}

type cdxTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type cdxComponent struct {
	Type       string        `json:"type"`
	BOMRef     string        `json:"bom-ref"`
	Name       string        `json:"name"`
	Version    string        `json:"version,omitempty"`
	Purl       string        `json:"purl"`
	Scope      string        `json:"scope,omitempty"`
	Hashes     []cdxHash     `json:"hashes,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

// WriteCycloneDX generates a CycloneDX 1.5 SBOM in JSON format.
func WriteCycloneDX(graph *resolver.Graph, ps *scorer.ProjectScore, opts SBOMOptions, w io.Writer) error {
	now := time.Now().UTC()

	root := &cdxComponent{
		Type:   "application",
		BOMRef: graph.Root,
		Name:   graph.Root,
		Purl:   fmt.Sprintf("pkg:golang/%s", graph.Root),
	}
	if opts.GoVersion != "" {
		root.Properties = append(root.Properties, cdxProperty{
			Name:  "unisupply:go_version",
			Value: opts.GoVersion,
		})
	}

	if v := overallGradeValue(opts.Grade); v != "" {
		root.Properties = append(root.Properties, cdxProperty{Name: "unisupply:grade", Value: v})
	}

	bom := cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: fmt.Sprintf("urn:uuid:%s", pseudoUUID(graph.Root, now)),
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: now.Format(time.RFC3339),
			Tools: []cdxTool{
				{Vendor: "UniDoc", Name: "unisupply", Version: version.Version},
			},
			Component: root,
		},
	}

	// Build dependency lookup for the dependency graph section.
	depChildren := make(map[string][]string) // module -> modules it depends on
	rows := gradeRowsByModule(opts.Grade)

	// Sorted order fixes the order of the components, of the root's dependsOn
	// list, and of each depChildren slice, which is filled in this loop.
	paths := graph.SortedPaths()
	for _, path := range paths {
		dep := graph.Dependencies[path]
		scope := "required"
		if !dep.Direct {
			scope = "optional" // CycloneDX uses optional for transitive
		}

		comp := cdxComponent{
			Type:    "library",
			BOMRef:  dep.Module.Path,
			Name:    dep.Module.Path,
			Version: dep.Module.Version,
			Purl:    goPurl(dep.Module.Path, dep.Module.Version),
			Scope:   scope,
		}

		// The row's grade (Grading v2): its letter and the one sentence that explains it.
		// A row without a letter carries no property: "no grade" is not a value.
		if row, ok := rows[dep.Module.Path]; ok && row.Letter != "" {
			comp.Properties = append(comp.Properties,
				cdxProperty{Name: "unisupply:grade", Value: gradeRowLabel(&row)},
				cdxProperty{Name: "unisupply:grade_reason", Value: row.Reason},
			)
		}

		bom.Components = append(bom.Components, comp)

		// Track parent relationships for the dependency graph.
		for _, parent := range dep.UsedBy {
			depChildren[parent] = append(depChildren[parent], dep.Module.Path)
		}
	}

	// Build dependencies section.
	// Root depends on direct deps.
	rootDep := cdxDependency{Ref: graph.Root}
	for _, path := range paths {
		if dep := graph.Dependencies[path]; dep.Direct {
			rootDep.DependsOn = append(rootDep.DependsOn, dep.Module.Path)
		}
	}
	bom.Dependencies = append(bom.Dependencies, rootDep)

	// Each module depends on its children, already sorted by the loop above.
	for _, parent := range slices.Sorted(maps.Keys(depChildren)) {
		if parent == graph.Root {
			continue
		}
		bom.Dependencies = append(bom.Dependencies, cdxDependency{
			Ref:       parent,
			DependsOn: depChildren[parent],
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bom)
}

// ---- SPDX 2.3 ----

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
	Annotations       []spdxAnnotation   `json:"annotations,omitempty"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	Supplier         string            `json:"supplier,omitempty"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
	Annotations      []spdxAnnotation  `json:"annotations,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxAnnotation struct {
	AnnotationDate string `json:"annotationDate"`
	AnnotationType string `json:"annotationType"`
	Annotator      string `json:"annotator"`
	Comment        string `json:"comment"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// WriteSPDX generates an SPDX 2.3 SBOM in JSON format.
func WriteSPDX(graph *resolver.Graph, ps *scorer.ProjectScore, opts SBOMOptions, w io.Writer) error {
	now := time.Now().UTC()

	doc := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              graph.Root,
		DocumentNamespace: fmt.Sprintf("https://spdx.org/spdxdocs/unisupply-%s-%s", graph.Root, now.Format("20060102T150405Z")),
		CreationInfo: spdxCreationInfo{
			Created:  now.Format(time.RFC3339),
			Creators: []string{fmt.Sprintf("Tool: unisupply-%s", version.Version)},
		},
	}

	// Root package. The main module has no version and no proxy download, so
	// versionInfo is omitted and downloadLocation is NOASSERTION.
	rootPkg := spdxPackage{
		SPDXID:           "SPDXRef-RootPackage",
		Name:             graph.Root,
		DownloadLocation: "NOASSERTION",
		FilesAnalyzed:    false,
		ExternalRefs: []spdxExternalRef{
			{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  fmt.Sprintf("pkg:golang/%s", graph.Root),
			},
		},
	}
	doc.Packages = append(doc.Packages, rootPkg)

	// Describe relationship.
	doc.Relationships = append(doc.Relationships, spdxRelationship{
		SPDXElementID:      "SPDXRef-DOCUMENT",
		RelationshipType:   "DESCRIBES",
		RelatedSPDXElement: "SPDXRef-RootPackage",
	})

	if v := overallGradeValue(opts.Grade); v != "" {
		doc.Annotations = append(doc.Annotations, spdxAnnotation{
			AnnotationDate: now.Format(time.RFC3339),
			AnnotationType: "REVIEW",
			Annotator:      fmt.Sprintf("Tool: unisupply-%s", version.Version),
			Comment:        "grade=" + v,
		})
	}

	rows := gradeRowsByModule(opts.Grade)
	pkgIdx := 0
	// Sorted order makes the SPDXRef-Package-N IDs map to the same modules on
	// every run.
	for _, path := range graph.SortedPaths() {
		dep := graph.Dependencies[path]
		pkgIdx++
		spdxID := fmt.Sprintf("SPDXRef-Package-%d", pkgIdx)

		pkg := spdxPackage{
			SPDXID:           spdxID,
			Name:             dep.Module.Path,
			VersionInfo:      dep.Module.Version,
			DownloadLocation: fmt.Sprintf("https://proxy.golang.org/%s/@v/%s.zip", dep.Module.Path, dep.Module.Version),
			FilesAnalyzed:    false,
			ExternalRefs: []spdxExternalRef{
				{
					ReferenceCategory: "PACKAGE-MANAGER",
					ReferenceType:     "purl",
					ReferenceLocator:  goPurl(dep.Module.Path, dep.Module.Version),
				},
			},
		}

		// The row's grade (Grading v2) as an annotation.
		if row, ok := rows[dep.Module.Path]; ok && row.Letter != "" {
			pkg.Annotations = append(pkg.Annotations, spdxAnnotation{
				AnnotationDate: now.Format(time.RFC3339),
				AnnotationType: "REVIEW",
				Annotator:      fmt.Sprintf("Tool: unisupply-%s", version.Version),
				Comment:        fmt.Sprintf("grade=%s reason=%s", gradeRowLabel(&row), row.Reason),
			})
		}

		doc.Packages = append(doc.Packages, pkg)

		// Relationship: root DEPENDS_ON this package.
		relType := "DEPENDS_ON"
		doc.Relationships = append(doc.Relationships, spdxRelationship{
			SPDXElementID:      "SPDXRef-RootPackage",
			RelationshipType:   relType,
			RelatedSPDXElement: spdxID,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// overallGradeValue is the overall grade for the SBOM root: the letter (with "*" when estimated), or "PENDING" followed
// by the check that did not run. It is "" when no grade was given.
func overallGradeValue(g *grade.Result) string {
	if g == nil {
		return ""
	}
	label := gradeLetterLabel(g)
	if label == "PENDING" && g.Pending != nil && g.Pending.Check != "" {
		label += " (" + g.Pending.Check + ")"
	}
	return label
}

// gradeRowsByModule indexes the grade's rows by module path. A nil grade yields an empty map.
func gradeRowsByModule(g *grade.Result) map[string]grade.RowResult {
	rows := make(map[string]grade.RowResult)
	if g == nil {
		return rows
	}
	for _, r := range g.Rows {
		if !r.Self {
			rows[r.Module] = r
		}
	}
	return rows
}

// goPurl constructs a Package URL for a Go module.
func goPurl(modPath, version string) string {
	return fmt.Sprintf("pkg:golang/%s@%s", modPath, version)
}

// pseudoUUID generates a deterministic UUID-like string from input for serial numbers.
func pseudoUUID(seed string, t time.Time) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", seed, t.UnixNano())))
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}
