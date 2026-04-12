package report

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scorer"
)

// SBOMOptions configures SBOM generation.
type SBOMOptions struct {
	GoVersion string
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
	Timestamp string       `json:"timestamp"`
	Tools     []cdxTool    `json:"tools"`
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
	Version    string        `json:"version"`
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

	bom := cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: fmt.Sprintf("urn:uuid:%s", pseudoUUID(graph.Root, now)),
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: now.Format(time.RFC3339),
			Tools: []cdxTool{
				{Vendor: "UniDoc", Name: "unisupply", Version: version},
			},
			Component: &cdxComponent{
				Type:    "application",
				BOMRef:  graph.Root,
				Name:    graph.Root,
				Version: opts.GoVersion,
				Purl:    fmt.Sprintf("pkg:golang/%s", graph.Root),
			},
		},
	}

	// Build dependency lookup for the dependency graph section.
	depChildren := make(map[string][]string) // module -> modules it depends on

	for _, dep := range graph.Dependencies {
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

		// Add risk score as a property.
		if ps != nil {
			for _, ds := range ps.Dependencies {
				if ds.Module == dep.Module.Path {
					comp.Properties = append(comp.Properties, cdxProperty{
						Name:  "unisupply:risk_score",
						Value: fmt.Sprintf("%d", ds.RiskScore),
					})
					comp.Properties = append(comp.Properties, cdxProperty{
						Name:  "unisupply:risk_level",
						Value: string(ds.RiskLevel),
					})
					break
				}
			}
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
	for _, dep := range graph.Dependencies {
		if dep.Direct {
			rootDep.DependsOn = append(rootDep.DependsOn, dep.Module.Path)
		}
	}
	bom.Dependencies = append(bom.Dependencies, rootDep)

	// Each module depends on its children.
	for parent, children := range depChildren {
		if parent == graph.Root {
			continue
		}
		bom.Dependencies = append(bom.Dependencies, cdxDependency{
			Ref:       parent,
			DependsOn: children,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bom)
}

// ---- SPDX 2.3 ----

type spdxDocument struct {
	SPDXVersion       string            `json:"spdxVersion"`
	DataLicense       string            `json:"dataLicense"`
	SPDXID            string            `json:"SPDXID"`
	Name              string            `json:"name"`
	DocumentNamespace string            `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo  `json:"creationInfo"`
	Packages          []spdxPackage     `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string              `json:"SPDXID"`
	Name             string              `json:"name"`
	VersionInfo      string              `json:"versionInfo"`
	DownloadLocation string              `json:"downloadLocation"`
	FilesAnalyzed    bool                `json:"filesAnalyzed"`
	Supplier         string              `json:"supplier,omitempty"`
	ExternalRefs     []spdxExternalRef   `json:"externalRefs,omitempty"`
	Annotations      []spdxAnnotation    `json:"annotations,omitempty"`
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
			Creators: []string{fmt.Sprintf("Tool: unisupply-%s", version)},
		},
	}

	// Root package.
	rootPkg := spdxPackage{
		SPDXID:           "SPDXRef-RootPackage",
		Name:             graph.Root,
		VersionInfo:      opts.GoVersion,
		DownloadLocation: fmt.Sprintf("https://proxy.golang.org/%s/@v/%s.zip", graph.Root, opts.GoVersion),
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

	pkgIdx := 0
	for _, dep := range graph.Dependencies {
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

		// Add risk score as annotation.
		if ps != nil {
			for _, ds := range ps.Dependencies {
				if ds.Module == dep.Module.Path {
					pkg.Annotations = append(pkg.Annotations, spdxAnnotation{
						AnnotationDate: now.Format(time.RFC3339),
						AnnotationType: "REVIEW",
						Annotator:      fmt.Sprintf("Tool: unisupply-%s", version),
						Comment:        fmt.Sprintf("risk_score=%d risk_level=%s", ds.RiskScore, ds.RiskLevel),
					})
					break
				}
			}
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
