// Package testutil provides shared test helpers for the unisupply test suite.
// It centralises construction of common test fixtures so individual test files
// remain focused on behaviour rather than setup boilerplate.
package testutil

import (
	"github.com/unidoc/unisupply/pkg/parser"
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// DepSpec is a declarative description of a single dependency used when
// building test graphs with MakeGraph.
type DepSpec struct {
	Path           string
	Version        string
	Direct         bool
	Depth          int
	UsedBy         []string
	TransitiveDeps int
}

// MakeGraph builds a resolver.Graph from the provided dependency specs.
// The graph Root is always set to "test/module".
func MakeGraph(deps ...DepSpec) *resolver.Graph {
	g := &resolver.Graph{
		Root:         "test/module",
		Dependencies: make(map[string]*resolver.Dependency, len(deps)),
	}
	for _, spec := range deps {
		g.Dependencies[spec.Path] = &resolver.Dependency{
			Module: parser.Module{
				Path:     spec.Path,
				Version:  spec.Version,
				Indirect: !spec.Direct,
			},
			Direct:         spec.Direct,
			Depth:          spec.Depth,
			UsedBy:         spec.UsedBy,
			TransitiveDeps: spec.TransitiveDeps,
		}
	}
	return g
}

// IntPtr returns a pointer to v.
func IntPtr(v int) *int {
	return &v
}

// FloatPtr returns a pointer to v.
func FloatPtr(v float64) *float64 {
	return &v
}

// MakeDep constructs a single resolver.Dependency for use in tests that do not
// need a full graph.
func MakeDep(path, version string, direct bool, depth int) *resolver.Dependency {
	return &resolver.Dependency{
		Module: parser.Module{
			Path:     path,
			Version:  version,
			Indirect: !direct,
		},
		Direct: direct,
		Depth:  depth,
	}
}

// MakeVuln constructs a scanner.Vulnerability with the given id, severity, and
// fixed version. All other fields are left at their zero values.
func MakeVuln(id, severity, fixedVersion string) scanner.Vulnerability {
	return scanner.Vulnerability{
		ID:           id,
		Severity:     severity,
		FixedVersion: fixedVersion,
	}
}

// MakeMaintenanceInfo constructs a scanner.MaintenanceInfo with the supplied
// maintenance signals.
func MakeMaintenanceInfo(monthsSince int, archived, deprecated bool) *scanner.MaintenanceInfo {
	return &scanner.MaintenanceInfo{
		MonthsSinceRelease: monthsSince,
		Archived:           archived,
		Deprecated:         deprecated,
	}
}

// MakeMaintainerInfo constructs a scanner.MaintainerInfo with the supplied
// ownership signals.
func MakeMaintainerInfo(busFactor, contributorCount int, isOrg bool) *scanner.MaintainerInfo {
	return &scanner.MaintainerInfo{
		BusFactor:        busFactor,
		ContributorCount: contributorCount,
		IsOrg:            isOrg,
	}
}
