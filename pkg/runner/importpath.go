package runner

import (
	"github.com/unidoc/unisupply/pkg/resolver"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// fillImportPaths sets Vulnerability.ImportPath on every finding whose reachability is "imported": the shortest chain of
// imports from one of the project's packages to the nearest of the vulnerable packages govulncheck found imported for it.
// It changes the findings in place.
//
// The chain comes from the package graph of one platform, so it is set only when that platform is the one the scan ran
// on (platform, from ScanInfo): with no graph, no platform, or another platform, nothing is set, because the graph is
// then not the one govulncheck analysed. A finding whose final reachability is "called" is left alone even when it
// recorded imported packages (an advisory with one package imported and another called).
func fillImportPaths(vulns map[string][]scanner.Vulnerability, pg *resolver.PackageGraph, platform string) {
	if pg == nil || platform == "" || pg.Platform != platform {
		return
	}
	for _, list := range vulns {
		for i := range list {
			v := &list[i]
			if v.Reachability == "imported" && len(v.ImportedPackages) > 0 {
				v.ImportPath = pg.ShortestImportPath(v.ImportedPackages)
			}
		}
	}
}
