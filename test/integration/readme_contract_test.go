package integration_test

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// readmePath is relative to this package directory, which is the working
// directory `go test` uses.
const readmePath = "../../README.md"

// securityPath is the prose mirror of the contract; TestNetworkContract_SecurityMDInSync
// keeps the two from diverging.
const securityPath = "../../SECURITY.md"

// contractSection is the README heading that owns the network contract table.
// The table under it is the single source of truth for which hosts unisupply
// may contact; TestNetworkContract_NoUndocumentedHosts enforces it against
// real behavior.
const contractSection = "## Privacy and network access"

// trustIndexPlaceholder is the contract row for the user-supplied Trust Index
// endpoint. It is a placeholder, not a host, so host-set comparisons skip it.
const trustIndexPlaceholder = "<trust-index-url>"

// networkContract is the parsed README contract.
type networkContract struct {
	// Hosts are the first-column values of the table, deduplicated, in README
	// order. A value may be a placeholder such as "<trust-index-url>" for a
	// host the user supplies.
	Hosts []string

	// RowCount is how many table rows name each host, before deduplication.
	// A host with several rows is several distinct operations — api.github.com
	// carries one row each for the maintainer scanner, the resilience scanner,
	// and GHSA enrichment — and TestNetworkContract_NoDeadRows uses this count
	// to require that every one of them is exercised, not just the host.
	RowCount map[string]int

	// NeverContacted are the hosts the README promises unisupply does not
	// call itself.
	NeverContacted []string
}

// has reports whether host appears in the contract table.
func (c networkContract) has(host string) bool {
	for _, h := range c.Hosts {
		if h == host {
			return true
		}
	}
	return false
}

var (
	// backtickCell captures the first backticked token in a table cell.
	backtickCell = regexp.MustCompile("`([^`]+)`")

	// hostLike matches a backticked token that reads like a hostname: dotted,
	// no spaces, no path separator. Keeps prose tokens such as `go mod verify`
	// and `GOPROXY` out of the never-contacted list.
	hostLike = regexp.MustCompile(`^[a-z0-9.-]+\.[a-z]{2,}$`)
)

// sectionLines returns the lines under heading, up to the next top-level
// heading, and reports whether the heading was found. Both documents put the
// contract under the same heading, and both parsers scope to it: a token that
// looks like a hostname elsewhere in the file must not be able to satisfy a
// contract assertion.
func sectionLines(all []string, heading string) ([]string, bool) {
	start := -1
	for i, line := range all {
		if strings.TrimSpace(line) == heading {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil, false
	}

	body := all[start:]
	for i, line := range body {
		if strings.HasPrefix(strings.TrimSpace(line), "## ") {
			return body[:i], true
		}
	}
	return body, true
}

// parseNetworkContract reads the network-contract table out of the README.
// Parsing the markdown directly (rather than restating the hosts in Go) is
// deliberate: it makes documentation drift a test failure.
func parseNetworkContract(t *testing.T, path string) networkContract {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	section, ok := sectionLines(strings.Split(string(data), "\n"), contractSection)
	if !ok {
		t.Fatalf("%s: section %q not found; the network contract must live under that heading", path, contractSection)
	}

	var (
		contract  = networkContract{RowCount: map[string]int{}}
		seen      = map[string]bool{}
		inTable   bool
		tableDone bool
	)
	for _, line := range section {
		trimmed := strings.TrimSpace(line)

		// The section holds more than one table (the offline-behavior table
		// follows), so bind to the one whose header column is "Host" and stop
		// collecting when it ends.
		isRow := strings.HasPrefix(trimmed, "|")
		switch {
		case !tableDone && isRow && isContractHeader(trimmed):
			inTable = true

		case inTable && !isRow:
			inTable, tableDone = false, true

		case inTable && isRow:
			host, ok := tableRowHost(trimmed)
			if !ok {
				continue
			}
			contract.RowCount[host]++
			if seen[host] {
				continue
			}
			seen[host] = true
			contract.Hosts = append(contract.Hosts, host)

		case strings.HasPrefix(trimmed, "**Not contacted directly:**"):
			contract.NeverContacted = append(contract.NeverContacted, neverContactedHosts(trimmed)...)
		}
	}

	if len(contract.Hosts) == 0 {
		t.Fatalf("%s: no host rows parsed from the %q table", path, contractSection)
	}
	if len(contract.NeverContacted) == 0 {
		t.Fatalf("%s: no hosts parsed from the \"Not contacted directly\" statement", path)
	}
	return contract
}

// isContractHeader reports whether row is the header of the host table.
func isContractHeader(row string) bool {
	cells := strings.Split(strings.Trim(row, "|"), "|")
	return len(cells) >= 2 && strings.EqualFold(strings.TrimSpace(cells[0]), "Host")
}

// tableRowHost extracts the backticked host from a markdown table row, and
// reports false for header and separator rows.
func tableRowHost(row string) (string, bool) {
	cells := strings.Split(strings.Trim(row, "|"), "|")
	if len(cells) < 2 {
		return "", false
	}
	m := backtickCell.FindStringSubmatch(cells[0])
	if m == nil {
		return "", false
	}
	// Backticks around `<trust-index-url>` and around real hosts alike; both
	// are contract rows.
	return strings.TrimSpace(m[1]), true
}

// neverContactedHosts pulls the hostnames out of the "Not contacted directly"
// statement. Only the first sentence is considered: the rest of the paragraph
// explains the `go mod verify` / `sum.golang.org` toolchain caveat and would
// otherwise contradict the list it qualifies.
func neverContactedHosts(line string) []string {
	// Cut at the first clause break. A bare "." is not a sentence end here —
	// every hostname contains one — so only "; " and ". " count.
	for _, sep := range []string{"; ", ". "} {
		if i := strings.Index(line, sep); i >= 0 {
			line = line[:i]
		}
	}

	var hosts []string
	for _, m := range backtickCell.FindAllStringSubmatch(line, -1) {
		token := strings.TrimSpace(m[1])
		if hostLike.MatchString(token) {
			hosts = append(hosts, token)
		}
	}
	return hosts
}

// TestParseNetworkContract_README pins the parser against the live README, so
// a reformatting of the table that silently empties the contract fails here
// rather than making the enforcement tests vacuous.
func TestParseNetworkContract_README(t *testing.T) {
	contract := parseNetworkContract(t, readmePath)

	// Hosts every version of the contract has carried. Not the full list —
	// TestNetworkContract_NoDeadRows enforces that side.
	for _, want := range []string{
		"proxy.golang.org",
		"vuln.go.dev",
		"api.osv.dev",
		"services.nvd.nist.gov",
		"api.github.com",
		"api.first.org",
		"www.cisa.gov",
		"cloud.unidoc.io",
		"<trust-index-url>",
	} {
		if !contract.has(want) {
			t.Errorf("contract table is missing %q; parsed hosts: %v", want, contract.Hosts)
		}
	}

	for _, want := range []string{"sum.golang.org", "pkg.go.dev"} {
		if !containsString(contract.NeverContacted, want) {
			t.Errorf("never-contacted list is missing %q; parsed: %v", want, contract.NeverContacted)
		}
	}
}

// TestParseNetworkContract_Synthetic exercises the parser's edges on a fixture
// it fully controls: header and separator rows are skipped, duplicate hosts
// collapse, prose backticks outside the table are ignored, and the paragraph
// after the never-contacted sentence does not leak hosts into that list.
func TestParseNetworkContract_Synthetic(t *testing.T) {
	doc := strings.Join([]string{
		"# Title",
		"",
		"## Something else",
		"",
		"| `not-a-contract-host.example` | ignored |",
		"",
		contractSection,
		"",
		"Prose mentioning `GOPROXY` and `go mod verify`.",
		"",
		"| Host | What is sent |",
		"| ---- | ------------ |",
		"| `proxy.example.org` | Module path |",
		"| `api.example.org` | Repo name |",
		"| `api.example.org` | Repo name again |",
		"| `<trust-index-url>` | Module paths |",
		"",
		"**Not contacted directly:** `sum.example.org` and `pkg.example.org` are never called; " +
			"note that the toolchain may verify against `leaked.example.org` on a cold cache.",
		"",
		"## Next section",
		"",
		"| `after-the-section.example` | ignored |",
	}, "\n")

	path := t.TempDir() + "/README.md"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	contract := parseNetworkContract(t, path)

	wantHosts := []string{"proxy.example.org", "api.example.org", "<trust-index-url>"}
	if strings.Join(contract.Hosts, ",") != strings.Join(wantHosts, ",") {
		t.Errorf("Hosts = %v, want %v", contract.Hosts, wantHosts)
	}

	// Deduplication is for the allowlist side; the coverage side needs to know
	// the duplicate row existed, so RowCount must still see both.
	if got := contract.RowCount["api.example.org"]; got != 2 {
		t.Errorf("RowCount[api.example.org] = %d, want 2 (duplicate rows are distinct operations)", got)
	}

	wantNever := []string{"sum.example.org", "pkg.example.org"}
	if strings.Join(contract.NeverContacted, ",") != strings.Join(wantNever, ",") {
		t.Errorf("NeverContacted = %v, want %v (the toolchain caveat must not leak in)",
			contract.NeverContacted, wantNever)
	}
}

// securityBriefPrefix anchors the SECURITY.md paragraph that summarizes the
// contract. Only that paragraph is parsed: a hostname elsewhere in the file
// (a reporting address, a link, an example) must not be able to satisfy the
// sync check on its own.
const securityBriefPrefix = "In brief:"

// notHostTokens are backticked tokens inside the summary paragraph that look
// like hostnames to hostLike but are filenames. hostLike is shared with
// neverContactedHosts, so exclude them here rather than tightening the regexp.
var notHostTokens = map[string]bool{
	"go.mod": true,
	"go.sum": true,
}

// parseSecurityBriefHosts pulls the hostnames out of SECURITY.md's "In brief"
// paragraph — from the line that opens it through the blank line that ends it.
// The search is scoped to the same heading the README table lives under, so an
// "In brief" paragraph elsewhere in the document (the disclosure-policy and
// scope sections both precede it) cannot be mistaken for the contract summary.
func parseSecurityBriefHosts(t *testing.T, path string) []string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	section, ok := sectionLines(strings.Split(string(data), "\n"), contractSection)
	if !ok {
		t.Fatalf("%s: section %q not found; the contract summary must live under the same heading "+
			"the README table uses", path, contractSection)
	}

	var (
		para  []string
		found bool
	)
	for _, line := range section {
		trimmed := strings.TrimSpace(line)
		if !found {
			if strings.HasPrefix(trimmed, securityBriefPrefix) {
				found = true
				para = append(para, trimmed)
			}
			continue
		}
		if trimmed == "" {
			break
		}
		para = append(para, trimmed)
	}
	if !found {
		t.Fatalf("%s: no paragraph starting with %q under %q; that paragraph is the prose mirror "+
			"of the README contract table and the sync check has nothing to compare against without it",
			path, securityBriefPrefix, contractSection)
	}

	var hosts []string
	seen := map[string]bool{}
	for _, m := range backtickCell.FindAllStringSubmatch(strings.Join(para, " "), -1) {
		token := strings.TrimSpace(m[1])
		if !hostLike.MatchString(token) || notHostTokens[token] || seen[token] {
			continue
		}
		seen[token] = true
		hosts = append(hosts, token)
	}
	if len(hosts) == 0 {
		t.Fatalf("%s: no hostnames parsed from the %q paragraph", path, securityBriefPrefix)
	}
	return hosts
}

// TestNetworkContract_SecurityMDInSync keeps SECURITY.md's prose summary of
// the contract from drifting away from the README table it summarizes. This
// drift is not hypothetical: the EPSS and KEV hosts were added to the table
// and not to the summary, and nothing caught it.
//
// The comparison runs in both directions and is scoped to the summary
// paragraph. A one-way substring search over the whole file would miss the
// reverse case — a host dropped from the README but left behind in
// SECURITY.md, which is the more misleading of the two, since it promises
// readers a contact that no longer happens.
func TestNetworkContract_SecurityMDInSync(t *testing.T) {
	contract := parseNetworkContract(t, readmePath)
	summary := parseSecurityBriefHosts(t, securityPath)

	inSummary := map[string]bool{}
	for _, h := range summary {
		inSummary[h] = true
	}

	documented := map[string]bool{}
	for _, host := range contract.Hosts {
		// The Trust Index row is a placeholder for a user-supplied URL;
		// SECURITY.md describes it in words, not as a hostname.
		if host == trustIndexPlaceholder {
			continue
		}
		documented[host] = true

		if !inSummary[host] {
			t.Errorf("README documents %q but SECURITY.md's summary paragraph does not mention it; "+
				"the two must describe the same contract", host)
		}
	}

	for _, host := range summary {
		if !documented[host] {
			t.Errorf("SECURITY.md's summary paragraph mentions %q, which the README contract table "+
				"no longer documents; remove it, or restore the row it summarizes", host)
		}
	}
}

// TestSecurityMDInSync_DetectsBothDirections proves the sync check has teeth in
// each direction, on fixtures it fully controls.
func TestSecurityMDInSync_DetectsBothDirections(t *testing.T) {
	readme := strings.Join([]string{
		contractSection,
		"",
		"| Host | What is sent |",
		"| ---- | ------------ |",
		"| `proxy.example.org` | Module path |",
		"| `api.example.org` | Repo name |",
		"",
		"**Not contacted directly:** `sum.example.org` is never called.",
	}, "\n")

	tests := []struct {
		name    string
		brief   string
		missing []string // hosts the comparison must flag
	}{
		{
			name:  "in sync",
			brief: "In brief: contacts `proxy.example.org` and `api.example.org` (reads `go.mod`).",
		},
		{
			name:    "host missing from SECURITY.md",
			brief:   "In brief: contacts `proxy.example.org` only.",
			missing: []string{"api.example.org"},
		},
		{
			name:    "stale host left in SECURITY.md",
			brief:   "In brief: contacts `proxy.example.org`, `api.example.org` and `removed.example.org`.",
			missing: []string{"removed.example.org"},
		},
		{
			name:    "mention outside the paragraph does not count",
			brief:   "In brief: contacts `proxy.example.org`.\n\nElsewhere we mention `api.example.org`.",
			missing: []string{"api.example.org"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			readmeFile := dir + "/README.md"
			securityFile := dir + "/SECURITY.md"
			if err := os.WriteFile(readmeFile, []byte(readme), 0o600); err != nil {
				t.Fatalf("writing README fixture: %v", err)
			}
			security := strings.Join([]string{
				"## Reporting a vulnerability",
				"",
				// A decoy: same lead-in, wrong section. Scoping to the contract
				// heading is what keeps this from being read as the summary.
				"In brief: report privately; do not open a public issue about `decoy.example.org`.",
				"",
				contractSection,
				"",
				tt.brief,
				"",
			}, "\n")
			if err := os.WriteFile(securityFile, []byte(security), 0o600); err != nil {
				t.Fatalf("writing SECURITY fixture: %v", err)
			}

			contract := parseNetworkContract(t, readmeFile)
			summary := parseSecurityBriefHosts(t, securityFile)

			got := symmetricDifference(contract.Hosts, summary)
			if strings.Join(got, ",") != strings.Join(tt.missing, ",") {
				t.Errorf("drift = %v, want %v", got, tt.missing)
			}
		})
	}
}

// symmetricDifference returns the hosts in exactly one of the two lists,
// sorted — the set TestNetworkContract_SecurityMDInSync reports as drift.
func symmetricDifference(readmeHosts, summaryHosts []string) []string {
	inSummary := map[string]bool{}
	for _, h := range summaryHosts {
		inSummary[h] = true
	}
	inReadme := map[string]bool{}
	for _, h := range readmeHosts {
		inReadme[h] = true
	}

	var diff []string
	for _, h := range readmeHosts {
		if h != trustIndexPlaceholder && !inSummary[h] {
			diff = append(diff, h)
		}
	}
	for _, h := range summaryHosts {
		if !inReadme[h] {
			diff = append(diff, h)
		}
	}
	sort.Strings(diff)
	return diff
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
