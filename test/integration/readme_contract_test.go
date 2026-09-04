package integration_test

import (
	"os"
	"regexp"
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

// networkContract is the parsed README contract.
type networkContract struct {
	// Hosts are the first-column values of the table, deduplicated, in README
	// order. A value may be a placeholder such as "<trust-index-url>" for a
	// host the user supplies.
	Hosts []string

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

// parseNetworkContract reads the network-contract table out of the README.
// Parsing the markdown directly (rather than restating the hosts in Go) is
// deliberate: it makes documentation drift a test failure.
func parseNetworkContract(t *testing.T, path string) networkContract {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	lines := strings.Split(string(data), "\n")
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == contractSection {
			start = i + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("%s: section %q not found; the network contract must live under that heading", path, contractSection)
	}

	var (
		contract  networkContract
		seen      = map[string]bool{}
		inTable   bool
		tableDone bool
	)
	for _, line := range lines[start:] {
		trimmed := strings.TrimSpace(line)

		// Stop at the next top-level section.
		if strings.HasPrefix(trimmed, "## ") {
			break
		}

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
			if !ok || seen[host] {
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

	wantNever := []string{"sum.example.org", "pkg.example.org"}
	if strings.Join(contract.NeverContacted, ",") != strings.Join(wantNever, ",") {
		t.Errorf("NeverContacted = %v, want %v (the toolchain caveat must not leak in)",
			contract.NeverContacted, wantNever)
	}
}

// TestNetworkContract_SecurityMDInSync keeps SECURITY.md's prose summary of
// the contract from drifting away from the README table it summarizes. This
// drift is not hypothetical: the EPSS and KEV hosts were added to the table
// and not to the summary, and nothing caught it.
func TestNetworkContract_SecurityMDInSync(t *testing.T) {
	contract := parseNetworkContract(t, readmePath)

	data, err := os.ReadFile(securityPath)
	if err != nil {
		t.Fatalf("reading %s: %v", securityPath, err)
	}
	text := string(data)

	for _, host := range contract.Hosts {
		// The Trust Index row is a placeholder for a user-supplied URL;
		// SECURITY.md describes it in words, not as a hostname.
		if host == "<trust-index-url>" {
			continue
		}
		if !strings.Contains(text, host) {
			t.Errorf("README documents %q but SECURITY.md's summary does not mention it; "+
				"the two must describe the same contract", host)
		}
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
