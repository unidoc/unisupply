package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/unidoc/unisupply/internal/testutil"
)

// Real warning strings from pkg/scorer/risk.go.
const (
	warnMaintainer  = "GitHub API unauthenticated — maintainer data unavailable for 3 module(s); maintainer weight excluded from those scores"
	warnMaintenance = "maintenance data unavailable for 2 module(s); maintenance weight excluded from those scores rather than scored as unknown"
	warnResilience  = "resilience data unavailable for 2 module(s); release-cadence and governance signals not measured"
	warnVulnScan    = "vulnerability scan did not run; the 40% vulnerability weight is excluded from every dependency score — these scores describe only the axes that were measured and are NOT comparable to a scan that checked for CVEs"
	warnEPSS        = "high-EPSS CVE GO-2024-0001 (93% exploitation probability) on dep github.com/x/y (unreachable) — verify reachability manually"
	warnKEV         = "KEV CVE GO-2024-0002 on dep github.com/x/y (test-only) — confirmed exploited in the wild; verify reachability manually"
)

func TestPublishedWarnings(t *testing.T) {
	got := publishedWarnings([]string{warnMaintainer, warnMaintenance, warnResilience, warnVulnScan, warnEPSS, warnKEV, warnVulnScan, "GitHub token rejected"})
	want := []string{
		"maintenance data unavailable for 2 module(s)",
		warnResilience,
		"vulnerability scan did not run",
		warnKEV,
		"GitHub token rejected",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("publishedWarnings =\n%q\nwant\n%q", got, want)
	}
	if publishedWarnings(nil) != nil || publishedWarnings([]string{warnMaintainer, warnEPSS}) != nil {
		t.Error("expected nil when nothing is left")
	}
	if got := publishedWarnings([]string{"all weight excluded"}); got != nil {
		t.Errorf("pure retired-model text kept: %q", got)
	}
}

// TestRetiredWarningsNotWritten checks the text SCAN LIMITATIONS block and the JSON warnings carry none of the retired
// score language, and still say the vulnerability scan did not run.
func TestRetiredWarningsNotWritten(t *testing.T) {
	graph := testutil.MakeGraph(testutil.DepSpec{Path: "github.com/example/pkg", Version: "v1.0.0", Direct: true})
	ps := scanNotesScore([]string{warnVulnScan, warnMaintainer, warnEPSS}, nil)

	var tb bytes.Buffer
	opts := TextOptions{NoColor: true, Writer: &tb}
	if err := WriteText(graph, ps, &opts); err != nil {
		t.Fatal(err)
	}
	var jb bytes.Buffer
	if err := WriteJSON(graph, ps, JSONOptions{}, &jb); err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(jb.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"text": tb.String(), "json": strings.Join(rep.Warnings, "\n")} {
		for _, bad := range []string{"weight", "comparable", "reachability manually", "maintainer data"} {
			if strings.Contains(out, bad) {
				t.Errorf("%s output contains %q:\n%s", name, bad, out)
			}
		}
		if !strings.Contains(out, "vulnerability scan did not run") {
			t.Errorf("%s output lost the vulnerability scan warning:\n%s", name, out)
		}
	}
}
