package scorer

import (
	"fmt"
	"strings"
	"testing"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/offline"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// maintainerWarning returns the maintainer-data warning produced for modules
// whose maintainer records carry the given unavailable reasons, for a scan
// whose GitHub requests did (authenticated) or did not carry an accepted token.
func maintainerWarning(t *testing.T, authenticated bool, reasons ...string) string {
	t.Helper()
	specs := make([]testutil.DepSpec, len(reasons))
	for i := range reasons {
		specs[i] = testutil.DepSpec{Path: "github.com/test/m" + string(rune('a'+i)), Version: "v1.0.0", Depth: 1}
	}
	input := twoAxisEmptyInput(testutil.MakeGraph(specs...))
	input.GitHubAuthenticated = authenticated
	for i, reason := range reasons {
		input.Maintainers[specs[i].Path] = &scanner.MaintainerInfo{UnavailableReason: reason}
	}
	for _, w := range ScoreAll(input).Warnings {
		if strings.Contains(w, "maintainer data unavailable") {
			return w
		}
	}
	t.Fatalf("no maintainer warning produced for reasons %v", reasons)
	return ""
}

// TestMaintainerUnavailableWarning_NamesTheCause verifies the warning is built
// from MaintainerInfo.UnavailableReason and from whether the scan used a token:
// a scan with a valid token that hit API errors is not told it was
// unauthenticated, and neither is one that GitHub rate-limited. Without a token
// (or with a rejected one, which the runner reports as not authenticated) the
// unauthenticated wording stays.
func TestMaintainerUnavailableWarning_NamesTheCause(t *testing.T) {
	rl, ae := scanner.UnavailableRateLimited, scanner.UnavailableAPIError
	tests := []struct {
		name          string
		authenticated bool
		reasons       []string
		want          string
	}{
		{"no token: rate limited keeps the unauthenticated wording", false, []string{rl, rl}, "GitHub API unauthenticated — maintainer data unavailable for 2 module(s)"},
		{"no token: no reason keeps the unauthenticated wording", false, []string{""}, "GitHub API unauthenticated — maintainer data unavailable for 1 module(s)"},
		{"no token: api errors", false, []string{ae, ae}, "GitHub API error — maintainer data unavailable for 2 module(s)"},
		{"no token: mixed", false, []string{ae, rl}, "GitHub API rate-limited or errored — maintainer data unavailable for 2 module(s)"},

		{"token: rate limited", true, []string{rl, rl}, "GitHub API rate-limited — maintainer data unavailable for 2 module(s)"},
		{"token: no reason", true, []string{""}, "GitHub API rate-limited — maintainer data unavailable for 1 module(s)"},
		{"token: api errors", true, []string{ae, ae}, "GitHub API error — maintainer data unavailable for 2 module(s)"},
		{"token: mixed", true, []string{ae, rl}, "GitHub API rate-limited or errored — maintainer data unavailable for 2 module(s)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maintainerWarning(t, tt.authenticated, tt.reasons...); !strings.HasPrefix(got, tt.want) {
				t.Errorf("warning = %q, want prefix %q", got, tt.want)
			}
		})
	}

	for _, authenticated := range []bool{false, true} {
		t.Run(fmt.Sprintf("offline wins (authenticated=%v)", authenticated), func(t *testing.T) {
			offline.Enable()
			t.Cleanup(offline.Disable)
			got := maintainerWarning(t, authenticated, scanner.UnavailableAPIError)
			if !strings.HasPrefix(got, "offline — maintainer data unavailable for 1 module(s)") {
				t.Errorf("warning = %q, want the offline cause", got)
			}
		})
	}
}
