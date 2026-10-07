package scorer

import (
	"strings"
	"testing"

	"github.com/unidoc/unisupply/internal/testutil"
	"github.com/unidoc/unisupply/pkg/offline"
	"github.com/unidoc/unisupply/pkg/scanner"
)

// maintainerWarning returns the maintainer-data warning produced for modules
// whose maintainer records carry the given unavailable reasons.
func maintainerWarning(t *testing.T, reasons ...string) string {
	t.Helper()
	specs := make([]testutil.DepSpec, len(reasons))
	for i := range reasons {
		specs[i] = testutil.DepSpec{Path: "github.com/test/m" + string(rune('a'+i)), Version: "v1.0.0", Depth: 1}
	}
	input := twoAxisEmptyInput(testutil.MakeGraph(specs...))
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
// from MaintainerInfo.UnavailableReason, so a scan with a valid token that hit
// API errors is not told it was unauthenticated.
func TestMaintainerUnavailableWarning_NamesTheCause(t *testing.T) {
	tests := []struct {
		name    string
		reasons []string
		want    string
	}{
		{"rate limited keeps the unauthenticated wording", []string{scanner.UnavailableRateLimited, scanner.UnavailableRateLimited}, "GitHub API unauthenticated — maintainer data unavailable for 2 module(s)"},
		{"no reason keeps the unauthenticated wording", []string{""}, "GitHub API unauthenticated — maintainer data unavailable for 1 module(s)"},
		{"api errors", []string{scanner.UnavailableAPIError, scanner.UnavailableAPIError}, "GitHub API error — maintainer data unavailable for 2 module(s)"},
		{"mixed", []string{scanner.UnavailableAPIError, scanner.UnavailableRateLimited}, "GitHub API rate-limited or errored — maintainer data unavailable for 2 module(s)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maintainerWarning(t, tt.reasons...); !strings.HasPrefix(got, tt.want) {
				t.Errorf("warning = %q, want prefix %q", got, tt.want)
			}
		})
	}

	t.Run("offline wins", func(t *testing.T) {
		offline.Enable()
		t.Cleanup(offline.Disable)
		got := maintainerWarning(t, scanner.UnavailableAPIError)
		if !strings.HasPrefix(got, "offline — maintainer data unavailable for 1 module(s)") {
			t.Errorf("warning = %q, want the offline cause", got)
		}
	})
}
