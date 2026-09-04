package scanner

import (
	"strings"
	"testing"
)

func failedWarning(id string) string {
	return severityLookupFailedPrefix + id + "; severity remains UNKNOWN"
}

func TestCollapseSeverityLookupWarnings(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "no warnings",
			in:   nil,
			want: nil,
		},
		{
			name: "unrelated warnings pass through in order",
			in:   []string{"first", "second"},
			want: []string{"first", "second"},
		},
		{
			// A summary of one is longer than the message it summarizes and
			// hides the ID behind a count.
			name: "single failure is left as itself",
			in:   []string{failedWarning("GO-2026-0001")},
			want: []string{failedWarning("GO-2026-0001")},
		},
		{
			name: "several failures collapse to one line",
			in: []string{
				failedWarning("GO-2026-0001"),
				failedWarning("GO-2026-0002"),
				failedWarning("GO-2026-0003"),
			},
			want: []string{
				"severity lookup failed (OSV/NVD/GitHub) for 3 advisories; severities remain UNKNOWN (GO-2026-0001, GO-2026-0002, GO-2026-0003)",
			},
		},
		{
			name: "more than five failures list the first five and elide",
			in: []string{
				failedWarning("GO-2026-0001"),
				failedWarning("GO-2026-0002"),
				failedWarning("GO-2026-0003"),
				failedWarning("GO-2026-0004"),
				failedWarning("GO-2026-0005"),
				failedWarning("GO-2026-0006"),
				failedWarning("GO-2026-0007"),
			},
			want: []string{
				"severity lookup failed (OSV/NVD/GitHub) for 7 advisories; severities remain UNKNOWN (GO-2026-0001, GO-2026-0002, GO-2026-0003, GO-2026-0004, GO-2026-0005, …)",
			},
		},
		{
			// The same advisory can be reported under two modules; the second
			// enrichment hits the cached failure and repeats the warning. One
			// advisory is not a group, so it stays verbatim.
			name: "repeats of one advisory stay verbatim",
			in: []string{
				failedWarning("GO-2026-0001"),
				failedWarning("GO-2026-0001"),
			},
			want: []string{failedWarning("GO-2026-0001")},
		},
		{
			name: "repeats are counted and listed once",
			in: []string{
				failedWarning("GO-2026-0001"),
				failedWarning("GO-2026-0001"),
				failedWarning("GO-2026-0002"),
			},
			want: []string{
				"severity lookup failed (OSV/NVD/GitHub) for 2 advisories; severities remain UNKNOWN (GO-2026-0001, GO-2026-0002)",
			},
		},
		{
			// Repeats must not consume the five displayed slots: without dedup
			// the list would stop at GO-2026-0003 and elide the rest.
			name: "repeats do not consume the displayed slots",
			in: []string{
				failedWarning("GO-2026-0001"),
				failedWarning("GO-2026-0001"),
				failedWarning("GO-2026-0002"),
				failedWarning("GO-2026-0002"),
				failedWarning("GO-2026-0003"),
				failedWarning("GO-2026-0004"),
				failedWarning("GO-2026-0005"),
				failedWarning("GO-2026-0006"),
			},
			want: []string{
				"severity lookup failed (OSV/NVD/GitHub) for 6 advisories; severities remain UNKNOWN (GO-2026-0001, GO-2026-0002, GO-2026-0003, GO-2026-0004, GO-2026-0005, …)",
			},
		},
		{
			// The summary replaces the group where the group began, so a
			// reader still sees warnings in the order they were produced.
			name: "summary lands at the position of the first collapsed warning",
			in: []string{
				"before",
				failedWarning("GO-2026-0001"),
				"between",
				failedWarning("GO-2026-0002"),
				"after",
			},
			want: []string{
				"before",
				"severity lookup failed (OSV/NVD/GitHub) for 2 advisories; severities remain UNKNOWN (GO-2026-0001, GO-2026-0002)",
				"between",
				"after",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := collapseSeverityLookupWarnings(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d warnings, want %d:\ngot:  %v\nwant: %v", len(got), len(tt.want), got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("warning %d:\n got %q\nwant %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestCollapseSeverityLookupWarnings_DoesNotMutateInput guards against the
// aggregate being built by slicing the caller's backing array.
func TestCollapseSeverityLookupWarnings_DoesNotMutateInput(t *testing.T) {
	in := []string{
		"keep me",
		failedWarning("GO-2026-0001"),
		failedWarning("GO-2026-0002"),
	}
	original := append([]string(nil), in...)

	collapseSeverityLookupWarnings(in)

	for i := range original {
		if in[i] != original[i] {
			t.Errorf("input mutated at %d: got %q, want %q", i, in[i], original[i])
		}
	}
}

// TestEnricherWarningUsesSharedPrefix ties the emitter to the aggregator: if
// the message in vulnenrich.go is reworded without updating the prefix, the
// collapse silently stops matching and the warning spam returns. Hermetic —
// every enrichment tier is answered by a stub that knows nothing.
func TestEnricherWarningUsesSharedPrefix(t *testing.T) {
	enricher := newEnricherWithTransport(t, &staticTransport{body: "{}", statusCode: 404}, "", nil)

	v := &Vulnerability{ID: "GO-2026-9999", Severity: "UNKNOWN"}
	warnings := enricher.Enrich(t.Context(), v)

	var found bool
	for _, w := range warnings {
		if strings.HasPrefix(w, severityLookupFailedPrefix) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no warning carried %q; the collapse in ScanVulns would never match:\n%v",
			severityLookupFailedPrefix, warnings)
	}
}
