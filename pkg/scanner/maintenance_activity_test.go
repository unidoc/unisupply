package scanner

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestMaintenanceInfo_JSONActivity verifies the activity fields are omitted
// when unknown, so a zero time is never serialized as year 0001.
func TestMaintenanceInfo_JSONActivity(t *testing.T) {
	unknown, err := json.Marshal(MaintenanceInfo{MonthsSinceRelease: 40})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{"last_activity", "months_since_activity"} {
		if strings.Contains(string(unknown), key) {
			t.Errorf("%s present for unknown activity: %s", key, unknown)
		}
	}

	known, err := json.Marshal(MaintenanceInfo{
		LastActivity:        time.Date(2026, time.August, 3, 0, 0, 0, 0, time.UTC),
		MonthsSinceActivity: 2,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"last_activity":"2026-08-03T00:00:00Z"`, `"months_since_activity":2`} {
		if !strings.Contains(string(known), want) {
			t.Errorf("missing %s in %s", want, known)
		}
	}
}

// TestMonthsSince_MatchesInternalFormula pins the exported helper to the
// formula behind MonthsSinceRelease.
func TestMonthsSince_MatchesInternalFormula(t *testing.T) {
	now := time.Date(2026, time.October, 7, 0, 0, 0, 0, time.UTC)
	for _, past := range []time.Time{
		{},
		time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2025, time.December, 31, 0, 0, 0, 0, time.UTC),
		time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC),
	} {
		if got, want := MonthsSince(now, past), monthsSince(now, past); got != want {
			t.Errorf("MonthsSince(%v) = %d, want %d", past, got, want)
		}
	}
}
