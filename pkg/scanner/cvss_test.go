package scanner

import (
	"math"
	"testing"
)

func TestCVSS3BaseScore(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 9.1},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5},
		{"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H", 6.1},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4},
		{"CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 2.0},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:L/I:N/A:N", 1.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O", 9.8},
	}
	for _, tc := range tests {
		t.Run(tc.vector, func(t *testing.T) {
			got, ok := cvss3BaseScore(tc.vector)
			if !ok {
				t.Fatalf("cvss3BaseScore(%q) ok=false, want true", tc.vector)
			}
			if math.Abs(got-tc.want) > 1e-9 {
				t.Errorf("cvss3BaseScore(%q) = %v, want %v", tc.vector, got, tc.want)
			}
		})
	}
}

func TestCVSS3BaseScore_Rejected(t *testing.T) {
	tests := map[string]string{
		"empty":          "",
		"v4":             "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		"v2":             "AV:N/AC:L/Au:N/C:P/I:P/A:P",
		"missing_A":      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
		"duplicate_AV":   "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"invalid_AV":     "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"garbage":        "CVSS:3.1/garbage",
		"invalid_scope":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",
		"invalid_PR":     "CVSS:3.1/AV:N/AC:L/PR:X/UI:N/S:U/C:H/I:H/A:H",
		"empty_metric":   "CVSS:3.1/AV:/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"trailing_slash": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/",
	}
	for name, vec := range tests {
		t.Run(name, func(t *testing.T) {
			if got, ok := cvss3BaseScore(vec); ok {
				t.Errorf("cvss3BaseScore(%q) = (%v, true), want ok=false", vec, got)
			}
		})
	}
}

func TestParseCVSSScore_Vector(t *testing.T) {
	if got, ok := parseCVSSScore("7.5"); !ok || got != 7.5 {
		t.Errorf("bare number: got (%v,%v)", got, ok)
	}
	if got, ok := parseCVSSScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"); !ok || math.Abs(got-7.5) > 1e-9 {
		t.Errorf("vector: got (%v,%v)", got, ok)
	}
	if _, ok := parseCVSSScore("CVSS:4.0/AV:N"); ok {
		t.Error("v4 vector must not parse")
	}
}
