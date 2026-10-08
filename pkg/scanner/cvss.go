package scanner

import (
	"math"
	"strings"
)

// cvss3Weights holds the numeric weights from the CVSS v3.1 specification,
// section 7.4. They are used by cvss3BaseScore.
var (
	cvss3AV  = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	cvss3AC  = map[string]float64{"L": 0.77, "H": 0.44}
	cvss3UI  = map[string]float64{"N": 0.85, "R": 0.62}
	cvss3CIA = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
)

// cvss3Base lists the base metrics that every v3 vector must carry.
var cvss3Base = [...]string{"AV", "AC", "PR", "UI", "S", "C", "I", "A"}

// cvss3BaseScore computes the CVSS v3.0 or v3.1 base score from a vector
// string such as "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
//
// All eight base metrics must be present exactly once with valid values.
// Temporal and environmental metrics are ignored. Any other prefix (v2, v4)
// or malformed input returns (0, false). A valid vector with no impact
// returns (0, true).
//
// The v3.1 formula is applied to v3.0 vectors as well. The two versions differ
// only in the Roundup edge cases (floating-point artefacts), which is accepted.
func cvss3BaseScore(vector string) (float64, bool) {
	var rest string
	switch {
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		rest = strings.TrimPrefix(vector, "CVSS:3.1/")
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		rest = strings.TrimPrefix(vector, "CVSS:3.0/")
	default:
		return 0, false
	}

	metrics := make(map[string]string, len(cvss3Base))
	for _, part := range strings.Split(rest, "/") {
		k, v, found := strings.Cut(part, ":")
		if !found || k == "" || v == "" {
			return 0, false
		}
		if _, dup := metrics[k]; dup {
			return 0, false
		}
		metrics[k] = v
	}

	for _, k := range cvss3Base {
		if _, ok := metrics[k]; !ok {
			return 0, false
		}
	}

	scopeChanged := false
	switch metrics["S"] {
	case "U":
	case "C":
		scopeChanged = true
	default:
		return 0, false
	}

	av, ok := cvss3AV[metrics["AV"]]
	if !ok {
		return 0, false
	}
	ac, ok := cvss3AC[metrics["AC"]]
	if !ok {
		return 0, false
	}
	ui, ok := cvss3UI[metrics["UI"]]
	if !ok {
		return 0, false
	}
	var pr float64
	switch metrics["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if scopeChanged {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if scopeChanged {
			pr = 0.5
		}
	default:
		return 0, false
	}
	c, ok := cvss3CIA[metrics["C"]]
	if !ok {
		return 0, false
	}
	i, ok := cvss3CIA[metrics["I"]]
	if !ok {
		return 0, false
	}
	a, ok := cvss3CIA[metrics["A"]]
	if !ok {
		return 0, false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * av * ac * pr * ui

	if scopeChanged {
		return cvss3Roundup(math.Min(1.08*(impact+exploitability), 10)), true
	}
	return cvss3Roundup(math.Min(impact+exploitability, 10)), true
}

// cvss3Roundup rounds up to one decimal place using the integer form from
// CVSS v3.1 specification Appendix A, which avoids floating-point artefacts.
func cvss3Roundup(x float64) float64 {
	i := int(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}
