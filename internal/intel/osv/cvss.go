package osv

import (
	"math"
	"strings"
)

// CVSS v3 base-score metrics. Only the base metric group is implemented: OSV
// records carry a base vector and nothing else, and temporal/environmental
// metrics would need data no advisory feed publishes.
//
// The formula is CVSS v3.1 §7.1 (identical to v3.0 apart from the roundup
// definition, which v3.1 tightened; v3.1's is used for both — the difference is
// a floating-point edge case, never a band change).
var (
	cvssAttackVector = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	cvssComplexity   = map[string]float64{"L": 0.77, "H": 0.44}
	cvssUI           = map[string]float64{"N": 0.85, "R": 0.62}
	cvssImpact       = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	// Privileges Required is scored differently when Scope is Changed.
	cvssPRUnchanged = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	cvssPRChanged   = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
)

// cvss3BaseScore computes the CVSS v3.x base score for a vector string
// ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"). ok is false when the vector
// is not a v3 vector or is missing a base metric — a partially-parsed vector is
// never scored, because a defaulted metric silently invents a severity.
func cvss3BaseScore(vector string) (score float64, ok bool) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) == 0 || !strings.HasPrefix(parts[0], "CVSS:3") {
		return 0, false
	}
	metrics := make(map[string]string, len(parts))
	for _, p := range parts[1:] {
		key, value, found := strings.Cut(p, ":")
		if found {
			metrics[key] = value
		}
	}

	scopeChanged := metrics["S"] == "C"
	pr := cvssPRUnchanged
	if scopeChanged {
		pr = cvssPRChanged
	}
	av, avOK := cvssAttackVector[metrics["AV"]]
	ac, acOK := cvssComplexity[metrics["AC"]]
	prv, prOK := pr[metrics["PR"]]
	ui, uiOK := cvssUI[metrics["UI"]]
	conf, cOK := cvssImpact[metrics["C"]]
	integ, iOK := cvssImpact[metrics["I"]]
	avail, aOK := cvssImpact[metrics["A"]]
	if !avOK || !acOK || !prOK || !uiOK || !cOK || !iOK || !aOK || metrics["S"] == "" {
		return 0, false
	}

	iscBase := 1 - ((1 - conf) * (1 - integ) * (1 - avail))
	var impact float64
	if scopeChanged {
		impact = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		impact = 6.42 * iscBase
	}
	if impact <= 0 {
		return 0, true
	}
	exploitability := 8.22 * av * ac * prv * ui
	if scopeChanged {
		return roundUp1(math.Min(1.08*(impact+exploitability), 10)), true
	}
	return roundUp1(math.Min(impact+exploitability, 10)), true
}

// roundUp1 is CVSS v3.1's "Roundup": the smallest number to one decimal place
// that is >= the input. Implemented on the integer domain as the spec's
// appendix A prescribes, so 4.02 does not round to 4.0 through float error.
func roundUp1(v float64) float64 {
	i := int(math.Round(v * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}
