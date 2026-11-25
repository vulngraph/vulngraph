package coverage

import (
	"sort"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/checks"
)

// otherKeyCombinationCap bounds the substitution search below. It mirrors
// checks.probeCombinationCap: past that point the answer is not computed, and
// the key is treated as evidence-bearing. That is the fail-safe direction — an
// over-reported gap wastes a reader's time, an under-reported one hides missing
// data, which is the failure this whole document exists to end.
const otherKeyCombinationCap = 4096

// evidenceKeys splits a check's RequiredKeys into the keys whose ABSENCE can
// hide a violation, and the keys whose absence cannot.
//
// The document measures key presence, and presence is the right measure for a
// coverage ratio. It is the wrong measure for a closing CONDITION: three k8s pod
// checks read `ns_psa_enforce` only to SUPPRESS themselves in
// Pod-Security-Admission privileged namespaces, so it is absent on every
// pod by design. Reporting that as an evidence gap tells a reader to make the
// collector emit the key — which would turn those checks OFF where they
// currently fire. Same shape for `archived` on github-no-branch-protection,
// where absent correctly means "not archived".
//
// The question asked here is the one Check.Evaluable already answers, lifted
// from a single asset to the predicate itself: with every OTHER required key
// present, is there an assignment under which the check stays silent and some
// value of k would have fired it? If yes, k's absence hides violations and is a
// real evidence gap. If no value of k can ever fire what absence did not, its
// absence never prevented the check concluding, and demanding it is bad advice.
//
// Evaluable is used as-is and unweakened: filling every other key leaves k as
// the single absent key, which is exactly the case Evaluable decides.
func evidenceKeys(c checks.Check, assetType string) (evidence, suppressor []string) {
	if len(c.RequiredKeys) == 0 {
		return nil, nil
	}
	// Nothing to probe with — a dynamic predicate, or one keyscan could not
	// analyse. Every key stays an evidence key rather than being quietly
	// excused.
	if c.Violates == nil || len(c.ProbeValues) == 0 {
		return append([]string(nil), c.RequiredKeys...), nil
	}
	// A predicate that never fires under ANY probe assignment tells us nothing
	// about which of its keys carry evidence — every one of them would look like
	// a suppressor. That happens whenever the predicate also depends on a
	// structural asset field a probe cannot supply (aws-ec2-public-ip needs a
	// PublicIP) or on a constant keyscan could not lift into ProbeValues
	// (aws-lambda-public-access compares against asset.PublicAccessConfirmed).
	// Inconclusive means every key stays an evidence key: silently excusing those
	// checks would hide real gaps, which is the failure mode this document must
	// never have.
	if !firable(c, assetType) {
		return append([]string(nil), c.RequiredKeys...), nil
	}
	for _, k := range c.RequiredKeys {
		if hidesAViolation(c, assetType, k) {
			evidence = append(evidence, k)
		} else {
			suppressor = append(suppressor, k)
		}
	}
	sort.Strings(evidence)
	sort.Strings(suppressor)
	return evidence, suppressor
}

// firable reports whether some assignment of every required key, drawn from the
// predicate's own probe values, makes it fire. When nothing does, the
// suppressor classification below is not evidence of anything.
func firable(c checks.Check, assetType string) bool {
	combos := 1
	for range c.RequiredKeys {
		combos *= len(c.ProbeValues)
		if combos > otherKeyCombinationCap {
			return false
		}
	}
	probe := newProbe(c, assetType, len(c.RequiredKeys))
	for i := 0; i < combos; i++ {
		n := i
		for _, k := range c.RequiredKeys {
			probe.Metadata[k] = c.ProbeValues[n%len(c.ProbeValues)]
			n /= len(c.ProbeValues)
		}
		if c.Violates(probe) {
			return true
		}
	}
	return false
}

func newProbe(c checks.Check, assetType string, keys int) asset.Asset {
	return asset.Asset{
		ID:       "coverage-probe",
		Type:     assetType,
		Provider: c.Provider,
		Metadata: make(map[string]string, keys),
	}
}

// hidesAViolation reports whether some assignment of c's other required keys
// leaves the predicate silent with key absent, while some probe value of key
// would have fired it.
func hidesAViolation(c checks.Check, assetType, key string) bool {
	others := make([]string, 0, len(c.RequiredKeys))
	for _, k := range c.RequiredKeys {
		if k != key {
			others = append(others, k)
		}
	}
	combos := 1
	for range others {
		combos *= len(c.ProbeValues)
		if combos > otherKeyCombinationCap {
			return true
		}
	}
	probe := newProbe(c, assetType, len(others))
	for i := 0; i < combos; i++ {
		n := i
		for _, k := range others {
			probe.Metadata[k] = c.ProbeValues[n%len(c.ProbeValues)]
			n /= len(c.ProbeValues)
		}
		if c.Violates(probe) {
			continue // already fired; this assignment says nothing about silence
		}
		if !c.Evaluable(probe) {
			return true // some value of the absent key would have fired it
		}
	}
	return false
}
