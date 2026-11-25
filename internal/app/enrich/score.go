package enrich

import "sort"

// Aggregate combines source factors into a final score, raises it to the
// highest declared floor, applies suppression, ceilings and root-cause
// delegation, and classifies the band. Pure — no infrastructure — so
// it is exhaustively table-testable. Factors are sorted by source name for a
// stable, deterministic breakdown regardless of the order sources finished
// evaluating.
//
// Arithmetic order — POSITIVES ARE CLAMPED BEFORE NEGATIVES APPLY:
//
//  1. Sum the positive points and clamp that subtotal to 100.
//  2. THEN add the negative points (demotes/penalties) to the clamped subtotal.
//  3. Then floor, then suppression, then ceiling, then root-cause delegation
//     (caps below page, overriding even a page floor), then the final 0..100
//     bound.
//
// Step 1 before step 2 is the whole point. Summing positives and negatives
// together and clamping only the *final* total at 100 would silently discard
// every demote on any finding whose positives already exceed 100 — a staging
// service account carrying principal_class -10 ("non-production principal")
// would score exactly the same as an otherwise-identical production one once
// the raw positive sum clears 100. Clamping the positive subtotal first means a
// negative factor is always spent against real headroom: it lowers the final
// score unless a later clamp (floor, suppression, ceiling, root-cause cap or the
// 0 bound) binds.
//
// Floor still beats a demote, deliberately, and that is why the floor is applied
// AFTER the negatives: a Floor is a source asserting "this must always be at
// least band X" (KEV's page floor), which is a stronger claim than "this
// principal matters a little less". A demote moves the score freely inside the
// headroom above the floor; it can never push it below.
func Aggregate(factors []Factor) Score {
	sort.Slice(factors, func(i, j int) bool { return factors[i].Source < factors[j].Source })

	positive, negative, floor, ceiling, suppressed, rootCause := 0, 0, 0, 0, false, false
	for _, f := range factors {
		rootCause = rootCause || f.RootCause
		if f.Points >= 0 {
			positive += f.Points
		} else {
			negative += f.Points
		}
		if f.Floor > floor {
			floor = f.Floor
		}
		if f.Ceiling > 0 && (ceiling == 0 || f.Ceiling < ceiling) {
			ceiling = f.Ceiling
		}
		if f.Suppress {
			suppressed = true
		}
	}
	// Step 1 + 2: clamp the positive subtotal, then spend the negatives against it.
	if positive > 100 {
		positive = 100
	}
	sum := positive + negative
	if sum < floor {
		sum = floor
	}
	// Suppression caps into the monitor band — an expected/benign finding stays
	// out of the actionable queue. But a PAGE-level floor is the strongest
	// assertion a source can make ("this always pages" — declared by KEV for a
	// known-exploited finding), so suppression must never override it. Lesser
	// floors (e.g. exposure promotion) remain suppressible. Enforcing this here
	// rather than per-source guarantees a new suppress-emitting source cannot
	// silently hide a known-exploited finding even if it forgets to self-check.
	if suppressed && sum >= ThresholdPipeline && floor < ThresholdPage {
		sum = ThresholdPipeline - 1
	}
	// A Ceiling caps the score below the declared threshold — same page-floor
	// exception as suppression: a source cannot cap a finding that another
	// source has asserted must always page (KEV, CriticalFloor).
	if ceiling > 0 && floor < ThresholdPage && sum >= ceiling {
		sum = ceiling - 1
	}
	// Root-cause delegation is the exception to that exception (see
	// Factor.RootCause): the page this finding's floor asserts is raised by
	// the root-cause findings that carry it, so it must not be raised twice.
	if rootCause && sum >= ThresholdPage {
		sum = ThresholdPage - 1
	}
	if sum < 0 {
		sum = 0
	}
	if sum > 100 {
		sum = 100
	}

	v := uint8(sum)
	return Score{Value: v, Band: bandFor(v), Factors: factors}
}

func bandFor(v uint8) Band {
	switch {
	case v >= ThresholdPage:
		return BandPage
	case v >= ThresholdHigh:
		return BandHigh
	case v >= ThresholdPipeline:
		return BandPipeline
	default:
		return BandMonitor
	}
}

// bandRank orders bands; an empty (never-enriched) band ranks below all.
func bandRank(b Band) int {
	switch b {
	case BandMonitor:
		return 1
	case BandPipeline:
		return 2
	case BandHigh:
		return 3
	case BandPage:
		return 4
	}
	return 0
}

// BandAtLeast reports whether band a ranks at or above b.
func BandAtLeast(a, b Band) bool { return bandRank(a) >= bandRank(b) }

// UrgentRegardlessOfReach reports whether a source floored the score to the
// high band or above on evidence that does not depend on the internet path:
// an active-threat detection (GuardDuty C&C/Backdoor/Exfiltration, GCP SCC), a
// live leaked credential, a dangling-DNS takeover. These are act-now classes
// that a page floor never lifts, so alerting must not wait for one.
//
// Derived from hasReachIndependentHighFloor (the consistency gate's and the
// belief's notion of the same thing) plus the DNS-takeover floor, so the three
// cannot drift. principal_class (a human able to self-escalate) and
// identity_hygiene (an SSO admin grant) also floor to High but stay out on
// purpose: they describe standing posture, not a live compromise, and paging on
// them would page on every admin.
func UrgentRegardlessOfReach(factors []Factor) bool {
	if hasReachIndependentHighFloor(factors) {
		return true
	}
	for _, f := range factors {
		if f.Source == sourceDNSTakeover && f.Floor >= ThresholdHigh {
			return true
		}
	}
	return false
}
