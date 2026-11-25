package findingctx

import (
	"strings"
	"testing"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/respond"
)

// TestToResponse_ExposureNeverContradictsMustFixReason reproduces the live API
// bug (GET /api/findings/{id}): exposure.internet_facing:false shipped alongside
// a must_fix_reason asserting transitive internet reachability, with nothing in
// the payload reconciling the two — a responder could not tell whether the
// resource was internet-facing or not. The wire response must always carry a
// field that agrees with must_fix_reason's transitive verdict whenever
// internet_facing is false, so the payload is self-consistent.
func TestToResponse_ExposureNeverContradictsMustFixReason(t *testing.T) {
	f := finding.Finding{
		ID: "f1", Title: "Privilege escalation path", MustFixClass: "must_fix",
		MustFixReason: "reachable from an internet-exposed asset (2 hops)",
	}
	pack := respond.ContextPack{
		Finding:  f,
		Exposure: respond.ExposureFlags{InternetFacing: false, Privileged: true},
		Blast:    respond.BlastSummary{Count: 2},
	}
	fc := FindingContext{ContextPack: pack, Narrative: buildNarrative(pack)}
	out := toResponse(fc)

	if out.Exposure.InternetFacing {
		t.Fatalf("expected internet_facing:false per the direct edge, got true")
	}
	if out.MustFixReason == "" {
		t.Fatalf("expected must_fix_reason to be carried through")
	}
	// The self-refuting combination from the live bug: internet_facing:false
	// AND must_fix_reason asserting reachability, with the exposure block giving
	// no signal that reconciles them.
	if !out.Exposure.InternetReachable {
		t.Errorf("exposure.internet_reachable must be true when must_fix_reason asserts transitive reachability evidence "+
			"(got internet_facing:false, internet_reachable:false, must_fix_reason=%q — self-refuting payload)", out.MustFixReason)
	}
	// And the narrative must not flatly say "not internet-facing" either.
	if want := "is not internet-facing"; strings.Contains(out.Narrative, want) {
		t.Errorf("narrative flatly claims %q while must_fix_reason asserts reachability\ngot: %s", want, out.Narrative)
	}
}

// TestToResponse_NotInternetFacingAndNotReachable is the control: no
// must-fix reachability evidence, so internet_reachable must stay false.
func TestToResponse_NotInternetFacingAndNotReachable(t *testing.T) {
	f := finding.Finding{ID: "f2", Title: "Misconfigured bucket policy"}
	pack := respond.ContextPack{
		Finding:  f,
		Exposure: respond.ExposureFlags{InternetFacing: false, Privileged: false},
	}
	fc := FindingContext{ContextPack: pack, Narrative: buildNarrative(pack)}
	out := toResponse(fc)

	if out.Exposure.InternetFacing || out.Exposure.InternetReachable {
		t.Errorf("expected both exposure flags false with no reachability evidence, got %+v", out.Exposure)
	}
}
