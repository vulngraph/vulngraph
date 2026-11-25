package findingctx

import (
	"strings"
	"testing"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/respond"
)

func TestBuildNarrative_RealAttackPath(t *testing.T) {
	pack := respond.ContextPack{
		Finding: finding.Finding{
			Title: "RCE in exposed API", ResourceName: "prod-web-1", ResourceType: "ec2_instance",
			Score: 94, CheckID: "CVE-2024-9999",
		},
		Exposure: respond.ExposureFlags{InternetFacing: true, Privileged: true},
		Blast:    respond.BlastSummary{Count: 18, ByType: map[string]int{"ec2_instance": 12, "rds_instance": 6}},
		CVE:      &respond.CVEContext{CVEID: "CVE-2024-9999", EPSS: 0.92, KEV: true, FixedVersion: "2.1.0"},
	}
	n := buildNarrative(pack)
	// Names the resource, the exploitability, the reach, and calls it a real path.
	for _, want := range []string{"prod-web-1", "ec2_instance", "CISA KEV", "EPSS 92%", "fixed in 2.1.0",
		"internet-facing and runs with a privileged identity", "18 other assets", "12 ec2_instance", "real attack path"} {
		if !strings.Contains(n, want) {
			t.Errorf("narrative missing %q\ngot: %s", want, n)
		}
	}
}

func TestBuildNarrative_NotDeployedNothingBurger(t *testing.T) {
	pack := respond.ContextPack{
		Finding: finding.Finding{
			Title: "KEV CVE in unused dependency", ResourceID: "pkg:golang/x/[email protected]", ResourceType: "package",
			Score: 22, CheckID: "CVE-2023-1111",
		},
		Exposure:    respond.ExposureFlags{InternetFacing: false, Privileged: false},
		Blast:       respond.BlastSummary{Count: 0},
		CVE:         &respond.CVEContext{CVEID: "CVE-2023-1111", KEV: true},
		SupplyChain: &respond.SupplyChainPath{RepoIDs: []string{"org/app"}},
	}
	n := buildNarrative(pack)
	for _, want := range []string{"not internet-facing", "blast radius is empty", "installed, not deployed", "Not deployed and not reachable"} {
		if !strings.Contains(n, want) {
			t.Errorf("narrative missing %q\ngot: %s", want, n)
		}
	}
}

// TestBuildNarrative_NotInternetFacingButTransitivelyReachable reproduces the
// live bug: a finding whose direct exposure edge is false (not internet-facing)
// but whose must_fix_reason carries positive transitive-reachability evidence
// from the enrich BFS ("reachable from an internet-exposed asset (2 hops)").
// The narrative must never flatly claim "is not internet-facing" in that case —
// that self-refutes the must_fix_reason shipped in the same payload — and it
// must qualify the direct-vs-transitive distinction instead.
func TestBuildNarrative_NotInternetFacingButTransitivelyReachable(t *testing.T) {
	pack := respond.ContextPack{
		Finding: finding.Finding{
			Title: "Privilege escalation path", ResourceName: "role-ci-deploy", ResourceType: "iam_role",
			Score: 78, MustFixClass: "must_fix",
			MustFixReason: "reachable from an internet-exposed asset (2 hops)",
		},
		Exposure: respond.ExposureFlags{InternetFacing: false, Privileged: true},
		Blast:    respond.BlastSummary{Count: 2},
	}
	n := buildNarrative(pack)

	if strings.Contains(n, "is not internet-facing") {
		t.Errorf("narrative flatly claims not-internet-facing while must_fix_reason asserts transitive reachability, unqualified — self-refuting payload\ngot: %s", n)
	}
	for _, want := range []string{"not directly internet-facing", "reachable from an internet-exposed asset (2 hops)"} {
		if !strings.Contains(n, want) {
			t.Errorf("narrative missing %q — must name the transitive reachability explicitly\ngot: %s", want, n)
		}
	}
}

// TestBuildNarrative_ComposesBlastUnmeasuredFragmentIntoTheSentence pins the
// composed sentence when must_fix_reason is itself a "·"-joined composite
// (mustfix.go's mustFixReason, e.g. "assumable from an internet-exposed asset
// · blast radius unmeasured") — the blast-known-ness fix added the
// "blast radius unmeasured" fragment, and nothing tested what the narrative
// looks like once it's spliced in alongside another fragment. The whole
// composite is spliced verbatim (this function's existing, deliberate design:
// the raw reason string IS the narrative fragment) — this test exists so a
// future reader sees exactly what that renders as, not just that it compiles.
func TestBuildNarrative_ComposesBlastUnmeasuredFragmentIntoTheSentence(t *testing.T) {
	pack := respond.ContextPack{
		Finding: finding.Finding{
			Title: "Privilege escalation path", ResourceName: "role-ci-deploy", ResourceType: "iam_role",
			Score: 78, MustFixClass: "must_fix",
			MustFixReason: "assumable from an internet-exposed asset · blast radius unmeasured",
		},
		Exposure: respond.ExposureFlags{InternetFacing: false, Privileged: false},
		Blast:    respond.BlastSummary{Count: 0, Known: false},
	}
	n := buildNarrative(pack)

	want := "but is assumable from an internet-exposed asset · blast radius unmeasured."
	if !strings.Contains(n, want) {
		t.Errorf("narrative missing the composed reason fragment %q\ngot: %s", want, n)
	}
}

// TestBuildNarrative_NotInternetFacingAndNotReachable is the control case: no
// must-fix reachability evidence at all, so the plain "not internet-facing"
// framing is accurate and must still be produced.
func TestBuildNarrative_NotInternetFacingAndNotReachable(t *testing.T) {
	pack := respond.ContextPack{
		Finding:  finding.Finding{Title: "Misconfigured bucket policy", ResourceType: "s3_bucket", Score: 30},
		Exposure: respond.ExposureFlags{InternetFacing: false, Privileged: false},
		Blast:    respond.BlastSummary{Count: 0},
	}
	n := buildNarrative(pack)
	if !strings.Contains(n, "is not internet-facing") {
		t.Errorf("expected plain not-internet-facing framing when there is no reachability evidence\ngot: %s", n)
	}
}

func TestBuildNarrative_IncludesFixHint(t *testing.T) {
	pack := respond.ContextPack{
		Finding:  finding.Finding{Title: "Public S3 bucket", ResourceID: "assets-bucket", ResourceType: "s3_bucket", Score: 70},
		Exposure: respond.ExposureFlags{InternetFacing: true},
		Blast:    respond.BlastSummary{Count: 0},
		Impact:   respond.ImpactAssessment{FixLocation: respond.FixLocation{Hint: "block public access on assets-bucket"}},
	}
	n := buildNarrative(pack)
	if !strings.Contains(n, "Fix: block public access on assets-bucket") {
		t.Errorf("narrative missing fix hint\ngot: %s", n)
	}
	// Exposed but no blast → "contained" framing, not a false "real attack path".
	if !strings.Contains(n, "no onward blast radius") {
		t.Errorf("expected contained framing\ngot: %s", n)
	}
}
