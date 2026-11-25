package enrich

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestClassifySafety(t *testing.T) {
	cases := []struct {
		name           string
		dependents     int
		present        bool
		prod           bool
		internetFacing bool
		want           string
	}{
		{"present unreferenced is safe", 0, true, false, false, SafetySafe},
		{"present but prod is risky", 0, true, true, false, SafetyRisky},
		{"present but internet-facing is risky", 0, true, false, true, SafetyRisky},
		{"depended-on is risky", 3, true, false, false, SafetyRisky},
		{"stale/gone (not present) is caution, not safe", 0, false, false, false, SafetyCaution},
		{"depended-on and stale is risky", 1, false, false, false, SafetyRisky},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifySafety(tc.dependents, tc.present, tc.prod, tc.internetFacing); got != tc.want {
				t.Fatalf("classifySafety(%d,%v,%v,%v) = %q, want %q",
					tc.dependents, tc.present, tc.prod, tc.internetFacing, got, tc.want)
			}
		})
	}
}

func TestIsPresent(t *testing.T) {
	now := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		a    asset.Asset
		want bool
	}{
		{"seen recently", asset.Asset{LastSeen: now.Add(-1 * time.Hour)}, true},
		{"stale (not seen in 30d)", asset.Asset{LastSeen: now.Add(-30 * 24 * time.Hour)}, false},
		{"never had a last-seen (uncorrelated)", asset.Asset{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPresent(tc.a, now); got != tc.want {
				t.Fatalf("isPresent = %v, want %v", got, tc.want)
			}
		})
	}
}

// The safety band reads asset.ClassifyEnvironment: only a positive prod
// classification makes an otherwise-safe resource risky. Unknown is its own
// state on this ADVISORY band and does not demote to risky (the mutation-gating
// readers in respond treat it as prod instead).
func TestAssessSafety_Environment(t *testing.T) {
	now := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	fnd := finding.Finding{ResourceID: "iam_role:abandoned"}
	for _, tc := range []struct {
		name string
		seed asset.Asset
		want string
	}{
		{"tagged prod is risky", asset.Asset{Tags: map[string]string{"example.io/env": "prod"}}, SafetyRisky},
		{"metadata prod is risky", asset.Asset{Metadata: map[string]string{"environment": "production"}}, SafetyRisky},
		{"GCP prod project is risky", asset.Asset{AccountID: "acme-prod-1"}, SafetyRisky},
		{"staging stays safe", asset.Asset{Tags: map[string]string{"env": "staging"}}, SafetySafe},
		{"dev stays safe", asset.Asset{Tags: map[string]string{"stage": "dev"}}, SafetySafe},
		{"unknown is not promoted to prod", asset.Asset{Tags: map[string]string{"team": "payments"}}, SafetySafe},
		{"conflicting env tags are unknown, not prod", asset.Asset{Tags: map[string]string{"env": "prod", "stage": "dev"}}, SafetySafe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.seed.LastSeen = now.Add(-time.Hour)
			p := fakeSafetyProvider{seed: tc.seed}
			require.Equal(t, tc.want, assessSafety(context.Background(), p, fnd, p.seed, now).Class)
		})
	}
}

// fakeSafetyProvider is a scriptable FixSafetyProvider for assessSafety tests.
type fakeSafetyProvider struct {
	seed      asset.Asset
	into      map[string][]asset.Edge // keyed by the first requested edge type
	out       map[string][]asset.Edge // keyed by edge type (EdgesOut)
	exposed   bool
	edgesErr  error
	outErr    error
	getErr    error
	exposeErr error
}

func (f fakeSafetyProvider) EdgesOut(_ context.Context, _ string, edgeType string) ([]asset.Edge, error) {
	if f.outErr != nil {
		return nil, f.outErr
	}
	return f.out[edgeType], nil
}

func (f fakeSafetyProvider) Get(context.Context, string) (asset.Asset, error) {
	return f.seed, f.getErr
}

// EdgesIntoTypes returns the union of the scripted edges for EVERY requested
// type — the real repo issues one `edge_type IN (…)` query, so keying only off
// types[0] would have made a widened dependentEdgeTypes untestable (and would
// have hidden the very bug fixed here).
func (f fakeSafetyProvider) EdgesIntoTypes(_ context.Context, _ string, types []string) ([]asset.Edge, error) {
	if f.edgesErr != nil {
		return nil, f.edgesErr
	}
	var out []asset.Edge
	for _, t := range types {
		out = append(out, f.into[t]...)
	}
	return out, nil
}

func (f fakeSafetyProvider) IsExposedEdge(context.Context, string) (bool, error) {
	return f.exposed, f.exposeErr
}

func TestAssessSafety(t *testing.T) {
	now := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	fnd := finding.Finding{ResourceID: "iam_role:abandoned"}

	t.Run("present unreferenced inactive principal is safe", func(t *testing.T) {
		p := fakeSafetyProvider{
			seed: asset.Asset{
				AccountID: "111122223333", Region: "eu-west-1",
				LastSeen: now.Add(-1 * time.Hour), // fresh → present
				Metadata: map[string]string{"inactive": "true"},
			},
		}
		got := assessSafety(context.Background(), p, fnd, p.seed, now)
		if got.Class != SafetySafe {
			t.Fatalf("Class = %q, want safe", got.Class)
		}
		if !got.Unused || got.Dependents != 0 {
			t.Fatalf("Unused=%v Dependents=%d, want true/0", got.Unused, got.Dependents)
		}
		if got.FixTarget != "console:111122223333:eu-west-1" {
			t.Fatalf("FixTarget = %q", got.FixTarget)
		}
	})

	t.Run("stale (gone) is caution, never safe", func(t *testing.T) {
		p := fakeSafetyProvider{seed: asset.Asset{LastSeen: now.Add(-40 * 24 * time.Hour)}}
		if got := assessSafety(context.Background(), p, fnd, p.seed, now); got.Class != SafetyCaution {
			t.Fatalf("Class = %q, want caution", got.Class)
		}
	})

	t.Run("dependents make it risky", func(t *testing.T) {
		p := fakeSafetyProvider{
			seed: asset.Asset{LastSeen: now.Add(-1 * time.Hour)},
			into: map[string][]asset.Edge{
				"dns_points_to": {{SrcID: "dns:a"}, {SrcID: "dns:b"}, {SrcID: "dns:a"}}, // one dup
			},
		}
		got := assessSafety(context.Background(), p, fnd, p.seed, now)
		if got.Dependents != 2 {
			t.Fatalf("Dependents = %d, want 2 (distinct)", got.Dependents)
		}
		if got.Class != SafetyRisky {
			t.Fatalf("Class = %q, want risky", got.Class)
		}
	})

	t.Run("deploys_to edge yields a repo fix target", func(t *testing.T) {
		p := fakeSafetyProvider{
			into: map[string][]asset.Edge{
				"deploys_to": {{SrcID: "github_repo:org/app", Properties: map[string]string{"confidence": "high"}}},
			},
		}
		got := assessSafety(context.Background(), p, fnd, p.seed, now)
		if got.FixTarget != "repo:github_repo:org/app" {
			t.Fatalf("FixTarget = %q", got.FixTarget)
		}
	})

	t.Run("fail-open: nil provider and no resource", func(t *testing.T) {
		if got := assessSafety(context.Background(), nil, fnd, asset.Asset{}, now); got.Class != "" {
			t.Fatalf("nil provider Class = %q, want empty", got.Class)
		}
		if got := assessSafety(context.Background(), fakeSafetyProvider{}, finding.Finding{}, asset.Asset{}, now); got.Class != "" {
			t.Fatalf("no-resource Class = %q, want empty", got.Class)
		}
	})

	t.Run("fail-open: dependents read error leaves band unknown", func(t *testing.T) {
		p := fakeSafetyProvider{edgesErr: errors.New("graph down")}
		if got := assessSafety(context.Background(), p, fnd, p.seed, now); got.Class != "" {
			t.Fatalf("edges error Class = %q, want empty", got.Class)
		}
	})

	// An IsExposedEdge error must not be discarded (exposed, _ := ...) and
	// silently default to exposed=false — which classifySafety could read as a confirmed "not
	// internet-facing" and promote an ACTUALLY-exposed, present, no-dependent
	// resource to SafetySafe. present=true + prod=false + dependents=0 is
	// exactly the shape that would produce SafetySafe on that bug; this
	// asserts it produces unknown ("") instead, the same fail-open treatment
	// the dependents-error case above already gets.
	t.Run("fail-open: exposed-edge read error leaves band unknown, never SafetySafe", func(t *testing.T) {
		p := fakeSafetyProvider{seed: asset.Asset{ID: "i-1", LastSeen: now}, exposeErr: errors.New("graph down")}
		got := assessSafety(context.Background(), p, fnd, p.seed, now)
		if got.Class != "" {
			t.Fatalf("exposed-edge error Class = %q, want empty (never SafetySafe on an unmeasured exposure)", got.Class)
		}
	})
}

// dependentEdgeTypes is the whole of the "does anything rely on this?" question.
// A type missing from it is not a smaller answer — it is a silent "nothing
// depends on this", which classifies the resource safe to delete. Every entry
// below is an edge_type that can point AT the judged
// resource; the exclusions are equally deliberate.
func TestDependentEdgeTypes(t *testing.T) {
	have := map[string]bool{}
	for _, e := range dependentEdgeTypes {
		if have[e] {
			t.Fatalf("duplicate edge type %q — the dependents count dedupes by src_id, but a duplicate here is a copy-paste bug", e)
		}
		have[e] = true
	}

	required := []struct {
		edgeType string
		why      string
	}{
		{"dns_points_to", "a DNS record resolves here"},
		{"executes_as", "a workload runs as this identity"},
		{"federated_access", "an external IdP federates into this identity"},
		{"depends_on", "the correct dependents for a package, kept for if that type becomes assessable"},
		{"runs_package", "an image ships this package"},
		{"accesses_secret", "an iam_role or service account reads this secret"},
		{"can_assume", "a principal can assume this role"},
		{"has_role", "an instance profile grants this role to a workload"},
		{"binds", "a RoleBinding references this Role"},
		{"targets", "a Service routes traffic to this workload"},
	}
	for _, r := range required {
		t.Run(r.edgeType, func(t *testing.T) {
			if !have[r.edgeType] {
				t.Fatalf("%q missing from dependentEdgeTypes: %s", r.edgeType, r.why)
			}
		})
	}

	excluded := []struct {
		edgeType string
		why      string
	}{
		{"deploys_to", "the deploying repo is the fix OWNER, not a runtime dependent — it feeds FixTarget"},
		{"attached_to", "no such edge_type exists in this platform; listing it would fake a fix for ebs_volume"},
		{"owns", "cloud_account owns ec2_instance is account ownership, not dependency — counting it makes every AWS resource permanently risky"},
	}
	for _, e := range excluded {
		t.Run("excluded/"+e.edgeType, func(t *testing.T) {
			if have[e.edgeType] {
				t.Fatalf("%q must not be a dependent edge: %s", e.edgeType, e.why)
			}
		})
	}
}

// One case per dependency class the widened set added: each must move the
// resource off "safe", because each means something breaks if the fix lands.
func TestAssessSafety_DependencyClassesAreNotSafe(t *testing.T) {
	now := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	present := asset.Asset{LastSeen: now.Add(-1 * time.Hour)}

	cases := []struct {
		name       string
		resourceID string
		edgeType   string
		srcs       []string
		wantDeps   int
	}{
		{"role a principal can assume", "arn:aws:iam::1:role/r", "can_assume", []string{"arn:aws:iam::1:user/u"}, 1},
		{"role an instance profile grants", "arn:aws:iam::1:role/r", "has_role", []string{"i-abc"}, 1},
		{"k8s role a binding references", "k8s_role:ns/r", "binds", []string{"k8s_role_binding:ns/b"}, 1},
		{"pod a service routes to", "k8s_pod:ns/p", "targets", []string{"k8s_service:ns/s"}, 1},
		{"secret a role reads", "arn:aws:secretsmanager:...:s", "accesses_secret", []string{"arn:aws:iam::1:role/r"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			edges := make([]asset.Edge, 0, len(tc.srcs))
			for _, s := range tc.srcs {
				edges = append(edges, asset.Edge{SrcID: s})
			}
			p := fakeSafetyProvider{seed: present, into: map[string][]asset.Edge{tc.edgeType: edges}}

			got := assessSafety(context.Background(), p, finding.Finding{ResourceID: tc.resourceID}, present, now)

			if got.Dependents != tc.wantDeps {
				t.Fatalf("Dependents = %d, want %d", got.Dependents, tc.wantDeps)
			}
			if got.Class != SafetyRisky {
				t.Fatalf("Class = %q, want risky — %s depends on this resource", got.Class, tc.edgeType)
			}
		})
	}
}

// The regression the widening must not cause: an unreferenced resource of an
// ASSESSABLE type is still safe. The fix must discriminate, not blanket-risky.
func TestAssessSafety_UnreferencedResourceStaysSafe(t *testing.T) {
	now := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	present := asset.Asset{LastSeen: now.Add(-1 * time.Hour)}
	p := fakeSafetyProvider{seed: present}

	f := finding.Finding{ResourceID: "arn:aws:iam::1:role/abandoned", ResourceType: "iam_role"}
	if got := assessSafety(context.Background(), p, f, present, now); got.Class != SafetySafe {
		t.Fatalf("Class = %q, want safe", got.Class)
	}
}

// A secret whose IAM policy the collector could not read has no accesses_secret
// edges for a reason unrelated to who reads it: zero dependents there is not a
// measurement, so it gets no class rather than "safe". The same secret with its
// policy read stays safe, so the rule discriminates.
func TestAssessSafety_UnreadDependentsCarryNoClass(t *testing.T) {
	now := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	f := finding.Finding{ResourceID: "proj/secret/db-password", ResourceType: "gcp_secret"}
	for _, tc := range []struct {
		known string
		want  string
	}{
		{known: "false", want: ""},
		{known: "true", want: SafetySafe},
	} {
		t.Run("accessors_known="+tc.known, func(t *testing.T) {
			seed := asset.Asset{Type: "gcp_secret", LastSeen: now.Add(-1 * time.Hour),
				Metadata: map[string]string{asset.MetaAccessorsKnown: tc.known}}
			got := assessSafety(context.Background(), fakeSafetyProvider{seed: seed}, f, seed, now)
			require.Equal(t, tc.want, got.Class)
			require.Zero(t, got.Dependents)
		})
	}
}

// A type the dependents model cannot answer for gets NO class — not "safe", which
// would recommend deleting it, and not "risky", which would be a verdict the model
// did not earn. The evidence fields are still populated.
//
// package is the case that forced this. Adding depends_on flips every open
// safe package finding to risky — because a package asset only
// exists in the graph BECAUSE something depends on it. That is the same worklist
// mirrored, not a better one, and "what breaks if this is deleted" is the wrong
// question for a finding whose action is `upgrade`.
func TestAssessSafety_UnassessableTypesCarryNoClass(t *testing.T) {
	now := time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	present := asset.Asset{LastSeen: now.Add(-1 * time.Hour), AccountID: "111122223333"}

	cases := []struct {
		name         string
		resourceType string
		resourceID   string
		into         map[string][]asset.Edge
	}{
		{
			// >= 1 dependent by construction: the "risky" answer.
			name: "package with dependents", resourceType: "package", resourceID: "pkg:npm/lodash@4.17.20",
			into: map[string][]asset.Edge{"depends_on": {{SrcID: "pkg:npm/app@1"}}},
		},
		{
			// The degenerate "safe" answer, from a type with no graph edges at all.
			name: "ebs_volume with no edges", resourceType: "ebs_volume", resourceID: "vol-123",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := fakeSafetyProvider{seed: present, into: tc.into}
			f := finding.Finding{ResourceID: tc.resourceID, ResourceType: tc.resourceType}

			got := assessSafety(context.Background(), p, f, present, now)

			if got.Class != "" {
				t.Fatalf("Class = %q, want empty — the model cannot answer for %s", got.Class, tc.resourceType)
			}
			if got.FixTarget == "" {
				t.Fatal("FixTarget must still be computed: withholding the verdict is not withholding the evidence")
			}
		})
	}
}

// Withholding a class must stay a short, argued list — it is a way to say "this
// model does not apply", never a way to silence a type whose edges have simply
// not been mapped.
func TestSafetyUnassessableTypesIsNarrow(t *testing.T) {
	for _, wanted := range []string{"package", "ebs_volume"} {
		if !safetyUnassessableTypes[wanted] {
			t.Fatalf("%q must be unassessable", wanted)
		}
	}
	for _, assessable := range []string{"iam_role", "gcp_service_account", "s3_bucket", "k8s_pod", "github_repo", "ec2_instance"} {
		if safetyUnassessableTypes[assessable] {
			t.Fatalf("%q has real inbound dependent edges — excluding it hides a usable signal", assessable)
		}
	}
	if len(safetyUnassessableTypes) > 4 {
		t.Fatalf("safetyUnassessableTypes has grown to %d: a growing exclusion list means the "+
			"dependents model is being worked around rather than fixed", len(safetyUnassessableTypes))
	}
}

// The IaC owner is a stronger fix location than a deploys_to shipper and must
// win: editing the console on a Terraform-declared resource is reverted by the
// next apply. Before this, nothing outside graphstore read this edge.
func TestFixTargetOf_DefinedInBeatsDeploysToAndConsole(t *testing.T) {
	p := fakeSafetyProvider{
		seed: asset.Asset{AccountID: "111122223333", Region: "eu-west-1"},
		out: map[string][]asset.Edge{
			"defined_in": {{DstID: "contoso/terraform-modules"}},
		},
		into: map[string][]asset.Edge{
			"deploys_to": {{SrcID: "org/app"}},
		},
	}
	f := finding.Finding{ResourceID: "arn:aws:iam::1:role/r"}

	got := assessSafety(context.Background(), p, f, p.seed, time.Now())

	if got.FixTarget != "repo:contoso/terraform-modules" {
		t.Fatalf("FixTarget = %q, want the declaring repo", got.FixTarget)
	}
}

// An exact declaration beats a merely-referencing one.
func TestFixTargetOf_DefinedInPrefersHighConfidence(t *testing.T) {
	p := fakeSafetyProvider{
		out: map[string][]asset.Edge{
			"defined_in": {
				{DstID: "org/loose", Properties: map[string]string{"confidence": "medium"}},
				{DstID: "org/exact", Properties: map[string]string{"confidence": "high"}},
			},
		},
	}
	f := finding.Finding{ResourceID: "r"}

	got := assessSafety(context.Background(), p, f, asset.Asset{}, time.Now())

	if got.FixTarget != "repo:org/exact" {
		t.Fatalf("FixTarget = %q, want the high-confidence declaration", got.FixTarget)
	}
}

// No IaC owner: the existing deploys_to → console order must be untouched.
func TestFixTargetOf_FallsBackWhenNoIaCOwner(t *testing.T) {
	p := fakeSafetyProvider{
		seed: asset.Asset{AccountID: "111122223333", Region: "eu-west-1"},
		into: map[string][]asset.Edge{"deploys_to": {{SrcID: "org/app"}}},
	}
	f := finding.Finding{ResourceID: "r"}

	if got := assessSafety(context.Background(), p, f, p.seed, time.Now()); got.FixTarget != "repo:org/app" {
		t.Fatalf("FixTarget = %q, want the deploys_to repo", got.FixTarget)
	}
}

// A lookup error must not swallow the weaker-but-available answers.
func TestFixTargetOf_DefinedInErrorFallsThrough(t *testing.T) {
	p := fakeSafetyProvider{
		seed:   asset.Asset{AccountID: "111122223333"},
		outErr: errors.New("ch down"),
	}
	f := finding.Finding{ResourceID: "r"}

	if got := assessSafety(context.Background(), p, f, p.seed, time.Now()); got.FixTarget != "console:111122223333" {
		t.Fatalf("FixTarget = %q, want the console fallback", got.FixTarget)
	}
}
