package checks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/checks/keyscan"
)

// TestRequiredKeysGeneratedIsCurrent re-derives the key and probe sets from the
// current source of this package and compares them to the committed generated file:
// a predicate edit that changes which metadata it reads fails CI until
// `go run ./cmd/checkkeys-gen` is re-run. The key names are fully derived; the
// probe values are only this package's literals, so a value the scan cannot
// resolve (an imported constant, a lookup table) must be declared in
// TableProbes. TestUnresolvedComparandsHaveTableProbes catches imported
// constants compared with ==, != or a switch case; other uses rely on the
// author.
func TestRequiredKeysGeneratedIsCurrent(t *testing.T) {
	scanned, err := keyscan.Scan(".")
	require.NoError(t, err, "scanning the checks package must succeed")
	require.NotEmpty(t, scanned)

	wantKeys := map[string][]string{}
	wantProbes := map[string][]string{}
	wantDynamic := map[string]bool{}
	wantLogic := map[string]string{}
	wantClock := map[string]bool{}
	for id, r := range scanned {
		wantLogic[id] = r.Logic
		if r.TimeDependent {
			wantClock[id] = true
		}
		if r.Dynamic {
			wantDynamic[id] = true
			wantKeys[id] = nil
			continue
		}
		wantKeys[id] = r.Keys
		if len(r.Keys) > 0 {
			wantProbes[id] = r.Probes
		}
	}
	require.Equal(t, wantKeys, derivedRequiredKeys,
		"internal/checks/required_keys_gen.go is stale — run: go run ./cmd/checkkeys-gen")
	require.Equal(t, wantProbes, derivedProbeValues,
		"internal/checks/required_keys_gen.go is stale — run: go run ./cmd/checkkeys-gen")
	require.Equal(t, wantDynamic, dynamicPredicateChecks,
		"internal/checks/required_keys_gen.go is stale — run: go run ./cmd/checkkeys-gen")
	require.Equal(t, wantLogic, derivedLogicDigests,
		"internal/checks/required_keys_gen.go is stale — run: go run ./cmd/checkkeys-gen")
	require.Equal(t, wantClock, derivedTimeDependent,
		"internal/checks/required_keys_gen.go is stale — run: go run ./cmd/checkkeys-gen")
}

// TestEveryRegisteredCheckWasScanned proves the derivation covers the catalogue.
// A check registered through a shape the scanner cannot see (a Check built at
// runtime, an ID that is not a literal) would silently get no keys and fall back
// to the old "absence means fixed" behaviour — invisibly, which is exactly how
// this class of defect survives. Registering one fails here instead.
func TestEveryRegisteredCheckWasScanned(t *testing.T) {
	for _, c := range Default().All() {
		_, ok := derivedRequiredKeys[c.ID]
		require.Truef(t, ok, "check %q is registered but was not derived — cmd/checkkeys-gen cannot see it", c.ID)
	}
}

// importedComparandValues resolves the imported values keyscan reports as
// comparands. A new one fails TestUnresolvedComparandsHaveTableProbes until it
// is added here.
var importedComparandValues = map[string]string{
	"asset.PublicAccessConfirmed": asset.PublicAccessConfirmed,
}

// TestUnresolvedComparandsHaveTableProbes: a predicate that compares metadata
// against an imported constant (public_access == asset.PublicAccessConfirmed)
// gets no probe for it from the derivation, so without TableProbes an absent
// key reads as "evaluated, clean" and the lifecycle reconcile closes the
// finding as fixed. Every such check must probe the constant's value.
func TestUnresolvedComparandsHaveTableProbes(t *testing.T) {
	scanned, err := keyscan.Scan(".")
	require.NoError(t, err)
	r := Default()
	for id, res := range scanned {
		c, ok := r.ByID(id)
		if !ok || len(res.Keys) == 0 || res.Dynamic {
			continue
		}
		for _, sel := range res.Unresolved {
			v, known := importedComparandValues[sel]
			require.Truef(t, known, "check %q compares against %s: add it to importedComparandValues", id, sel)
			require.Containsf(t, c.ProbeValues, v,
				"check %q compares against %s but does not probe %q: add it to TableProbes", id, sel, v)
		}
	}
}

// TestPublicAccessChecksWithholdOnUnreadPolicy pins the consequence: a
// collector that could not read the resource policy leaves public_access out,
// and that must never let a public-exposure finding close as fixed.
func TestPublicAccessChecksWithholdOnUnreadPolicy(t *testing.T) {
	r := Default()
	for _, id := range []string{
		"aws-lambda-public-access", "aws-kms-key-policy-public", "aws-ecr-repository-policy-public",
		"aws-secretsmanager-resource-policy-public", "aws-eventbridge-bus-policy-public",
		"gcp-cloudrun-unauthenticated", "aws-sqs-queue-policy-public",
	} {
		c, ok := r.ByID(id)
		require.Truef(t, ok, "check %q must be registered", id)
		require.Falsef(t, c.Evaluable(asset.Asset{Type: c.AssetType, Provider: c.Provider, Metadata: map[string]string{}}),
			"%s: an absent public_access is unobserved, not private", id)
		require.Truef(t, c.Evaluable(asset.Asset{Type: c.AssetType, Provider: c.Provider, Metadata: map[string]string{"public_access": "none"}}),
			"%s: an observed non-public policy is a real answer", id)
	}
}

// TestRequiredKeysCoverKnownRegressions pins the four checks that can close
// findings as REMEDIATED against evidence that has merely vanished. If a
// predicate is edited so its evidence key stops being required, this is the
// test that says so.
func TestRequiredKeysCoverKnownRegressions(t *testing.T) {
	want := map[string]string{
		"github-no-branch-protection":    "branch_protection",
		"aws-s3-no-versioning":           "versioning",
		"aws-s3-access-logging-disabled": "logging",
		"gcp-sa-unused":                  "sa_last_auth_days",
	}
	r := Default()
	for id, key := range want {
		c, ok := r.ByID(id)
		require.Truef(t, ok, "check %q must be registered", id)
		require.Containsf(t, c.RequiredKeys, key, "check %q must require its evidence key %q", id, key)
	}
}

// TestEvaluableSeparatesEvidenceFromSuppressor is the heart of the design.
//
// A syntactic "every key the predicate reads must be present" rule is wrong in
// both directions, and this table holds one example of each: the three k8s
// pod checks read ns_psa_enforce only to EXEMPT themselves, and that key is
// absent on most pods — requiring it would freeze every pod
// finding open forever. github-no-branch-protection reads `archived` the same way, while
// its actual evidence key is the one that vanished. So Evaluable asks the
// semantic question instead: could any value of the missing keys have made this
// predicate fire?
func TestEvaluableSeparatesEvidenceFromSuppressor(t *testing.T) {
	r := Default()
	tests := []struct {
		name     string
		checkID  string
		metadata map[string]string
		want     bool
		why      string
	}{
		{
			name: "branch protection absent — the evidence itself is missing", checkID: "github-no-branch-protection",
			metadata: map[string]string{"archived": "false"}, want: false,
			why: "branch_protection can be absent on any repo; closing findings as fixed on this silence would be wrong",
		},
		{
			name: "branch protection observed as enabled", checkID: "github-no-branch-protection",
			metadata: map[string]string{"branch_protection": "enabled", "archived": "false"}, want: true,
			why: "the collector observed the setting — silence here is a real fix",
		},
		{
			name: "archived absent but branch protection observed", checkID: "github-no-branch-protection",
			metadata: map[string]string{"branch_protection": "enabled"}, want: true,
			why: "archived is a suppressor: no value of it can turn an enabled protection into a violation",
		},
		{
			name: "cloudfront web ACL key absent", checkID: "aws-cloudfront-no-waf",
			metadata: map[string]string{}, want: false,
			why: "observedNone fires on a PRESENT empty value, so an absent key is unobserved, not protected",
		},
		{
			name: "cloudfront web ACL observed", checkID: "aws-cloudfront-no-waf",
			metadata: map[string]string{"web_acl_id": "arn:aws:wafv2:us-east-1:1:global/webacl/edge/1"}, want: true,
		},
		{
			name: "gcp sa last-auth absent (Policy Analyzer unavailable)", checkID: "gcp-sa-unused",
			metadata: map[string]string{"disabled": "false", "roles": "roles/editor"}, want: false,
			why: "the -1 'never authenticated' sentinel would have fired; absence is not proof of activity",
		},
		{
			name: "gcp sa last-auth observed as recent", checkID: "gcp-sa-unused",
			metadata: map[string]string{"disabled": "false", "roles": "roles/editor", "roles_complete": "true", "sa_last_auth_days": "3"}, want: true,
		},
		{
			name: "k8s pod: ns_psa_enforce absent, pod not privileged", checkID: "k8s-privileged-container",
			metadata: map[string]string{"privileged": "false", "namespace": "billing"}, want: true,
			why: "ns_psa_enforce only ever suppresses; absent on most pods, so a presence rule would freeze them all",
		},
		{
			name: "k8s pod: host_network absent", checkID: "k8s-host-network-pod",
			metadata: map[string]string{"namespace": "billing", "ns_psa_enforce": "baseline"}, want: false,
			why: "host_network is the evidence, not the exemption",
		},
		{
			name: "aws iam overprivileged: Access Advisor data absent on an admin role", checkID: "aws-iam-overprivileged-role",
			metadata: map[string]string{"admin": "true"}, want: false,
			why: "the whole predicate is the Access Advisor comparison; without it nothing was measured",
		},
		{
			name: "aws iam overprivileged: not an admin role at all", checkID: "aws-iam-overprivileged-role",
			// The last-used keys are the ones a successful GetRole always writes;
			// they are read by the dormant-admin step-aside, and leaving them out
			// as well would only measure the probe cap, not the admin gate. The
			// sync job stamps a complete standard tier on this fully observed identity.
			metadata: map[string]string{"admin": "false", "last_used_observed": "true", "last_used_days": "3", "path": "/", "created_days": "400", "privilege_tier": "standard", "organization_policy_complete": "true"}, want: true,
			why: "the admin gate short-circuits, so no value of the aa_ keys matters",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, ok := r.ByID(tt.checkID)
			require.Truef(t, ok, "check %q must be registered", tt.checkID)
			got := c.Evaluable(asset.Asset{ID: "res-1", Type: c.AssetType, Provider: c.Provider, Metadata: tt.metadata})
			require.Equalf(t, tt.want, got, "Evaluable = %v, want %v — %s", got, tt.want, tt.why)
		})
	}
}

// Evaluable must not mutate the asset it probes: the same asset is handed to
// every other check in the sweep, and a leaked probe value would make one
// check's uncertainty another check's evidence.
func TestEvaluableDoesNotMutateTheAsset(t *testing.T) {
	c, ok := Default().ByID("github-no-branch-protection")
	require.True(t, ok)
	md := map[string]string{"archived": "false"}
	a := asset.Asset{ID: "org/repo", Type: "github_repo", Provider: asset.ProviderGitHub, Metadata: md}
	require.False(t, c.Evaluable(a))
	require.Equal(t, map[string]string{"archived": "false"}, md, "probing must leave the caller's metadata untouched")
}

// A check whose predicate reads no metadata is always evaluable — it decides on
// structural asset fields the collector always supplies.
func TestEvaluableTrueForStructuralPredicates(t *testing.T) {
	c, ok := Default().ByID("aws-ec2-public-ip")
	require.True(t, ok)
	require.Empty(t, c.RequiredKeys)
	require.True(t, c.Evaluable(asset.Asset{ID: "i-1", Type: "ec2_instance", Provider: asset.ProviderAWS}))
}

// Evaluability is the metric's source: applicable counts what the check grades,
// evaluable counts what it can actually see.
func TestRegistryEvaluability(t *testing.T) {
	r := NewRegistry()
	r.Register(awsS3AccessLoggingDisabled)
	stats := r.Evaluability([]asset.Asset{
		{ID: "b1", Type: "s3_bucket", Provider: asset.ProviderAWS, Metadata: map[string]string{"logging": "enabled"}},
		{ID: "b2", Type: "s3_bucket", Provider: asset.ProviderAWS, Metadata: map[string]string{}},
		{ID: "i1", Type: "ec2_instance", Provider: asset.ProviderAWS},
	})
	require.Len(t, stats, 1)
	require.Equal(t, "aws-s3-access-logging-disabled", stats[0].CheckID)
	require.Equal(t, 2, stats[0].Applicable, "only s3 buckets are graded by an s3 check")
	require.Equal(t, 1, stats[0].Evaluable)
	require.InDelta(t, 0.5, stats[0].Ratio(), 1e-9)

	// Nothing applicable is idle, not blind: reporting 0 would bury the checks
	// that really are blind under noise from every check a connector doesn't hold.
	empty := Evaluability{CheckID: "x"}
	require.Equal(t, 1.0, empty.Ratio())
}
