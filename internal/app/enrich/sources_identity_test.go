package enrich

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type fakeAssetGetter struct{ a asset.Asset }

func (f fakeAssetGetter) Get(context.Context, string) (asset.Asset, error) { return f.a, nil }

type fakeEdges struct {
	into     []asset.Edge
	humans   []asset.Asset
	intoErr  error
	byIDsErr error
}

func (f fakeEdges) EdgesInto(context.Context, string, string) ([]asset.Edge, error) {
	return f.into, f.intoErr
}
func (f fakeEdges) ByIDs(context.Context, []string) ([]asset.Asset, error) {
	return f.humans, f.byIDsErr
}

type fakeSSO struct {
	info SSOInfo
	ok   bool
}

func (f fakeSSO) ResolveRole(context.Context, asset.Asset) (SSOInfo, bool) { return f.info, f.ok }

func roleFinding(md map[string]string, privesc bool) (finding.Finding, fakeAssetGetter) {
	f := finding.Finding{ResourceID: "role:x", ResourceType: "iam_role"}
	if privesc {
		f.CheckID = "iam-privesc-01"
	}
	return f, fakeAssetGetter{a: asset.Asset{Metadata: md}}
}

func TestIdentityHygiene_Role(t *testing.T) {
	ctx := context.Background()

	t.Run("public_trust elevates with floor", func(t *testing.T) {
		f, g := roleFinding(map[string]string{"public_trust": "true"}, true)
		factor, ok, _ := IdentityHygiene{Assets: g}.Evaluate(ctx, f)
		if !ok || factor.Points <= 0 || factor.Floor != ThresholdPipeline {
			t.Fatalf("want elevate+floor, got %+v ok=%v", factor, ok)
		}
	})

	t.Run("uncorroborated SAML trust on privesc does NOT suppress", func(t *testing.T) {
		// No SSO resolver — the platform cannot observe the IdP at all (no
		// human_identity assets, no IdP connector). An unobservable control is
		// absence of evidence and must never demote.
		f, g := roleFinding(map[string]string{"federated_trust": "saml"}, true)
		factor, ok, _ := IdentityHygiene{Assets: g}.Evaluate(ctx, f)
		if ok && factor.Suppress {
			t.Fatalf("uncorroborated SAML must not suppress, got %+v", factor)
		}
	})

	t.Run("machine OIDC trust on privesc does NOT suppress", func(t *testing.T) {
		// GitHub Actions / EKS IRSA federation involves no human and no MFA.
		f, g := roleFinding(map[string]string{"federated_trust": "oidc"}, true)
		sso := fakeSSO{info: SSOInfo{PermissionSet: "ReadOnly"}, ok: true}
		factor, ok, _ := IdentityHygiene{Assets: g, SSO: sso}.Evaluate(ctx, f)
		if ok && factor.Suppress {
			t.Fatalf("machine OIDC must not suppress, got %+v", factor)
		}
	})

	t.Run("SSO admin permission set elevates, not suppressed", func(t *testing.T) {
		// An SSO role with SAML federated_trust that WOULD normally be suppressed,
		// but whose permission set grants admin, must elevate instead.
		f, g := roleFinding(map[string]string{"federated_trust": "saml"}, true)
		sso := fakeSSO{info: SSOInfo{PermissionSet: "AdministratorAccess", GrantsAdmin: true}, ok: true}
		factor, ok, _ := IdentityHygiene{Assets: g, SSO: sso}.Evaluate(ctx, f)
		if !ok || factor.Suppress || factor.Points <= 0 {
			t.Fatalf("SSO admin grant must elevate, not suppress, got %+v ok=%v", factor, ok)
		}
	})

	t.Run("SSO non-admin permission set still suppresses via SAML", func(t *testing.T) {
		f, g := roleFinding(map[string]string{"federated_trust": "saml"}, true)
		sso := fakeSSO{info: SSOInfo{PermissionSet: "ReadOnly", GrantsAdmin: false}, ok: true}
		factor, ok, _ := IdentityHygiene{Assets: g, SSO: sso}.Evaluate(ctx, f)
		if !ok || !factor.Suppress {
			t.Fatalf("a non-admin SSO role stays suppressed via SAML trust, got %+v ok=%v", factor, ok)
		}
	})

	t.Run("mfa-required on privesc suppresses", func(t *testing.T) {
		f, g := roleFinding(map[string]string{"mfa_required_to_assume": "true"}, true)
		factor, ok, _ := IdentityHygiene{Assets: g}.Evaluate(ctx, f)
		if !ok || !factor.Suppress {
			t.Fatalf("want suppress, got %+v ok=%v", factor, ok)
		}
	})

	t.Run("service-only trust entry does NOT suppress", func(t *testing.T) {
		// "Only an AWS service can assume this role" is the definition of a workload
		// role, not a gate on it: it is the credential an attacker gets for free
		// after SSRF/RCE on the workload. This single disjunct used to suppress
		// most "controlled" iam_role privesc findings, including critical/high ones.
		f, g := roleFinding(map[string]string{"trust_entry": "service"}, true)
		factor, ok, _ := IdentityHygiene{Assets: g}.Evaluate(ctx, f)
		if ok && factor.Suppress {
			t.Fatalf("service-only trust must not suppress, got %+v", factor)
		}
	})

	t.Run("admin service role right-sizes instead of being suppressed", func(t *testing.T) {
		// The path those findings now take: no control, so scoring falls through to
		// adminRightSizing rather than being pinned into monitor.
		f, g := roleFinding(map[string]string{
			"trust_entry": "service", "admin": "true", "last_used_days": "3",
		}, true)
		factor, ok, _ := IdentityHygiene{Assets: g}.Evaluate(ctx, f)
		if !ok || factor.Suppress || factor.Points <= 0 {
			t.Fatalf("an actively-used admin workload role must score, not suppress, got %+v ok=%v", factor, ok)
		}
	})

	t.Run("cross-account trust entry does not suppress", func(t *testing.T) {
		f, g := roleFinding(map[string]string{"trust_entry": "cross_account"}, true)
		factor, ok, _ := IdentityHygiene{Assets: g}.Evaluate(ctx, f)
		if ok && factor.Suppress {
			t.Fatalf("cross_account is a weaker gate — must not fully suppress, got %+v", factor)
		}
	})

	t.Run("KEV never suppressed by controls", func(t *testing.T) {
		f, g := roleFinding(map[string]string{"mfa_required_to_assume": "true"}, true)
		f.KnownExploited = true
		factor, ok, _ := IdentityHygiene{Assets: g}.Evaluate(ctx, f)
		if ok && factor.Suppress {
			t.Fatalf("KEV must not be suppressed")
		}
	})

	t.Run("dormant admin demotes", func(t *testing.T) {
		f, g := roleFinding(map[string]string{"admin": "true", "last_used_days": "200"}, false)
		factor, ok, _ := IdentityHygiene{Assets: g}.Evaluate(ctx, f)
		if !ok || factor.Points >= 0 {
			t.Fatalf("want negative, got %+v ok=%v", factor, ok)
		}
	})

	t.Run("unknown metadata → no signal (never demote on absence)", func(t *testing.T) {
		f, g := roleFinding(map[string]string{}, true)
		_, ok, _ := IdentityHygiene{Assets: g}.Evaluate(ctx, f)
		if ok {
			t.Fatal("empty metadata must contribute nothing")
		}
	})

	t.Run("human without MFA federated in elevates", func(t *testing.T) {
		f, g := roleFinding(map[string]string{}, true)
		edges := fakeEdges{
			into:   []asset.Edge{{SrcID: "human:a", SrcType: "human_identity"}},
			humans: []asset.Asset{{ID: "human:a", Metadata: map[string]string{"mfa_enabled": "false"}}},
		}
		factor, ok, _ := IdentityHygiene{Assets: g, Edges: edges}.Evaluate(ctx, f)
		if !ok || factor.Points <= 0 {
			t.Fatalf("want elevate, got %+v ok=%v", factor, ok)
		}
	})
}

func TestIdentityHygiene_User(t *testing.T) {
	ctx := context.Background()
	mk := func(md map[string]string) (finding.Finding, fakeAssetGetter) {
		return finding.Finding{ResourceID: "user:x", ResourceType: "iam_user"}, fakeAssetGetter{a: asset.Asset{Metadata: md}}
	}
	t.Run("console user without MFA elevates", func(t *testing.T) {
		f, g := mk(map[string]string{"console_access": "true", "mfa_enabled": "false"})
		factor, ok, _ := IdentityHygiene{Assets: g}.Evaluate(ctx, f)
		if !ok || factor.Points <= 0 {
			t.Fatalf("want elevate, got %+v ok=%v", factor, ok)
		}
	})
	t.Run("console user with MFA is measured and clean", func(t *testing.T) {
		f, g := mk(map[string]string{"console_access": "true", "mfa_enabled": "true"})
		_, ok, err := IdentityHygiene{Assets: g}.Evaluate(ctx, f)
		require.NoError(t, err)
		require.False(t, ok)
	})
	t.Run("root without a password is measured and clean", func(t *testing.T) {
		f, g := mk(map[string]string{"root": "true", "console_access": "false", "mfa_enabled": "false"})
		_, ok, err := IdentityHygiene{Assets: g}.Evaluate(ctx, f)
		require.NoError(t, err)
		require.False(t, ok)
	})
	// An unread credential report leaves the root's console_access absent:
	// the no-MFA penalty is unknown, not cleared, and the rest still scores.
	t.Run("unread console access is unmeasured", func(t *testing.T) {
		f, g := mk(map[string]string{"root": "true", "mfa_enabled": "false", "active_key_count": "2"})
		factor, ok, err := IdentityHygiene{Assets: g}.Evaluate(ctx, f)
		require.Error(t, err)
		require.True(t, ok)
		require.Equal(t, 4, factor.Points)
		require.NotContains(t, factor.Detail, "without MFA")
	})
	t.Run("inactive principal demotes", func(t *testing.T) {
		f, g := mk(map[string]string{"inactive": "true"})
		factor, ok, _ := IdentityHygiene{Assets: g}.Evaluate(ctx, f)
		if !ok || factor.Points >= 0 {
			t.Fatalf("want negative, got %+v ok=%v", factor, ok)
		}
	})
	t.Run("non-iam resource ignored", func(t *testing.T) {
		f := finding.Finding{ResourceID: "s3:x", ResourceType: "s3_bucket"}
		_, ok, _ := IdentityHygiene{Assets: fakeAssetGetter{}}.Evaluate(ctx, f)
		if ok {
			t.Fatal("non-iam must be ignored")
		}
	})
}

// An ABSENT last_used_days means the collector's GetRole call failed, so nothing
// was observed about this role's activity. Unknown must move the score in neither
// direction — no dormancy demote, no active-use promote — the same rule the rest
// of this source states: absence of evidence never scores.
func TestAdminRightSizing_AbsentLastUsedIsUnknown(t *testing.T) {
	pts, notes := adminRightSizing(map[string]string{"admin": "true"})
	require.Zero(t, pts, "an unobserved role is neither dormant nor active")
	require.Empty(t, notes)
}

// "9999" is the collector's observed-never-used sentinel, not a day count.
// Rendering it verbatim produced "admin role unused for 9999d" — a fabricated 27
// years that reads as real evidence.
func TestIdentityHygiene_NeverUsedSentinelNotRenderedAsDays(t *testing.T) {
	meta := map[string]string{"admin": "true", "last_used_days": neverUsedSentinel}
	_, notes := adminRightSizing(meta)
	require.NotEmpty(t, notes)
	for _, n := range notes {
		require.NotContains(t, n, "9999", "the sentinel must never surface as a day count")
	}
	require.Contains(t, notes[0], "no recorded use")

	// A real measurement still renders as days.
	real := map[string]string{"admin": "true", "last_used_days": "120"}
	_, realNotes := adminRightSizing(real)
	require.Contains(t, realNotes[0], "120d")
}

// TestClassifyRoleTrust is the direct table for the ONE definition of a
// compensating control on an IAM role, shared by the IdentityHygiene score source
// and mustfix.go's isControlled. The two used to carry separate copies of the same
// disjunct, so a wrong answer had to be fixed twice or they would disagree about
// the same role — the score band said one thing and must_fix_class another.
func TestClassifyRoleTrust(t *testing.T) {
	ctx := context.Background()
	nonAdmin := fakeSSO{info: SSOInfo{PermissionSet: "ReadOnly", GrantsAdmin: false}, ok: true}
	admin := fakeSSO{info: SSOInfo{PermissionSet: "AdministratorAccess", GrantsAdmin: true}, ok: true}
	unresolved := fakeSSO{ok: false}

	tests := []struct {
		name    string
		md      map[string]string
		sso     SSOResolver
		want    roleTrustControl
		demotes bool
	}{
		// ── the only observed controls ────────────────────────────────────────
		{"MFA required by the trust policy", map[string]string{"mfa_required_to_assume": "true"}, nil, roleTrustMFA, true},
		{"SAML corroborated by a collected non-admin permission set", map[string]string{"federated_trust": "saml"}, nonAdmin, roleTrustSSONonAdmin, true},

		// ── an admin SSO grant is an anti-control and outranks everything ─────
		{"SSO permission set grants admin", map[string]string{"federated_trust": "saml"}, admin, roleTrustSSOAdminGrant, false},
		{"admin SSO grant outranks an MFA-required trust policy", map[string]string{"mfa_required_to_assume": "true"}, admin, roleTrustSSOAdminGrant, false},

		// ── removed grounds: absence of evidence never demotes ────────────────
		{"service-only trust is a workload role, not a gate", map[string]string{"trust_entry": "service"}, nil, roleTrustNone, false},
		{"service-only trust on an admin role is still not a gate", map[string]string{"trust_entry": "service", "admin": "true"}, nonAdmin, roleTrustNone, false},
		{"machine OIDC (GitHub Actions / EKS IRSA) is not MFA", map[string]string{"federated_trust": "oidc"}, nil, roleTrustNone, false},
		{"machine OIDC is not rescued by an SSO resolution", map[string]string{"federated_trust": "oidc"}, nonAdmin, roleTrustNone, false},
		{"SAML with no resolver — the IdP is unobservable", map[string]string{"federated_trust": "saml"}, nil, roleTrustNone, false},
		{"SAML whose permission set is absent from the graph", map[string]string{"federated_trust": "saml"}, unresolved, roleTrustNone, false},
		{"mixed trust entry", map[string]string{"trust_entry": "mixed"}, nil, roleTrustNone, false},
		{"cross-account trust entry", map[string]string{"trust_entry": "cross_account"}, nil, roleTrustNone, false},
		{"no metadata at all", map[string]string{}, nil, roleTrustNone, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, detail := classifyRoleTrust(ctx, asset.Asset{Type: "iam_role", Metadata: tc.md}, tc.sso)
			require.Equal(t, tc.want, got)
			require.Equal(t, tc.demotes, got.demotes())
			if got == roleTrustNone {
				require.Empty(t, detail, "no control means no evidence string to render")
			} else {
				require.NotEmpty(t, detail, "a control must render the evidence it was observed from")
			}
		})
	}
}

// TestClassifyRoleTrustNeverDemotesOnAbsence is the principle stated as a
// property: no combination of trust metadata alone — with nothing positively
// observed — may ever demote. This is the rule the iam_user branch of isControlled
// always stated ("Absence of evidence never demotes") and the iam_role branch
// violated.
func TestClassifyRoleTrustNeverDemotesOnAbsence(t *testing.T) {
	ctx := context.Background()
	for _, entry := range []string{"service", "federated", "mixed", "cross_account", "same_account", "public", ""} {
		for _, fed := range []string{"oidc", "saml", ""} {
			md := map[string]string{"trust_entry": entry, "federated_trust": fed}
			got, _ := classifyRoleTrust(ctx, asset.Asset{Type: "iam_role", Metadata: md}, nil)
			require.Falsef(t, got.demotes(),
				"trust_entry=%q federated_trust=%q demoted with no observed control (no MFA condition, no collected SSO permission set)", entry, fed)
		}
	}
}

// A failed read of the federated humans is not "no human lacks MFA": the
// source reports an error so the pipeline records it unmeasured, instead of
// silently scoring the role without the federation factor.
func TestIdentityHygiene_MFAGapReadErrorIsUnmeasured(t *testing.T) {
	ctx := context.Background()
	f, g := roleFinding(map[string]string{}, true)
	human := []asset.Edge{{SrcType: "human_identity", SrcID: "h1"}}
	boom := errors.New("ch timeout")

	for name, edges := range map[string]fakeEdges{
		"edges read fails":  {intoErr: boom},
		"humans read fails": {into: human, byIDsErr: boom},
	} {
		t.Run(name, func(t *testing.T) {
			_, ok, err := IdentityHygiene{Assets: g, Edges: edges}.Evaluate(ctx, f)
			require.ErrorIs(t, err, boom)
			require.False(t, ok)
		})
	}

	factor, ok, err := IdentityHygiene{Assets: g, Edges: fakeEdges{
		into: human, humans: []asset.Asset{{Metadata: map[string]string{"mfa_enabled": "false"}}},
	}}.Evaluate(ctx, f)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 10, factor.Points)
}
