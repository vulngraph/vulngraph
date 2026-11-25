package okta

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// fakeOpts tunes the Okta stand-in so a test can break exactly one endpoint.
type fakeOpts struct {
	// factorsFor maps user ID → the raw factors JSON array served for them.
	factorsFor map[string]string
	// factorStatus, when non-zero, is returned for every factors call instead.
	factorStatus int
	// policyStatus, when non-zero, is returned for every policy call instead.
	policyStatus int
	// enrollRuleGroups scopes the MFA_ENROLL rule to these Okta group IDs.
	enrollRuleGroups string
	// accessRuleFactorMode is the authentication-policy rule's factorMode.
	accessRuleFactorMode string
	// memberStatus, when non-zero, is returned for every group-membership call.
	memberStatus int

	factorCalls int32
}

// oktaFake serves the endpoints the collector reads: users, groups, group
// members, per-user factors, policies and policy rules.
func oktaFake(t *testing.T, o *fakeOpts) *httptest.Server {
	t.Helper()
	if o == nil {
		o = &fakeOpts{}
	}
	if o.accessRuleFactorMode == "" {
		o.accessRuleFactorMode = "2FA"
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path
		switch {
		case strings.HasPrefix(p, "/api/v1/users/") && strings.HasSuffix(p, "/factors"):
			atomic.AddInt32(&o.factorCalls, 1)
			if o.factorStatus != 0 {
				w.WriteHeader(o.factorStatus)
				return
			}
			uid := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v1/users/"), "/factors")
			body, ok := o.factorsFor[uid]
			if !ok {
				body = `[]`
			}
			_, _ = w.Write([]byte(body))

		case strings.HasPrefix(p, "/api/v1/policies/") && strings.HasSuffix(p, "/rules"):
			if o.policyStatus != 0 {
				w.WriteHeader(o.policyStatus)
				return
			}
			id := strings.TrimSuffix(strings.TrimPrefix(p, "/api/v1/policies/"), "/rules")
			if id == "penroll" {
				_, _ = w.Write([]byte(`[{"status":"ACTIVE",
					"conditions":{"people":{"groups":{"include":[` + o.enrollRuleGroups + `]}}},
					"actions":{"enroll":{"self":"CHALLENGE"}}}]`))
				return
			}
			_, _ = w.Write([]byte(`[{"status":"ACTIVE","conditions":{"people":{"groups":{"include":["g1"]}}},
				"actions":{"appSignOn":{"access":"ALLOW","verificationMethod":{"factorMode":"` +
				o.accessRuleFactorMode + `"}}}}]`))

		case strings.HasPrefix(p, "/api/v1/policies"):
			if o.policyStatus != 0 {
				w.WriteHeader(o.policyStatus)
				return
			}
			if r.URL.Query().Get("type") == policyTypeMFAEnroll {
				_, _ = w.Write([]byte(`[{"id":"penroll","status":"ACTIVE","conditions":{}}]`))
				return
			}
			_, _ = w.Write([]byte(`[{"id":"paccess","status":"ACTIVE","conditions":{}}]`))

		case strings.HasPrefix(p, "/api/v1/groups/") && strings.HasSuffix(p, "/users"):
			if o.memberStatus != 0 {
				w.WriteHeader(o.memberStatus)
				return
			}
			_, _ = w.Write([]byte(`[{"id":"u1"},{"id":"u2"}]`))

		case strings.HasPrefix(p, "/api/v1/groups"):
			_, _ = w.Write([]byte(`[{"id":"g1","profile":{"name":"Platform Engineers"}}]`))

		case strings.HasPrefix(p, "/api/v1/users"):
			_, _ = w.Write([]byte(`[
				{"id":"u1","status":"ACTIVE","lastLogin":"2026-07-30T10:00:00.000Z",
				 "profile":{"login":"ada@example.com","email":"ada@example.com","firstName":"Ada","lastName":"L","department":"Eng","title":"SRE"},
				 "credentials":{"provider":{"type":"ACTIVE_DIRECTORY"}}},
				{"id":"u2","status":"ACTIVE","profile":{"login":"bo@example.com","email":"bo@example.com"},
				 "credentials":{"provider":{"type":"OKTA"}}}
			]`))

		default:
			http.NotFound(w, r)
		}
	}))
}

// collectFrom runs the collector against the fake. Production uses safenet
// (SSRF-blocking), which refuses the loopback address httptest binds to; same
// package, so this reaches the unexported field without loosening the real
// constructor.
func collectFrom(t *testing.T, srv *httptest.Server) (map[string]asset.Asset, []asset.Edge, bool) {
	t.Helper()
	c := &Collector{client: srv.Client()}
	res, err := c.Collect(context.Background(), map[string]string{
		"domain": srv.URL, "api_token": "t",
	})
	require.NoError(t, err)
	byID := map[string]asset.Asset{}
	for _, a := range res.Assets {
		byID[a.ID] = a
	}
	return byID, res.Edges, res.Partial
}

// TestCollect_GroupNodesExistForMembershipEdges is the regression for a dangling
// edge: the collector emitted member_of edges pointing at "okta:group:<id>" while
// nothing ever created that node, so the destination of every membership edge did
// not exist and the group name survived only as an edge property.
func TestCollect_GroupNodesExistForMembershipEdges(t *testing.T) {
	srv := oktaFake(t, nil)
	defer srv.Close()

	byID, edges, _ := collectFrom(t, srv)

	grp, ok := byID["okta:group:g1"]
	require.True(t, ok, "the group every member_of edge points at must exist as a node")
	require.Equal(t, "Platform Engineers", grp.Name, "the group name belongs on the node, not only on the edge")
	require.Equal(t, "group", grp.Metadata["identity_kind"])

	require.NotEmpty(t, edges)
	for _, e := range edges {
		require.Equal(t, "member_of", e.EdgeType)
		if e.SrcType == "human_identity" {
			_, srcOK := byID[e.SrcID]
			_, dstOK := byID[e.DstID]
			require.True(t, srcOK, "edge source %s must be a collected node", e.SrcID)
			require.True(t, dstOK, "edge destination %s must be a collected node", e.DstID)
		}
	}
}

// TestCollect_LinksToSharedSSOGroupNode pins the join that puts a person on the
// other end of the sso_group / sso_permission_set nodes the AWS collectors
// already emit. Without it those nodes attach to nobody and the whole
// "SSO-gated is a compensating control" argument has no human on either side.
func TestCollect_LinksToSharedSSOGroupNode(t *testing.T) {
	srv := oktaFake(t, nil)
	defer srv.Close()

	byID, edges, _ := collectFrom(t, srv)

	grp := byID["okta:group:g1"]
	require.Equal(t, "sso_group", grp.Type, "an Okta group is a group, not a person")
	require.Equal(t, "okta", string(grp.Provider),
		"Okta must not claim the AWS-owned sso_group:<name> row")

	var found bool
	for _, e := range edges {
		if e.SrcID == "okta:group:g1" && e.DstID == "sso_group:Platform Engineers" {
			found = true
			require.Equal(t, "sso_group", e.DstType)
			require.Equal(t, "scim_display_name", e.Properties["basis"])
		}
	}
	require.True(t, found, "the IdP group must link to the AWS Identity Center group of the same name")
}

// TestCollect_MFAFactorsObserved is the point of the connector: enrollment comes
// from GET /api/v1/users/{id}/factors, and is recorded per user.
func TestCollect_MFAFactorsObserved(t *testing.T) {
	opts := &fakeOpts{factorsFor: map[string]string{
		"u1": `[{"factorType":"push","provider":"OKTA","status":"ACTIVE"},
		        {"factorType":"webauthn","provider":"FIDO","status":"ACTIVE"},
		        {"factorType":"sms","provider":"OKTA","status":"PENDING_ACTIVATION"}]`,
		"u2": `[]`,
	}}
	srv := oktaFake(t, opts)
	defer srv.Close()

	byID, _, partial := collectFrom(t, srv)
	require.False(t, partial, "every lookup succeeded, so the sweep is complete")

	require.Equal(t, "true", byID["okta:u1"].Metadata["mfa_enabled"])
	require.Equal(t, "2", byID["okta:u1"].Metadata["mfa_active_factor_count"],
		"a PENDING_ACTIVATION factor is not yet a second factor")
	require.Equal(t, "push,webauthn", byID["okta:u1"].Metadata["mfa_factor_types"])

	require.Equal(t, "false", byID["okta:u2"].Metadata["mfa_enabled"],
		"an OBSERVED empty factor list is a real negative")
	require.Equal(t, "0", byID["okta:u2"].Metadata["mfa_active_factor_count"])
}

// TestCollect_FactorFailureLeavesMFAUnknown is the fail-closed guard. A failed
// factor lookup must leave the key ABSENT — never "false". enrich.IdentityHygiene
// scores mfa_enabled=="false" as a claim ("a human identity without MFA can
// federate into this privilege-escalation-capable role"), so a read error must
// not manufacture that claim, and it must not manufacture the reassuring one
// either.
func TestCollect_FactorFailureLeavesMFAUnknown(t *testing.T) {
	srv := oktaFake(t, &fakeOpts{factorStatus: http.StatusInternalServerError})
	defer srv.Close()

	byID, _, partial := collectFrom(t, srv)
	require.True(t, partial, "an unreadable MFA state makes the sweep partial")

	var users int
	for _, a := range byID {
		if a.Metadata["identity_kind"] != "user" {
			continue
		}
		users++
		_, present := a.Metadata["mfa_enabled"]
		require.False(t, present, "an unreadable factor state must stay absent, not read as false")
		_, cnt := a.Metadata["mfa_active_factor_count"]
		require.False(t, cnt, "no factor count may be published for an unknown state")
	}
	require.Equal(t, 2, users)
}

// TestCollect_NoFabricatedMFAClaim pins the original correctness fix: mfa_enabled
// was derived from credentials.provider.type, the PASSWORD provider, which says
// nothing about factor enrollment. The provider is still recorded, under its real
// name, answering the question it actually answers.
func TestCollect_NoFabricatedMFAClaim(t *testing.T) {
	srv := oktaFake(t, nil)
	defer srv.Close()

	byID, _, _ := collectFrom(t, srv)
	require.Equal(t, "ACTIVE_DIRECTORY", byID["okta:u1"].Metadata["credential_provider"])
	require.Equal(t, "OKTA", byID["okta:u2"].Metadata["credential_provider"])
	// The AD-sourced user has no factors in this fixture; the observed answer is
	// "false", which is what the old provider-derived guess got backwards.
	require.Equal(t, "false", byID["okta:u1"].Metadata["mfa_enabled"])
}

// TestCollect_PolicyGapPerGroup is the "gap for one group" case: an org-wide
// enrollment mandate can coexist with an authentication policy that still admits
// one group on a single factor.
func TestCollect_PolicyGapPerGroup(t *testing.T) {
	srv := oktaFake(t, &fakeOpts{accessRuleFactorMode: "1FA"})
	defer srv.Close()

	byID, _, _ := collectFrom(t, srv)
	grp := byID["okta:group:g1"]
	require.Equal(t, "true", grp.Metadata["mfa_enroll_required"],
		"the MFA_ENROLL rule is unscoped, so it applies to everyone")
	require.Equal(t, "true", grp.Metadata["single_factor_access_allowed"],
		"an ALLOW rule with factorMode 1FA is the legacy conditional-access gap")
}

// TestCollect_PolicyGapAbsentWhenScoped checks the negative direction: the same
// group with a 2FA-only sign-on rule carries an explicit false, not an omission.
func TestCollect_PolicyGapAbsentWhenScoped(t *testing.T) {
	srv := oktaFake(t, &fakeOpts{enrollRuleGroups: `"other"`})
	defer srv.Close()

	byID, _, _ := collectFrom(t, srv)
	grp := byID["okta:group:g1"]
	require.Equal(t, "false", grp.Metadata["mfa_enroll_required"],
		"the enroll rule is scoped to a different group")
	require.Equal(t, "false", grp.Metadata["single_factor_access_allowed"])
}

// TestCollect_PolicyFailureLeavesPolicyUnknown is the second fail-closed guard: a
// partial policy read must publish NO policy keys. Half a policy set answers "is
// there an MFA gap for this group?" in the reassuring direction.
func TestCollect_PolicyFailureLeavesPolicyUnknown(t *testing.T) {
	srv := oktaFake(t, &fakeOpts{policyStatus: http.StatusInternalServerError})
	defer srv.Close()

	byID, _, partial := collectFrom(t, srv)
	require.True(t, partial, "an unreadable policy set makes the sweep partial")

	grp := byID["okta:group:g1"]
	_, enroll := grp.Metadata["mfa_enroll_required"]
	require.False(t, enroll, "an unreadable enrollment policy must stay absent")
	_, single := grp.Metadata["single_factor_access_allowed"]
	require.False(t, single, "an unreadable sign-on policy must stay absent")
}

// TestCollect_MemberFailureMakesSweepPartial pins a deletion-reconciliation hazard: an
// unreadable group membership used to be swallowed by a bare `continue`, so the
// sweep reported a COMPLETE result while a whole group's memberships were
// missing — and deletion reconciliation is entitled to resolve findings on a
// complete result. Absence must be reported as absence.
func TestCollect_MemberFailureMakesSweepPartial(t *testing.T) {
	srv := oktaFake(t, &fakeOpts{memberStatus: http.StatusInternalServerError})
	defer srv.Close()

	_, edges, partial := collectFrom(t, srv)
	require.True(t, partial, "unreadable memberships must not be reported as a complete sweep")
	for _, e := range edges {
		require.NotEqual(t, "human_identity", e.SrcType,
			"no membership may be invented for a group whose members could not be read")
	}
}
