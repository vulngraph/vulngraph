package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssoadmintypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/aws/smithy-go"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// capabilitySSOAdmin is the collect.Result.MarkCapabilityProven /
// connector_proven_capabilities key for "this connector's credentials have
// successfully called ListPermissionSets at least once" — see collectSSO's
// ownership check for why that proof, not account ownership alone, is what
// catches a delegated-admin regression. Kept as a plain string (matching
// connector.CapabilitySSOAdmin) rather than importing internal/app/connector:
// collect and its provider packages stay decoupled from app domains;
// internal/jobs/sync.go is the seam that bridges the two.
const capabilitySSOAdmin = "sso_admin"

// hasProvenCapability reports whether capability was proven for this
// connector in a PRIOR sweep, via the comma-separated set
// internal/jobs/sync.go writes into cfg[collect.ProvenCapabilitiesConfigKey].
// Consulting cfg rather than this sweep's own evidence matters: the proof
// must survive sweeps where this call is never reached at all.
func hasProvenCapability(cfg map[string]string, capability string) bool {
	for c := range strings.SplitSeq(cfg[collect.ProvenCapabilitiesConfigKey], ",") {
		if strings.TrimSpace(c) == capability {
			return true
		}
	}
	return false
}

// ssoAPI is the slice of AWS IAM Identity Center (SSO) the collector needs.
type ssoAPI interface {
	ListInstances(context.Context, *ssoadmin.ListInstancesInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error)
	ListPermissionSets(context.Context, *ssoadmin.ListPermissionSetsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListPermissionSetsOutput, error)
	DescribePermissionSet(context.Context, *ssoadmin.DescribePermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.DescribePermissionSetOutput, error)
	ListManagedPoliciesInPermissionSet(context.Context, *ssoadmin.ListManagedPoliciesInPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListManagedPoliciesInPermissionSetOutput, error)
	GetInlinePolicyForPermissionSet(context.Context, *ssoadmin.GetInlinePolicyForPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.GetInlinePolicyForPermissionSetOutput, error)
	ListAccountsForProvisionedPermissionSet(context.Context, *ssoadmin.ListAccountsForProvisionedPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountsForProvisionedPermissionSetOutput, error)
	ListAccountAssignments(context.Context, *ssoadmin.ListAccountAssignmentsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountAssignmentsOutput, error)
}

// identityStoreAPI resolves Identity Center principal GUIDs to human names and
// expands the groups those principals belong to.
type identityStoreAPI interface {
	DescribeUser(context.Context, *identitystore.DescribeUserInput, ...func(*identitystore.Options)) (*identitystore.DescribeUserOutput, error)
	DescribeGroup(context.Context, *identitystore.DescribeGroupInput, ...func(*identitystore.Options)) (*identitystore.DescribeGroupOutput, error)
	ListGroupMemberships(context.Context, *identitystore.ListGroupMembershipsInput, ...func(*identitystore.Options)) (*identitystore.ListGroupMembershipsOutput, error)
}

// collectIdentityCenter gathers AWS IAM Identity Center (SSO) permission sets,
// their attached policies, and their account assignments — the human-access
// layer that the trust-policy CanAssume graph is blind to (engineers reach
// cloud roles via SSO permission sets, not sts:AssumeRole trust chains).
//
// ListInstances succeeds for any member account, not just the admin one — the
// real admin/member boundary is the next call, ListPermissionSets, which only
// the management/delegated-admin account may call. A member account's denial
// there is a stable IAM fact, so collectSSO treats it as a clean no-op rather
// than an error; that carve-out is what makes it safe to run this collector on
// every AWS connector. The no-op is gated on the account OWNING the instance
// (InstanceMetadata.OwnerAccountId), not on the error shape alone: a denial on
// the owning account is a regression and must flip the connector Partial.
//
// Identity Center instances are region-homed, so this sweeps a candidate set
// of regions (identityCenterRegions) and dedupes the permission sets it finds
// by ARN. The bool return reports whether ANY probed region proved the
// sso_admin capability this sweep; the caller feeds it into
// collect.Result.MarkCapabilityProven, and internal/jobs/sync.go persists it
// so a future denial can be judged a regression even where ownership alone
// would read as a confirmed non-owner (the delegated-admin gap; see collectSSO).
func collectIdentityCenter(ctx context.Context, cfg map[string]string, accountID string, now time.Time) ([]asset.Asset, []asset.Edge, bool, error) {
	alreadyProven := hasProvenCapability(cfg, capabilitySSOAdmin)
	seen := map[string]bool{}
	seenEdge := map[string]bool{}
	var out []asset.Asset
	var outEdges []asset.Edge
	var firstErr error
	var regressionErr error
	var proven bool
	for _, region := range identityCenterRegions(cfg) {
		awsCfg, err := baseConfig(ctx, withRegion(cfg, region))
		if err != nil {
			return nil, nil, proven, fmt.Errorf("collectIdentityCenter: %w", err)
		}
		assets, edges, regionProven, err := collectSSO(ctx, ssoadmin.NewFromConfig(awsCfg), identitystore.NewFromConfig(awsCfg), accountID, now, alreadyProven)
		if regionProven {
			proven = true
		}
		if err != nil {
			if errors.Is(err, errSSOAdminRegression) && regressionErr == nil {
				regressionErr = err
			}
			if firstErr == nil {
				firstErr = err
			}
			continue // a region the role can't reach must not sink the others
		}
		for _, a := range assets {
			if !seen[a.ID] {
				seen[a.ID] = true
				out = append(out, a)
			}
		}
		// Deduped like the assets: the same instance can answer in more than one
		// probed region, and a group node/edge repeats across permission sets.
		for _, e := range edges {
			k := e.SrcID + "|" + e.EdgeType + "|" + e.DstID
			if !seenEdge[k] {
				seenEdge[k] = true
				outEdges = append(outEdges, e)
			}
		}
	}
	// A regression is surfaced unconditionally, before the len(out) == 0 rule
	// below, so it can't be masked by another region succeeding. Returning no
	// assets here is deliberate — Partial is what stops the stored
	// sso_permission_set / sso_group assets being pruned while access is broken.
	if regressionErr != nil {
		return nil, nil, proven, fmt.Errorf("collectIdentityCenter: %w", regressionErr)
	}
	// Otherwise surface an error only when nothing was collected, so a genuine
	// permission/region failure still registers as a best-effort skip.
	if len(out) == 0 && firstErr != nil {
		return nil, nil, proven, fmt.Errorf("collectIdentityCenter: %w", firstErr)
	}
	return out, outEdges, proven, nil
}

// errSSOAdminRegression marks a ListPermissionSets denial on an account that
// has already proven sso_admin in an earlier sweep — the delegated-admin
// regression this file exists to catch. It must be distinguishable from an ordinary
// region-unreachable error because collectIdentityCenter's best-effort
// aggregation would otherwise drop it whenever another region succeeded,
// letting the regression disappear silently instead of flagging Partial.
var errSSOAdminRegression = errors.New("collect/aws: ListPermissionSets denied on a proven sso_admin account")

// identityCenterRegions is the candidate set to probe for Identity Center
// instances: the connector's own region plus the common SSO home regions, or an
// explicit "identity_center_regions" override. Deduped, order-stable. A probe
// in a region with no instance is a cheap empty ListInstances, so the set stays
// small rather than scanning every enabled region on all connectors.
func identityCenterRegions(cfg map[string]string) []string {
	if v := strings.TrimSpace(cfg["identity_center_regions"]); v != "" {
		var out []string
		for r := range strings.SplitSeq(v, ",") {
			if r = strings.TrimSpace(r); r != "" {
				out = append(out, r)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range []string{cfg["region"], "us-east-1", "eu-west-1", "eu-central-1"} {
		if r != "" && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// collectSSO gathers Identity Center permission sets and their assignments
// for one instance. alreadyProven says whether this connector proved the
// sso_admin capability (a successful ListPermissionSets call) in a PRIOR
// sweep — that closes the delegated-admin gap in the ownership check below,
// since OwnerAccountId never changes to reflect delegation and so a delegated
// admin reads as a confirmed non-owner forever.
//
// The bool return reports whether ListPermissionSets succeeded at least once
// THIS sweep (independent of alreadyProven, which is about prior sweeps).
func collectSSO(ctx context.Context, sso ssoAPI, ids identityStoreAPI, accountID string, now time.Time, alreadyProven bool) ([]asset.Asset, []asset.Edge, bool, error) {
	// Deliberately NO no-op carve-out here, unlike
	// ListPermissionSets below. Two reasons, either one sufficient on its own:
	//   1. ListInstances already succeeds for a member account
	//      (see the doc comment above), so a member account is not denied at
	//      this call — there is no known-benign denial to carve out.
	//   2. A denial here happens BEFORE any InstanceMetadata is returned, so
	//      there is no OwnerAccountId to check — the ownership signal step 1
	//      relies on to tell a benign member denial from an admin-account
	//      regression does not exist yet. No-opping blindly here would be the
	//      exact unmeasured-guess mistake step 1 avoids, just moved one
	//      call earlier. Failing loud (Partial) is the
	//      safe direction: a stuck-Partial connector is visible and
	//      recoverable, a wrongly-no-opped admin account is a silent deletion.
	inst, err := sso.ListInstances(ctx, &ssoadmin.ListInstancesInput{})
	if err != nil {
		return nil, nil, false, fmt.Errorf("collectSSO: list instances: %w", err)
	}
	if inst == nil || len(inst.Instances) == 0 {
		return nil, nil, false, nil // no Identity Center instance in this account/region — clean no-op
	}

	var assets []asset.Asset
	var edges []asset.Edge
	var proven bool
	for _, in := range inst.Instances {
		instanceARN := awssdk.ToString(in.InstanceArn)
		storeID := awssdk.ToString(in.IdentityStoreId)
		if instanceARN == "" {
			continue
		}
		// Ownership decides whether an AccessDeniedException below is expected
		// or a regression: InstanceMetadata.OwnerAccountId names the account
		// that owns this Identity Center instance (the management account, for
		// an organization instance).
		//
		// KNOWN GAP — delegated administrators. OwnerAccountId stays the
		// management account even when SSO administration is delegated to
		// another account, so a delegated admin reads here as !isOwner and its
		// denial is treated as a member no-op — swallowing a real regression on
		// the one account this check exists to protect. Closing it needs a
		// signal ListInstances doesn't carry (organizations:
		// ListDelegatedAdministrators, or a configured admin-account list); not
		// done here. Do NOT fail closed on every !isOwner denial instead — that
		// would break every member account's sweep.
		//
		// Three-way rule:
		//   - ownerKnown && isOwner: this account IS the admin — a denial here
		//     is a real regression, returned as an error (Partial).
		//   - ownerKnown && !isOwner: confirmed member — the denial is a
		//     permanent IAM fact, so it's a clean no-op.
		//   - !ownerKnown: cannot tell the two apart, so it fails CLOSED to the
		//     error path rather than defaulting to the (more common) no-op.
		//
		// alreadyProven — persisted proof this account succeeded at this exact
		// call in a prior sweep — overrides both ownership branches: it closes
		// the delegated-admin gap, since a denial on an account that has ever
		// proven the capability can only mean regression, never the
		// steady-state member fact.
		owner := awssdk.ToString(in.OwnerAccountId)
		ownerKnown := owner != ""
		isOwner := ownerKnown && owner == accountID

		psARNs, err := listPermissionSetARNs(ctx, sso, instanceARN)
		if err != nil {
			// ListPermissionSets is the actual admin/member boundary (see
			// collectIdentityCenter's doc comment): ListInstances already
			// succeeded, so every account reaches this line, and only the
			// admin account may call ListPermissionSets. A confirmed member's
			// denial no-ops this instance instead of propagating — but only
			// when ownership is known, this account isn't it, and it has never
			// proven the capability before. Nothing has been collected for this
			// instance yet, so no-opping here discards zero data; once
			// ListPermissionSets succeeds, every later error in this loop is a
			// real regression, never a no-op.
			switch {
			case isSSONoOpErr(err) && alreadyProven:
				// proven → regression, not a no-op (closes the delegated-admin gap).
				log.FromContext(ctx).Warn().
					Str("account_id", accountID).Str("instance_arn", instanceARN).Err(err).
					Msg("sso: ListPermissionSets denied on an account that has PREVIOUSLY proven sso_admin — treating as a regression, not a member no-op (closes the delegated-admin gap)")
			case isSSONoOpErr(err) && ownerKnown && !isOwner:
				log.FromContext(ctx).Info().
					Str("account_id", accountID).Str("owner_account_id", owner).
					Str("instance_arn", instanceARN).Err(err).
					Msg("sso: non-owner account denied ListPermissionSets, skipping instance (expected for a member; see the delegated-admin gap above)")
				continue
			case isSSONoOpErr(err) && !ownerKnown:
				log.FromContext(ctx).Warn().
					Str("account_id", accountID).Str("instance_arn", instanceARN).Err(err).
					Msg("sso: ListPermissionSets denied and instance ownership unknown (empty OwnerAccountId) — failing closed, not treating as member no-op")
			}
			if isSSONoOpErr(err) && alreadyProven {
				return nil, nil, proven, fmt.Errorf("collectSSO: %w: %w", errSSOAdminRegression, err)
			}
			return nil, nil, proven, fmt.Errorf("collectSSO: %w", err)
		}
		// ListPermissionSets just succeeded: this account is proven to be the
		// admin account. internal/jobs/sync.go persists this so a future
		// sweep's denial on this exact account is judged a regression even
		// where ownership alone would say "confirmed non-owner" forever.
		proven = true
		// One resolver per instance: caches each principal so a group assigned
		// across many permission sets/accounts costs ONE identity-store call, not
		// hundreds (which throttle identitystore and mass-fall-back to GUIDs).
		resolver := newPrincipalResolver(ids, storeID)
		for _, psARN := range psARNs {
			a, accounts, assignees, err := permissionSetAsset(ctx, sso, resolver, instanceARN, psARN, accountID, now)
			if err != nil {
				return nil, nil, proven, fmt.Errorf("collectSSO: permission set %s: %w", psARN, err)
			}
			assets = append(assets, a)
			grantAssets, grantEdges := ssoGrantGraph(a, accounts, assignees, resolver.userEmails, now)
			assets = append(assets, grantAssets...)
			edges = append(edges, grantEdges...)
		}
		// Expand the assigned GROUPS into their members. Without this the
		// collector produces zero human identities in an org that grants SSO
		// access exclusively to groups (the common case) — the user-assignee
		// branch in ssoGrantGraph is only ever reached for direct user
		// assignments, and most access is granted via groups.
		assets = append(assets, ssoGroupMembers(ctx, resolver, now)...)
		// Surface (don't swallow) name-resolution failures: a nonzero fallback
		// count means assignees show as GUIDs — the firstErr says why (throttle /
		// AccessDenied / empty DisplayName / wrong region).
		if resolver.fails > 0 {
			log.FromContext(ctx).Warn().
				Int("fallbacks", resolver.fails).Int("resolved", resolver.resolved).
				Str("instance", instanceARN).Err(resolver.firstErr).
				Msg("sso: principal name resolution fell back to GUID")
		}
	}
	return assets, edges, proven, nil
}

// ssoGrantGraph turns one permission set's provisioned accounts and assigned
// principals into graph nodes and edges, so the platform's actual provisioned
// state contributes real topology.
//
// Group nodes are keyed "sso_group:<name>" (by display name, not GUID), which
// is the join point the Okta collector's SCIM name match lands on.
//
// Only GROUP assignees produce an assigned_to edge into the permission set:
// that rel is declared SSOGroup→SSOPermSet in graphschema, and pointing it at
// a human_identity source instead would silently drop every row at Ladybug load
// (rel From/To node labels are load-bearing, not advisory). A user assignee
// still gets a human_identity node emitted below — its resolved email lets
// correlate's HumanIdentityFederation join it to github_repo/iam_role without
// a direct edge — wiring that edge would need a new graphschema rel and a
// SchemaVersion bump.
func ssoGrantGraph(ps asset.Asset, accounts, assignees []string, userEmails map[string]string, now time.Time) ([]asset.Asset, []asset.Edge) {
	grantsAdmin := ps.Metadata["grants_admin"] == "true"
	props := map[string]string{"provenance": "identity_center", "confidence": "1.0"}

	var assets []asset.Asset
	var edges []asset.Edge

	for _, acct := range accounts {
		if acct == "" {
			continue
		}
		// "aws:<id>" matches the AWS collector's account-node convention
		// (accountAsset), so these join the live account topology rather than
		// dead-ending on a node this function invented.
		acctID := "aws:" + acct
		edges = append(edges, asset.Edge{
			SrcID: ps.ID, SrcType: "sso_permission_set",
			DstID: acctID, DstType: "cloud_account",
			EdgeType: "grants_access_to", Properties: props,
		})
		if grantsAdmin {
			edges = append(edges, asset.Edge{
				SrcID: ps.ID, SrcType: "sso_permission_set",
				DstID: acctID, DstType: "cloud_account",
				EdgeType: "grants_admin", Properties: props,
			})
		}
	}

	for _, a := range assignees {
		if name, ok := strings.CutPrefix(a, "group:"); ok && name != "" {
			gID := "sso_group:" + name
			assets = append(assets, asset.Asset{
				ID: gID, Name: name, Type: "sso_group",
				Provider: asset.ProviderAWS, DiscoveredAt: now, LastSeen: now,
				Metadata: map[string]string{"source": "identity_center"},
			})
			edges = append(edges, asset.Edge{
				SrcID: gID, SrcType: "sso_group",
				DstID: ps.ID, DstType: "sso_permission_set",
				EdgeType: "assigned_to", Properties: props,
			})
			continue
		}
		name, ok := strings.CutPrefix(a, "user:")
		if !ok || name == "" {
			continue // an unresolved GUID
		}
		uID := "sso_user:" + name
		email := userEmails[a]
		assets = append(assets, asset.Asset{
			ID: uID, Name: name, Type: "human_identity",
			Domain:   email,
			Provider: asset.ProviderAWS, DiscoveredAt: now, LastSeen: now,
			Metadata: map[string]string{"source": "identity_center", "sso_username": name},
		})
	}
	return assets, edges
}

// ssoGroupMembers expands every group that holds a permission set into the
// people inside it, as human_identity assets.
//
// It emits assets only, no edges: the group→user relationship would need a
// new graphschema rel and a SchemaVersion bump. The asset alone is what the
// identity census counts, and correlate's HumanIdentityFederation joins these
// people to roles and repos by resolved email without a direct edge.
//
// Membership lookup is best-effort per group — an AccessDenied on one group
// must not lose the other groups' members — so failures are recorded on the
// resolver's fallback counter (which the caller logs) rather than returned.
func ssoGroupMembers(ctx context.Context, r *principalResolver, now time.Time) []asset.Asset {
	// Stable output order: the collector's assets feed a content hash, so
	// iterating a map directly would make identical collections look like drift.
	labels := make([]string, 0, len(r.groupIDs))
	for label := range r.groupIDs {
		labels = append(labels, label)
	}
	sort.Strings(labels)

	var out []asset.Asset
	seen := map[string]bool{}
	for _, label := range labels {
		groupName := strings.TrimPrefix(label, "group:")
		for _, userID := range r.groupMemberIDs(ctx, r.groupIDs[label]) {
			// resolve() is cached per principal, so a person in five groups costs
			// one DescribeUser — the same throttling fix the assignee path needed.
			userLabel := r.resolve(ctx, ssoadmintypes.PrincipalTypeUser, userID)
			name, ok := strings.CutPrefix(userLabel, "user:")
			if !ok || name == "" {
				continue // an unresolved GUID: no identity to record
			}
			id := "sso_user:" + name
			if seen[id] {
				continue // already emitted via another group or a direct assignment
			}
			seen[id] = true
			out = append(out, asset.Asset{
				ID: id, Name: name, Type: "human_identity",
				Domain:       r.userEmails[userLabel],
				Provider:     asset.ProviderAWS,
				DiscoveredAt: now, LastSeen: now,
				Metadata: map[string]string{
					"source":       "identity_center",
					"sso_username": name,
					// The group is how this person holds cloud access. Kept as
					// metadata rather than an edge (see the doc comment), but it is
					// the audit trail for why they are in the census at all.
					"sso_group": groupName,
				},
			})
		}
	}
	return out
}

// isSSONoOpErr reports whether an Identity Center admin-API error means "this
// account isn't the management/delegated-admin account" — the clean no-op
// case — as opposed to a transient failure (throttle, timeout, 5xx) that must
// still be surfaced so the sweep is flagged Partial. Same shape as
// isOrgNoOpErr in scp.go, which solves the identical management-account-only
// problem for AWS Organizations.
func isSSONoOpErr(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.ErrorCode() == "AccessDeniedException"
}

func listPermissionSetARNs(ctx context.Context, sso ssoAPI, instanceARN string) ([]string, error) {
	var out []string
	var token *string
	for {
		page, err := sso.ListPermissionSets(ctx, &ssoadmin.ListPermissionSetsInput{
			InstanceArn: &instanceARN, NextToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("list permission sets: %w", err)
		}
		out = append(out, page.PermissionSets...)
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		token = page.NextToken
	}
}

// permissionSetAsset builds one sso_permission_set asset — its name, whether
// it grants admin (AdministratorAccess managed policy or an inline
// wildcard-action Allow) — and returns the accounts it is provisioned to and
// the principals assigned it, so the caller can turn them into graph edges
// as well as metadata.
func permissionSetAsset(ctx context.Context, sso ssoAPI, resolver *principalResolver, instanceARN, psARN, accountID string, now time.Time) (asset.Asset, []string, []string, error) {
	name := psARN
	if d, err := sso.DescribePermissionSet(ctx, &ssoadmin.DescribePermissionSetInput{
		InstanceArn: &instanceARN, PermissionSetArn: &psARN,
	}); err == nil && d.PermissionSet != nil {
		if n := awssdk.ToString(d.PermissionSet.Name); n != "" {
			name = n
		}
	}

	managed, err := listManagedPolicyNames(ctx, sso, instanceARN, psARN)
	if err != nil {
		return asset.Asset{}, nil, nil, err
	}
	grantsAdmin := false
	for _, m := range managed {
		if strings.Contains(m, "AdministratorAccess") {
			grantsAdmin = true
		}
	}
	// Inline policy: a wildcard-action Allow also grants admin (reuses the IAM
	// collector's tolerant policy parser). A permission set with no inline
	// policy answers with an empty document, so an error is an unread policy:
	// unless the managed policies already proved admin, the verdict is unknown.
	adminKnown := true
	switch inline, err := sso.GetInlinePolicyForPermissionSet(ctx, &ssoadmin.GetInlinePolicyForPermissionSetInput{
		InstanceArn: &instanceARN, PermissionSetArn: &psARN,
	}); {
	case err != nil || inline == nil:
		adminKnown = grantsAdmin
	case grantsWildcardAction(awssdk.ToString(inline.InlinePolicy)):
		grantsAdmin = true
	}

	accounts, assignees, err := listAssignments(ctx, sso, resolver, instanceARN, psARN)
	if err != nil {
		return asset.Asset{}, nil, nil, err
	}

	meta := map[string]string{
		"instance_arn":     instanceARN,
		"managed_policies": strings.Join(managed, ","),
		"account_count":    strconv.Itoa(len(accounts)),
		"accounts":         strings.Join(accounts, ","),
		"assignee_count":   strconv.Itoa(len(assignees)),
		"assignees":        strings.Join(assignees, ","),
	}
	if adminKnown {
		meta["grants_admin"] = strconv.FormatBool(grantsAdmin)
	}
	return asset.Asset{
		ID:           psARN,
		Name:         name,
		Type:         "sso_permission_set",
		Provider:     asset.ProviderAWS,
		Region:       "global",
		AccountID:    accountID,
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}, accounts, assignees, nil
}

func listManagedPolicyNames(ctx context.Context, sso ssoAPI, instanceARN, psARN string) ([]string, error) {
	var out []string
	var token *string
	for {
		page, err := sso.ListManagedPoliciesInPermissionSet(ctx, &ssoadmin.ListManagedPoliciesInPermissionSetInput{
			InstanceArn: &instanceARN, PermissionSetArn: &psARN, NextToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("list managed policies: %w", err)
		}
		for _, p := range page.AttachedManagedPolicies {
			if n := awssdk.ToString(p.Name); n != "" {
				out = append(out, n)
			}
		}
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		token = page.NextToken
	}
}

// listAssignments returns the accounts a permission set is provisioned into and
// the deduplicated, resolved principal names assigned it ("user:alice",
// "group:platform-admins"). Principal resolution is best-effort — an
// identity-store lookup miss falls back to the principal GUID.
func listAssignments(ctx context.Context, sso ssoAPI, resolver *principalResolver, instanceARN, psARN string) (accounts, assignees []string, err error) {
	var acctToken *string
	for {
		page, err := sso.ListAccountsForProvisionedPermissionSet(ctx, &ssoadmin.ListAccountsForProvisionedPermissionSetInput{
			InstanceArn: &instanceARN, PermissionSetArn: &psARN, NextToken: acctToken,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("list provisioned accounts: %w", err)
		}
		accounts = append(accounts, page.AccountIds...)
		if page.NextToken == nil || *page.NextToken == "" {
			break
		}
		acctToken = page.NextToken
	}

	seen := map[string]bool{}
	for _, acct := range accounts {
		var asgToken *string
		for {
			page, err := sso.ListAccountAssignments(ctx, &ssoadmin.ListAccountAssignmentsInput{
				InstanceArn: &instanceARN, AccountId: &acct, PermissionSetArn: &psARN, NextToken: asgToken,
			})
			if err != nil {
				return nil, nil, fmt.Errorf("list account assignments: %w", err)
			}
			for _, asg := range page.AccountAssignments {
				label := resolver.resolve(ctx, asg.PrincipalType, awssdk.ToString(asg.PrincipalId))
				if label != "" && !seen[label] {
					seen[label] = true
					assignees = append(assignees, label)
				}
			}
			if page.NextToken == nil || *page.NextToken == "" {
				break
			}
			asgToken = page.NextToken
		}
	}
	sort.Strings(accounts)
	sort.Strings(assignees)
	return accounts, assignees, nil
}
