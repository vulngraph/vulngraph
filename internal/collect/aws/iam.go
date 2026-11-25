package aws

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Access Advisor polling bounds. The job runs server-side and usually completes
// within a poll or two; we cap the wait so a slow job never stalls collection.
const (
	aaPollAttempts = 6
	aaPollInterval = 1500 * time.Millisecond
)

// iamAPI is the slice of the IAM SDK the collector uses — small enough to fake.
type iamAPI interface {
	ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListRolePolicies(context.Context, *iam.ListRolePoliciesInput, ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	GetRolePolicy(context.Context, *iam.GetRolePolicyInput, ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	ListUsers(context.Context, *iam.ListUsersInput, ...func(*iam.Options)) (*iam.ListUsersOutput, error)
	ListAttachedUserPolicies(context.Context, *iam.ListAttachedUserPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	ListUserPolicies(context.Context, *iam.ListUserPoliciesInput, ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error)
	GetUserPolicy(context.Context, *iam.GetUserPolicyInput, ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error)
	ListMFADevices(context.Context, *iam.ListMFADevicesInput, ...func(*iam.Options)) (*iam.ListMFADevicesOutput, error)
	GetLoginProfile(context.Context, *iam.GetLoginProfileInput, ...func(*iam.Options)) (*iam.GetLoginProfileOutput, error)
	GetPolicy(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
	ListAccessKeys(context.Context, *iam.ListAccessKeysInput, ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	// GetAccessKeyLastUsed reports when a key last signed a request — the "is this
	// long-lived key actually used, or a forgotten/leaked liability" signal.
	GetAccessKeyLastUsed(context.Context, *iam.GetAccessKeyLastUsedInput, ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error)
	// GetRole returns RoleLastUsed and PermissionsBoundary (ListRoles populates
	// neither) — the real "when was this role last assumed" and "is its grant
	// capped by a boundary" signals.
	GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	// GetUser returns PermissionsBoundary for a user (ListUsers does not populate
	// it) — used to cap admin-ish user findings by their boundary.
	GetUser(context.Context, *iam.GetUserInput, ...func(*iam.Options)) (*iam.GetUserOutput, error)
	// Access Advisor: which services a principal has actually used. Async —
	// Generate returns a job id, Get polls it to completion.
	GenerateServiceLastAccessedDetails(context.Context, *iam.GenerateServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error)
	GetServiceLastAccessedDetails(context.Context, *iam.GetServiceLastAccessedDetailsInput, ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error)
	// GetAccountSummary reports account-level credential state (root access keys,
	// root MFA) — the only source for the account root user.
	GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
}

// staleKeyDays is the idle threshold (CIS AWS 1.x, aligned with the 90-day
// credential-hygiene window) past which an active access key counts as unused.
const staleKeyDays = 90

// collectIAM gathers IAM roles and users with their policy documents (attached
// managed, inline, and — for roles — the trust policy). Principals become assets
// whose metadata carries the policies the CIEM checks evaluate. Authentication
// is the connector's role assumption / static keys (baseConfig).
// Each attached managed policy is also emitted as a separate iam_policy asset
// with a has_policy edge from the principal to the policy.
func collectIAM(ctx context.Context, cfg map[string]string, accountID string, now time.Time) ([]asset.Asset, []asset.Edge, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("collectIAM: %w", err)
	}
	// IAM is a global service; pin to the partition's home region.
	awsCfg.Region = globalRegionFor(awsCfg.Region)
	client := iam.NewFromConfig(awsCfg)
	cache := newManagedPolicyCache(client)

	// Root first: one GetAccountSummary call carrying the highest-severity IAM
	// signal (root access keys / no MFA). Running it before the per-principal
	// policy crawl means IAM throttling or a deadline expiring mid-crawl can't
	// silently drop it.
	partition := partitionFor(cfg["region"])
	root, rootErr := collectRootAccount(ctx, client, partition, accountID, now)
	if rootErr != nil {
		log.FromContext(ctx).Warn().Err(rootErr).Str("account_id", accountID).
			Msg("iam root account collection failed — root-credential checks will not run this sweep")
	} else {
		rootDetails(ctx, client, partition, accountID, root.Metadata)
		if err := rootDetailError(root.Metadata); err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("account_id", accountID).
				Msg("iam root details unknown this sweep (check iam:ListVirtualMFADevices, iam:GenerateCredentialReport, iam:GetCredentialReport)")
		}
	}

	roleAssets, roleEdges, err := collectRoles(ctx, client, cache, accountID, now)
	if err != nil {
		return nil, nil, fmt.Errorf("collectIAM: %w", err)
	}
	userAssets, userEdges, err := collectUsers(ctx, client, cache, accountID, now)
	if err != nil {
		return nil, nil, fmt.Errorf("collectIAM: %w", err)
	}
	assets := dedupePolicyAssets(append(roleAssets, userAssets...))
	// The account root is not returned by ListUsers — it was fetched separately
	// (above) so the "root has active access keys / no MFA" checks have an asset
	// to evaluate.
	if rootErr == nil {
		assets = append(assets, root)
	}
	return assets, append(roleEdges, userEdges...), nil
}

// collectRootAccount emits a synthetic iam_user asset for the account root from
// GetAccountSummary (root keys and MFA). Whether root has a password at all —
// console_access — comes from the credential report (rootDetails). Best-
// effort: on error the root asset is omitted rather than failing IAM collection,
// but the error is returned so the caller can log WHY — a silently dropped root
// asset hides critical root-credential findings.
func collectRootAccount(ctx context.Context, c iamAPI, partition, accountID string, now time.Time) (asset.Asset, error) {
	out, err := c.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return asset.Asset{}, fmt.Errorf("collectRootAccount: GetAccountSummary: %w", err)
	}
	if out == nil {
		return asset.Asset{}, errors.New("collectRootAccount: empty GetAccountSummary response")
	}
	rootKeys := out.SummaryMap["AccountAccessKeysPresent"] // 1 if the root user has ≥1 access key
	rootMFA := out.SummaryMap["AccountMFAEnabled"]         // 1 if the root user has MFA enabled
	return asset.Asset{
		ID:        "arn:" + partition + ":iam::" + accountID + ":root",
		Name:      "root",
		Type:      "iam_user",
		Provider:  asset.ProviderAWS,
		Region:    "global",
		AccountID: accountID,
		Metadata: map[string]string{
			"root":             "true",
			"active_key_count": strconv.Itoa(int(rootKeys)),
			"mfa_enabled":      fmt.Sprintf("%t", rootMFA == 1),
		},
		DiscoveredAt: now,
		LastSeen:     now,
	}, nil
}

func collectRoles(ctx context.Context, c iamAPI, cache *managedPolicyCache, accountID string, now time.Time) ([]asset.Asset, []asset.Edge, error) {
	var (
		assets      []asset.Asset
		edges       []asset.Edge
		marker      *string
		roles       int
		getRoleFail int // roles whose GetRole failed — their last-used is UNKNOWN, not never
		policyGaps  int // roles whose policy set could not be fully read
	)
	for {
		out, err := c.ListRoles(ctx, &iam.ListRolesInput{Marker: marker})
		if err != nil {
			return nil, nil, fmt.Errorf("collectRoles: %w", err)
		}
		for _, r := range out.Roles {
			name := awssdk.ToString(r.RoleName)
			arn := awssdk.ToString(r.Arn)
			pp := rolePolicies(ctx, c, cache, name, arn, accountID, now)
			policies := pp.docs
			assets = append(assets, pp.assets...)
			edges = append(edges, pp.edges...)
			if !pp.complete {
				policyGaps++
			}
			// Trust policy (who may assume this role).
			trustDoc := ""
			if r.AssumeRolePolicyDocument != nil {
				trustDoc = decodePolicyDocument(awssdk.ToString(r.AssumeRolePolicyDocument))
				policies = append(policies, policyDoc{
					Name:     name + "-trust",
					Type:     "trust",
					Document: trustDoc,
				})
			}
			meta := map[string]string{
				"path": awssdk.ToString(r.Path),
			}
			// Age bounds what a "never used" last-used reading means: a role
			// created last week with no recorded use is new, not dormant.
			if r.CreateDate != nil {
				meta["created_days"] = daysSince(now, *r.CreateDate)
			}
			// Last-used. ListRoles does NOT populate RoleLastUsed in practice (only
			// GetRole does), but if it ever does that is a real observation, so take
			// it; the GetRole read below refines it.
			lastUsed, lastUsedObserved := "", false
			if r.RoleLastUsed != nil && r.RoleLastUsed.LastUsedDate != nil {
				lastUsed, lastUsedObserved = daysSince(now, *r.RoleLastUsed.LastUsedDate), true
			}
			// The permission boundary caps this role's effective permissions, so
			// it must be attached BEFORE anything evaluates them — CIEM privesc
			// detection, the allows_action/secret-access correlators, and
			// isAdminish below all read these policies and intersect the
			// boundary in. Fetched for EVERY role, not just admin-ish ones:
			// privesc rules match specific action combinations rather than a
			// wildcard, so a capped non-admin role still needs its cap applied.
			// Failed reads preserve an incomplete restriction for downstream analysis.
			roles++
			det := roleDetails(ctx, c, name, now)
			if !det.observed {
				getRoleFail++
			}
			switch {
			case det.observed && det.lastUsedDays != roleNeverUsed:
				lastUsed, lastUsedObserved = det.lastUsedDays, true // GetRole saw a real date
			case det.observed && !lastUsedObserved:
				lastUsed, lastUsedObserved = roleNeverUsed, true // GetRole positively saw none
			}
			// last_used_days is written ONLY when a read actually observed it —
			// absent means unknown (the repo-wide convention), never a
			// never-used guess. last_used_observed marks the value as
			// positively observed, the same promise sa_last_auth_observed_days
			// makes for the GCP collector.
			if lastUsedObserved {
				meta["last_used_days"] = lastUsed
				meta["last_used_observed"] = "true"
			}
			policies = withPermissionBoundary(ctx, cache, policies, meta, det.boundaryARN, det.boundaryObserved)
			// An incomplete policy set is a subset of the role's real grant:
			// publishing it as the whole would read as "this role grants less"
			// and close findings on what was merely unread, so it is omitted.
			if pp.complete {
				meta["policies"] = encodePolicies(policies)
			}
			maps.Copy(meta, pp.grantMetadata())
			// isAdminish runs once against the policy set, boundary included, so
			// a deny-all or narrowing boundary prevents the admin verdict rather
			// than having to be un-set afterwards. A partial set may omit a deny.
			if pp.complete && isAdminish(ctx, arn, policies) {
				meta["admin"] = "true"
				// Access Advisor is expensive (generate + poll), so admin-ish only.
				// The real last-used date already came from roleDetails above.
				for k, v := range roleUsage(ctx, c, arn, now) {
					meta[k] = v
				}
			}
			// Flag roles whose trust policy allows ANY principal to assume them —
			// a public AssumeRole misconfiguration (account-confused-deputy risk).
			//
			// Written on BOTH outcomes, gated on trustDoc having a real document
			// to evaluate (not on the predicate result): writing only on the
			// positive case would make "evaluated and not public" identical to
			// "no trust document available", and aws-iam-public-trust-policy
			// reads exactly this key.
			if trustDoc != "" {
				meta["public_trust"] = strconv.FormatBool(trustHasWildcardPrincipal(trustDoc))
				// Compensating-control signal for scoring: an MFA-gated or
				// IdP-federated assumption path is materially harder to exploit,
				// so a privesc finding on such a role is demoted.
				meta["mfa_required_to_assume"] = strconv.FormatBool(trustRequiresMFA(trustDoc))
			}
			if kind, provider := trustFederation(trustDoc); kind != "" {
				meta["federated_trust"] = kind
				meta["federated_provider"] = provider
			}
			// Inbound assumability class + concrete entry principals — lets scoring
			// and narratives reason about who can actually reach this role (a
			// cross-account-only or IdP-only entry is a compensating control).
			if class, principals := trustEntryClass(trustDoc, accountID); class != "" {
				meta["trust_entry"] = class
				if len(principals) > 0 {
					// Sort BEFORE truncating: this set is rendered into one
					// string, so an unstable order would re-serialize the same
					// set differently every sweep and make the truncated
					// principals arbitrary.
					principals = slices.Sorted(slices.Values(principals))
					if len(principals) > 5 {
						principals = principals[:5]
					}
					meta["trust_principals"] = strings.Join(principals, ",")
				}
			}
			assets = append(assets, asset.Asset{
				ID:           arn,
				Name:         name,
				Type:         "iam_role",
				Provider:     asset.ProviderAWS,
				Region:       "global",
				AccountID:    accountID,
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if !out.IsTruncated {
			// Counted, not logged per role: a throttled sweep would otherwise emit
			// one line per role. Absent last_used_days is invisible by design, so
			// this is the only place the operator learns HOW MUCH of the account's
			// role activity went unobserved this sweep.
			if getRoleFail > 0 {
				log.FromContext(ctx).Warn().
					Str("account_id", accountID).Int("roles", roles).Int("get_role_failed", getRoleFail).
					Msg("iam GetRole failed for some roles — their last-used and permission boundary are unknown this sweep")
			}
			if policyGaps > 0 {
				log.FromContext(ctx).Warn().
					Str("account_id", accountID).Int("roles", roles).Int("policies_unread", policyGaps).
					Msg("iam policy read failed for some roles — their policies metadata is omitted (unknown) this sweep")
			}
			return assets, edges, nil
		}
		marker = out.Marker
	}
}

// userBoundaryARN distinguishes observed absence from an unread attachment.
func userBoundaryARN(ctx context.Context, c iamAPI, userName string) (string, bool) {
	gu, err := c.GetUser(ctx, &iam.GetUserInput{UserName: &userName})
	if err != nil || gu == nil || gu.User == nil {
		return "", false
	}
	if gu.User.PermissionsBoundary == nil {
		return "", true
	}
	arn := awssdk.ToString(gu.User.PermissionsBoundary.PermissionsBoundaryArn)
	return arn, arn != ""
}

// roleNeverUsed is the last_used_days value for a role AWS positively reports as
// never used, or not used inside GetRole's ~400-day tracking window. It is a
// sentinel, not a day count — never render or do arithmetic on it as one. Written
// ONLY alongside last_used_observed=true; enrich mirrors it as neverUsedSentinel.
const roleNeverUsed = "9999"

// roleDetail is what one GetRole call observed about a role. observed
// separates "GetRole said this role has no last-used date" from "GetRole
// failed" — a zero roleDetail means UNKNOWN, not never-used.
type roleDetail struct {
	boundaryARN      string
	boundaryObserved bool
	lastUsedDays     string // roleNeverUsed when AWS reports no last-used date
	observed         bool   // GetRole returned a role — the fields below are facts
}

// roleDetails fetches the two things ListRoles omits — the permission-boundary
// ARN and the real last-used date — in ONE GetRole call. Separate from
// roleUsage so the boundary is collected for EVERY role while roleUsage's
// expensive Access Advisor generate-and-poll stays limited to admin-ish
// roles, without describing an admin-ish role twice.
//
// Any error yields the zero roleDetail: boundary and activity are unknown.
func roleDetails(ctx context.Context, c iamAPI, roleName string, now time.Time) roleDetail {
	gr, err := c.GetRole(ctx, &iam.GetRoleInput{RoleName: &roleName})
	if err != nil || gr == nil || gr.Role == nil {
		return roleDetail{}
	}
	d := roleDetail{observed: true, boundaryObserved: true, lastUsedDays: roleNeverUsed}
	if pb := gr.Role.PermissionsBoundary; pb != nil {
		d.boundaryARN = awssdk.ToString(pb.PermissionsBoundaryArn)
		d.boundaryObserved = d.boundaryARN != ""
	}
	if lu := gr.Role.RoleLastUsed; lu != nil && lu.LastUsedDate != nil {
		d.lastUsedDays = daysSince(now, *lu.LastUsedDate)
	}
	return d
}

// daysSince renders whole days between t and now as a metadata string.
func daysSince(now, t time.Time) string {
	return strconv.Itoa(int(now.Sub(t).Hours() / 24))
}

// roleUsage fetches IAM Access Advisor service-usage for one role, for
// right-sizing over-privileged roles with evidence ("admin granted, only 6 of 312
// services used in 90d"). Best-effort: any API error or poll timeout returns
// whatever was gathered so far (collection never fails on this).
//
// Deliberately does NOT call GetRole — roleDetails already did, for every role,
// and calling it again here would describe admin-ish roles twice.
func roleUsage(ctx context.Context, c iamAPI, arn string, now time.Time) (aa map[string]string) {
	aa = map[string]string{}

	gen, err := c.GenerateServiceLastAccessedDetails(ctx, &iam.GenerateServiceLastAccessedDetailsInput{Arn: &arn})
	if err != nil || gen.JobId == nil {
		return aa
	}
	for i := 0; i < aaPollAttempts; i++ {
		det, derr := c.GetServiceLastAccessedDetails(ctx, &iam.GetServiceLastAccessedDetailsInput{JobId: gen.JobId})
		if derr != nil {
			return aa
		}
		if det.JobStatus == iamtypes.JobStatusTypeInProgress {
			select {
			case <-ctx.Done():
				return aa
			case <-time.After(aaPollInterval):
			}
			continue
		}
		if det.JobStatus != iamtypes.JobStatusTypeCompleted {
			return aa
		}
		granted := len(det.ServicesLastAccessed)
		used := 0
		var usedSvcs []string
		var mostRecent time.Time
		for _, s := range det.ServicesLastAccessed {
			if s.LastAuthenticated == nil {
				continue
			}
			used++
			if ns := awssdk.ToString(s.ServiceNamespace); ns != "" {
				usedSvcs = append(usedSvcs, ns)
			}
			if s.LastAuthenticated.After(mostRecent) {
				mostRecent = *s.LastAuthenticated
			}
		}
		aa["aa_services_granted"] = strconv.Itoa(granted)
		aa["aa_services_used"] = strconv.Itoa(used)
		if len(usedSvcs) > 0 {
			if len(usedSvcs) > 40 {
				usedSvcs = usedSvcs[:40]
			}
			aa["aa_used_services"] = strings.Join(usedSvcs, ",")
		}
		if !mostRecent.IsZero() {
			aa["aa_last_used_days"] = strconv.Itoa(int(now.Sub(mostRecent).Hours() / 24))
		}
		return aa
	}
	return aa
}

func collectUsers(ctx context.Context, c iamAPI, cache *managedPolicyCache, accountID string, now time.Time) ([]asset.Asset, []asset.Edge, error) {
	var (
		assets     []asset.Asset
		edges      []asset.Edge
		marker     *string
		users      int
		credFail   int // users with at least one unread credential setting
		policyFail int // users whose policy set could not be fully read
	)
	for {
		out, err := c.ListUsers(ctx, &iam.ListUsersInput{Marker: marker})
		if err != nil {
			return nil, nil, fmt.Errorf("collectUsers: %w", err)
		}
		for _, u := range out.Users {
			users++
			name := awssdk.ToString(u.UserName)
			arn := awssdk.ToString(u.Arn)
			pp := userPolicies(ctx, c, cache, name, arn, accountID, now)
			policies := pp.docs
			assets = append(assets, pp.assets...)
			edges = append(edges, pp.edges...)
			userMeta, credGaps := userCredentials(ctx, c, name, now)
			if credGaps > 0 {
				credFail++
			}
			userMeta["path"] = awssdk.ToString(u.Path)
			if u.CreateDate != nil {
				userMeta["created_days"] = daysSince(now, *u.CreateDate) // same role as on roles: age gates "never used"
			}
			// Password last used (days since last console login, -1 = never) —
			// straight from ListUsers, so it is always an observation.
			userMeta["password_last_used_days"] = "-1"
			if u.PasswordLastUsed != nil {
				userMeta["password_last_used_days"] = strconv.Itoa(int(now.Sub(*u.PasswordLastUsed).Hours() / 24))
			}
			// Scoped grants need their boundary too: escalation rules need not
			// require a wildcard identity Allow.
			boundaryARN, boundaryObserved := userBoundaryARN(ctx, c, name)
			policies = withPermissionBoundary(ctx, cache, policies, userMeta, boundaryARN, boundaryObserved)
			// Same rule as roles: a partially read policy set is omitted, never
			// published as the user's whole grant.
			if pp.complete {
				userMeta["policies"] = encodePolicies(policies)
			} else {
				policyFail++
			}
			maps.Copy(userMeta, pp.grantMetadata())
			if pp.complete && isAdminish(ctx, arn, policies) {
				userMeta["admin"] = "true"
			}
			assets = append(assets, asset.Asset{
				ID:           arn,
				Name:         name,
				Type:         "iam_user",
				Provider:     asset.ProviderAWS,
				Region:       "global",
				AccountID:    accountID,
				Metadata:     userMeta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if !out.IsTruncated {
			if credFail > 0 || policyFail > 0 {
				log.FromContext(ctx).Warn().
					Str("account_id", accountID).Int("users", users).
					Int("credentials_unread", credFail).Int("policies_unread", policyFail).
					Msg("iam reads failed for some users — the affected keys are omitted (unknown) this sweep")
			}
			return assets, edges, nil
		}
		marker = out.Marker
	}
}

// ─── trust-policy signals ────────────────────────────────────────────────────
//
// All four of these delegate to ciem.EvaluateTrustPolicy — the shared,
// deny-aware trust evaluator — rather than each scanning Allow statements on
// its own; an Allow-only parser here would grade an organization-confined
// trust as PUBLIC and miss the Deny-based MFA guardrail.
//
// Trust-entry class names are re-exported from ciem so the metadata vocabulary
// has one definition.
const (
	trustEntryPublic      = ciem.TrustEntryPublic
	trustEntryMixed       = ciem.TrustEntryMixed
	trustEntryFederated   = ciem.TrustEntryFederated
	trustEntryCrossAcct   = ciem.TrustEntryCrossAcct
	trustEntrySameAcct    = ciem.TrustEntrySameAcct
	trustEntryServiceOnly = ciem.TrustEntryServiceOnly
)

// trustHasWildcardPrincipal reports whether a role's trust policy genuinely
// admits any principal in any AWS account. A wildcard gated by a Condition that
// pins the caller (aws:PrincipalOrgID, aws:SourceAccount, …), or confined by a
// sibling Deny on such a key, is not a public trust; one gated only by TLS, MFA
// or an sts:ExternalId still is (see ciem.EvaluateTrustPolicy).
func trustHasWildcardPrincipal(doc string) bool {
	return ciem.EvaluateTrustPolicy(doc).PublicEntry
}

// trustRequiresMFA reports whether the role cannot be assumed without an
// MFA-authenticated session, whether enforced by a Condition on every Allow or by
// a Deny that blocks assumption when MFA is absent. This is a compensating-control
// signal for scoring: an MFA-gated privesc path is materially harder to exploit.
func trustRequiresMFA(doc string) bool {
	return ciem.EvaluateTrustPolicy(doc).RequiresMFA
}

// trustFederation classifies the identity-provider federation a role's trust
// policy relies on, returning the kind ("saml"|"oidc"|"") and the provider
// ARN/host. This is the signal that assumption is gated by an external IdP
// (Okta/Google/GitHub OIDC), not a raw key.
func trustFederation(doc string) (kind, provider string) {
	eval := ciem.EvaluateTrustPolicy(doc)
	return eval.FederationKind, eval.FederationProvider
}

// trustEntryClass classifies a role's inbound assumability and returns the
// concrete AWS principal ARNs that may assume it (for evidence in narratives),
// with any principal an explicit Deny excludes already removed. Service
// principals are neutral — they never make a role human-reachable, so "federated
// + services" still classifies as federated.
func trustEntryClass(doc, accountID string) (class string, awsPrincipals []string) {
	eval := ciem.EvaluateTrustPolicy(doc)
	return eval.EntryClass(accountID), eval.AWSPrincipals
}
