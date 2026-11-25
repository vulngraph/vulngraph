package aws

import (
	"context"
	"maps"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// Every reader in this file follows the repo's absent-means-unknown rule: a key
// is written only from a successful read, and a failed read leaves it absent.
// A failed read written as "false" or "0" is indistinguishable from an
// observation, and the lifecycle reconcile would close real findings on it
// (no MFA, console access, admin policy) the first time IAM throttled.

// principalPolicies is what one principal's policy listing produced. complete
// is false when any listing, inline document or managed document could not be
// read: the policy set is then a subset of the truth, and the caller must not
// publish it as the principal's whole grant.
type principalPolicies struct {
	docs     []policyDoc
	assets   []asset.Asset
	edges    []asset.Edge
	complete bool
	// Which kinds of read document grant Allow *:* on their own: a principal
	// whose only such grant is a customer-managed policy is reported once, on
	// the policy (aws-iam-policy-full-admin), whose fix also fixes it.
	customerFullAdmin, otherFullAdmin bool
	// inlineKMSDecryptAll: an inline document allows kms:Decrypt or
	// ReEncryptFrom on every key (FSBP KMS.2).
	inlineKMSDecryptAll bool
	// cloudShell: AWSCloudShellFullAccess is attached (CIS AWS 2.20).
	cloudShell bool
}

// grantMetadata is the principal keys derived from its read documents. Only a
// complete policy set supports them: an unread inline policy may be the one
// that grants.
//
// The CloudShell attachment is the exception: a listed attachment is an
// observation even when some other document was unreadable.
func (p *principalPolicies) grantMetadata() map[string]string {
	if !p.complete {
		if p.cloudShell {
			return map[string]string{"cloudshell_full_access": "true"}
		}
		return nil
	}
	out := map[string]string{
		"inline_kms_decrypt_all": strconv.FormatBool(p.inlineKMSDecryptAll),
		"cloudshell_full_access": strconv.FormatBool(p.cloudShell),
	}
	if p.customerFullAdmin || p.otherFullAdmin {
		out["full_admin_customer_policy_only"] = strconv.FormatBool(!p.otherFullAdmin)
	}
	return out
}

// managedPolicyRef is one attached managed policy, whatever principal kind it
// was listed for.
type managedPolicyRef struct{ name, arn string }

// addManaged records attached managed policies: the embedded document, the
// iam_policy asset and the has_policy edge from the principal.
func (p *principalPolicies) addManaged(ctx context.Context, cache *managedPolicyCache, refs []managedPolicyRef, srcID, srcType, accountID string, now time.Time) {
	for _, r := range refs {
		doc, ok := cache.document(ctx, r.arn)
		if !ok {
			p.complete = false
		}
		p.docs = append(p.docs, policyDoc{Name: r.name, Type: "identity", Managed: true, Document: doc})
		meta := map[string]string{
			"policy_name": r.name,
			"policy_arn":  r.arn,
			"account_id":  accountID,
			"managed_by":  "customer",
		}
		if isAWSManagedPolicyARN(r.arn) {
			meta["managed_by"] = "aws"
			p.cloudShell = p.cloudShell || strings.HasSuffix(r.arn, ":policy/AWSCloudShellFullAccess")
		}
		if facts, parsed := identityGrantFacts(doc); ok && parsed {
			maps.Copy(meta, policyGrantMetadata(facts))
			if facts.fullAdmin {
				if meta["managed_by"] == "customer" {
					p.customerFullAdmin = true
				} else {
					p.otherFullAdmin = true
				}
			}
		}
		p.assets = append(p.assets, asset.Asset{
			ID:           r.arn,
			Name:         r.name,
			Type:         "iam_policy",
			Provider:     asset.ProviderAWS,
			Region:       "global",
			AccountID:    accountID,
			Metadata:     meta,
			DiscoveredAt: now,
			LastSeen:     now,
		})
		p.edges = append(p.edges, asset.Edge{
			SrcID: srcID, SrcType: srcType,
			DstID: r.arn, DstType: "iam_policy",
			EdgeType: "has_policy",
		})
	}
}

func (p *principalPolicies) addInline(name, encodedDoc string) {
	doc := decodePolicyDocument(encodedDoc)
	p.docs = append(p.docs, policyDoc{Name: name, Type: "identity", Document: doc})
	if facts, ok := identityGrantFacts(doc); ok {
		p.otherFullAdmin = p.otherFullAdmin || facts.fullAdmin
		p.inlineKMSDecryptAll = p.inlineKMSDecryptAll || facts.kmsDecryptAll
	}
}

func toManagedRefs(name, arn *string) managedPolicyRef {
	return managedPolicyRef{name: awssdk.ToString(name), arn: awssdk.ToString(arn)}
}

// rolePolicies lists a role's attached managed and inline policies, every page.
func rolePolicies(ctx context.Context, c iamAPI, cache *managedPolicyCache, role, roleARN, accountID string, now time.Time) principalPolicies {
	p := principalPolicies{complete: true}
	for marker := (*string)(nil); ; {
		att, err := c.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: &role, Marker: marker})
		if err != nil || att == nil {
			p.complete = false
			break
		}
		refs := make([]managedPolicyRef, 0, len(att.AttachedPolicies))
		for _, ap := range att.AttachedPolicies {
			refs = append(refs, toManagedRefs(ap.PolicyName, ap.PolicyArn))
		}
		p.addManaged(ctx, cache, refs, roleARN, "iam_role", accountID, now)
		if !att.IsTruncated {
			break
		}
		marker = att.Marker
	}
	for marker := (*string)(nil); ; {
		inl, err := c.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: &role, Marker: marker})
		if err != nil || inl == nil {
			p.complete = false
			break
		}
		for _, name := range inl.PolicyNames {
			gp, err := c.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: &role, PolicyName: &name})
			if err != nil || gp == nil {
				p.complete = false
				continue
			}
			p.addInline(name, awssdk.ToString(gp.PolicyDocument))
		}
		if !inl.IsTruncated {
			break
		}
		marker = inl.Marker
	}
	return p
}

// userPolicies lists a user's attached managed and inline policies, every page.
func userPolicies(ctx context.Context, c iamAPI, cache *managedPolicyCache, user, userARN, accountID string, now time.Time) principalPolicies {
	p := principalPolicies{complete: true}
	for marker := (*string)(nil); ; {
		att, err := c.ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: &user, Marker: marker})
		if err != nil || att == nil {
			p.complete = false
			break
		}
		refs := make([]managedPolicyRef, 0, len(att.AttachedPolicies))
		for _, ap := range att.AttachedPolicies {
			refs = append(refs, toManagedRefs(ap.PolicyName, ap.PolicyArn))
		}
		p.addManaged(ctx, cache, refs, userARN, "iam_user", accountID, now)
		if !att.IsTruncated {
			break
		}
		marker = att.Marker
	}
	for marker := (*string)(nil); ; {
		inl, err := c.ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: &user, Marker: marker})
		if err != nil || inl == nil {
			p.complete = false
			break
		}
		for _, name := range inl.PolicyNames {
			gp, err := c.GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: &user, PolicyName: &name})
			if err != nil || gp == nil {
				p.complete = false
				continue
			}
			p.addInline(name, awssdk.ToString(gp.PolicyDocument))
		}
		if !inl.IsTruncated {
			break
		}
		marker = inl.Marker
	}
	return p
}

// userCredentials reads one user's console, MFA and access-key state. gaps
// counts the reads that failed; their keys are absent from the returned map.
func userCredentials(ctx context.Context, c iamAPI, name string, now time.Time) (meta map[string]string, gaps int) {
	meta = map[string]string{}

	// Console access: GetLoginProfile answers NoSuchEntity for a user with no
	// password. Only THAT error is the observation "no console access"; any
	// other (AccessDenied, throttle) is unknown.
	consoleKnown, console := false, false
	switch _, err := c.GetLoginProfile(ctx, &iam.GetLoginProfileInput{UserName: &name}); {
	case err == nil:
		consoleKnown, console = true, true
	case awsErrCode(err) == "NoSuchEntity":
		consoleKnown = true
	default:
		gaps++
	}
	if consoleKnown {
		meta["console_access"] = strconv.FormatBool(console)
	}

	if mfa, err := c.ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: &name}); err == nil && mfa != nil {
		meta["mfa_enabled"] = strconv.FormatBool(len(mfa.MFADevices) > 0)
	} else {
		gaps++
	}

	keysKnown, activeKeys := false, 0
	if keys, err := c.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: &name}); err == nil && keys != nil {
		keysKnown = true
		var km map[string]string
		km, activeKeys = accessKeyState(ctx, c, keys.AccessKeyMetadata, now)
		for k, v := range km {
			meta[k] = v
		}
	} else {
		gaps++
	}

	// Inactive = no console password AND no active access keys. Either half
	// observed as "in use" settles it as active; only both halves observed as
	// unused make it inactive.
	switch {
	case consoleKnown && keysKnown:
		meta["inactive"] = strconv.FormatBool(!console && activeKeys == 0)
	case (consoleKnown && console) || (keysKnown && activeKeys > 0):
		meta["inactive"] = "false"
	}
	return meta, gaps
}

// accessKeyState derives access-key age, last use, staleness and the active
// count from a successful ListAccessKeys. access_key_stale flags a long-lived
// key that is idle (last used >= staleKeyDays ago) or was provisioned but never
// used and is old enough to be a forgotten liability.
//
// A failed GetAccessKeyLastUsed makes that key's last use unknown, so
// access_key_last_used_days is omitted (the failed key may be the most recent)
// and access_key_stale is omitted unless another key PROVED staleness.
func accessKeyState(ctx context.Context, c iamAPI, keys []iamtypes.AccessKeyMetadata, now time.Time) (map[string]string, int) {
	var (
		oldest         time.Time
		mostRecentUsed = -1 // -1 = no active key has ever been used
		active         int
		stale          bool
		lookupFailed   bool
		maxIdle        = -1 // the longest any active key has gone unused (never used: its age)
	)
	for _, k := range keys {
		if k.Status != iamtypes.StatusTypeActive || k.CreateDate == nil {
			continue
		}
		active++
		if oldest.IsZero() || k.CreateDate.Before(oldest) {
			oldest = *k.CreateDate
		}
		ageDays := int(now.Sub(*k.CreateDate).Hours() / 24)
		lu, err := c.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: k.AccessKeyId})
		if err != nil || lu == nil {
			lookupFailed = true
			continue
		}
		usedDays := -1 // the lookup succeeded and reported no last-used date
		if lu.AccessKeyLastUsed != nil && lu.AccessKeyLastUsed.LastUsedDate != nil {
			usedDays = int(now.Sub(*lu.AccessKeyLastUsed.LastUsedDate).Hours() / 24)
			if mostRecentUsed == -1 || usedDays < mostRecentUsed {
				mostRecentUsed = usedDays
			}
		}
		if usedDays >= staleKeyDays || (usedDays == -1 && ageDays >= staleKeyDays) {
			stale = true
		}
		idle := usedDays
		if usedDays == -1 {
			idle = ageDays
		}
		maxIdle = max(maxIdle, idle)
	}
	meta := map[string]string{
		"active_key_count":    strconv.Itoa(active),
		"access_key_age_days": "0",
	}
	if !oldest.IsZero() {
		meta["access_key_age_days"] = strconv.Itoa(int(now.Sub(oldest).Hours() / 24))
	}
	if !lookupFailed {
		meta["access_key_last_used_days"] = strconv.Itoa(mostRecentUsed)
		// -1 with no active key; CIS AWS 2.11 grades each key's idle time.
		meta["access_key_max_idle_days"] = strconv.Itoa(maxIdle)
	}
	if stale || !lookupFailed {
		meta["access_key_stale"] = strconv.FormatBool(stale)
	}
	return meta, active
}
