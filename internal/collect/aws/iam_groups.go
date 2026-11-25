package aws

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// IAM groups, every customer-managed policy (attached or not), server
// certificates and the AWS Support role — the account-wide IAM reads the
// per-principal crawl in iam.go does not make (CIS AWS 2.14, 2.15, 2.17,
// 2.20; FSBP IAM.1, IAM.21, KMS.1, KMS.2).
//
// Groups and customer-managed policies come from one paginated
// GetAccountAuthorizationDetails listing rather than a call per group and per
// policy. A group carries no has_policy edges: its iam_policy assets are
// already reachable from the users and roles that hold them, and the edge
// registry (internal/graphschema) does not declare groups.

// iamAccountWideAPI is the IAM surface this file reads.
type iamAccountWideAPI interface {
	policyDocAPI
	GetAccountAuthorizationDetails(context.Context, *iam.GetAccountAuthorizationDetailsInput, ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error)
	GetGroup(context.Context, *iam.GetGroupInput, ...func(*iam.Options)) (*iam.GetGroupOutput, error)
	ListServerCertificates(context.Context, *iam.ListServerCertificatesInput, ...func(*iam.Options)) (*iam.ListServerCertificatesOutput, error)
	ListEntitiesForPolicy(context.Context, *iam.ListEntitiesForPolicyInput, ...func(*iam.Options)) (*iam.ListEntitiesForPolicyOutput, error)
}

// awsSupportAccessPolicy is the managed policy CIS AWS 2.15 wants attached to
// at least one role.
const awsSupportAccessPolicy = "AWSSupportAccess"

// iamAccountWide is what collectIAMAccountWide read. settings are
// aws_account_settings keys. err joins every read that failed; the assets of
// the reads that succeeded are still returned.
type iamAccountWide struct {
	assets   []asset.Asset
	settings map[string]string
	err      error
}

func collectIAMAccountWide(ctx context.Context, cfg map[string]string, accountID string, now time.Time) iamAccountWide {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return iamAccountWide{err: fmt.Errorf("collectIAMAccountWide: %w", err)}
	}
	awsCfg.Region = globalRegionFor(awsCfg.Region)
	return readIAMAccountWide(ctx, iam.NewFromConfig(awsCfg), partitionFor(cfg["region"]), accountID, now)
}

func readIAMAccountWide(ctx context.Context, c iamAccountWideAPI, partition, accountID string, now time.Time) iamAccountWide {
	var out iamAccountWide
	var errs []error
	groups, policies, err := readAuthorizationDetails(ctx, c, accountID, now)
	if err != nil {
		errs = append(errs, err)
	} else {
		out.assets = append(out.assets, groups...)
		out.assets = append(out.assets, policies...)
	}
	certs, err := readServerCertificates(ctx, c, accountID, now)
	if err != nil {
		errs = append(errs, err)
	} else {
		out.assets = append(out.assets, certs...)
	}
	if n, err := countPolicyRoles(ctx, c, "arn:"+partition+":iam::aws:policy/"+awsSupportAccessPolicy); err != nil {
		errs = append(errs, err)
	} else {
		out.settings = map[string]string{"support_role_count": strconv.Itoa(n)}
	}
	out.err = errors.Join(errs...)
	return out
}

// readAuthorizationDetails lists every group and customer-managed policy. Any
// page error fails the listing: a short group list would read as groups that
// no longer exist.
func readAuthorizationDetails(ctx context.Context, c iamAccountWideAPI, accountID string, now time.Time) (groups, policies []asset.Asset, err error) {
	var (
		groupDetails []iamtypes.GroupDetail
		customer     = map[string]string{} // policy ARN → default-version document
		marker       *string
	)
	for {
		page, err := c.GetAccountAuthorizationDetails(ctx, &iam.GetAccountAuthorizationDetailsInput{
			Filter: []iamtypes.EntityType{iamtypes.EntityTypeGroup, iamtypes.EntityTypeLocalManagedPolicy},
			Marker: marker,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("readAuthorizationDetails: iam:GetAccountAuthorizationDetails: %w", err)
		}
		groupDetails = append(groupDetails, page.GroupDetailList...)
		for _, p := range page.Policies {
			a, doc := customerPolicyAsset(p, accountID, now)
			if doc != "" {
				customer[a.ID] = doc
			}
			policies = append(policies, a)
		}
		if !page.IsTruncated {
			break
		}
		marker = page.Marker
	}
	cache := newManagedPolicyCache(c)
	memberGaps := 0
	for _, g := range groupDetails {
		a := groupAsset(ctx, c, cache, customer, g, accountID, now)
		if _, ok := a.Metadata["member_count"]; !ok {
			memberGaps++
		}
		groups = append(groups, a)
	}
	if memberGaps > 0 {
		log.FromContext(ctx).Warn().Str("account_id", accountID).Int("groups", len(groups)).Int("members_unread", memberGaps).
			Msg("iam GetGroup failed for some groups — their member count is unknown this sweep")
	}
	return groups, policies, nil
}

// customerPolicyAsset renders one customer-managed policy, attached or not.
// doc is its default version's document, "" when the listing did not carry it.
func customerPolicyAsset(p iamtypes.ManagedPolicyDetail, accountID string, now time.Time) (asset.Asset, string) {
	arn := awssdk.ToString(p.Arn)
	name := awssdk.ToString(p.PolicyName)
	meta := map[string]string{
		"policy_name": name,
		"policy_arn":  arn,
		"account_id":  accountID,
		"managed_by":  "customer",
	}
	if p.AttachmentCount != nil {
		meta["attachment_count"] = strconv.Itoa(int(*p.AttachmentCount))
	}
	if p.PermissionsBoundaryUsageCount != nil {
		meta["boundary_usage_count"] = strconv.Itoa(int(*p.PermissionsBoundaryUsageCount))
	}
	doc := ""
	for _, v := range p.PolicyVersionList {
		if v.IsDefaultVersion {
			doc = decodePolicyDocument(awssdk.ToString(v.Document))
		}
	}
	if facts, ok := identityGrantFacts(doc); ok {
		maps.Copy(meta, policyGrantMetadata(facts))
	}
	return asset.Asset{
		ID: arn, Name: name, Type: "iam_policy", Provider: asset.ProviderAWS,
		Region: "global", AccountID: accountID, Metadata: meta,
		DiscoveredAt: now, LastSeen: now,
	}, doc
}

// groupAsset grades one group's policy set the way iam_principals.go grades a
// user's or role's: the grant keys only from a complete set, admin from the
// effective-permission evaluator.
func groupAsset(ctx context.Context, c iamAccountWideAPI, cache *managedPolicyCache, customer map[string]string, g iamtypes.GroupDetail, accountID string, now time.Time) asset.Asset {
	p := principalPolicies{complete: true}
	for _, ap := range g.AttachedManagedPolicies {
		arn := awssdk.ToString(ap.PolicyArn)
		doc, ok := customer[arn]
		if !ok {
			doc, ok = cache.document(ctx, arn)
		}
		p.addGroupManaged(awssdk.ToString(ap.PolicyName), arn, doc, ok)
	}
	for _, ip := range g.GroupPolicyList {
		p.addInline(awssdk.ToString(ip.PolicyName), awssdk.ToString(ip.PolicyDocument))
	}
	name := awssdk.ToString(g.GroupName)
	meta := map[string]string{"path": awssdk.ToString(g.Path)}
	maps.Copy(meta, p.grantMetadata())
	admin := isAdminish(ctx, name, p.docs)
	switch {
	case p.complete:
		meta["policies"] = encodePolicies(p.docs)
		meta["admin"] = strconv.FormatBool(admin)
	case admin:
		meta["admin"] = "true" // an admin grant seen in a partial set is still observed
	}
	if n, err := groupMemberCount(ctx, c, name); err == nil {
		meta["member_count"] = strconv.Itoa(n)
	}
	return asset.Asset{
		ID: awssdk.ToString(g.Arn), Name: name, Type: "iam_group", Provider: asset.ProviderAWS,
		Region: "global", AccountID: accountID, Metadata: meta,
		DiscoveredAt: now, LastSeen: now,
	}
}

// addGroupManaged is addManaged without the iam_policy asset and edge: the
// customer-managed policies are emitted from the authorization listing, and
// AWS-managed ones by the principals that hold them.
func (p *principalPolicies) addGroupManaged(name, arn, doc string, read bool) {
	if !read {
		p.complete = false
	}
	p.docs = append(p.docs, policyDoc{Name: name, Type: "identity", Managed: true, Document: doc})
	aws := isAWSManagedPolicyARN(arn)
	if aws && strings.HasSuffix(arn, ":policy/AWSCloudShellFullAccess") {
		p.cloudShell = true
	}
	if facts, ok := identityGrantFacts(doc); read && ok && facts.fullAdmin {
		if aws {
			p.otherFullAdmin = true
		} else {
			p.customerFullAdmin = true
		}
	}
}

func groupMemberCount(ctx context.Context, c iamAccountWideAPI, group string) (int, error) {
	n := 0
	for marker := (*string)(nil); ; {
		out, err := c.GetGroup(ctx, &iam.GetGroupInput{GroupName: &group, Marker: marker})
		if err != nil {
			return 0, fmt.Errorf("groupMemberCount: %w", err)
		}
		n += len(out.Users)
		if !out.IsTruncated {
			return n, nil
		}
		marker = out.Marker
	}
}

// readServerCertificates lists the IAM server certificates (CIS AWS 2.17).
func readServerCertificates(ctx context.Context, c iamAccountWideAPI, accountID string, now time.Time) ([]asset.Asset, error) {
	var out []asset.Asset
	for marker := (*string)(nil); ; {
		page, err := c.ListServerCertificates(ctx, &iam.ListServerCertificatesInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("readServerCertificates: iam:ListServerCertificates: %w", err)
		}
		for _, m := range page.ServerCertificateMetadataList {
			meta := map[string]string{"path": awssdk.ToString(m.Path)}
			if m.Expiration != nil {
				meta["expiration"] = m.Expiration.UTC().Format(time.RFC3339)
			}
			if m.UploadDate != nil {
				meta["upload_date"] = m.UploadDate.UTC().Format(time.RFC3339)
			}
			out = append(out, asset.Asset{
				ID: awssdk.ToString(m.Arn), Name: awssdk.ToString(m.ServerCertificateName), Type: "iam_server_certificate",
				Provider: asset.ProviderAWS, Region: "global", AccountID: accountID, Metadata: meta,
				DiscoveredAt: now, LastSeen: now,
			})
		}
		if !page.IsTruncated {
			return out, nil
		}
		marker = page.Marker
	}
}

// countPolicyRoles counts the roles a managed policy is attached to.
func countPolicyRoles(ctx context.Context, c iamAccountWideAPI, policyARN string) (int, error) {
	n := 0
	for marker := (*string)(nil); ; {
		page, err := c.ListEntitiesForPolicy(ctx, &iam.ListEntitiesForPolicyInput{
			PolicyArn: &policyARN, EntityFilter: iamtypes.EntityTypeRole, Marker: marker,
		})
		if err != nil {
			return 0, fmt.Errorf("countPolicyRoles: iam:ListEntitiesForPolicy %s: %w", policyARN, err)
		}
		n += len(page.PolicyRoles)
		if !page.IsTruncated {
			return n, nil
		}
		marker = page.Marker
	}
}
