package aws

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// AWS Organizations posture (CIS AWS 2.1.1, 2.1.2, 2.1.5, 2.1.6). Like the SCP
// collector (scp.go) it runs on every AWS connector and does anything only on
// the one that can read Organizations — the management account, or the
// Organizations delegated administrator. Every other connector sees
// AccessDenied on ListRoots and emits nothing, so a sweep that never reaches
// the management account leaves these controls unknown, never passing.
//
// It emits one aws_organization asset (organization-wide settings) and one
// aws_org_account asset per active member account (its guardrails), so an
// organization-wide gap is one finding, not one per account.

const (
	orgPostureType        = "aws_organization"
	orgAccountPostureType = "aws_org_account"
)

type orgPostureAPI interface {
	ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
	ListAccounts(context.Context, *organizations.ListAccountsInput, ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error)
	ListParents(context.Context, *organizations.ListParentsInput, ...func(*organizations.Options)) (*organizations.ListParentsOutput, error)
	ListPoliciesForTarget(context.Context, *organizations.ListPoliciesForTargetInput, ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error)
	DescribeResourcePolicy(context.Context, *organizations.DescribeResourcePolicyInput, ...func(*organizations.Options)) (*organizations.DescribeResourcePolicyOutput, error)
	ListAWSServiceAccessForOrganization(context.Context, *organizations.ListAWSServiceAccessForOrganizationInput, ...func(*organizations.Options)) (*organizations.ListAWSServiceAccessForOrganizationOutput, error)
	ListDelegatedAdministrators(context.Context, *organizations.ListDelegatedAdministratorsInput, ...func(*organizations.Options)) (*organizations.ListDelegatedAdministratorsOutput, error)
	ListDelegatedServicesForAccount(context.Context, *organizations.ListDelegatedServicesForAccountInput, ...func(*organizations.Options)) (*organizations.ListDelegatedServicesForAccountOutput, error)
}

type orgFeaturesAPI interface {
	ListOrganizationsFeatures(context.Context, *iam.ListOrganizationsFeaturesInput, ...func(*iam.Options)) (*iam.ListOrganizationsFeaturesOutput, error)
}

// delegableSecurityServices are the security services that support a
// delegated administrator, keyed by the trusted-access principal
// ListAWSServiceAccessForOrganization reports; the value is the principal a
// delegation is registered under (AWS Config registers either spelling).
var delegableSecurityServices = map[string][]string{
	"access-analyzer.amazonaws.com":          {"access-analyzer.amazonaws.com"},
	"auditmanager.amazonaws.com":             {"auditmanager.amazonaws.com"},
	"backup.amazonaws.com":                   {"backup.amazonaws.com"},
	"cloudtrail.amazonaws.com":               {"cloudtrail.amazonaws.com"},
	"config.amazonaws.com":                   {"config.amazonaws.com", "config-multiaccountsetup.amazonaws.com"},
	"config-multiaccountsetup.amazonaws.com": {"config.amazonaws.com", "config-multiaccountsetup.amazonaws.com"},
	"detective.amazonaws.com":                {"detective.amazonaws.com"},
	"fms.amazonaws.com":                      {"fms.amazonaws.com"},
	"guardduty.amazonaws.com":                {"guardduty.amazonaws.com"},
	"iam.amazonaws.com":                      {"iam.amazonaws.com"},
	"inspector2.amazonaws.com":               {"inspector2.amazonaws.com"},
	"macie.amazonaws.com":                    {"macie.amazonaws.com"},
	"securityhub.amazonaws.com":              {"securityhub.amazonaws.com"},
	"securitylake.amazonaws.com":             {"securitylake.amazonaws.com"},
	"security-ir.amazonaws.com":              {"security-ir.amazonaws.com"},
	"sso.amazonaws.com":                      {"sso.amazonaws.com"},
}

// orgPolicyManagementActions are the Organizations actions a policy-management
// delegation (CIS AWS 2.1.5) grants through the organization's resource policy.
var orgPolicyManagementActions = []string{
	"organizations:createpolicy", "organizations:updatepolicy", "organizations:attachpolicy",
	"organizations:detachpolicy", "organizations:deletepolicy",
}

// defaultGuardrail is the AWS-managed policy Organizations attaches to every
// root, OU and account when a policy type is enabled; it restricts nothing.
var defaultGuardrail = map[orgtypes.PolicyType]string{
	orgtypes.PolicyTypeServiceControlPolicy:  "FullAWSAccess",
	orgtypes.PolicyTypeResourceControlPolicy: "RCPFullAWSAccess",
}

func collectOrgPosture(ctx context.Context, cfg map[string]string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectOrgPosture: %w", err)
	}
	awsCfg.Region = globalRegionFor(awsCfg.Region)
	return readOrgPosture(ctx, organizations.NewFromConfig(awsCfg, organizationsRetryer), iam.NewFromConfig(awsCfg), now)
}

// readOrgPosture errors only when the eligibility probe or the organization or
// account listing fails; a failed per-setting read leaves its key absent.
func readOrgPosture(ctx context.Context, c orgPostureAPI, features orgFeaturesAPI, now time.Time) ([]asset.Asset, error) {
	roots, err := c.ListRoots(ctx, &organizations.ListRootsInput{})
	if err != nil {
		if isOrgNoOpErr(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("readOrgPosture: organizations:ListRoots: %w", err)
	}
	org, err := c.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil || org.Organization == nil {
		return nil, fmt.Errorf("readOrgPosture: organizations:DescribeOrganization: %w", orEmpty(err))
	}
	orgID := awssdk.ToString(org.Organization.Id)
	mgmt := awssdk.ToString(org.Organization.MasterAccountId)

	enabled := map[orgtypes.PolicyType]bool{}
	for _, r := range roots.Roots {
		for _, pt := range r.PolicyTypes {
			if pt.Status == orgtypes.PolicyTypeStatusEnabled {
				enabled[pt.Type] = true
			}
		}
	}

	var gaps []string
	meta := map[string]string{
		"organization_id":       orgID,
		"management_account_id": mgmt,
		"scp_enabled":           strconv.FormatBool(enabled[orgtypes.PolicyTypeServiceControlPolicy]),
		"rcp_enabled":           strconv.FormatBool(enabled[orgtypes.PolicyTypeResourceControlPolicy]),
	}
	if kv, err := rootAccessFeatures(ctx, features); err != nil {
		gaps = append(gaps, err.Error())
	} else {
		maps.Copy(meta, kv)
	}
	if v, err := policyManagementDelegated(ctx, c); err != nil {
		gaps = append(gaps, err.Error())
	} else {
		meta["policy_management_delegated"] = v
	}
	if kv, err := securityServiceDelegation(ctx, c); err != nil {
		gaps = append(gaps, err.Error())
	} else {
		maps.Copy(meta, kv)
	}
	out := []asset.Asset{{
		ID: "aws_org:" + orgID, Name: "Organization " + orgID, Type: orgPostureType,
		Provider: asset.ProviderAWS, Region: "global", AccountID: mgmt, Metadata: meta,
		DiscoveredAt: now, LastSeen: now,
	}}

	accounts, err := activeMemberAccounts(ctx, c, mgmt)
	if err != nil {
		return nil, fmt.Errorf("readOrgPosture: %w", err)
	}
	w := &guardrailWalker{c: c, parent: map[string]string{}, attached: map[string]bool{}}
	for _, r := range roots.Roots {
		w.parent[awssdk.ToString(r.Id)] = "" // the walk ends at a root; ListParents does not accept one
	}
	walkGaps := 0
	for _, acct := range accounts {
		am := map[string]string{
			"scp_enabled": meta["scp_enabled"],
			"rcp_enabled": meta["rcp_enabled"],
		}
		for pt, key := range map[orgtypes.PolicyType]string{
			orgtypes.PolicyTypeServiceControlPolicy:  "scp_guardrail",
			orgtypes.PolicyTypeResourceControlPolicy: "rcp_guardrail",
		} {
			if !enabled[pt] {
				am[key] = "false" // nothing of this type can be attached
				continue
			}
			has, err := w.hasGuardrail(ctx, acct, pt)
			if err != nil {
				walkGaps++
				continue
			}
			am[key] = strconv.FormatBool(has)
		}
		out = append(out, asset.Asset{
			ID: "aws_org_account:" + acct, Name: "Organization account " + acct, Type: orgAccountPostureType,
			Provider: asset.ProviderAWS, Region: "global", AccountID: acct, Metadata: am,
			DiscoveredAt: now, LastSeen: now,
		})
	}
	if walkGaps > 0 {
		gaps = append(gaps, fmt.Sprintf("%d account guardrail walks failed (organizations:ListParents / ListPoliciesForTarget)", walkGaps))
	}
	if len(gaps) > 0 {
		log.FromContext(ctx).Warn().Str("organization_id", orgID).Strs("unread", gaps).
			Msg("aws organizations posture partly unread; the affected keys are unknown this sweep")
	}
	return out, nil
}

// rootAccessFeatures reads centralized root access (CIS AWS 2.1.1). IAM must
// be called from the management account or IAM's delegated administrator;
// from any other account the answer is unknown. Trusted access for IAM not
// enabled is an observation: the features cannot be on.
func rootAccessFeatures(ctx context.Context, c orgFeaturesAPI) (map[string]string, error) {
	out, err := c.ListOrganizationsFeatures(ctx, &iam.ListOrganizationsFeaturesInput{})
	switch {
	case err == nil:
		return map[string]string{
			"root_credentials_management": strconv.FormatBool(slices.Contains(out.EnabledFeatures, iamtypes.FeatureTypeRootCredentialsManagement)),
			"root_sessions":               strconv.FormatBool(slices.Contains(out.EnabledFeatures, iamtypes.FeatureTypeRootSessions)),
		}, nil
	case awsErrCode(err) == "ServiceAccessNotEnabledException":
		return map[string]string{"root_credentials_management": "false", "root_sessions": "false"}, nil
	}
	return nil, fmt.Errorf("iam:ListOrganizationsFeatures: %w", err)
}

// policyManagementDelegated reports whether the organization's resource policy
// delegates policy management (CIS AWS 2.1.5). No resource policy at all is
// the observation "not delegated".
func policyManagementDelegated(ctx context.Context, c orgPostureAPI) (string, error) {
	out, err := c.DescribeResourcePolicy(ctx, &organizations.DescribeResourcePolicyInput{})
	if err != nil {
		if awsErrCode(err) == "ResourcePolicyNotFoundException" {
			return "false", nil
		}
		return "", fmt.Errorf("organizations:DescribeResourcePolicy: %w", err)
	}
	if out.ResourcePolicy == nil {
		return "", errors.New("organizations:DescribeResourcePolicy: empty response")
	}
	doc := awssdk.ToString(out.ResourcePolicy.Content)
	for _, s := range resourcePolicyStatements(doc) {
		if !strings.EqualFold(s.Effect, "Allow") || len(s.Principal) == 0 {
			continue
		}
		for _, p := range resourcePolicyActionPatterns(s.Action) {
			for _, a := range orgPolicyManagementActions {
				if ok, _ := path.Match(p, a); ok {
					return "true", nil
				}
			}
		}
	}
	return "false", nil
}

// securityServiceDelegation lists the security services with trusted access
// enabled that support a delegated administrator but have none (CIS AWS
// 2.1.6). Any failed page leaves both keys unread.
func securityServiceDelegation(ctx context.Context, c orgPostureAPI) (map[string]string, error) {
	var trusted []string
	for token := (*string)(nil); ; {
		page, err := c.ListAWSServiceAccessForOrganization(ctx, &organizations.ListAWSServiceAccessForOrganizationInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("organizations:ListAWSServiceAccessForOrganization: %w", err)
		}
		for _, s := range page.EnabledServicePrincipals {
			if p := awssdk.ToString(s.ServicePrincipal); delegableSecurityServices[p] != nil {
				trusted = append(trusted, p)
			}
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	delegated := map[string]bool{}
	admins := 0
	for token := (*string)(nil); ; {
		page, err := c.ListDelegatedAdministrators(ctx, &organizations.ListDelegatedAdministratorsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("organizations:ListDelegatedAdministrators: %w", err)
		}
		for _, d := range page.DelegatedAdministrators {
			if st := delegatedAdminState(d); st != "" && st != string(orgtypes.AccountStateActive) {
				continue // a closed account administers nothing
			}
			admins++
			svcs, err := delegatedServices(ctx, c, awssdk.ToString(d.Id))
			if err != nil {
				return nil, err
			}
			for _, s := range svcs {
				delegated[s] = true
			}
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	var undelegated []string
	for _, p := range trusted {
		if !slices.ContainsFunc(delegableSecurityServices[p], func(d string) bool { return delegated[d] }) {
			undelegated = append(undelegated, p)
		}
	}
	sort.Strings(trusted)
	sort.Strings(undelegated)
	return map[string]string{
		"trusted_security_services":     strings.Join(trusted, ","),
		"undelegated_security_services": strings.Join(undelegated, ","),
		"delegated_admin_count":         strconv.Itoa(admins),
	}, nil
}

func delegatedAdminState(d orgtypes.DelegatedAdministrator) string {
	if d.State != "" {
		return string(d.State)
	}
	return string(d.Status)
}

func delegatedServices(ctx context.Context, c orgPostureAPI, account string) ([]string, error) {
	var out []string
	for token := (*string)(nil); ; {
		page, err := c.ListDelegatedServicesForAccount(ctx, &organizations.ListDelegatedServicesForAccountInput{AccountId: &account, NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("organizations:ListDelegatedServicesForAccount %s: %w", account, err)
		}
		for _, s := range page.DelegatedServices {
			out = append(out, awssdk.ToString(s.ServicePrincipal))
		}
		if page.NextToken == nil {
			return out, nil
		}
		token = page.NextToken
	}
}

// activeMemberAccounts lists the organization's ACTIVE accounts other than
// the management account, which SCPs and RCPs never restrict.
func activeMemberAccounts(ctx context.Context, c orgPostureAPI, mgmt string) ([]string, error) {
	var out []string
	for token := (*string)(nil); ; {
		page, err := c.ListAccounts(ctx, &organizations.ListAccountsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("organizations:ListAccounts: %w", err)
		}
		for _, a := range page.Accounts {
			id := awssdk.ToString(a.Id)
			if id == "" || id == mgmt || accountState(a) != string(orgtypes.AccountStateActive) {
				continue
			}
			out = append(out, id)
		}
		if page.NextToken == nil {
			return out, nil
		}
		token = page.NextToken
	}
}

// guardrailWalker answers "does any policy other than the default full-access
// one apply to this account" by walking account → OUs → root, caching each
// target's parent and verdict so a shared OU is read once per sweep.
type guardrailWalker struct {
	c        orgPostureAPI
	parent   map[string]string // child → parent ("" at the root)
	attached map[string]bool   // policyType/target → a non-default policy is attached
}

func (w *guardrailWalker) hasGuardrail(ctx context.Context, target string, pt orgtypes.PolicyType) (bool, error) {
	for seen := 0; target != "" && seen < 10; seen++ { // Organizations nests at most 5 OUs deep
		has, err := w.targetHasGuardrail(ctx, target, pt)
		if err != nil || has {
			return has, err
		}
		next, err := w.parentOf(ctx, target)
		if err != nil {
			return false, err
		}
		target = next
	}
	return false, nil
}

func (w *guardrailWalker) targetHasGuardrail(ctx context.Context, target string, pt orgtypes.PolicyType) (bool, error) {
	key := string(pt) + "/" + target
	if v, ok := w.attached[key]; ok {
		return v, nil
	}
	has := false
	for token := (*string)(nil); ; {
		page, err := w.c.ListPoliciesForTarget(ctx, &organizations.ListPoliciesForTargetInput{TargetId: &target, Filter: pt, NextToken: token})
		if err != nil {
			return false, fmt.Errorf("organizations:ListPoliciesForTarget %s: %w", target, err)
		}
		for _, p := range page.Policies {
			if !p.AwsManaged || awssdk.ToString(p.Name) != defaultGuardrail[pt] {
				has = true
			}
		}
		if page.NextToken == nil {
			break
		}
		token = page.NextToken
	}
	w.attached[key] = has
	return has, nil
}

func (w *guardrailWalker) parentOf(ctx context.Context, child string) (string, error) {
	if p, ok := w.parent[child]; ok {
		return p, nil
	}
	out, err := w.c.ListParents(ctx, &organizations.ListParentsInput{ChildId: &child})
	if err != nil {
		return "", fmt.Errorf("organizations:ListParents %s: %w", child, err)
	}
	p := ""
	if len(out.Parents) > 0 {
		p = awssdk.ToString(out.Parents[0].Id)
	}
	if p == child {
		p = ""
	}
	w.parent[child] = p
	return p, nil
}
