package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// The aws_org connector's config keys this package reads (ADR 091). The
// connector domain validates them; this package only interprets them.
const (
	orgKeyHubAuth           = "hub_auth"
	orgKeyManagementRoleARN = "management_role_arn"
	orgKeyMemberRoleName    = "member_role_name"
	orgKeyExternalID        = "external_id"
	orgKeyHubRoleARN        = keyHubRoleARN

	hubAuthAccessKey = "access_key"

	// defaultMemberRoleName is the role deploy/aws/graph-readonly-role.yaml
	// creates in every member account.
	defaultMemberRoleName = "GraphReadOnly"

	// maxTestSample caps how many member roles a connection test assumes.
	maxTestSample = 10
)

// OrgAccount is one account as AWS Organizations lists it.
type OrgAccount struct {
	ID    string
	Name  string
	Email string
	// State is the Organizations account State (ACTIVE, SUSPENDED,
	// PENDING_CLOSURE, CLOSED, PENDING_ACTIVATION), or the retired Status
	// field's value when an older endpoint returns only that.
	State string
	// OUPath is the root-to-parent chain of ids (r-…, ou-…). OUPathKnown is
	// false when the walk was not requested or did not reach the account: an
	// empty path is not "in no OU".
	OUPath      []string
	OUPathKnown bool
}

// orgsAPI is the Organizations surface account discovery needs.
type orgsAPI interface {
	ListAccounts(context.Context, *organizations.ListAccountsInput, ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error)
	ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	ListOrganizationalUnitsForParent(context.Context, *organizations.ListOrganizationalUnitsForParentInput, ...func(*organizations.Options)) (*organizations.ListOrganizationalUnitsForParentOutput, error)
	ListAccountsForParent(context.Context, *organizations.ListAccountsForParentInput, ...func(*organizations.Options)) (*organizations.ListAccountsForParentOutput, error)
}

// hubSTSAPI is what the connection test calls as the hub identity.
type hubSTSAPI interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

// memberProbeAPI is the one read the connection test makes inside a member
// account, to tell "role assumed" from "role assumed but reads denied".
type memberProbeAPI interface {
	GetAccountSummary(context.Context, *iam.GetAccountSummaryInput, ...func(*iam.Options)) (*iam.GetAccountSummaryOutput, error)
}

// Org is the hub-side client for an aws_org connector: it lists the
// organization's accounts and tests the hub → member role chain. The factories
// exist so tests can substitute fakes for AWS.
type Org struct {
	hubConfig func(ctx context.Context, cfg map[string]string) (awssdk.Config, error)
	newOrgs   func(awssdk.Config) orgsAPI
	newSTS    func(awssdk.Config) hubSTSAPI
	newProbe  func(awssdk.Config) memberProbeAPI
}

// NewOrg returns an Org that calls AWS.
func NewOrg() *Org {
	return &Org{
		hubConfig: hubConfig,
		newOrgs:   func(c awssdk.Config) orgsAPI { return organizations.NewFromConfig(c, organizationsRetryer) },
		newSTS:    func(c awssdk.Config) hubSTSAPI { return sts.NewFromConfig(c) },
		newProbe:  func(c awssdk.Config) memberProbeAPI { return iam.NewFromConfig(c) },
	}
}

// organizationsRetryer gives Organizations adaptive retries. Its API is
// throttled hard (single-digit TPS per account) and the OU walk makes one call
// per OU back to back, so the standard three attempts give up on a large
// organization; adaptive mode also slows the client down rather than only
// retrying. A throttle that still exhausts this fails the listing as a whole,
// which changes no child.
//
// RetryMaxAttempts is cleared first: NewFromConfig wraps any Retryer in the
// ambient AWS_MAX_ATTEMPTS when it is non-zero (see route53Retryer).
func organizationsRetryer(o *organizations.Options) {
	o.RetryMaxAttempts = 0
	o.Retryer = retry.NewAdaptiveMode(func(ao *retry.AdaptiveModeOptions) {
		ao.StandardOptions = append(ao.StandardOptions, func(so *retry.StandardOptions) {
			so.MaxAttempts = 10
			so.MaxBackoff = 30 * time.Second
		})
	})
}

// hubConfig builds the hub identity's AWS config: Vulngraph's own ambient
// credentials (IRSA, EKS Pod Identity, instance role) by default, or the org
// connector's stored access key when hub_auth is access_key. With
// hub_role_arn set, those credentials are only the principal the hub role
// trusts, and the config is the hub role's session assumed from them.
func hubConfig(ctx context.Context, cfg map[string]string) (awssdk.Config, error) {
	region := cfg["region"]
	if region == "" {
		region = "us-east-1"
	}
	opts := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if cfg[orgKeyHubAuth] == hubAuthAccessKey {
		keyID, secret := cfg["aws_access_key_id"], cfg["aws_secret_access_key"]
		if keyID == "" || secret == "" {
			return awssdk.Config{}, fmt.Errorf("hubConfig: hub_auth=access_key requires aws_access_key_id and aws_secret_access_key")
		}
		// An IAM user's key is never itself a hub session: the roles in the
		// chain trust only the hub role, so it must assume hub_role_arn.
		if cfg[orgKeyHubRoleARN] == "" {
			return awssdk.Config{}, fmt.Errorf("hubConfig: hub_auth=access_key requires hub_role_arn")
		}
		opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(keyID, secret, "")))
	}
	out, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return awssdk.Config{}, fmt.Errorf("hubConfig: %w", err)
	}
	if hub := cfg[orgKeyHubRoleARN]; hub != "" {
		out = withHubRole(out, hub)
	}
	return out, nil
}

// managementConfig is the hub config re-credentialed as the management (or
// delegated-admin) account's discovery role, signed for the partition's
// global region because Organizations is a global service.
func (o *Org) managementConfig(hub awssdk.Config, cfg map[string]string) awssdk.Config {
	out := hub.Copy()
	out.Region = globalRegionFor(hub.Region)
	out.Credentials = awssdk.NewCredentialsCache(stscreds.NewAssumeRoleProvider(
		sts.NewFromConfig(hub), cfg[orgKeyManagementRoleARN], func(ao *stscreds.AssumeRoleOptions) {
			ao.ExternalID = awssdk.String(cfg[orgKeyExternalID])
		}))
	return out
}

// ListAccounts lists every account in the organization, in every state. Any
// failure — including one on a later page — fails the whole listing: a
// partial list would read as "these accounts left the organization".
//
// withOUs also walks the OU tree so each account carries its OU path; it is
// only needed to evaluate OU filters and costs one call per OU.
func (o *Org) ListAccounts(ctx context.Context, cfg map[string]string, withOUs bool) ([]OrgAccount, error) {
	if cfg[orgKeyManagementRoleARN] == "" {
		return nil, fmt.Errorf("ListAccounts: management_role_arn is required")
	}
	hub, err := o.hubConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("ListAccounts: %w", err)
	}
	client := o.newOrgs(o.managementConfig(hub, cfg))

	var accounts []OrgAccount
	var token *string
	for {
		out, err := client.ListAccounts(ctx, &organizations.ListAccountsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("ListAccounts: organizations:ListAccounts: %w", err)
		}
		for _, a := range out.Accounts {
			if id := awssdk.ToString(a.Id); id != "" {
				accounts = append(accounts, OrgAccount{
					ID: id, Name: awssdk.ToString(a.Name), Email: awssdk.ToString(a.Email), State: accountState(a),
				})
			}
		}
		if out.NextToken == nil {
			break
		}
		token = out.NextToken
	}
	if !withOUs {
		return accounts, nil
	}
	paths, err := ouPaths(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("ListAccounts: %w", err)
	}
	for i := range accounts {
		if p, ok := paths[accounts[i].ID]; ok {
			accounts[i].OUPath, accounts[i].OUPathKnown = p, true
		}
	}
	return accounts, nil
}

// accountState prefers State; Status was retired by AWS in September 2026 and
// is read only when State is absent.
func accountState(a orgtypes.Account) string {
	if a.State != "" {
		return string(a.State)
	}
	return string(a.Status)
}

// ouPaths walks the organization breadth-first from its root and returns each
// account's root-to-parent path.
func ouPaths(ctx context.Context, client orgsAPI) (map[string][]string, error) {
	roots, err := client.ListRoots(ctx, &organizations.ListRootsInput{})
	if err != nil {
		return nil, fmt.Errorf("ouPaths: organizations:ListRoots: %w", err)
	}
	type node struct {
		id   string
		path []string
	}
	var queue []node
	for _, r := range roots.Roots {
		id := awssdk.ToString(r.Id)
		queue = append(queue, node{id: id, path: []string{id}})
	}
	out := map[string][]string{}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		var token *string
		for {
			page, err := client.ListAccountsForParent(ctx, &organizations.ListAccountsForParentInput{ParentId: &n.id, NextToken: token})
			if err != nil {
				return nil, fmt.Errorf("ouPaths: organizations:ListAccountsForParent %s: %w", n.id, err)
			}
			for _, a := range page.Accounts {
				out[awssdk.ToString(a.Id)] = n.path
			}
			if page.NextToken == nil {
				break
			}
			token = page.NextToken
		}
		token = nil
		for {
			page, err := client.ListOrganizationalUnitsForParent(ctx, &organizations.ListOrganizationalUnitsForParentInput{ParentId: &n.id, NextToken: token})
			if err != nil {
				return nil, fmt.Errorf("ouPaths: organizations:ListOrganizationalUnitsForParent %s: %w", n.id, err)
			}
			for _, ou := range page.OrganizationalUnits {
				id := awssdk.ToString(ou.Id)
				child := append(append([]string{}, n.path...), id)
				queue = append(queue, node{id: id, path: child})
			}
			if page.NextToken == nil {
				break
			}
			token = page.NextToken
		}
	}
	return out, nil
}

// Member-check causes. STS answers a missing role, a trust policy that does
// not name the hub and a wrong ExternalId with the same AccessDenied, so those
// three share one cause; the detail says so.
const (
	CauseOK                  = "ok"
	CauseRoleMissingOrDenied = "role_missing_or_untrusted"
	CauseHubNotPermitted     = "hub_not_permitted"
	CauseSCPDeny             = "scp_deny"
	CauseReadsDenied         = "reads_denied"
	CauseHubCredentials      = "hub_credentials_invalid"
	CauseThrottled           = "throttled"
	CauseError               = "error"
)

// OrgTestResult is a connection test's outcome, step by step. A step that
// could not run because an earlier one failed is left with Ran false.
type OrgTestResult struct {
	HubOK       bool
	HubIdentity string
	HubError    string

	ListRan      bool
	ListOK       bool
	AccountCount int
	ListError    string

	Members []MemberCheck
}

// MemberCheck is the hub → member role chain tested in one account.
type MemberCheck struct {
	AccountID string
	OK        bool
	Cause     string
	Detail    string
}

// Test verifies an aws_org connector end to end: the hub credential works,
// the management role lists the organization, and the member role can be
// assumed (and read with) in a sample of active accounts. It never returns an
// error: every failure is a step result the caller shows.
func (o *Org) Test(ctx context.Context, cfg map[string]string) OrgTestResult {
	var res OrgTestResult
	hub, err := o.hubConfig(ctx, cfg)
	if err != nil {
		res.HubError = err.Error()
		return res
	}
	hubSTS := o.newSTS(hub)
	id, err := hubSTS.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		res.HubError = fmt.Sprintf("sts:GetCallerIdentity as the hub failed — graph has no working AWS identity: %v", err)
		return res
	}
	res.HubOK, res.HubIdentity = true, awssdk.ToString(id.Arn)

	res.ListRan = true
	accounts, err := o.ListAccounts(ctx, cfg, false)
	if err != nil {
		res.ListError = fmt.Sprintf("%s: %v", explainManagementErr(err), err)
		return res
	}
	res.ListOK, res.AccountCount = true, len(accounts)

	for _, acct := range testSample(accounts) {
		res.Members = append(res.Members, o.checkMember(ctx, hub, hubSTS, cfg, acct))
	}
	return res
}

// testSample picks the accounts a test assumes into: the first active ones by
// id, at most maxTestSample. The test is interactive and STS is rate-limited;
// the full fan-out is what the children's own syncs do.
func testSample(accounts []OrgAccount) []string {
	var out []string
	for _, a := range accounts {
		if a.State == string(orgtypes.AccountStateActive) {
			out = append(out, a.ID)
		}
	}
	sort.Strings(out)
	if len(out) > maxTestSample {
		out = out[:maxTestSample]
	}
	return out
}

func (o *Org) checkMember(ctx context.Context, hub awssdk.Config, hubSTS hubSTSAPI, cfg map[string]string, accountID string) MemberCheck {
	roleARN := memberRoleARN(cfg[orgKeyManagementRoleARN], accountID, cfg[orgKeyMemberRoleName])
	out, err := hubSTS.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         awssdk.String(roleARN),
		RoleSessionName: awssdk.String("graph-connection-test"),
		ExternalId:      awssdk.String(cfg[orgKeyExternalID]),
	})
	if err != nil {
		cause, detail := classifyAssumeErr(err)
		return MemberCheck{AccountID: accountID, Cause: cause, Detail: fmt.Sprintf("sts:AssumeRole %s: %s (%v)", roleARN, detail, err)}
	}
	member := hub.Copy()
	member.Region = globalRegionFor(hub.Region)
	member.Credentials = credentials.NewStaticCredentialsProvider(
		awssdk.ToString(out.Credentials.AccessKeyId), awssdk.ToString(out.Credentials.SecretAccessKey), awssdk.ToString(out.Credentials.SessionToken))
	if _, err := o.newProbe(member).GetAccountSummary(ctx, &iam.GetAccountSummaryInput{}); err != nil {
		cause := CauseError
		detail := "the role was assumed but iam:GetAccountSummary failed"
		switch {
		case isSCPDeny(err):
			cause, detail = CauseSCPDeny, "the role was assumed but a service control policy denies its reads"
		case isDenyErr(err):
			cause, detail = CauseReadsDenied, "the role was assumed but has no read permissions — attach SecurityAudit and ViewOnlyAccess"
		}
		return MemberCheck{AccountID: accountID, Cause: cause, Detail: fmt.Sprintf("%s (%v)", detail, err)}
	}
	return MemberCheck{AccountID: accountID, OK: true, Cause: CauseOK}
}

// memberRoleARN is the member role Vulngraph assumes in accountID, in the
// management role's partition. roleName defaults to defaultMemberRoleName.
func memberRoleARN(managementRoleARN, accountID, roleName string) string {
	if roleName == "" {
		roleName = defaultMemberRoleName
	}
	partition := "aws"
	if parts := strings.SplitN(managementRoleARN, ":", 3); len(parts) == 3 && parts[0] == "arn" && parts[1] != "" {
		partition = parts[1]
	}
	return fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, accountID, roleName)
}

// classifyAssumeErr names the likely cause of a failed sts:AssumeRole.
func classifyAssumeErr(err error) (cause, detail string) {
	switch {
	case isCredentialErr(err):
		return CauseHubCredentials, "AWS rejected the hub credential itself"
	case isSCPDeny(err):
		return CauseSCPDeny, "a service control policy denies the hub's sts:AssumeRole"
	case isDenyErr(err) && strings.Contains(err.Error(), "identity-based policy"):
		return CauseHubNotPermitted, "the hub role's own policy does not allow sts:AssumeRole on this role — deploy graph-hub-role.yaml with the same member role name"
	case isDenyErr(err):
		return CauseRoleMissingOrDenied, "the role is not deployed in this account, its trust policy does not name the hub role, or the ExternalId does not match (STS reports all three the same way)"
	case isThrottle(err):
		return CauseThrottled, "STS throttled the request — retry the test"
	}
	return CauseError, "the call failed"
}

// explainManagementErr names the likely cause of a failed ListAccounts.
func explainManagementErr(err error) string {
	switch {
	case isSCPDeny(err):
		return "a service control policy denies the management role's Organizations reads"
	case isDenyErr(err):
		return "the hub could not assume the management role, or the role lacks organizations:ListAccounts — check its trust policy, ExternalId and that it is in the management or delegated-admin account"
	case errors.Is(err, context.DeadlineExceeded):
		return "listing the organization timed out"
	}
	return "listing the organization failed"
}

// isSCPDeny reports whether AWS attributes a deny to a service control policy.
func isSCPDeny(err error) bool {
	return isDenyErr(err) && strings.Contains(err.Error(), "service control policy")
}

func isThrottle(err error) bool {
	switch awsErrCode(err) {
	case "Throttling", "ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded":
		return true
	}
	return false
}
