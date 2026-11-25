package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

// scpAssetPrefix keys the per-account SCP asset so the CIEM consumer can look it
// up by "aws_scp:<accountID>".
const scpAssetPrefix = "aws_scp:"

// orgAPI is the slice of AWS Organizations the SCP collector needs. Only the
// management or a delegated-admin account can read the hierarchy. Ordinary
// member accounts can still observe their own DescribeOrganization identity.
type orgAPI interface {
	ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
	ListAccounts(context.Context, *organizations.ListAccountsInput, ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error)
	ListParents(context.Context, *organizations.ListParentsInput, ...func(*organizations.Options)) (*organizations.ListParentsOutput, error)
	ListPoliciesForTarget(context.Context, *organizations.ListPoliciesForTargetInput, ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error)
	DescribePolicy(context.Context, *organizations.DescribePolicyInput, ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
}

// collectSCPs observes organization membership and per-level SCP attachments.
// Management/delegated-admin connectors persist policy context for member
// accounts. Other connectors can still observe their own membership, or a
// positive standalone exemption, without having permission to read the hierarchy.
// Missing hierarchy inventory remains unknown at the analysis boundary.
func collectSCPs(ctx context.Context, cfg map[string]string, accountID string, now time.Time) ([]asset.Asset, string, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, "", fmt.Errorf("collectSCPs: %w", err)
	}
	awsCfg.Region = globalRegionFor(awsCfg.Region) // Organizations is global, homed per partition
	client := organizations.NewFromConfig(awsCfg)
	return collectSCPsForAccountWithMembership(ctx, client, accountID, now)
}

func collectSCPsWith(ctx context.Context, client orgAPI, now time.Time) ([]asset.Asset, error) {
	return collectSCPsForAccount(ctx, client, "", now)
}

func collectSCPsForAccount(ctx context.Context, client orgAPI, accountID string, now time.Time) ([]asset.Asset, error) {
	assets, _, err := collectSCPsForAccountWithMembership(ctx, client, accountID, now)
	return assets, err
}

func collectSCPsForAccountWithMembership(ctx context.Context, client orgAPI, accountID string, now time.Time) ([]asset.Asset, string, error) {
	org, err := client.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "AWSOrganizationsNotInUseException" && accountID != "" {
			evidence := ciem.AWSOrganizationEvidence{AccountID: accountID, Applicability: "exempt", Reason: "standalone", Complete: true, ObservedAt: now}
			return []asset.Asset{scpEvidenceAsset(evidence, now)}, encodeMembership(evidence), nil
		}
		return nil, "", fmt.Errorf("collectSCPs: organization membership unknown: %w", err)
	}
	if org == nil || org.Organization == nil || awssdk.ToString(org.Organization.MasterAccountId) == "" {
		return nil, "", errors.New("collectSCPs: management account identity missing")
	}
	management := awssdk.ToString(org.Organization.MasterAccountId)
	membership := encodeMembership(ciem.AWSOrganizationEvidence{AccountID: accountID, ManagementAccountID: management, ObservedAt: now})
	var out []asset.Asset
	if accountID == management {
		out = append(out, scpEvidenceAsset(ciem.AWSOrganizationEvidence{AccountID: management, ManagementAccountID: management, Applicability: "exempt", Reason: "management", Complete: true}, now))
	}
	roots, err := readSCPRootStatus(ctx, client)
	if err != nil {
		if isOrgNoOpErr(err) {
			return out, membership, nil // a member's denied inventory read proves no exemption
		}
		return out, membership, fmt.Errorf("collectSCPs: roots: %w", err)
	}
	docCache := map[string]string{}
	var token *string
	seenTokens := map[string]bool{}
	for {
		page, err := client.ListAccounts(ctx, &organizations.ListAccountsInput{NextToken: token})
		if err != nil || page == nil {
			return out, membership, fmt.Errorf("collectSCPs: list accounts incomplete: %v", err)
		}
		for _, account := range page.Accounts {
			id := awssdk.ToString(account.Id)
			if id == "" || id == accountID && id == management {
				continue
			}
			if state := accountState(account); state != "" && state != string(orgtypes.AccountStateActive) {
				continue
			}
			evidence := ciem.AWSOrganizationEvidence{AccountID: id, ManagementAccountID: management, Applicability: "unknown"}
			if id == management {
				evidence.Applicability, evidence.Reason, evidence.Complete = "exempt", "management", true
			} else {
				evidence = collectMemberSCPs(ctx, client, evidence, roots, docCache)
			}
			out = append(out, scpEvidenceAsset(evidence, now))
		}
		if page.NextToken == nil {
			return out, membership, nil
		}
		if seenTokens[*page.NextToken] {
			return out, membership, errors.New("collectSCPs: repeated account pagination token")
		}
		seenTokens[*page.NextToken] = true
		token = page.NextToken
	}
}

func scpEvidenceAsset(evidence ciem.AWSOrganizationEvidence, now time.Time) asset.Asset {
	evidence.ObservedAt = now
	var documents []policyDoc
	seen := map[string]bool{}
	for _, level := range evidence.Levels {
		for _, policy := range level.Policies {
			key := policy.Name + "\x00" + policy.Document
			if seen[key] {
				continue
			}
			seen[key] = true
			documents = append(documents, policyDoc{Name: policy.Name, Type: "scp", Managed: true, Document: policy.Document, Incomplete: policy.Incomplete})
		}
	}
	raw, _ := json.Marshal(evidence)
	return asset.Asset{
		ID: scpAssetPrefix + evidence.AccountID, Name: "SCPs for " + evidence.AccountID,
		Type: "aws_scp_set", Provider: asset.ProviderAWS, Region: "global", AccountID: evidence.AccountID,
		Metadata: map[string]string{
			ciem.MetaAWSOrganization: string(raw), "policies": encodePolicies(documents),
			"policy_count": strconv.Itoa(len(documents)), "policies_complete": strconv.FormatBool(evidence.Complete),
		},
		DiscoveredAt: now, LastSeen: now,
	}
}

// isOrgNoOpErr reports whether an Organizations error means "this account can't
// use Organizations" (not the management/delegated-admin account, or the org
// isn't in use) — the clean no-op case, distinct from a transient failure.
func isOrgNoOpErr(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "AccessDeniedException", "AWSOrganizationsNotInUseException":
		return true
	}
	return false
}

// describeSCP fetches a policy document by id. Best-effort: an error yields "".
func describeSCP(ctx context.Context, client orgAPI, policyID string) string {
	out, err := client.DescribePolicy(ctx, &organizations.DescribePolicyInput{PolicyId: awssdk.String(policyID)})
	if err != nil || out == nil || out.Policy == nil {
		return ""
	}
	return awssdk.ToString(out.Policy.Content)
}

// The member connector observes its own organization even when only management
// can read the policy hierarchy. Keep this witness on its principals, separately
// from persisted management-owned policy inventory, so a join/move immediately
// invalidates a contradictory old exemption without replacing valid SCPs.
func encodeMembership(evidence ciem.AWSOrganizationEvidence) string {
	if evidence.AccountID == "" {
		return ""
	}
	raw, _ := json.Marshal(evidence)
	return string(raw)
}

func stampOrganizationMembership(assets []asset.Asset, accountID, membership string) {
	for i := range assets {
		a := &assets[i]
		if a.Provider != asset.ProviderAWS || a.AccountID != accountID || (a.Type != "iam_user" && a.Type != "iam_role") {
			continue
		}
		metadata := make(map[string]string, len(a.Metadata)+1)
		for key, value := range a.Metadata {
			metadata[key] = value
		}
		metadata[ciem.MetaAWSOrganizationMembership] = membership
		a.Metadata = metadata
	}
}
