package ciem

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

const (
	// PolicyAWSOrganization is inventory evidence, not an IAM policy document.
	PolicyAWSOrganization         = "aws_organization"
	MetaAWSOrganization           = "organization_policies"
	MetaAWSOrganizationComplete   = "organization_policy_complete"
	MetaAWSOrganizationMembership = "organization_membership"
	// The scheduler backs unchanged connectors off to 12h; tolerate one missed
	// cycle, then stop using persisted restrictions or exemptions as proof.
	AWSOrganizationMaxAge = 24 * time.Hour
)

// AWSOrganizationPolicies is shared by CIEM and correlation. No inventory row
// is unknown, not proof of absent guardrails. Unknown applicability cannot
// apply a member-only Deny to an exempt principal.
func AWSOrganizationPolicies(principal asset.Asset, contexts []Policy) ([]Policy, bool) {
	return awsOrganizationPoliciesAt(principal, contexts, time.Now())
}

func awsOrganizationPoliciesAt(principal asset.Asset, contexts []Policy, now time.Time) ([]Policy, bool) {
	if isAWSServiceLinkedRole(principal) {
		return nil, true
	}
	unknown := []Policy{{Type: PolicySCP, Incomplete: true}}
	var raw string
	for _, context := range contexts {
		if context.Type != PolicyAWSOrganization || context.Document == "" || raw != "" && raw != context.Document {
			return unknown, false
		}
		raw = context.Document
	}
	var evidence AWSOrganizationEvidence
	if raw == "" || json.Unmarshal([]byte(raw), &evidence) != nil || evidence.AccountID == "" || evidence.AccountID != principal.AccountID {
		return unknown, false
	}
	if !organizationEvidenceFresh(evidence.ObservedAt, now) {
		return unknown, false
	}
	if rawMembership := principal.Metadata[MetaAWSOrganizationMembership]; rawMembership != "" {
		var membership AWSOrganizationEvidence
		if json.Unmarshal([]byte(rawMembership), &membership) != nil || membership.AccountID != principal.AccountID ||
			!organizationEvidenceFresh(membership.ObservedAt, now) {
			return unknown, false
		}
		if membership.ManagementAccountID != evidence.ManagementAccountID ||
			(membership.Reason == "standalone") != (evidence.Reason == "standalone") {
			return unknown, false
		}
	}
	if evidence.Applicability == "exempt" && evidence.Complete {
		switch evidence.Reason {
		case "management":
			if evidence.ManagementAccountID == evidence.AccountID {
				return nil, true
			}
		case "standalone":
			return nil, true
		case "disabled":
			if evidence.RootID != "" && evidence.RootSCPStatus == "disabled" {
				return nil, true
			}
		}
		return unknown, false
	}
	if evidence.Applicability != "member" || evidence.ManagementAccountID == "" || evidence.ManagementAccountID == evidence.AccountID ||
		evidence.RootID == "" || evidence.RootSCPStatus != "enabled" || len(evidence.Levels) == 0 {
		return unknown, false
	}
	complete := evidence.Complete
	byTarget := map[string]SCPLevel{}
	for _, level := range evidence.Levels {
		if _, duplicate := byTarget[level.TargetID]; duplicate || level.TargetID == "" {
			return unknown, false
		}
		byTarget[level.TargetID] = level
	}
	seen := map[string]bool{}
	target := evidence.AccountID
	var policies []Policy
	rootSeen := false
	for target != "" {
		level, present := byTarget[target]
		if !present {
			complete = false
			break
		}
		if seen[target] {
			return unknown, false
		}
		seen[target] = true
		if target == evidence.RootID {
			if level.ParentID != "" {
				return unknown, false
			}
			rootSeen = true
		}
		level.Complete = level.Complete && level.Policies != nil
		complete = complete && level.Complete
		for _, document := range level.Policies {
			statements, err := ParseAWSPolicy(document.Document)
			if document.Incomplete || err != nil || len(statements) == 0 {
				complete = false
			}
		}
		policies = append(policies, Policy{Type: PolicySCP, SCPLevel: &level})
		target = level.ParentID
	}
	if len(seen) != len(byTarget) {
		return unknown, false // disconnected observations do not establish ancestry
	}
	complete = complete && rootSeen
	if !complete {
		policies = append(policies, Policy{Type: PolicySCP, Incomplete: true})
	}
	return policies, complete
}

// The reserved ARN path and reserved role-name prefix identify service-linked
// roles; a service trust principal or a generic /service-role/ path does not.
func isAWSServiceLinkedRole(a asset.Asset) bool {
	// Correlation projects type and ARN but omits Provider. The reserved ARN
	// validates an absent provider; an explicitly conflicting provider is rejected.
	if a.Type != "iam_role" || a.Provider != "" && a.Provider != asset.ProviderAWS {
		return false
	}
	arn := strings.SplitN(a.ID, ":", 6)
	if len(arn) != 6 || arn[0] != "arn" || arn[1] == "" || arn[2] != "iam" || arn[3] != "" || arn[4] == "" || arn[4] != a.AccountID {
		return false
	}
	parts := strings.Split(arn[5], "/")
	if len(parts) != 4 || parts[0] != "role" || parts[1] != "aws-service-role" || parts[2] == "" ||
		!strings.HasPrefix(parts[3], "AWSServiceRoleFor") || parts[3] == "AWSServiceRoleFor" || strings.ContainsAny(arn[5], "*?${") {
		return false
	}
	path := "/aws-service-role/" + parts[2] + "/"
	return a.Metadata["path"] == "" || a.Metadata["path"] == path
}

// StampAWSOrganizationCoverage copies metadata so shared input maps cannot leak
// a verdict from one principal into another.
func StampAWSOrganizationCoverage(assets []asset.Asset, coverage map[string]bool) {
	for i := range assets {
		complete, ok := coverage[assets[i].ID]
		if !ok {
			continue
		}
		metadata := make(map[string]string, len(assets[i].Metadata)+1)
		for key, value := range assets[i].Metadata {
			metadata[key] = value
		}
		metadata[MetaAWSOrganizationComplete] = "false"
		if complete {
			metadata[MetaAWSOrganizationComplete] = "true"
		}
		assets[i].Metadata = metadata
	}
}

func organizationEvidenceFresh(observed, now time.Time) bool {
	return !observed.IsZero() && !observed.After(now.Add(5*time.Minute)) && now.Sub(observed) <= AWSOrganizationMaxAge
}
