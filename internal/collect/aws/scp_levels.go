package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

func readSCPRootStatus(ctx context.Context, client orgAPI) (map[string]string, error) {
	roots := map[string]string{}
	var token *string
	seen := map[string]bool{}
	for {
		page, err := client.ListRoots(ctx, &organizations.ListRootsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("list roots: %w", err)
		}
		if page == nil {
			return nil, errors.New("list roots: empty response")
		}
		for _, root := range page.Roots {
			id := awssdk.ToString(root.Id)
			if id == "" {
				return nil, errors.New("list roots: missing root id")
			}
			status := "disabled" // PolicyTypes lists the types enabled at this root.
			seenSCP, malformed := false, false
			for _, policyType := range root.PolicyTypes {
				if policyType.Type == "" {
					malformed = true
				}
				if policyType.Type == orgtypes.PolicyTypeServiceControlPolicy {
					malformed = malformed || seenSCP
					seenSCP = true
					status = "unknown"
					if policyType.Status == orgtypes.PolicyTypeStatusEnabled {
						status = "enabled"
					}
				}
			}
			if malformed {
				status = "unknown"
			}
			if prior, duplicate := roots[id]; duplicate && prior != status {
				status = "unknown"
			}
			roots[id] = status
		}
		if page.NextToken == nil {
			if len(roots) == 0 {
				return nil, errors.New("list roots: no organization root observed")
			}
			return roots, nil
		}
		if seen[*page.NextToken] {
			return nil, errors.New("list roots: repeated pagination token")
		}
		seen[*page.NextToken] = true
		token = page.NextToken
	}
}

func collectMemberSCPs(ctx context.Context, client orgAPI, evidence ciem.AWSOrganizationEvidence, roots map[string]string, cache map[string]string) ciem.AWSOrganizationEvidence {
	// AWS currently has one root per organization. Only an observed single root
	// establishes its policy status before the account's parent walk completes.
	if len(roots) == 1 {
		for id, status := range roots {
			evidence.RootID, evidence.RootSCPStatus = id, status
		}
		if evidence.RootSCPStatus == "disabled" {
			evidence.Applicability, evidence.Reason, evidence.Complete = "exempt", "disabled", true
			return evidence
		}
	}
	evidence.Levels, evidence.Complete = readSCPLevels(ctx, client, evidence.AccountID, cache)
	if len(evidence.Levels) > 0 {
		last := evidence.Levels[len(evidence.Levels)-1]
		if status, ok := roots[last.TargetID]; ok {
			evidence.RootID, evidence.RootSCPStatus = last.TargetID, status
		}
	}
	switch evidence.RootSCPStatus {
	case "enabled":
		evidence.Applicability = "member"
	case "disabled":
		evidence.Applicability, evidence.Reason, evidence.Complete = "exempt", "disabled", true
	default:
		evidence.Complete = false
	}
	return evidence
}

func readSCPLevels(ctx context.Context, client orgAPI, account string, cache map[string]string) ([]ciem.SCPLevel, bool) {
	var levels []ciem.SCPLevel
	visited := map[string]bool{}
	target := account
	complete := true
	for target != "" && !visited[target] {
		visited[target] = true
		level := readSCPLevel(ctx, client, target, cache)
		complete = complete && level.Complete
		if strings.HasPrefix(target, "r-") {
			return append(levels, level), complete
		}
		parents, err := client.ListParents(ctx, &organizations.ListParentsInput{ChildId: awssdk.String(target)})
		if err != nil || parents == nil || len(parents.Parents) != 1 {
			return append(levels, level), false
		}
		level.ParentID = awssdk.ToString(parents.Parents[0].Id)
		levels = append(levels, level)
		target = level.ParentID
	}
	return levels, false
}

func readSCPLevel(ctx context.Context, client orgAPI, target string, cache map[string]string) ciem.SCPLevel {
	level := ciem.SCPLevel{TargetID: target, Complete: true, Policies: []ciem.SCPPolicyDocument{}}
	seenPolicies, seenTokens := map[string]bool{}, map[string]bool{}
	var token *string
	for {
		page, err := client.ListPoliciesForTarget(ctx, &organizations.ListPoliciesForTargetInput{TargetId: awssdk.String(target), Filter: orgtypes.PolicyTypeServiceControlPolicy, NextToken: token})
		if err != nil || page == nil {
			level.Complete = false
			return level
		}
		for _, policy := range page.Policies {
			id := awssdk.ToString(policy.Id)
			if id == "" {
				level.Complete = false
				continue
			}
			if seenPolicies[id] {
				continue
			}
			seenPolicies[id] = true
			document := cache[id]
			if document == "" {
				document = describeSCP(ctx, client, id)
				if document != "" {
					cache[id] = document
				}
			}
			missing := document == ""
			level.Complete = level.Complete && !missing
			level.Policies = append(level.Policies, ciem.SCPPolicyDocument{Name: awssdk.ToString(policy.Name), Document: document, Incomplete: missing})
		}
		if page.NextToken == nil {
			return level
		}
		if seenTokens[*page.NextToken] {
			level.Complete = false
			return level
		}
		seenTokens[*page.NextToken] = true
		token = page.NextToken
	}
}
