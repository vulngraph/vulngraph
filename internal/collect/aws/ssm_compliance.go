package aws

import (
	"context"
	"errors"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// Systems Manager compliance for managed instances: the Patch Manager verdict
// (AWS FSBP SSM.2) and the State Manager association verdict (SSM.3), read
// with ssm:ListResourceComplianceSummaries — one listing per compliance type
// for the whole region — and stamped onto ec2_instance by regionInventory.
//
// An instance with no summary of a type is not graded: FSBP evaluates only
// instances Patch Manager (or an association) actually covers, and "no
// record" is not "compliant". A listing that fails, or runs past
// ssmComplianceMaxPages, stamps nothing for that type.

// ssmComplianceTypes maps each graded compliance type to the instance key it
// is stamped as.
var ssmComplianceTypes = map[string]string{
	"Patch":       "ssm_patch_compliance",
	"Association": "ssm_association_compliance",
}

// ssmComplianceMaxPages caps one type's listing (50 summaries a page, so
// 20,000 instances). Past it the listing is incomplete and nothing is
// stamped — a partial set cannot tell an absent record from an unread one.
const ssmComplianceMaxPages = 400

var errSSMCompliancePageCap = errors.New("compliance summary listing exceeded the page cap")

type ssmComplianceAPI interface {
	ListResourceComplianceSummaries(context.Context, *ssm.ListResourceComplianceSummariesInput, ...func(*ssm.Options)) (*ssm.ListResourceComplianceSummariesOutput, error)
}

// ssmCompliance is one region's compliance read: instance id → stamp key →
// COMPLIANT / NON_COMPLIANT, and the listings that failed (by stamp key).
type ssmCompliance struct {
	status map[string]map[string]string
	failed map[string]error
}

func readSSMCompliance(ctx context.Context, client ssmComplianceAPI) ssmCompliance {
	c := ssmCompliance{status: map[string]map[string]string{}, failed: map[string]error{}}
	for ctype, key := range ssmComplianceTypes {
		got, err := listComplianceSummaries(ctx, client, ctype)
		if err != nil {
			c.failed[key] = err
			continue
		}
		for id, status := range got {
			if c.status[id] == nil {
				c.status[id] = map[string]string{}
			}
			c.status[id][key] = status
		}
	}
	return c
}

func listComplianceSummaries(ctx context.Context, client ssmComplianceAPI, ctype string) (map[string]string, error) {
	out := map[string]string{}
	var token *string
	for range ssmComplianceMaxPages {
		page, err := client.ListResourceComplianceSummaries(ctx, &ssm.ListResourceComplianceSummariesInput{
			Filters: []ssmtypes.ComplianceStringFilter{
				{Key: awssdk.String("ComplianceType"), Type: ssmtypes.ComplianceQueryOperatorTypeEqual, Values: []string{ctype}},
				{Key: awssdk.String("ResourceType"), Type: ssmtypes.ComplianceQueryOperatorTypeEqual, Values: []string{"ManagedInstance"}},
			},
			NextToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("listComplianceSummaries %s: %w", ctype, err)
		}
		for _, item := range page.ResourceComplianceSummaryItems {
			if id := awssdk.ToString(item.ResourceId); id != "" && item.Status != "" {
				out[id] = string(item.Status)
			}
		}
		if page.NextToken == nil {
			return out, nil
		}
		token = page.NextToken
	}
	return nil, fmt.Errorf("listComplianceSummaries %s: %w", ctype, errSSMCompliancePageCap)
}

// stamp writes the instance's compliance keys from listings that succeeded.
func (c ssmCompliance) stamp(id string, meta map[string]string) {
	if meta == nil {
		return
	}
	for key, status := range c.status[id] {
		if c.failed[key] == nil {
			meta[key] = status
		}
	}
}
