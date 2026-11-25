package aws

import (
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// stampLambdaAZCount writes vpc_az_count on every VPC-attached Lambda
// function: the number of distinct Availability Zones its subnets span (AWS
// FSBP Lambda.5 wants at least two). The zones live on the subnet assets the
// same sweep collected; when any of the function's subnets was not collected
// (a failed subnet listing, another account's subnet) the count is unknown
// and the key is omitted rather than undercounted.
func stampLambdaAZCount(assets []asset.Asset) {
	azBySubnet := map[string]string{}
	for _, a := range assets {
		if a.Type == "subnet" && a.Provider == asset.ProviderAWS {
			if az := a.Metadata["availability_zone"]; az != "" {
				azBySubnet[a.ID] = az
			}
		}
	}
	for i := range assets {
		a := &assets[i]
		if a.Type != "lambda_function" || a.Metadata == nil {
			continue
		}
		ids := splitCSV(a.Metadata["subnet_ids"])
		if len(ids) == 0 {
			continue
		}
		zones := map[string]bool{}
		known := true
		for _, id := range ids {
			az, ok := azBySubnet[id]
			if !ok {
				known = false
				break
			}
			zones[az] = true
		}
		if known {
			a.Metadata["vpc_az_count"] = strconv.Itoa(len(zones))
		}
	}
}
