package azure

import "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"

// A successful list with an empty custom-rule set is an observed default deny.
// Missing objects or rule properties are incomplete evidence, not empty sets.
func nsgRulesComplete(nsg *armnetwork.SecurityGroup) bool {
	if nsg == nil || nsg.Properties == nil {
		return false
	}
	for _, r := range nsg.Properties.SecurityRules {
		if r == nil || r.Properties == nil {
			return false
		}
		p := r.Properties
		if p.Direction == nil || p.Access == nil || p.Protocol == nil || p.Priority == nil {
			return false
		}
		if len(nonEmpty(append([]*string{p.SourceAddressPrefix}, p.SourceAddressPrefixes...))) == 0 && len(p.SourceApplicationSecurityGroups) == 0 {
			return false
		}
		if len(nonEmpty(append([]*string{p.DestinationAddressPrefix}, p.DestinationAddressPrefixes...))) == 0 && len(p.DestinationApplicationSecurityGroups) == 0 {
			return false
		}
		if len(nonEmpty(append([]*string{p.DestinationPortRange}, p.DestinationPortRanges...))) == 0 {
			return false
		}
		if len(nonEmpty(append([]*string{p.SourcePortRange}, p.SourcePortRanges...))) == 0 {
			return false
		}
	}
	return true
}
