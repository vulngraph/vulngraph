package azure

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// collectNetworking pulls vNets, subnets, NSGs (with ingress rules), and
// public IP addresses for a subscription. NSG inbound rules (Allow and Deny,
// with priority) are serialised into Metadata["ingress"] — see nsgRule.
func collectNetworking(ctx context.Context, cred azcore.TokenCredential, subscriptionID string, now time.Time) ([]asset.Asset, []asset.Edge, error) {
	client, err := armnetwork.NewVirtualNetworksClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, nil, fmt.Errorf("collectNetworking: vnets client: %w", err)
	}
	nsgClient, err := armnetwork.NewSecurityGroupsClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, nil, fmt.Errorf("collectNetworking: nsg client: %w", err)
	}
	pipClient, err := armnetwork.NewPublicIPAddressesClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, nil, fmt.Errorf("collectNetworking: pip client: %w", err)
	}

	var assets []asset.Asset
	var edges []asset.Edge

	// Virtual Networks + Subnets
	vnetPager := client.NewListAllPager(nil)
	for vnetPager.More() {
		page, err := vnetPager.NextPage(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("collectNetworking: list vnets: %w", err)
		}
		for _, vnet := range page.Value {
			if vnet.ID == nil {
				continue
			}
			loc := strVal(vnet.Location)
			vnetAsset := asset.Asset{
				ID:           *vnet.ID,
				Name:         strVal(vnet.Name),
				Type:         "azure_vnet",
				Provider:     asset.ProviderAzure,
				Region:       loc,
				AccountID:    subscriptionID,
				Metadata:     vnetMetadata(vnet),
				DiscoveredAt: now,
				LastSeen:     now,
			}
			assets = append(assets, vnetAsset)

			if vnet.Properties == nil {
				continue
			}
			for _, sn := range vnet.Properties.Subnets {
				if sn.ID == nil {
					continue
				}
				snAsset := asset.Asset{
					ID:           *sn.ID,
					Name:         strVal(sn.Name),
					Type:         "azure_subnet",
					Provider:     asset.ProviderAzure,
					Region:       loc,
					AccountID:    subscriptionID,
					Metadata:     subnetMetadata(sn),
					DiscoveredAt: now,
					LastSeen:     now,
				}
				assets = append(assets, snAsset)
				edges = append(edges, asset.Edge{
					SrcID: *sn.ID, SrcType: "azure_subnet",
					DstID: *vnet.ID, DstType: "azure_vnet",
					EdgeType: "in_vpc",
				})
			}
		}
	}

	// Network Security Groups (with ingress rules for reachability)
	nsgPager := nsgClient.NewListAllPager(nil)
	for nsgPager.More() {
		page, err := nsgPager.NextPage(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("collectNetworking: list nsgs: %w", err)
		}
		for _, nsg := range page.Value {
			if nsg.ID == nil {
				continue
			}
			meta := map[string]string{"nsg_rules_complete": fmt.Sprintf("%t", nsgRulesComplete(nsg))}
			if ingress := nsgIngress(nsg); ingress != "" {
				meta["ingress"] = ingress
			}
			assets = append(assets, asset.Asset{
				ID:           *nsg.ID,
				Name:         strVal(nsg.Name),
				Type:         "security_group",
				Provider:     asset.ProviderAzure,
				Region:       strVal(nsg.Location),
				AccountID:    subscriptionID,
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
	}

	// Public IP Addresses
	pipPager := pipClient.NewListAllPager(nil)
	for pipPager.More() {
		page, err := pipPager.NextPage(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("collectNetworking: list pips: %w", err)
		}
		for _, pip := range page.Value {
			if pip.ID == nil {
				continue
			}
			publicIP := ""
			if pip.Properties != nil {
				publicIP = strVal(pip.Properties.IPAddress)
			}
			assets = append(assets, asset.Asset{
				ID:           *pip.ID,
				Name:         strVal(pip.Name),
				Type:         "azure_public_ip",
				Provider:     asset.ProviderAzure,
				Region:       strVal(pip.Location),
				AccountID:    subscriptionID,
				PublicIP:     publicIP,
				Metadata:     publicIPMetadata(pip),
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
	}

	return assets, edges, nil
}

// publicIPMetadata maps one public IP address. "public" is written only when
// the properties block came back: without it whether an address is allocated
// was not observed, and "false" would read as an unallocated IP.
func publicIPMetadata(pip *armnetwork.PublicIPAddress) map[string]string {
	if pip.Properties == nil {
		return map[string]string{}
	}
	return map[string]string{"public": boolStr(strVal(pip.Properties.IPAddress) != "")}
}

// vnetMetadata maps one VNet. ddos_protection is written only when the
// properties block came back: EnableDdosProtection is false until set, but a
// VNet with no properties at all says nothing about it.
func vnetMetadata(v *armnetwork.VirtualNetwork) map[string]string {
	meta := map[string]string{"address_space": vnetAddressSpace(v)}
	if v.Properties != nil {
		meta["ddos_protection"] = boolStr(v.Properties.EnableDdosProtection != nil && *v.Properties.EnableDdosProtection)
	}
	return meta
}

// subnetMetadata maps one subnet from the VNet listing. nsg_id is "" when the
// subnet's properties were returned with no NSG association (observed none)
// and absent when the properties were not returned at all.
func subnetMetadata(sn *armnetwork.Subnet) map[string]string {
	meta := map[string]string{"address_prefix": ""}
	if sn.Properties == nil {
		return meta
	}
	meta["address_prefix"] = strVal(sn.Properties.AddressPrefix)
	meta["nsg_id"] = ""
	if nsg := sn.Properties.NetworkSecurityGroup; nsg != nil {
		meta["nsg_id"] = strVal(nsg.ID)
	}
	return meta
}

func vnetAddressSpace(v *armnetwork.VirtualNetwork) string {
	if v.Properties == nil || v.Properties.AddressSpace == nil {
		return ""
	}
	prefixes := make([]string, 0, len(v.Properties.AddressSpace.AddressPrefixes))
	for _, p := range v.Properties.AddressSpace.AddressPrefixes {
		if p != nil {
			prefixes = append(prefixes, *p)
		}
	}
	return strings.Join(prefixes, ",")
}

// nsgRule is one inbound NSG rule as serialised into Metadata["ingress"]. It
// extends the AWS sgIngressRule shape (protocol/from_port/to_port/cidrs) with
// access and priority, because Azure evaluates rules in priority order with
// first match winning: a Deny above an Allow closes the port, so dropping
// Deny rules overstates exposure. A rule listing several port ranges becomes
// one entry per range, all sharing the rule's priority and access. The
// destination is kept too (address prefixes, service tags or "*", and
// application security group IDs): a Deny above an Allow closes only the
// destinations it names, so a consumer credits it only where it covers the
// Allow's. The built-in default rules are not serialised; consumers treat
// "no rule matched" as the default DenyAllInBound.
type nsgRule struct {
	Protocol        string   `json:"protocol"`
	FromPort        int32    `json:"from_port"`
	ToPort          int32    `json:"to_port"`
	CIDRs           []string `json:"cidrs,omitempty"`
	SourcePorts     []string `json:"source_ports"`
	Destinations    []string `json:"destinations,omitempty"`
	DestinationASGs []string `json:"destination_asgs,omitempty"`
	Access          string   `json:"access"`
	Priority        int32    `json:"priority"`
}

// nsgIngress serialises an NSG's inbound custom rules, Allow and Deny alike.
func nsgIngress(nsg *armnetwork.SecurityGroup) string {
	if nsg.Properties == nil {
		return ""
	}
	var rules []nsgRule
	for _, r := range nsg.Properties.SecurityRules {
		if r == nil || r.Properties == nil {
			continue
		}
		rules = append(rules, nsgRuleEntries(r.Properties)...)
	}
	if len(rules) == 0 {
		return ""
	}
	return marshalJSON(rules)
}

// nsgRuleEntries expands one inbound security rule into an entry per
// destination port range; outbound rules yield nothing.
func nsgRuleEntries(p *armnetwork.SecurityRulePropertiesFormat) []nsgRule {
	if p.Direction != nil && *p.Direction != armnetwork.SecurityRuleDirectionInbound {
		return nil
	}
	access := "allow"
	if p.Access != nil && *p.Access == armnetwork.SecurityRuleAccessDeny {
		access = "deny"
	}
	var priority int32
	if p.Priority != nil {
		priority = *p.Priority
	}
	sources := nonEmpty(append([]*string{p.SourceAddressPrefix}, p.SourceAddressPrefixes...))
	destinations := nonEmpty(append([]*string{p.DestinationAddressPrefix}, p.DestinationAddressPrefixes...))
	var destASGs []string
	for _, g := range p.DestinationApplicationSecurityGroups {
		if g != nil {
			destASGs = append(destASGs, nonEmpty([]*string{g.ID})...)
		}
	}
	ranges := nonEmpty(append([]*string{p.DestinationPortRange}, p.DestinationPortRanges...))
	if len(ranges) == 0 {
		ranges = []string{"*"}
	}
	out := make([]nsgRule, 0, len(ranges))
	for _, pr := range ranges {
		from, to := portRange(pr)
		out = append(out, nsgRule{
			Protocol:        azProtocol(p.Protocol),
			FromPort:        from,
			ToPort:          to,
			CIDRs:           sources,
			SourcePorts:     nonEmpty(append([]*string{p.SourcePortRange}, p.SourcePortRanges...)),
			Destinations:    destinations,
			DestinationASGs: destASGs,
			Access:          access,
			Priority:        priority,
		})
	}
	return out
}

// nonEmpty dereferences the non-nil, non-blank strings in ps.
func nonEmpty(ps []*string) []string {
	var out []string
	for _, p := range ps {
		if v := strings.TrimSpace(strVal(p)); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// azProtocol lowercases an NSG rule protocol, tolerating a nil pointer so one
// malformed rule cannot panic and abort the whole networking sync.
func azProtocol(p *armnetwork.SecurityRuleProtocol) string {
	if p == nil {
		return ""
	}
	return strings.ToLower(string(*p))
}

func portRange(s string) (int32, int32) {
	if s == "*" || s == "" {
		return 0, 65535
	}
	parts := strings.SplitN(s, "-", 2)
	from := parseInt32(parts[0])
	if len(parts) == 1 {
		return from, from
	}
	return from, parseInt32(parts[1])
}
