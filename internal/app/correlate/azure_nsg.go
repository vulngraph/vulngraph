package correlate

import (
	"encoding/json"
	"net/netip"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// One public IP configuration and the subnet/NIC NSGs its packet traverses.
// Legacy rows lack the endpoint fields and can establish only candidates when
// a rule needs those fields; they do not describe an arbitrary destination VM.
type azureNIC struct {
	Public        bool     `json:"public"`
	NSGIDs        []string `json:"nsg_ids"`
	PublicIPSKU   string   `json:"public_ip_sku"`
	NSGUnknown    bool     `json:"nsg_unknown"`
	PrivateIP     string   `json:"private_ip"`
	PublicIP      string   `json:"public_ip"`
	ASGs          []string `json:"asgs"`
	EndpointKnown bool     `json:"endpoint_known"`
}

func azureVMNICs(inst asset.Asset) []azureNIC {
	var nics []azureNIC
	raw, present := inst.Metadata["nic_nsgs"]
	if present && json.Unmarshal([]byte(raw), &nics) == nil && nics != nil {
		if len(nics) == 1 && !nics[0].EndpointKnown {
			nics[0].PrivateIP, nics[0].PublicIP = inst.PrivateIP, inst.PublicIP
		}
		if inst.Metadata["network_interfaces_complete"] == "false" {
			nics = append(nics, azureNIC{Public: true, NSGUnknown: true})
		}
		return nics
	}
	if !present && (inst.PublicIP != "" || inst.Metadata["direct_public_ip"] == "true") {
		return []azureNIC{{Public: true, NSGIDs: splitValues(inst.Metadata["nsg_ids"]),
			PrivateIP: inst.PrivateIP, PublicIP: inst.PublicIP, NSGUnknown: true}}
	}
	if inst.Metadata["direct_public_ip"] != "false" || present {
		return []azureNIC{{Public: true, NSGUnknown: true}}
	}
	return nil
}

type azureExposure struct{ ports, nsgs, tier, via, possiblePorts string }

func azureVMExposure(inst asset.Asset, nsgByID map[string]asset.Asset) (azureExposure, bool) {
	var possible azureExposure
	for _, nic := range azureVMNICs(inst) {
		if !nic.Public {
			continue
		}
		e, open := azureNICExposure(nic, nsgByID)
		if !open {
			continue
		}
		if e.tier == asset.PublicAccessConfirmed {
			return e, true
		}
		possible = e
	}
	return possible, possible.ports != ""
}

func azureNICExposure(nic azureNIC, nsgByID map[string]asset.Asset) (azureExposure, bool) {
	unknown := nic.NSGUnknown
	var sets [][]ingressRule
	for _, id := range nic.NSGIDs {
		nsg, ok := nsgByID[strings.ToLower(id)]
		if !ok {
			unknown = true
			continue
		}
		var rules []ingressRule
		raw := nsg.Metadata["ingress"]
		if raw == "" {
			if nsg.Metadata["nsg_rules_complete"] != "true" {
				unknown = true
				continue
			}
		} else if json.Unmarshal([]byte(raw), &rules) != nil || rules == nil {
			unknown = true
			continue
		}
		if nsg.Metadata["nsg_rules_complete"] == "false" {
			unknown = true
			continue
		}
		sets = append(sets, rules)
	}
	if len(sets) > 0 {
		ports, possiblePorts, tier := nsgPacketPorts(sets, nic).summary(!unknown)
		return azureExposure{ports, strings.Join(nic.NSGIDs, ","), tier, "azure_nsg_world_open", possiblePorts}, ports != ""
	}
	if unknown {
		return azureExposure{"all", strings.Join(nic.NSGIDs, ","), asset.PublicAccessPossible, "azure_nsg_unknown", ""}, true
	}
	switch strings.ToLower(nic.PublicIPSKU) {
	case "standard", "standardv2":
		return azureExposure{}, false
	case "basic":
		tier := asset.PublicAccessPossible
		if _, err := netip.ParseAddr(nic.PublicIP); err == nil {
			tier = asset.PublicAccessConfirmed
		}
		return azureExposure{"all", "", tier, "azure_no_nsg_basic_ip", ""}, true
	default:
		return azureExposure{"all", "", asset.PublicAccessPossible, "azure_no_nsg_ip_sku_unknown", ""}, true
	}
}

func nsgOpenPorts(sets [][]ingressRule) string {
	return nsgPacketPorts(sets, azureNIC{}).all
}

func nsgProtoMatches(rule, proto string) bool {
	switch normalizedIPProtocol(rule) {
	case "*", "any", "-1":
		return true
	default:
		return normalizedIPProtocol(rule) == proto
	}
}

func securityGroupsByFoldedID(g Graph) map[string]asset.Asset {
	out := make(map[string]asset.Asset, len(g.securityGroups))
	for _, a := range g.securityGroups {
		out[strings.ToLower(a.ID)] = a
	}
	return out
}
