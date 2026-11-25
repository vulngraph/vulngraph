package gcp

import (
	"fmt"

	compute "google.golang.org/api/compute/v1"
)

// Each public address stays with its own network and destination. Combining
// the primary NIC's network with another NIC's public IP invents a path.
type gceNetworkInterface struct {
	Network      string   `json:"network"`
	PrivateIPv4  string   `json:"private_ipv4"`
	PublicIPv4   string   `json:"public_ipv4"`
	ExternalIPv6 []string `json:"external_ipv6"`
	Unknown      bool     `json:"unknown,omitempty"`
}

func applyGCENetworkInterfaces(g *gceInstance, interfaces []*compute.NetworkInterface) {
	g.NetworkInterfaces = []gceNetworkInterface{}
	if len(interfaces) == 0 {
		g.NetworkInterfaces = append(g.NetworkInterfaces, gceNetworkInterface{Unknown: true})
		return
	}
	for _, ni := range interfaces {
		if ni == nil {
			g.NetworkInterfaces = append(g.NetworkInterfaces, gceNetworkInterface{Unknown: true})
			continue
		}
		n := gceNetworkInterface{Network: lastSegment(ni.Network), PrivateIPv4: ni.NetworkIP}
		if g.Network == "" {
			g.Network, g.PrivateIP = n.Network, n.PrivateIPv4
		}
		for _, ac := range ni.AccessConfigs {
			g.ExternalIPConfigured = true
			if ac == nil || ac.NatIP == "" {
				n.Unknown = true
				continue
			}
			n.PublicIPv4 = ac.NatIP
		}
		for _, ac := range ni.Ipv6AccessConfigs {
			g.ExternalIPConfigured = true
			if ac == nil || ac.ExternalIpv6 == "" {
				n.Unknown = true
				continue
			}
			v := ac.ExternalIpv6
			if ac.ExternalIpv6PrefixLength > 0 && ac.ExternalIpv6PrefixLength <= 128 {
				v = fmt.Sprintf("%s/%d", v, ac.ExternalIpv6PrefixLength)
			}
			n.ExternalIPv6 = append(n.ExternalIPv6, v)
		}
		if g.PublicIP == "" {
			g.PublicIP = n.PublicIPv4
		}
		g.NetworkInterfaces = append(g.NetworkInterfaces, n)
	}
}

// Missing interface evidence cannot establish the negative public-IP posture.
// A positive access-config observation remains valid despite another gap.
func gceExternalIPObserved(interfaces []gceNetworkInterface) bool {
	if len(interfaces) == 0 {
		return false
	}
	for _, n := range interfaces {
		if n.Unknown {
			return false
		}
	}
	return true
}
