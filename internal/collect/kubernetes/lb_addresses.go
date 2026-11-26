package kubernetes

import "net/netip"

// lbAddress prefers an observed public IP over an unresolved hostname. A set
// containing only non-public addresses does not establish internet exposure.
func lbAddress(addresses []string) (candidate string, privateOnly, publicIP bool) {
	observed := false
	privateOnly = true
	for _, value := range addresses {
		if value == "" {
			continue
		}
		observed = true
		ip, err := netip.ParseAddr(value)
		if err != nil {
			privateOnly = false
			if candidate == "" {
				candidate = value
			}
			continue
		}
		ip = ip.Unmap()
		if ip.IsPrivate() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		privateOnly = false
		if !publicIP {
			candidate = value
		}
		publicIP = true
	}
	return candidate, observed && privateOnly, publicIP
}
