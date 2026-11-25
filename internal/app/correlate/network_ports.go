package correlate

import "github.com/vulngraph/vulngraph/internal/app/asset"

// A confirmed path on one port does not prove any other candidate port. Keep
// the sets separate so the edge's grade agrees with every port in its summary.
type networkPorts struct {
	all, confirmed, possible string
}

func evaluateNetworkPorts(protos []string, cuts []int32, evaluate func(string, int32) networkMatch) networkPorts {
	type port struct {
		proto string
		n     int32
	}
	results := map[port]networkMatch{}
	var out networkPorts
	out.all = openPortLabel(protos, cuts, func(proto string, n int32) bool {
		m := evaluate(proto, n)
		results[port{proto, n}] = m
		return m != networkNo
	})
	out.confirmed = openPortLabel(protos, cuts, func(proto string, n int32) bool {
		return results[port{proto, n}] == networkYes
	})
	out.possible = openPortLabel(protos, cuts, func(proto string, n int32) bool {
		return results[port{proto, n}] == networkUnknown
	})
	return out
}

func (p networkPorts) summary(observed bool) (ports, possible, tier string) {
	if observed && p.confirmed != "" {
		return p.confirmed, p.possible, asset.PublicAccessConfirmed
	}
	return p.all, "", asset.PublicAccessPossible
}
