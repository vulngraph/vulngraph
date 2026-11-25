package correlate

import (
	"fmt"
	"slices"
	"strings"
)

// portfulProtocols carry port numbers; any other protocol (icmp, esp, …) is
// evaluated once, port-less.
var portfulProtocols = map[string]bool{"tcp": true, "udp": true, "sctp": true}

// openPortLabel evaluates open(proto, port) for every protocol over the
// elementary port intervals cut by the rule boundaries in cuts (each rule's
// from and to+1), and renders the open ranges as "tcp:22,tcp:80-443,icmp".
// Every port inside one interval is matched by exactly the same rules, so
// testing the interval's first port decides it. "" means nothing is open.
func openPortLabel(protos []string, cuts []int32, open func(proto string, port int32) bool) string {
	cuts = append(slices.Clone(cuts), 0, 65536)
	slices.Sort(cuts)
	cuts = slices.Compact(cuts)

	var parts []string
	for _, proto := range protos {
		if !portfulProtocols[proto] {
			if open(proto, 0) {
				parts = append(parts, proto)
			}
			continue
		}
		start := int32(-1)
		flush := func(end int32) {
			switch {
			case start < 0:
			case start == end:
				parts = append(parts, fmt.Sprintf("%s:%d", proto, start))
			default:
				parts = append(parts, fmt.Sprintf("%s:%d-%d", proto, start, end))
			}
			start = -1
		}
		for i := 0; i+1 < len(cuts); i++ {
			lo := cuts[i]
			if lo < 0 || lo > 65535 {
				continue
			}
			if open(proto, lo) {
				if start < 0 {
					start = lo
				}
			} else {
				flush(lo - 1)
			}
		}
		flush(65535)
	}
	return strings.Join(parts, ",")
}
