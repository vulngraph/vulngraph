package correlate

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type stagedDNSTarget struct{ id, kind string }

func dnsValueKey(value string) string {
	if net.ParseIP(value) != nil {
		return "ip:" + value
	}
	return "domain:" + strings.ToLower(strings.TrimSuffix(value, "."))
}

// Keep the same global smallest-ID target cap as DNSPointsTo. Collect wanted
// values first, scan matching target types once, then replay records. Paging
// targets independently would apply the cap once per page and change topology.
func (s *Service) runStagedDNS(ctx context.Context, snapshot stagedView) error {
	targets := make(map[string][]stagedDNSTarget)
	var used int64
	charge := func(bytes int64) error {
		if used+bytes > s.staged.ContextBytes {
			return fmt.Errorf("DNS matching index: %w", ErrStagedBudget)
		}
		used += bytes
		return nil
	}
	read := func(types []string, consume func([]asset.Asset) error) error {
		return snapshot.Read(ctx, types, nil, s.staged.PageRows, s.staged.PageBytes, consume)
	}
	if err := read([]string{"dns_record"}, func(page []asset.Asset) error {
		for _, record := range page {
			for _, value := range splitValues(record.Metadata["values"]) {
				key := dnsValueKey(value)
				if _, exists := targets[key]; !exists {
					if err := charge(int64(len(key) + 96)); err != nil {
						return err
					}
					targets[key] = nil
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	add := func(key string, a asset.Asset) error {
		list, wanted := targets[key]
		if !wanted {
			return nil
		}
		candidate := stagedDNSTarget{a.ID, a.Type}
		position, _ := slices.BinarySearchFunc(list, candidate, func(a, b stagedDNSTarget) int { return strings.Compare(a.id, b.id) })
		if position >= maxDNSTargetsPerValue {
			return nil
		}
		bytes := int64(len(a.ID) + len(a.Type) + 96)
		if len(list) == maxDNSTargetsPerValue {
			last := list[len(list)-1]
			bytes -= int64(len(last.id) + len(last.kind) + 96)
		}
		if err := charge(bytes); err != nil {
			return err
		}
		if len(list) < maxDNSTargetsPerValue {
			list = append(list, stagedDNSTarget{})
		}
		copy(list[position+1:], list[position:len(list)-1])
		list[position] = candidate
		targets[key] = list
		return nil
	}
	if len(targets) == 0 {
		return nil
	}
	var types []string
	for _, kind := range correlationTypes {
		if !isDNSNameType(kind) {
			types = append(types, kind)
		}
	}
	if err := read(types, func(page []asset.Asset) error {
		for _, a := range page {
			for _, ip := range splitValues(a.PublicIP) {
				if err := add("ip:"+ip, a); err != nil {
					return err
				}
			}
			if a.Domain != "" {
				if err := add("domain:"+strings.ToLower(strings.TrimSuffix(a.Domain, ".")), a); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return read([]string{"dns_record"}, func(page []asset.Asset) error {
		for _, record := range page {
			for _, value := range splitValues(record.Metadata["values"]) {
				for _, target := range targets[dnsValueKey(value)] {
					// The legacy rule caps before filtering target types. Keep that
					// order when other rules load extra types into the shared view.
					if !dnsPointsToTargetTypes[target.kind] {
						continue
					}
					if err := ctx.Err(); err != nil {
						return err
					}
					if err := snapshot.StageEdges([]asset.Edge{dnsResolutionEdge(record.ID, target.id, target.kind, value)}); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}
