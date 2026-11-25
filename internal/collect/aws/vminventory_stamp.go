package aws

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// regionInventory is one region's SSM inventory read, run beside the region's
// collector fan-out and applied to its EC2 instances once both are done.
//
// It deliberately never flags the sweep Partial or counts toward sweepTally.
// It enumerates no type that deletion reconciliation acts on (package assets are
// never MarkComplete'd and runs_package edges expire by freshness), so its
// failure cannot be mistaken for a deletion — and SSM is the permission most
// connectors will not have granted yet: routing a denial through regionSkip would
// switch off finding auto-resolution for every such account, every sweep. The
// unknown-ness is carried where a consumer can see it instead: on each instance,
// as package_inventory=none with the reason.
type regionInventory struct {
	done       chan struct{}
	inv        map[string]vmInventory
	err        error
	compliance ssmCompliance
}

// startRegionInventory launches the region's inventory read. A nil cache (a test
// Collector built without New) or no credentials returns nil: nothing is stamped
// and instances carry no package_inventory key at all, which reads as unknown.
func (c *Collector) startRegionInventory(ctx context.Context, cfg map[string]string, accountID, region string, budget *inventoryBudget, now time.Time) *regionInventory {
	if c.inventory == nil || c.newSSM == nil {
		return nil
	}
	r := &regionInventory{done: make(chan struct{})}
	go func() {
		defer close(r.done)
		defer func() {
			if rec := recover(); rec != nil {
				log.FromContext(ctx).Error().Any("panic", rec).Str("region", region).Msg("ssm inventory panicked; region's instances stamped none")
				r.inv, r.err = nil, fmt.Errorf("ssm inventory panic: %v", rec)
			}
		}()
		client, err := c.newSSM(ctx, cfg)
		if err != nil {
			r.err = fmt.Errorf("startRegionInventory: %w", err)
			return
		}
		r.inv, r.err = collectSSMInventory(ctx, client, c.inventory, budget, accountID+"/"+region, c.advisory, now)
		r.compliance = readSSMCompliance(ctx, client)
	}()
	return r
}

func defaultSSM(ctx context.Context, cfg map[string]string) (ssmInventoryAPI, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("defaultSSM: %w", err)
	}
	return ssm.NewFromConfig(awsCfg), nil
}

// apply waits for the read and stamps every instance of the region with its
// package-inventory known-ness, returning the package assets + runs_package
// edges for the instances that have one. seen dedups package assets across the
// sweep's regions: a package installed on a whole fleet is one asset row.
//
// instances' Metadata maps are the SAME maps already appended to the sweep's
// result (a struct copy shares its map), so the stamp lands on the emitted
// assets without re-appending them.
func (r *regionInventory) apply(ctx context.Context, instances []asset.Asset, seen map[string]bool, now time.Time) ([]asset.Asset, []asset.Edge) {
	if r == nil {
		return nil, nil
	}
	<-r.done
	if r.err != nil {
		log.FromContext(ctx).Warn().Err(r.err).Int("instances", len(instances)).
			Msg("ssm inventory unavailable — region's instances stamped package_inventory=none (no software inventory, not a clean one)")
	}
	for key, err := range r.compliance.failed {
		log.FromContext(ctx).Warn().Err(err).Str("key", key).
			Msg("ssm compliance listing failed — instances carry no compliance verdict of that type this sweep")
	}
	var (
		assets []asset.Asset
		edges  []asset.Edge
	)
	for _, inst := range instances {
		r.compliance.stamp(inst.ID, inst.Metadata)
		v := r.verdict(inst.ID)
		stampInventory(inst.Metadata, asset.PackageInventorySSM, v)
		// ssm_managed (FSBP SSM.1) is written only from a complete managed-node
		// listing: a denied or failed listing leaves it absent, never "false".
		if r.err == nil && inst.Metadata != nil {
			_, managed := r.inv[inst.ID]
			inst.Metadata["ssm_managed"] = strconv.FormatBool(managed)
		}
		if v.gap != "" {
			continue
		}
		pkgAssets, pkgEdges := pkginventory.InventoryGraph(inst.ID, inst.Type, v.pkgs, now)
		for _, a := range pkgAssets {
			if !seen[a.ID] {
				seen[a.ID] = true
				assets = append(assets, a)
			}
		}
		edges = append(edges, pkgEdges...)
	}
	return assets, edges
}

func (r *regionInventory) verdict(id string) vmInventory {
	if r.err != nil {
		if isDenyErr(r.err) {
			return vmInventory{gap: gapAccessDenied}
		}
		return vmInventory{gap: gapUnavailable}
	}
	v, ok := r.inv[id]
	if !ok {
		return vmInventory{gap: gapNotManaged}
	}
	return v
}

// stampInventory writes the known-ness keys. A gap writes ONLY none + reason:
// an ecosystem on an instance with no inventory would read as coverage.
func stampInventory(meta map[string]string, source string, v vmInventory) {
	if meta == nil {
		return
	}
	if v.gap != "" {
		meta[asset.MetaPackageInventory] = asset.PackageInventoryNone
		meta[asset.MetaPackageInventoryGap] = v.gap
		return
	}
	meta[asset.MetaPackageInventory] = source
	meta[asset.MetaPackageInventoryObservedOn] = v.observedOn
	meta[asset.MetaPackageEcosystem] = v.ecosystem
	meta[asset.MetaPackageCVEMatchable] = fmt.Sprintf("%t", v.cveGap == "")
	if v.cveGap != "" {
		meta[asset.MetaPackageCVEGap] = v.cveGap
	}
}
