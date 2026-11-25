package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// EC2 software inventory from AWS Systems Manager Inventory: the installed
// packages the SSM agent reports (inventory type AWS:Application), read with
// ssm:DescribeInstanceInformation + ssm:ListInventoryEntries — both read-only.
//
// ListInventoryEntries is per instance and pages 50 packages at a time, so a host
// costs ~10-40 calls. Re-reading every host every 2h sweep would be thousands of
// calls per region, so packages are cached on the Collector and each instance is
// re-read only once per inventoryRefreshAfter, oldest first, inside a per-region
// and per-sweep time budget. The cache is process memory only: after a restart an
// instance reads as "inventory_pending" (none) until its turn comes — the safe
// direction, never a clean-looking empty list.

const (
	ssmApplicationType = "AWS:Application"

	// inventoryRefreshAfter is how long a fetched package list is reused.
	inventoryRefreshAfter = 20 * time.Hour
	// inventoryNoDataRefreshAfter is how long a "no inventory yet" result is
	// reused. A new instance has none until its agent's first capture, so the
	// negative is re-checked after hours rather than held for a day.
	inventoryNoDataRefreshAfter = 2 * time.Hour
	// inventoryStaleAfter is how long a cached list may still be EMITTED when its
	// refresh keeps missing the budget. It must stay under the 48h graph-edge
	// freshness window (graphschema.EdgeFreshnessCond): past it the instance
	// reads as none rather than re-stamping edges nobody re-observed.
	inventoryStaleAfter = 40 * time.Hour
	// inventoryCaptureMaxAge: an agent that stopped reporting leaves its last
	// capture in SSM forever. A week-old capture is not today's package list.
	inventoryCaptureMaxAge = 7 * 24 * time.Hour

	// inventoryMaxPages caps one instance at 10,000 packages. A host over it is
	// recorded as none, not truncated: a partial list cannot support a verdict.
	inventoryMaxPages = 200
	// inventoryRegionBudget / inventorySweepBudget bound wall-clock spent on
	// refreshes per region and per sweep, so inventory can never eat the 30m
	// sync deadline the rest of the account needs.
	inventoryRegionBudget = 60 * time.Second
	inventorySweepBudget  = 6 * time.Minute
	// inventoryConcurrency instances are read at once, paced to at most one
	// call per inventoryCallInterval across all of them; the SDK's retryer
	// absorbs any throttling beyond that.
	inventoryConcurrency = 4
)

// inventoryCallInterval paces ListInventoryEntries to ≤20 TPS per region. A var,
// not a const, so tests can lower it instead of waiting out the pacing.
var inventoryCallInterval = 50 * time.Millisecond

// Gap reasons stamped as asset.MetaPackageInventoryGap when an instance has no
// usable inventory.
const (
	gapNotManaged          = "not_ssm_managed"
	gapUnsupportedPlatform = "unsupported_platform"
	gapNoInventoryData     = "no_inventory_data"
	gapStaleInventory      = "stale_inventory"
	gapOverPackageCap      = "over_package_cap"
	gapPending             = "inventory_pending"
	gapAccessDenied        = "ssm_access_denied"
	gapUnavailable         = "ssm_unavailable"
)

type ssmInventoryAPI interface {
	// The compliance listing rides the inventory's client and goroutine
	// (ssm_compliance.go): both are per-region SSM reads stamped onto the
	// same instances once the region's fan-out is done.
	ssmComplianceAPI
	DescribeInstanceInformation(context.Context, *ssm.DescribeInstanceInformationInput, ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error)
	ListInventoryEntries(context.Context, *ssm.ListInventoryEntriesInput, ...func(*ssm.Options)) (*ssm.ListInventoryEntriesOutput, error)
}

// vmInventory is one instance's inventory verdict for this sweep.
type vmInventory struct {
	gap        string // non-empty = no usable inventory
	ecosystem  string
	cveGap     string // non-empty = the inventory cannot support a CVE verdict (asset.CVEGap*)
	observedOn string
	pkgs       []pkginventory.InstalledPackage
}

// managedNode is what DescribeInstanceInformation says about one instance.
type managedNode struct {
	ecosystem string
	gap       string
}

// cachedInventory is one instance's last successful (or conclusive) read.
// scope is "<account>/<region>": the Collector — and so the cache — serves every
// AWS connector, and eviction must only ever touch the scope being swept.
type cachedInventory struct {
	scope     string
	fetchedAt time.Time
	captured  time.Time
	ecosystem string
	gap       string // a conclusive no-data / over-cap result is cached too
	setKey    string
}

// refreshAfter is how long this entry is reused before it is re-read.
func (e cachedInventory) refreshAfter() time.Duration {
	if e.gap == gapNoInventoryData {
		return inventoryNoDataRefreshAfter
	}
	return inventoryRefreshAfter
}

// inventoryCache holds package lists across sweeps. Package sets are interned:
// an autoscaling fleet of one AMI shares one slice instead of one per host.
type inventoryCache struct {
	mu      sync.Mutex
	entries map[string]cachedInventory
	sets    map[string]*packageSet
}

type packageSet struct {
	pkgs []pkginventory.InstalledPackage
	refs int
}

func newInventoryCache() *inventoryCache {
	return &inventoryCache{entries: map[string]cachedInventory{}, sets: map[string]*packageSet{}}
}

func (c *inventoryCache) get(id string) (cachedInventory, []pkginventory.InstalledPackage, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	if !ok {
		return cachedInventory{}, nil, false
	}
	var pkgs []pkginventory.InstalledPackage
	if s := c.sets[e.setKey]; s != nil {
		pkgs = s.pkgs
	}
	return e, pkgs, true
}

func (c *inventoryCache) put(id string, e cachedInventory, pkgs []pkginventory.InstalledPackage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(pkgs) > 0 {
		e.setKey = packageSetKey(e.ecosystem, pkgs)
		if s, ok := c.sets[e.setKey]; ok {
			s.refs++
		} else {
			c.sets[e.setKey] = &packageSet{pkgs: pkgs, refs: 1}
		}
	}
	c.releaseLocked(id)
	c.entries[id] = e
}

// evictScope drops every entry of scope whose instance is no longer managed.
func (c *inventoryCache) evictScope(scope string, keep map[string]managedNode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, e := range c.entries {
		if _, ok := keep[id]; !ok && e.scope == scope {
			c.releaseLocked(id)
			delete(c.entries, id)
		}
	}
}

func (c *inventoryCache) releaseLocked(id string) {
	old, ok := c.entries[id]
	if !ok || old.setKey == "" {
		return
	}
	if s := c.sets[old.setKey]; s != nil {
		if s.refs--; s.refs <= 0 {
			delete(c.sets, old.setKey)
		}
	}
}

// packageSetKey identifies a package list by content, order-independently.
func packageSetKey(ecosystem string, pkgs []pkginventory.InstalledPackage) string {
	keys := make([]string, len(pkgs))
	for i, p := range pkgs {
		keys[i] = p.Name + "\x00" + p.Version + "\x00" + p.SourceName
	}
	sort.Strings(keys)
	return ecosystem + "\x01" + strings.Join(keys, "\x01")
}

// inventoryBudget is the per-sweep refresh allowance, spent region by region.
type inventoryBudget struct{ remaining time.Duration }

func (b *inventoryBudget) take() time.Duration { return min(b.remaining, inventoryRegionBudget) }
func (b *inventoryBudget) spend(d time.Duration) {
	b.remaining = max(b.remaining-d, 0)
}

// collectSSMInventory resolves the inventory of every SSM-managed EC2 instance
// in the client's region; scope is "<account>/<region>". An error means DescribeInstanceInformation itself
// failed: nothing is known about any instance in the region, and the caller
// stamps them all none.
func collectSSMInventory(ctx context.Context, client ssmInventoryAPI, cache *inventoryCache, budget *inventoryBudget, scope string, advisory distro.Sources, now time.Time) (map[string]vmInventory, error) {
	managed, err := describeManagedNodes(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("collectSSMInventory: %w", err)
	}
	cache.evictScope(scope, managed)

	started := time.Now()
	unread := gapPending
	if denied := refreshInventories(ctx, client, cache, scope, managed, budget.take(), now); denied {
		unread = gapAccessDenied
	}
	budget.spend(time.Since(started))

	out := make(map[string]vmInventory, len(managed))
	for id, node := range managed {
		out[id] = resolveInventory(cache, id, node, unread, advisory, now)
	}
	return out, nil
}

// describeManagedNodes lists the region's SSM-managed EC2 instances. Every page
// is read or the call errors: a managed instance missing from this map is
// stamped not_ssm_managed, so a truncated listing would mislabel real coverage.
func describeManagedNodes(ctx context.Context, client ssmInventoryAPI) (map[string]managedNode, error) {
	out := map[string]managedNode{}
	var token *string
	for {
		page, err := client.DescribeInstanceInformation(ctx, &ssm.DescribeInstanceInformationInput{
			MaxResults: awssdk.Int32(50), NextToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("describeManagedNodes: %w", err)
		}
		for _, info := range page.InstanceInformationList {
			id := awssdk.ToString(info.InstanceId)
			if !strings.HasPrefix(id, "i-") {
				continue // hybrid (mi-) nodes are not EC2 instances
			}
			out[id] = classifyManagedNode(info)
		}
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		token = page.NextToken
	}
}

func classifyManagedNode(info ssmtypes.InstanceInformation) managedNode {
	if info.PlatformType != ssmtypes.PlatformTypeLinux {
		return managedNode{gap: gapUnsupportedPlatform}
	}
	eco := pkginventory.InventoryEcosystem(ssmDistro(awssdk.ToString(info.PlatformName)), awssdk.ToString(info.PlatformVersion))
	if eco == "" {
		return managedNode{gap: gapUnsupportedPlatform}
	}
	return managedNode{ecosystem: eco}
}

// ssmDistro maps SSM's PlatformName ("Amazon Linux", "Ubuntu", "Red Hat
// Enterprise Linux Server", …) to an os-release ID.
func ssmDistro(platformName string) string {
	n := strings.ToLower(platformName)
	for _, m := range []struct{ match, id string }{
		{"amazon linux", "amzn"}, {"ubuntu", "ubuntu"}, {"debian", "debian"},
		{"red hat", "rhel"}, {"centos", "centos"}, {"rocky", "rocky"},
		{"almalinux", "almalinux"}, {"oracle", "ol"}, {"opensuse", "opensuse-leap"},
		{"suse", "sles"}, {"sles", "sles"},
	} {
		if strings.Contains(n, m.match) {
			return m.id
		}
	}
	return ""
}

// refreshInventories re-reads the instances whose cached list is missing, due, or
// stamped with a different OS ecosystem, never-read first then oldest, until
// the budget runs out. A failed read keeps the previous entry; an access denial
// stops the region (every further call would be refused the same way) and is
// reported so unread instances say why.
func refreshInventories(ctx context.Context, client ssmInventoryAPI, cache *inventoryCache, scope string, managed map[string]managedNode, budget time.Duration, now time.Time) (denied bool) {
	type due struct {
		id   string
		last time.Time
	}
	var queue []due
	for id, node := range managed {
		if node.gap != "" {
			continue
		}
		e, _, ok := cache.get(id)
		if ok && now.Sub(e.fetchedAt) < e.refreshAfter() && e.ecosystem == node.ecosystem {
			continue
		}
		queue = append(queue, due{id: id, last: e.fetchedAt})
	}
	if len(queue) == 0 || budget <= 0 {
		return false
	}
	sort.Slice(queue, func(i, j int) bool {
		if !queue[i].last.Equal(queue[j].last) {
			return queue[i].last.Before(queue[j].last)
		}
		return queue[i].id < queue[j].id
	})

	rctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	pace := time.NewTicker(inventoryCallInterval)
	defer pace.Stop()
	logger := log.FromContext(ctx)

	work := make(chan string)
	var (
		wg       sync.WaitGroup
		deniedMu sync.Mutex
	)
	for range inventoryConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error().Any("panic", rec).Str("scope", scope).Msg("ssm inventory read panicked")
				}
			}()
			for id := range work {
				node := managed[id]
				entry, pkgs, err := readInventory(rctx, client, pace.C, id, node.ecosystem, now)
				if err != nil {
					if rctx.Err() == nil {
						logger.Warn().Err(err).Str("scope", scope).Str("instance_id", id).Msg("ssm inventory read failed; previous inventory kept")
					}
					if isDenyErr(err) {
						deniedMu.Lock()
						denied = true
						deniedMu.Unlock()
						cancel()
					}
					continue
				}
				entry.scope = scope
				cache.put(id, entry, pkgs)
			}
		}()
	}
	for _, d := range queue {
		if rctx.Err() != nil {
			break
		}
		select {
		case work <- d.id:
		case <-rctx.Done():
		}
	}
	close(work)
	wg.Wait()
	return denied
}

// readInventory reads one instance's full AWS:Application list.
func readInventory(ctx context.Context, client ssmInventoryAPI, pace <-chan time.Time, id, ecosystem string, now time.Time) (cachedInventory, []pkginventory.InstalledPackage, error) {
	entry := cachedInventory{fetchedAt: now, ecosystem: ecosystem}
	var (
		pkgs  []pkginventory.InstalledPackage
		token *string
	)
	for page := 0; ; page++ {
		if page == inventoryMaxPages {
			entry.gap = gapOverPackageCap
			return entry, nil, nil
		}
		select {
		case <-pace:
		case <-ctx.Done():
			return cachedInventory{}, nil, fmt.Errorf("readInventory %s: %w", id, ctx.Err())
		}
		out, err := client.ListInventoryEntries(ctx, &ssm.ListInventoryEntriesInput{
			InstanceId: awssdk.String(id), TypeName: awssdk.String(ssmApplicationType),
			MaxResults: awssdk.Int32(50), NextToken: token,
		})
		if err != nil {
			return cachedInventory{}, nil, fmt.Errorf("readInventory %s: %w", id, err)
		}
		if page == 0 {
			entry.captured = parseCaptureTime(awssdk.ToString(out.CaptureTime))
		}
		for _, e := range out.Entries {
			if p, ok := pkginventory.InventoryPackage(ecosystem, e["Name"], e["Version"], e["Release"], e["Epoch"], ssmApplicationType); ok {
				// rpm's PackageId is the SOURCERPM; dpkg's is a binary file name.
				p.SourceName = pkginventory.SourceRPMName(e["PackageId"])
				pkgs = append(pkgs, p)
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	if len(pkgs) == 0 || entry.captured.IsZero() {
		entry.gap = gapNoInventoryData
		return entry, nil, nil
	}
	return entry, pkgs, nil
}

// parseCaptureTime reads SSM's capture timestamp ("2024-05-01T10:00:00Z").
// Unparseable is zero, which resolveInventory treats as no data.
func parseCaptureTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// resolveInventory turns the cache state for one managed instance into this
// sweep's verdict. Every path that is not a fresh, complete, recent list is a gap.
//
// unread is the gap for an instance with no usable cached read: pending when the
// budget ran out, access denied when SSM refused the reads.
func resolveInventory(cache *inventoryCache, id string, node managedNode, unread string, advisory distro.Sources, now time.Time) vmInventory {
	if node.gap != "" {
		return vmInventory{gap: node.gap}
	}
	e, pkgs, ok := cache.get(id)
	switch {
	case !ok, e.ecosystem != node.ecosystem, now.Sub(e.fetchedAt) > inventoryStaleAfter:
		return vmInventory{gap: unread}
	case e.gap != "":
		return vmInventory{gap: e.gap}
	case now.Sub(e.captured) > inventoryCaptureMaxAge:
		return vmInventory{gap: gapStaleInventory}
	}
	return vmInventory{
		ecosystem:  node.ecosystem,
		cveGap:     pkginventory.CVEGap(node.ecosystem, pkginventory.HasSourceNames(pkgs), advisory, now),
		observedOn: e.captured.UTC().Format(time.DateOnly),
		pkgs:       pkgs,
	}
}
