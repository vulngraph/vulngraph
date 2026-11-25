// Package aws collects EC2, Route53, ALBv2, Elastic IP, and Subnet inventory
// from an AWS account. Authentication is OIDC-only: a federated
// base identity assumes the connector's role_arn; no static keys.
package aws

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// slowCollectorThreshold gates the per-collector timing warns below. 10s is
// well above any single paginated AWS Describe* call's normal cost;
// anything past it is either throttling or an account large enough to need
// a structural fix, both worth a log line, neither worth failing the sync
// over. A var, not a const, so tests can lower it instead of sleeping.
var slowCollectorThreshold = 10 * time.Second

type ec2API interface {
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeSubnets(context.Context, *ec2.DescribeSubnetsInput, ...func(*ec2.Options)) (*ec2.DescribeSubnetsOutput, error)
	DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
	DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
	DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	// Snapshots + AMIs: public-sharing is a direct data-exfiltration path.
	DescribeSnapshots(context.Context, *ec2.DescribeSnapshotsInput, ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
	DescribeImages(context.Context, *ec2.DescribeImagesInput, ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
	DescribeVpcs(context.Context, *ec2.DescribeVpcsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcsOutput, error)
	DescribeVpcPeeringConnections(context.Context, *ec2.DescribeVpcPeeringConnectionsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcPeeringConnectionsOutput, error)
	// Route tables decide whether a subnet is public (routes.go).
	DescribeRouteTables(context.Context, *ec2.DescribeRouteTablesInput, ...func(*ec2.Options)) (*ec2.DescribeRouteTablesOutput, error)
	// VPC endpoints become the vpc `endpoint_services` key (network.go).
	DescribeVpcEndpoints(context.Context, *ec2.DescribeVpcEndpointsInput, ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error)
	// Flow logs and, for default VPCs, whether anything runs in them (vpc_flowlogs.go).
	DescribeFlowLogs(context.Context, *ec2.DescribeFlowLogsInput, ...func(*ec2.Options)) (*ec2.DescribeFlowLogsOutput, error)
	DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
}

// Collector implements collect.Collector for AWS.
type Collector struct {
	newClient func(ctx context.Context, cfg map[string]string) (ec2API, string, error)
	// newSTS builds the client for the up-front identity check (resolveAccount).
	// Nil skips the check — only unit tests that never touch real AWS leave it
	// unset.
	newSTS func(ctx context.Context, cfg map[string]string) (stsAPI, error)
	// newSSM + inventory read EC2 software inventory (vminventory.go). Nil skips
	// it: instances then carry no package_inventory key, which reads as unknown.
	newSSM    func(ctx context.Context, cfg map[string]string) (ssmInventoryAPI, error)
	inventory *inventoryCache
	// advisory is the advisory sources this deployment queries: a VM whose
	// distribution's source is switched off is stamped unmatchable.
	advisory distro.Sources
}

// New builds the collector. advisory names the switched-on advisory feeds
// (jobs.Feeds.AdvisorySources).
func New(advisory distro.Sources) *Collector {
	return &Collector{newClient: defaultClient, newSTS: defaultSTS, newSSM: defaultSSM, inventory: newInventoryCache(), advisory: advisory}
}

// Collect runs the full inventory pull and classifies the outcome: an AWS auth
// failure (the hub can't assume this account's role, or the credential is
// expired) is wrapped as collect.ErrPermanent so the sync worker records an
// error and cancels rather than retries it.
func (c *Collector) Collect(ctx context.Context, cfg map[string]string) (collect.Result, error) {
	res, err := c.collectAll(withConfigCache(ctx), cfg)
	if err != nil && !errors.Is(err, collect.ErrPermanent) && isPermanentAWSErr(err) {
		return res, fmt.Errorf("%w: %v", collect.ErrPermanent, err)
	}
	return res, err
}

func (c *Collector) collectAll(ctx context.Context, cfg map[string]string) (collect.Result, error) {
	now := time.Now()
	hasCreds := cfg["role_arn"] != "" || cfg["aws_access_key_id"] != ""

	accountID, err := c.resolveAccount(ctx, cfg)
	if err != nil {
		return collect.Result{}, fmt.Errorf("Collect: %w", err)
	}

	regions, regionsFellBack, err := c.regionsFor(ctx, cfg)
	if err != nil {
		return collect.Result{}, fmt.Errorf("Collect: %w", err)
	}

	var result collect.Result

	// A fallback region list is not a real enumeration of the account's
	// enabled regions — DescribeRegions failed or returned nothing, and we
	// scanned only the configured base region instead. Flag the sweep
	// partial so the sync worker does not run deletion reconciliation as if
	// every region had been looked at (see regionsFor's doc comment).
	if regionsFellBack {
		log.FromContext(ctx).Warn().Msg("region enumeration failed or returned no regions; falling back to configured base region only — sweep flagged partial")
		result.Partial = true
	}

	// Regions whose EKS ListClusters succeeded this sweep — see
	// uninventoriedEKSClusterFindings for why a failed listing must not be read
	// as "no such cluster".
	eksListedRegions := map[string]bool{}
	// Peering IDs already emitted — guarded by resultMu like eksListedRegions.
	seenPeerings := map[string]bool{}
	// Regions whose route tables were fully read, for annotateRouting after the
	// region loop — guarded by resultMu. A region absent here leaves its
	// subnets' public-ness unknown rather than private.
	routesByRegion := map[string]*regionRoutes{}
	// Volume IDs with at least one snapshot, per region whose snapshot listing
	// succeeded — guarded by resultMu. A region absent here leaves its volumes'
	// has_snapshot unknown rather than false.
	snapshotVolumesByRegion := map[string]map[string]bool{}

	// Emit the cloud_account anchor node once per sync, unconditionally — not
	// gated on EC2 instances existing. Without this, an account with zero EC2
	// instances anywhere never gets an "aws:<accountID>" node, leaving
	// grants_access_to/grants_admin SSO edges pointing at a nonexistent asset.
	if accountID != "" {
		result.Assets = append(result.Assets, accountAsset(accountID, cfg["name"], now))
	}

	// resultMu guards every write to result/eksListedRegions from here on: the
	// region loop below fans its per-region collector calls out across
	// goroutines (see regionConcurrency), so skip() and every task that
	// mutates result must take the lock. The global-services block after the
	// region loop stays sequential and pays the same lock for consistency —
	// negligible cost, one code path to reason about instead of two.
	var resultMu sync.Mutex

	// tally counts task outcomes so a sweep AWS refused end to end is an error,
	// not a partial success (see sweepTally).
	tally := &sweepTally{}

	// markSkipped logs a best-effort collector skip AND flags the result
	// partial: an incomplete sweep means an absent asset may just be
	// un-fetched, so the sync worker must not treat it as deleted (deletion
	// reconciliation).
	markSkipped := func(err error, region, what string) {
		ev := log.FromContext(ctx).Warn().Err(err)
		if accountID != "" {
			ev = ev.Str("account_id", accountID)
		}
		if region != "" {
			ev = ev.Str("region", region)
		}
		ev.Msg(what + " collection skipped")
		resultMu.Lock()
		result.Partial = true
		resultMu.Unlock()
	}
	// skip is the failure path for every non-regional task.
	skip := func(err error, region, what string) {
		tally.failed(err)
		markSkipped(err, region, what)
	}

	// complete is skip's counterpart and lives here, immediately beside it, for
	// one reason: the claim "this listing was complete" is only true because of
	// the error handling directly above. A collector call may declare its scope
	// complete ONLY when it returned a nil error AND its own pagination loop
	// reads every page and returns (nil, err) on any page error — so a nil error
	// is a completeness guarantee rather than a best-effort summary. Calling
	// complete from anywhere that cannot see the error path is how a false
	// completeness claim gets made.
	//
	// family is the API surface, not the asset type: the scope key must stay
	// stable across sweeps because a watermark gauge is keyed on it.
	//
	// It takes completeMu rather than resultMu deliberately. Every call site is
	// inside a regional task, most of which already hold resultMu while
	// appending assets, and sync.Mutex is not reentrant — sharing resultMu would
	// make the natural call position a deadlock. completeMu guards
	// result.CompletedEnumerations and nothing else.
	var completeMu sync.Mutex
	complete := func(region, family string, types []string, n int) {
		completeMu.Lock()
		defer completeMu.Unlock()
		result.MarkComplete(region+"/"+family, types, n)
	}

	// Instance-profile → role map, built once for the account before the region
	// loop (IAM is global, EC2 is not). On failure the map stays nil and
	// instances carry no iam_role_arn — an unknown role must not be guessed.
	var profileRoles map[string]string
	if hasCreds {
		tally.started()
		if m, err := collectInstanceProfileRoles(ctx, cfg); err == nil {
			profileRoles = m
		} else {
			skip(err, "", "iam instance profile")
		}
	}

	// Regional services: EC2 (SGs/instances/subnets/EIPs) and ELBv2 exist
	// per-region, so we scan every enabled region (a single-region scan
	// misses the bulk of an account's resources).
	//
	// Each region's ~20 collector calls fan out across goroutines bounded by
	// regionConcurrency rather than running strictly sequentially: the cost is
	// dominated by I/O-wait (sequential AWS API round-trips per region), not
	// compute, so fanning them out removes the serial RTT accumulation without
	// meaningfully raising CPU load or tripping AWS's per-account rate limits.
	//
	// regionConcurrency bounds how many collector tasks run at once WITHIN a
	// region; the region loop is sequential, so this does not grow with the
	// region count. Some tasks fan out internally under their own bounds
	// (eachBounded, lbDetailConcurrency and others), so in-flight AWS calls can
	// exceed 8.
	const regionConcurrency = 8

	invBudget := &inventoryBudget{remaining: inventorySweepBudget}
	seenPackages := map[string]bool{}

	regionalStarted := time.Now()
	for _, region := range regions {
		regionStarted := time.Now()
		rcfg := withRegion(cfg, region)
		client, _, err := c.newClient(ctx, rcfg)
		if err != nil {
			return collect.Result{}, fmt.Errorf("Collect: region %s: %w", region, err)
		}

		// regionSkip holds each failure until the whole region has run, so a
		// region closed to the connector (regionDenied) can be told apart from
		// ordinary gaps before anything flags the sweep partial.
		var (
			failuresMu     sync.Mutex
			regionFailures []regionFailure
			// regionInstances is this region's EC2 listing, kept for the SSM
			// inventory stamp after the fan-out (nil when the listing failed).
			regionInstances []asset.Asset
			// ledger settles the regional services whose endpoint did not
			// resolve once the region has run (regional_offered.go).
			ledger regionLedger
		)
		var inventory *regionInventory
		if hasCreds {
			inventory = c.startRegionInventory(ctx, rcfg, accountID, region, invBudget, now)
		}
		regionSkip := func(err error, _, what string) {
			tally.failed(err)
			failuresMu.Lock()
			regionFailures = append(regionFailures, regionFailure{err: err, what: what})
			failuresMu.Unlock()
		}

		// Every regional task below is best-effort: a transient throttle or a
		// per-region permission gap (a region the role can't fully see) must not
		// discard the whole multi-region account inventory and permanently cancel
		// the connector (same reasoning as the best-effort services below). Losing
		// one region's SGs is far better than losing every region's everything.
		// Each closure is self-contained (captures only region-loop-scoped
		// constants — client/rcfg/region/accountID/now/ctx — that are read-only
		// for the lifetime of this one region's fan-out, never reassigned by any
		// task), so running them concurrently changes nothing about what each one
		// does, only when its result lands.
		tasks := []func(){
			// VPC peering is regional: each region lists the peerings its VPCs
			// take part in, so a cross-region peering shows up in both regions
			// and is deduplicated by peering ID.
			func() {
				peerings, err := collectVPCPeerings(ctx, client)
				if err != nil {
					regionSkip(err, region, "vpc peering")
					return
				}
				resultMu.Lock()
				defer resultMu.Unlock()
				for _, p := range peerings {
					if !seenPeerings[p.id] {
						seenPeerings[p.id] = true
						result.Edges = append(result.Edges, p.edges...)
					}
				}
			},
			func() {
				vpcs, err := collectVPCs(ctx, client, region, accountID, now)
				if err != nil {
					regionSkip(err, region, "vpc")
					return
				}
				if err := annotateFlowLogs(ctx, client, vpcs); err != nil {
					log.FromContext(ctx).Warn().Err(err).Str("region", region).
						Msg("vpc flow logs unreadable (check ec2:DescribeFlowLogs); flow-log coverage unknown this sweep")
				}
				complete(region, "ec2:vpcs", []string{"vpc"}, len(vpcs))
				resultMu.Lock()
				defer resultMu.Unlock()
				result.Assets = append(result.Assets, vpcs...)
			},
			func() {
				sgs, sgEdges, err := collectSecurityGroups(ctx, client, region, accountID, now)
				if err != nil {
					regionSkip(err, region, "security group")
					return
				}
				complete(region, "ec2:security-groups", []string{"security_group"}, len(sgs))
				resultMu.Lock()
				defer resultMu.Unlock()
				result.Assets = append(result.Assets, sgs...)
				result.Edges = append(result.Edges, sgEdges...)
			},
			func() {
				instancesStarted := time.Now()
				instances, instEdges, err := collectInstances(ctx, client, region, accountID, now, profileRoles)
				if instancesElapsed := time.Since(instancesStarted); instancesElapsed > slowCollectorThreshold {
					log.FromContext(ctx).Warn().Str("region", region).Str("account_id", accountID).
						Dur("elapsed", instancesElapsed).Int("count", len(instances)).
						Msg("collectInstances took longer than expected")
				}
				if err != nil {
					regionSkip(err, region, "ec2 instance")
					return
				}
				complete(region, "ec2:instances", []string{"ec2_instance"}, len(instances))
				ledger.coreSucceeded()
				resultMu.Lock()
				defer resultMu.Unlock()
				regionInstances = instances
				result.Assets = append(result.Assets, instances...)
				result.Edges = append(result.Edges, instEdges...)
			},
			func() {
				subnets, subnetEdges, err := collectSubnets(ctx, client, region, accountID, now)
				if err != nil {
					regionSkip(err, region, "subnet")
					return
				}
				complete(region, "ec2:subnets", []string{"subnet"}, len(subnets))
				resultMu.Lock()
				defer resultMu.Unlock()
				result.Assets = append(result.Assets, subnets...)
				result.Edges = append(result.Edges, subnetEdges...)
			},
			// Route tables produce no assets — they become routing facts on the
			// subnets (annotateRouting) — so there is no enumeration to declare
			// complete; a failure still goes through regionSkip, because the
			// routing keys it would have written vanish and the sweep must not
			// read that as remediation.
			func() {
				rr, err := collectRouteTables(ctx, client)
				if err != nil {
					regionSkip(err, region, "route table")
					return
				}
				resultMu.Lock()
				defer resultMu.Unlock()
				routesByRegion[region] = rr
			},
			func() {
				eips, err := collectElasticIPs(ctx, client, region, accountID, now)
				if err != nil {
					regionSkip(err, region, "elastic ip")
					return
				}
				// DescribeAddresses is not paginated (no NextToken in the API at
				// all), so a nil error is the whole account-region's EIP set.
				complete(region, "ec2:addresses", []string{"elastic_ip"}, len(eips))
				resultMu.Lock()
				defer resultMu.Unlock()
				result.Assets = append(result.Assets, eips...)
			},
			func() {
				volumesStarted := time.Now()
				vols, err := collectVolumes(ctx, client, region, accountID, now)
				if volumesElapsed := time.Since(volumesStarted); volumesElapsed > slowCollectorThreshold {
					log.FromContext(ctx).Warn().Str("region", region).Str("account_id", accountID).
						Dur("elapsed", volumesElapsed).Int("count", len(vols)).
						Msg("collectVolumes took longer than expected")
				}
				if err != nil {
					regionSkip(err, region, "volume")
					return
				}
				resultMu.Lock()
				defer resultMu.Unlock()
				result.Assets = append(result.Assets, vols...)
			},
			// Snapshots/images are best-effort: a role missing ec2:DescribeSnapshots /
			// ec2:DescribeImages must not sink the whole account's inventory (same
			// reasoning as Lambda/RDS/EKS below). A permission gap loses only the
			// exfil-check assets for that region, not everything collected so far.
			func() {
				snaps, err := collectSnapshots(ctx, client, region, accountID, now)
				if err != nil {
					regionSkip(err, region, "ebs snapshot")
					return
				}
				resultMu.Lock()
				defer resultMu.Unlock()
				result.Assets = append(result.Assets, snaps...)
				snapshotVolumesByRegion[region] = snapshotVolumeIDs(snaps)
			},
			func() {
				images, err := collectImages(ctx, client, region, accountID, now)
				if err != nil {
					regionSkip(err, region, "ami")
					return
				}
				resultMu.Lock()
				defer resultMu.Unlock()
				result.Assets = append(result.Assets, images...)
			},
		}

		// ELBv2/Lambda/RDS/EKS need real creds; skipped when neither is present (unit tests).
		if hasCreds {
			tasks = append(tasks,
				// ELBv2 is best-effort too: a missing elasticloadbalancing:Describe*
				// permission must not sink the whole account (it sat fail-closed above
				// its already-best-effort peers).
				func() {
					lbs, lbEdges, err := collectELBv2(ctx, rcfg, region, accountID, now)
					if err != nil {
						regionSkip(err, region, "elbv2")
						return
					}
					resultMu.Lock()
					defer resultMu.Unlock()
					result.Assets = append(result.Assets, lbs...)
					result.Edges = append(result.Edges, lbEdges...)
				},
				// Lambda, RDS, EKS and the simple-service loop are best-effort:
				// a timeout or permission error in one must not abort the others
				// or fail the whole account sync (same reasoning as GuardDuty).
				func() {
					more, err := collectLambda(ctx, rcfg, region, accountID, now)
					if err != nil {
						regionSkip(err, region, "lambda")
						return
					}
					resultMu.Lock()
					defer resultMu.Unlock()
					result.Assets = append(result.Assets, more...)
				},
				func() {
					more, partial, nodegroupsPartial, err := collectEKS(ctx, rcfg, region, accountID, now)
					if err != nil {
						regionSkip(err, region, "eks")
						return
					}
					resultMu.Lock()
					defer resultMu.Unlock()
					result.Assets = append(result.Assets, more...)
					// Unlisted node groups are missing, not deleted; the clusters
					// are still a complete listing.
					result.Partial = result.Partial || nodegroupsPartial
					if partial {
						result.Partial = true
						return
					}
					// Record that we actually LOOKED here: absence of a cluster is only
					// evidence in a region whose listing succeeded and emitted every
					// cluster it listed (uninventoriedEKSClusterFindings).
					eksListedRegions[region] = true
				},
				// ecs also emits container assets + ecs_service->container edges,
				// running-task image digests (runs_image) and load_balancer->service
				// links — needs the edge return the asset-only services loop below
				// doesn't carry. partial: a sub-listing (running tasks, a task
				// definition, target groups) failed but the services are real.
				func() {
					more, edges, partial, err := collectECS(ctx, rcfg, region, accountID, now)
					if err != nil {
						regionSkip(err, region, "ecs")
						return
					}
					resultMu.Lock()
					defer resultMu.Unlock()
					result.Assets = append(result.Assets, more...)
					result.Edges = append(result.Edges, edges...)
					if partial {
						result.Partial = true
					}
				},
				// GuardDuty threat findings (provider-native). Best-effort: a region
				// with GuardDuty disabled or a transient error must not fail the whole
				// account sync — log and move on.
				//
				// A complete listing is declared AFTER its findings are in the
				// result, unlike the asset scopes above: the sync worker closes
				// every stored finding a complete scope did not return, so a claim
				// that outlived its payload (a panic between the two) would close
				// live threats rather than merely skew a gauge.
				func() {
					gd, listed, err := collectGuardDuty(ctx, rcfg, region, now)
					if err != nil {
						regionSkip(err, region, "guardduty")
						return
					}
					resultMu.Lock()
					result.Findings = append(result.Findings, gd...)
					resultMu.Unlock()
					if listed {
						complete(region, collect.GuardDutyFindingsFamily, []string{collect.GuardDutyFindingType}, len(gd))
					}
				},
			)

			// List-and-emit regional services (regional_catalogue.go), each a
			// best-effort task: a timeout or access-denied on one service must
			// not prevent the others from running.
			tasks = append(tasks, regionalServiceTasks(ctx, rcfg, region, accountID, now, regionalHooks{
				skip: regionSkip, complete: complete,
				notOffered: ledger.notOffered, unproven: ledger.unproven,
				add: func(more []asset.Asset, partial bool, proven string) {
					resultMu.Lock()
					defer resultMu.Unlock()
					result.Assets = append(result.Assets, more...)
					result.Partial = result.Partial || partial
					if proven != "" {
						result.MarkCapabilityProven(proven)
					}
				},
			})...)
		}

		var wg sync.WaitGroup
		sem := make(chan struct{}, regionConcurrency)
		for _, task := range tasks {
			wg.Add(1)
			sem <- struct{}{}
			go func(task func()) {
				defer wg.Done()
				defer func() { <-sem }()
				defer func() {
					if rec := recover(); rec != nil {
						// Route through regionSkip(), not a bare log line: every other
						// failure path flags result.Partial through it so deletion
						// reconciliation knows this region's inventory is incomplete,
						// not legitimately empty.
						regionSkip(fmt.Errorf("panic: %v", rec), region, "regional collector")
					}
				}()
				tally.started()
				task()
			}(task)
		}
		wg.Wait()

		pkgAssets, pkgEdges := inventory.apply(ctx, regionInstances, seenPackages, now)
		result.Assets = append(result.Assets, pkgAssets...)
		result.Edges = append(result.Edges, pkgEdges...)

		denied, failures := ledger.settle(len(tasks), regionFailures, tally)
		ledger.warnWithdrawn(ctx, region)
		if denied {
			log.FromContext(ctx).Warn().Str("region", region).Str("account_id", accountID).
				Int("calls", len(tasks)).Err(failures[0].err).
				Msg("region denied to the connector (every call refused, typically a region-deny SCP); excluded from coverage — nothing in it is marked complete, so its stored inventory is left alone")
		} else {
			for _, f := range failures {
				markSkipped(f.err, region, f.what)
			}
		}

		if regionElapsed := time.Since(regionStarted); regionElapsed > slowCollectorThreshold {
			log.FromContext(ctx).Warn().Str("region", region).Str("account_id", accountID).
				Dur("elapsed", regionElapsed).
				Msg("region collection took longer than expected")
		}
	}
	if regionalElapsed := time.Since(regionalStarted); regionalElapsed > slowCollectorThreshold {
		log.FromContext(ctx).Warn().Str("account_id", accountID).Int("regions", len(regions)).
			Dur("elapsed", regionalElapsed).
			Msg("all-regions collection took longer than expected — global services (S3/IAM/Route53/SSO/SCP/CloudTrail) get whatever is left of the shared sync deadline, though they now run concurrently rather than queued behind each other")
	}

	// Global services — IAM, Route53, S3, SSO, SCPs and CloudTrail are not regional.
	// Each is best-effort: a permission gap or transient error on one must not
	// discard the entire account inventory or cancel the connector. See
	// collectGlobalServices (globalservices.go).
	if hasCreds {
		collectGlobalServices(ctx, cfg, accountID, now, skip, tally, &resultMu, &result)
	}

	// Every call AWS refused, none failing for any other reason: the connector
	// cannot read this account at all, which is an error to fix, not a sweep
	// that happened to come back partial.
	if tally.allRefused() {
		return collect.Result{}, fmt.Errorf("%w: AWS refused every collection call for account %s — the connector's credentials or role permissions are unusable", collect.ErrPermanent, accountID)
	}

	annotateRouting(result.Assets, routesByRegion)
	annotateVolumeSnapshots(result.Assets, snapshotVolumesByRegion)
	joinCrossAssetFacts(result.Assets) // needs every collector's output, regional and global

	// Inventory coverage: EKS clusters GuardDuty reports threats about that this
	// sweep's asset inventory does not contain. Runs last so it sees every asset
	// and every provider finding collected above.
	result.Findings = append(result.Findings,
		uninventoriedEKSClusterFindings(result.Findings, result.Assets, eksListedRegions, now)...)

	return result, nil
}

// regionsFor returns the regions to scan. An explicit "regions" config (CSV)
// wins; otherwise it enumerates the account's enabled regions via
// DescribeRegions, falling back to the single base "region" if enumeration
// returns nothing (e.g. unit tests, or a transient failure).
//
// The second return value reports whether the returned list is a FALLBACK —
// not a real enumeration — rather than the account's true enabled-region
// set. A fallback list must never be read as "the missing regions hold
// nothing": the caller must flag the sweep partial, or a silent shrink of
// the region set would look, in aggregate, like a full account enumeration.
func (c *Collector) regionsFor(ctx context.Context, cfg map[string]string) ([]string, bool, error) {
	if v := strings.TrimSpace(cfg["regions"]); v != "" {
		var out []string
		for r := range strings.SplitSeq(v, ",") {
			if r = strings.TrimSpace(r); r != "" {
				out = append(out, r)
			}
		}
		if len(out) > 0 {
			return out, false, nil
		}
	}

	client, base, err := c.newClient(ctx, cfg)
	if err != nil {
		return nil, false, err
	}
	out, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil || out == nil || len(out.Regions) == 0 {
		if base == "" {
			return nil, false, fmt.Errorf("regionsFor: no region configured and enumeration failed: %w", err)
		}
		// Only a genuine DescribeRegions error is a fallback that must flag
		// the sweep partial: it silently shrinks the region set out from
		// under the caller. A nil error with zero regions is the enumeration
		// legitimately succeeding at "nothing" (also the shape unit tests
		// use to opt out of multi-region enumeration) — that is not a
		// truncated read, so it is not flagged.
		return []string{base}, err != nil, nil
	}
	regions := make([]string, 0, len(out.Regions))
	for _, r := range out.Regions {
		if n := awssdk.ToString(r.RegionName); n != "" {
			regions = append(regions, n)
		}
	}
	return regions, false, nil
}

// withRegion returns a copy of cfg with the region overridden, so each region's
// clients (built from cfg via baseConfig) target that region.
func withRegion(cfg map[string]string, region string) map[string]string {
	out := make(map[string]string, len(cfg)+1)
	maps.Copy(out, cfg)
	out["region"] = region
	return out
}

// ec2HttpTokens returns the IMDSv2 enforcement status from instance metadata
// options: "required" = IMDSv2 enforced (safe), "optional" = IMDSv1 still
// allowed (SSRF risk).
//
// The bool is false when DescribeInstances returned no MetadataOptions at
// all — nothing was observed, and the caller omits the key rather than
// defaulting to "optional", which would manufacture the exact violation
// aws-ec2-imdsv2-not-required fires on out of a collection gap.
func ec2HttpTokens(opts *ec2types.InstanceMetadataOptionsResponse) (string, bool) {
	if opts == nil {
		return "", false
	}
	return string(opts.HttpTokens), true
}

func sgCSV(groups []ec2types.GroupIdentifier) string {
	ids := make([]string, 0, len(groups))
	for _, g := range groups {
		if id := awssdk.ToString(g.GroupId); id != "" {
			ids = append(ids, id)
		}
	}
	return strings.Join(ids, ",")
}

func defaultClient(ctx context.Context, cfg map[string]string) (ec2API, string, error) {
	region := cfg["region"]
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, "", fmt.Errorf("defaultClient: %w", err)
	}
	return ec2.NewFromConfig(awsCfg), region, nil
}

// accountAsset returns a cloud_account Asset for the given AWS account ID and name.
// It is emitted once per sync so the graph has an AWSAccount anchor node.
// DiscoveredAt/LastSeen MUST be set to now: the assets table is TTL'd on
// last_seen + 180 DAY, so a zero LastSeen makes the row instantly TTL-eligible
// and it gets purged before it ever renders (the anchor never persisted).
func accountAsset(accountID, accountName string, now time.Time) asset.Asset {
	name := accountName
	if name == "" {
		name = accountID
	}
	return asset.Asset{
		ID:           "aws:" + accountID,
		Type:         "cloud_account",
		Name:         name,
		Provider:     "aws",
		AccountID:    accountID,
		DiscoveredAt: now,
		LastSeen:     now,
		Metadata: map[string]string{
			"account_id": accountID,
			"provider":   "aws",
			// account_anchor marks the synthetic per-account root node and
			// changes this asset's ContentHash (which excludes LastSeen), so a
			// LastSeen-only fix still busts any stale stored hash and forces
			// the anchor to be re-materialised.
			"account_anchor": "true",
		},
	}
}

// ownsEdge returns an Owns edge from the cloud_account to the given EC2 instance asset.
func ownsEdge(accountID, assetID string) asset.Edge {
	return asset.Edge{
		SrcID:    "aws:" + accountID,
		SrcType:  "cloud_account",
		DstID:    assetID,
		DstType:  "ec2_instance",
		EdgeType: "owns",
	}
}
