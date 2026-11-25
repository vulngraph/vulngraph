package aws

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// route53ZoneConcurrency bounds concurrent per-zone record-set pagination,
// mirroring s3BucketConcurrency: each hosted zone's ListResourceRecordSets
// pagination is independent, and running them sequentially is the
// whole-account sync's own bottleneck on an account with many zones or one
// very large zone.
//
// Set lower than s3BucketConcurrency deliberately: Route53's own
// account-level rate limit (AWS documents ListResourceRecordSets at 5 req/s
// per account, far tighter than S3's) can trip Throttling: Rate exceeded at
// higher fan-out, exhausting the SDK's default retry and permanently
// skipping zones. route53Retryer (below) absorbs bursts that do occur; this
// constant keeps the steady-state request rate under the limit in the first
// place — retries alone can't fix it once concurrency is high enough that
// every attempt's retry races the same throttle.
const route53ZoneConcurrency = 3

// route53Retryer widens the SDK's default 3-attempt/20s-backoff retry —
// insufficient for a service documented at 5 req/s per account, where a
// transient burst can need more than 3 tries to clear. 8 attempts with
// exponential backoff up to 30s absorbs a burst instead of permanently
// skipping the zone's records.
//
// Clears o.RetryMaxAttempts to 0 before setting o.Retryer: route53.New calls
// finalizeRetryMaxAttempts, which — only when RetryMaxAttempts != 0 — wraps
// whatever Retryer is set in retry.AddWithMaxAttempts, silently overriding
// our 8 back down to whatever RetryMaxAttempts resolves to from ambient AWS
// config (e.g. AWS_MAX_ATTEMPTS). Clearing it first prevents that override.
func route53Retryer() func(*route53.Options) {
	return func(o *route53.Options) {
		o.RetryMaxAttempts = 0
		o.Retryer = retry.NewStandard(func(so *retry.StandardOptions) {
			so.MaxAttempts = 8
			so.MaxBackoff = 30 * time.Second
		})
	}
}

type route53API interface {
	ListHostedZones(context.Context, *route53.ListHostedZonesInput, ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	ListResourceRecordSets(context.Context, *route53.ListResourceRecordSetsInput, ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
	ListQueryLoggingConfigs(context.Context, *route53.ListQueryLoggingConfigsInput, ...func(*route53.Options)) (*route53.ListQueryLoggingConfigsOutput, error)
}

// collectRoute53 returns the account's DNS inventory plus whether the
// collection was partial — some zone's record listing failed (permission gap,
// throttle, or the shared sync deadline) and its records were skipped rather
// than fabricated. The caller (collectAll) must flag the whole account's
// result Partial when true, so deletion reconciliation does not
// read an unfetched zone's records as deleted.
func collectRoute53(ctx context.Context, cfg map[string]string, accountID string, now time.Time) ([]asset.Asset, []asset.Edge, bool, error) {
	// Route53 is global — no region needed for the client.
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, nil, false, fmt.Errorf("collectRoute53: %w", err)
	}
	// Route53 is global; sign for the partition's home region.
	awsCfg.Region = globalRegionFor(awsCfg.Region)
	client := route53.NewFromConfig(awsCfg, route53Retryer())
	return collectDNSRecords(ctx, client, accountID, now)
}

func collectDNSRecords(ctx context.Context, client route53API, accountID string, now time.Time) ([]asset.Asset, []asset.Edge, bool, error) {
	var (
		assets []asset.Asset
		edges  []asset.Edge
	)

	// Hosted-zone listing stays sequential: it is one cheap paginated call per
	// ~100 zones (accounts hold tens of zones, not thousands), unlike the
	// per-zone RECORD listing below, which is where the real cost lives.
	var zones []r53types.HostedZone
	var zoneMarker *string
	for {
		out, err := client.ListHostedZones(ctx, &route53.ListHostedZonesInput{Marker: zoneMarker})
		if err != nil {
			return nil, nil, false, fmt.Errorf("collectDNSRecords: list zones: %w", err)
		}
		zones = append(zones, out.HostedZones...)
		if !out.IsTruncated {
			break
		}
		zoneMarker = out.NextMarker
	}

	// One account-wide listing answers which zones log DNS queries (AWS FSBP
	// Route53.2). On failure the map stays nil and no zone carries the key.
	logged, err := queryLoggedZones(ctx, client)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("route53 query logging config listing failed; zones' query logging is unknown this sweep")
	}

	// Each zone's own record-set pagination is independent, so it is fanned
	// out — mirroring regionConcurrency/s3BucketConcurrency's exact shape:
	// bounded goroutines, a WaitGroup, and a mutex-guarded merge of the shared
	// slices/partial flag.
	var (
		wg      sync.WaitGroup
		sem     = make(chan struct{}, route53ZoneConcurrency)
		mu      sync.Mutex
		partial bool
	)
	logger := log.FromContext(ctx)
	for _, zone := range zones {
		wg.Add(1)
		sem <- struct{}{}
		go func(zone r53types.HostedZone) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error().Any("panic", rec).Str("zone", awssdk.ToString(zone.Id)).
						Msg("route53 zone collection panicked; zone omitted")
					mu.Lock()
					partial = true
					mu.Unlock()
				}
			}()

			zoneID := awssdk.ToString(zone.Id)
			zoneName := strings.TrimSuffix(awssdk.ToString(zone.Name), ".")
			private := zone.Config != nil && zone.Config.PrivateZone

			// Emit the hosted zone as a first-class asset so DNS records can be
			// traversed as members of a zone in the graph.
			zoneAssetID := "aws-zone:" + zoneID
			zoneAsset := asset.Asset{
				Type:         "dns_zone",
				ID:           zoneAssetID,
				Name:         zoneName,
				Provider:     asset.ProviderAWS,
				Region:       "global",
				AccountID:    accountID,
				Metadata:     map[string]string{"zone_id": zoneID, "provider": "aws", "private_zone": fmt.Sprintf("%t", private)},
				DiscoveredAt: now,
				LastSeen:     now,
			}
			if logged != nil {
				zoneAsset.Metadata["query_logging"] = fmt.Sprintf("%t", logged[strings.TrimPrefix(zoneID, hostedZonePrefix)])
			}

			var zoneAssets []asset.Asset
			var zoneEdges []asset.Edge
			zoneAssets = append(zoneAssets, zoneAsset)

			var (
				rrNameMarker *string
				rrTypeMarker r53types.RRType
				zonePartial  bool
			)
			for {
				rrs, err := client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
					HostedZoneId:    zone.Id,
					StartRecordName: rrNameMarker,
					StartRecordType: rrTypeMarker,
				})
				if err != nil {
					// One zone's records failing (permission gap, throttle, or a
					// shared-deadline cancellation) must not discard every other
					// zone or sink the account's whole inventory. Skip this zone's
					// remaining records, but DO flag partial, so an absent zone's
					// records are not read as deleted.
					logger.Warn().Err(err).Str("zone", zoneID).Msg("route53 record listing skipped for zone")
					zonePartial = true
					break
				}
				for _, rr := range rrs.ResourceRecordSets {
					name := strings.TrimSuffix(awssdk.ToString(rr.Name), ".")
					id := fmt.Sprintf("%s/%s/%s", zoneID, string(rr.Type), name)
					// For Alias records (CloudFront, ALB, API GW, S3 website),
					// Route53 uses AliasTarget instead of ResourceRecords. Store the
					// alias DNSName as the "values" field so takeover checks fire.
					recType := string(rr.Type)
					values := recordValues(rr.ResourceRecords)
					if rr.AliasTarget != nil && values == "" {
						values = awssdk.ToString(rr.AliasTarget.DNSName)
						recType = "ALIAS"
					}

					// DNS records in public zones are internet-accessible by definition.
					// Mark them so the enrichment exposure factor fires.
					var publicIP string
					if !private && recType == "A" {
						publicIP = values // A record in public zone = direct public IP
					}

					a := asset.Asset{
						ID:        id,
						Name:      name,
						Type:      "dns_record",
						Provider:  asset.ProviderAWS,
						Region:    "global",
						AccountID: accountID,
						Domain:    name,
						PublicIP:  publicIP,
						Metadata: map[string]string{
							"zone_id":   zoneID,
							"zone_name": zoneName,
							"type":      recType,
							"ttl":       fmt.Sprintf("%d", awssdk.ToInt64(rr.TTL)),
							"values":    values,
							"private":   fmt.Sprintf("%t", private),
							"public":    fmt.Sprintf("%t", !private),
						},
						DiscoveredAt: now,
						LastSeen:     now,
					}
					zoneAssets = append(zoneAssets, a)
					zoneEdges = append(zoneEdges, asset.Edge{
						SrcID:    id,
						SrcType:  "dns_record",
						DstID:    zoneAssetID,
						DstType:  "dns_zone",
						EdgeType: "member_of_zone",
					})
				}
				if !rrs.IsTruncated {
					break
				}
				rrNameMarker = rrs.NextRecordName
				rrTypeMarker = rrs.NextRecordType
			}

			mu.Lock()
			assets = append(assets, zoneAssets...)
			edges = append(edges, zoneEdges...)
			if zonePartial {
				partial = true
			}
			mu.Unlock()
		}(zone)
	}
	wg.Wait()

	return assets, edges, partial, nil
}

func recordValues(records []r53types.ResourceRecord) string {
	vals := make([]string, len(records))
	for i, r := range records {
		vals[i] = awssdk.ToString(r.Value)
	}
	return strings.Join(vals, ",")
}

// hostedZonePrefix is how ListHostedZones prefixes a zone ID; the query
// logging listing reports the bare ID.
const hostedZonePrefix = "/hostedzone/"

// queryLoggedZones returns the bare IDs of every hosted zone with a query
// logging configuration. Any page error fails the listing: a partial set
// would read the unlisted zones as unlogged.
func queryLoggedZones(ctx context.Context, client route53API) (map[string]bool, error) {
	out := map[string]bool{}
	var token *string
	for {
		page, err := client.ListQueryLoggingConfigs(ctx, &route53.ListQueryLoggingConfigsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("queryLoggedZones: %w", err)
		}
		for _, c := range page.QueryLoggingConfigs {
			out[strings.TrimPrefix(awssdk.ToString(c.HostedZoneId), hostedZonePrefix)] = true
		}
		if page.NextToken == nil {
			return out, nil
		}
		token = page.NextToken
	}
}
