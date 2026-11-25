package gcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/api/dns/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type dnsAPI interface {
	ListZones(ctx context.Context, projectID string) ([]*dns.ManagedZone, error)
	ListRecords(ctx context.Context, projectID, zone string) ([]*dns.ResourceRecordSet, error)
}

type gcpDNSClient struct {
	svc *dns.Service
}

func (c *gcpDNSClient) ListZones(ctx context.Context, projectID string) ([]*dns.ManagedZone, error) {
	var zones []*dns.ManagedZone
	call := c.svc.ManagedZones.List(projectID)
	if err := call.Pages(ctx, func(page *dns.ManagedZonesListResponse) error {
		zones = append(zones, page.ManagedZones...)
		return nil
	}); err != nil {
		return nil, err
	}
	return zones, nil
}

func (c *gcpDNSClient) ListRecords(ctx context.Context, projectID, zone string) ([]*dns.ResourceRecordSet, error) {
	var records []*dns.ResourceRecordSet
	call := c.svc.ResourceRecordSets.List(projectID, zone)
	if err := call.Pages(ctx, func(page *dns.ResourceRecordSetsListResponse) error {
		records = append(records, page.Rrsets...)
		return nil
	}); err != nil {
		return nil, err
	}
	return records, nil
}

func collectGCPDNS(ctx context.Context, client dnsAPI, projectID string, now time.Time) ([]asset.Asset, []asset.Edge, error) {
	zones, err := client.ListZones(ctx, projectID)
	if err != nil {
		return nil, nil, fmt.Errorf("collectGCPDNS: list zones: %w", err)
	}

	var assets []asset.Asset
	var edges []asset.Edge
	for _, zone := range zones {
		zoneAssetID := fmt.Sprintf("gcp-zone:%s/%s", projectID, zone.Name)
		zoneName := strings.TrimSuffix(zone.DnsName, ".")
		assets = append(assets, asset.Asset{
			Type:         "dns_zone",
			ID:           zoneAssetID,
			Name:         zoneName,
			Provider:     asset.ProviderGCP,
			Region:       "global",
			AccountID:    projectID,
			Metadata:     zoneMetadata(zone),
			DiscoveredAt: now,
			LastSeen:     now,
		})

		records, err := client.ListRecords(ctx, projectID, zone.Name)
		if err != nil {
			return nil, nil, fmt.Errorf("collectGCPDNS: list records zone %s: %w", zone.Name, err)
		}
		for _, rr := range records {
			name := strings.TrimSuffix(rr.Name, ".")
			id := fmt.Sprintf("%s/dns/%s/%s", projectID, zone.Name, rr.Name)
			assets = append(assets, asset.Asset{
				ID:        id,
				Name:      name,
				Type:      "dns_record",
				Provider:  asset.ProviderGCP,
				Region:    "global",
				AccountID: projectID,
				Domain:    name,
				Metadata: map[string]string{
					"zone":    zone.Name,
					"type":    rr.Type,
					"ttl":     fmt.Sprintf("%d", rr.Ttl),
					"values":  strings.Join(rr.Rrdatas, ","),
					"private": fmt.Sprintf("%t", zone.Visibility == "private"),
				},
				DiscoveredAt: now,
				LastSeen:     now,
			})
			edges = append(edges, asset.Edge{
				SrcID:    id,
				SrcType:  "dns_record",
				DstID:    zoneAssetID,
				DstType:  "dns_zone",
				EdgeType: "member_of_zone",
			})
		}
	}
	return assets, edges, nil
}

// newDNSClient builds a Cloud DNS client using Application Default Credentials:
// the pod's Workload-Identity service account in GKE, gcloud ADC in
// local dev. No key is stored on the connector.
func newDNSClient(ctx context.Context) (*gcpDNSClient, error) {
	svc, err := dns.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newDNSClient: %w", err)
	}
	return &gcpDNSClient{svc: svc}, nil
}

// zoneMetadata records a managed zone's DNSSEC posture (CIS GCP 3.3-3.5)
// alongside its identity. On a public zone the API omits dnssecConfig when
// every field is at its default, and the default state is off, so a public
// zone read without one is observed off. Private zones cannot use DNSSEC and
// get no state. The key algorithms are those defaultKeySpecs names for each
// key type, comma-joined.
func zoneMetadata(zone *dns.ManagedZone) map[string]string {
	md := map[string]string{"zone_id": zone.Name, "provider": "gcp", "visibility": zone.Visibility}
	if zone.Visibility == "" {
		md["visibility"] = "public" // the API default for a managed zone
	}
	if zone.DnssecConfig == nil && md["visibility"] == "public" {
		md["dnssec_state"] = "off"
	}
	if c := zone.DnssecConfig; c != nil {
		md["dnssec_state"] = c.State
		var ksk, zsk []string
		for _, spec := range c.DefaultKeySpecs {
			if spec == nil {
				continue
			}
			switch spec.KeyType {
			case "keySigning":
				ksk = append(ksk, strings.ToLower(spec.Algorithm))
			case "zoneSigning":
				zsk = append(zsk, strings.ToLower(spec.Algorithm))
			}
		}
		md["dnssec_ksk_algorithms"] = strings.Join(ksk, ",")
		md["dnssec_zsk_algorithms"] = strings.Join(zsk, ",")
	}
	return md
}
