package correlate

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func dnsRecord(id, typ, values string) asset.Asset {
	return asset.Asset{ID: id, Type: "dns_record", Metadata: map[string]string{"type": typ, "values": values}}
}

func TestDNSPointsTo_MatchesPublicIP(t *testing.T) {
	g := NewGraph([]asset.Asset{
		dnsRecord("rec-a", "A", "1.2.3.4"),
		{ID: "i-123", Type: "ec2_instance", PublicIP: "1.2.3.4"},
	})

	edges := DNSPointsTo{}.Correlate(g)
	require.Len(t, edges, 1)
	require.Equal(t, "rec-a", edges[0].SrcID)
	require.Equal(t, "i-123", edges[0].DstID)
	require.Equal(t, "ec2_instance", edges[0].DstType)
	require.Equal(t, EdgeDNSPointsTo, edges[0].EdgeType)
	require.Equal(t, "1.2.3.4", edges[0].Properties["matched_value"])
	require.Equal(t, "correlate", edges[0].Properties["origin"])
}

func TestDNSPointsTo_CrossCloudAndMultiValue(t *testing.T) {
	// One A record with two IPs resolving to assets in different clouds.
	g := NewGraph([]asset.Asset{
		dnsRecord("rec", "A", "1.2.3.4, 5.6.7.8"),
		{ID: "aws-eip", Type: "elastic_ip", PublicIP: "1.2.3.4"},
		{ID: "gcp-vm", Type: "gce_instance", PublicIP: "5.6.7.8"},
	})

	edges := DNSPointsTo{}.Correlate(g)
	require.Len(t, edges, 2)
	dst := map[string]string{}
	for _, e := range edges {
		dst[e.DstID] = e.DstType
	}
	require.Equal(t, "elastic_ip", dst["aws-eip"])
	require.Equal(t, "gce_instance", dst["gcp-vm"])
}

func TestDNSPointsTo_CNAMEMatchesLoadBalancerDomain(t *testing.T) {
	g := NewGraph([]asset.Asset{
		dnsRecord("rec-cname", "CNAME", "my-lb-123.eu-west-1.elb.amazonaws.com"),
		{ID: "arn:alb", Type: "load_balancer", Domain: "my-lb-123.eu-west-1.elb.amazonaws.com"},
	})

	edges := DNSPointsTo{}.Correlate(g)
	require.Len(t, edges, 1)
	require.Equal(t, "arn:alb", edges[0].DstID)
	require.Equal(t, "load_balancer", edges[0].DstType)
}

func TestDNSPointsTo_NoMatchIsDanglingCandidate(t *testing.T) {
	// A record pointing to an IP no asset owns — produces no edge (the absence
	// is what dangling detection keys on).
	g := NewGraph([]asset.Asset{dnsRecord("rec", "A", "203.0.113.99")})
	require.Empty(t, DNSPointsTo{}.Correlate(g))
}

func TestDNSPointsTo_EmptyValues(t *testing.T) {
	g := NewGraph([]asset.Asset{dnsRecord("rec", "A", "")})
	require.Empty(t, DNSPointsTo{}.Correlate(g))
}

func TestDNSPointsTo_CapsFanOutPerValue(t *testing.T) {
	// A shared/anycast IP owned by many assets must fan out to at most
	// maxDNSTargetsPerValue edges, deterministically (lowest IDs kept).
	assets := []asset.Asset{dnsRecord("rec", "A", "1.2.3.4")}
	total := maxDNSTargetsPerValue + 10
	for i := range total {
		// zero-padded id so lexical order == numeric order
		assets = append(assets, asset.Asset{
			ID:       fmt.Sprintf("i-%03d", i),
			Type:     "ec2_instance",
			PublicIP: "1.2.3.4",
		})
	}
	g := NewGraph(assets)

	edges := DNSPointsTo{}.Correlate(g)
	require.Len(t, edges, maxDNSTargetsPerValue, "fan-out capped at maxDNSTargetsPerValue")

	// Deterministic: the kept edges are the lexically-lowest IDs.
	got := make([]string, len(edges))
	for i, e := range edges {
		got[i] = e.DstID
	}
	require.Equal(t, "i-000", got[0])
	require.NotContains(t, got, fmt.Sprintf("i-%03d", total-1), "the tail must be dropped")

	// Stable across repeated runs (guards against map-iteration nondeterminism).
	edges2 := DNSPointsTo{}.Correlate(g)
	got2 := make([]string, len(edges2))
	for i, e := range edges2 {
		got2[i] = e.DstID
	}
	require.Equal(t, got, got2, "truncation must be deterministic")
}

func TestDNSPointsTo_AtCapNotTruncated(t *testing.T) {
	// Exactly maxDNSTargetsPerValue matches: all kept, none dropped.
	assets := []asset.Asset{dnsRecord("rec", "A", "1.2.3.4")}
	for i := range maxDNSTargetsPerValue {
		assets = append(assets, asset.Asset{
			ID:       fmt.Sprintf("i-%03d", i),
			Type:     "ec2_instance",
			PublicIP: "1.2.3.4",
		})
	}
	g := NewGraph(assets)
	require.Len(t, DNSPointsTo{}.Correlate(g), maxDNSTargetsPerValue)
}

// A dns_record carries a Domain (its own name) and, for an A record, a
// PublicIP copied off its own values. Indexing those made every record a
// resolution TARGET: nearly all dns_points_to edges pointed at another
// dns_record on a large estate. Only infrastructure is a valid target.
func TestDNSPointsTo_NeverTargetsAnotherDNSRecord(t *testing.T) {
	g := NewGraph([]asset.Asset{
		// Two A records sharing an IP, both carrying it in public_ip as the
		// collector writes it, plus the one real asset that owns it.
		{ID: "rec-a", Type: "dns_record", Domain: "a.example.com", PublicIP: "1.2.3.4",
			Metadata: map[string]string{"type": "A", "values": "1.2.3.4"}},
		{ID: "rec-b", Type: "dns_record", Domain: "b.example.com", PublicIP: "1.2.3.4",
			Metadata: map[string]string{"type": "A", "values": "1.2.3.4"}},
		{ID: "i-1", Type: "ec2_instance", PublicIP: "1.2.3.4"},
	})

	edges := DNSPointsTo{}.Correlate(g)
	require.Len(t, edges, 2, "one edge per record, to the instance only")
	for _, e := range edges {
		require.Equal(t, "i-1", e.DstID)
		require.Equal(t, "ec2_instance", e.DstType)
	}
}

func TestDNSPointsTo_CNAMENeverTargetsAnotherDNSRecord(t *testing.T) {
	g := NewGraph([]asset.Asset{
		{ID: "rec-cname", Type: "dns_record", Domain: "www.example.com",
			Metadata: map[string]string{"type": "CNAME", "values": "app.example.com"}},
		// The apex record for the CNAME target — a name, not infrastructure.
		{ID: "rec-apex", Type: "dns_record", Domain: "app.example.com",
			Metadata: map[string]string{"type": "A", "values": "1.2.3.4"}},
		{ID: "arn:alb", Type: "load_balancer", Domain: "app.example.com"},
	})

	edges := DNSPointsTo{}.Correlate(g)
	require.Len(t, edges, 1)
	require.Equal(t, "arn:alb", edges[0].DstID)
}

// dns_zone assets are names too — excluded from the target indexes for the same
// reason (collectors give them no domain/public_ip today, so this is a guard).
func TestDNSPointsTo_NeverTargetsADNSZone(t *testing.T) {
	g := NewGraph([]asset.Asset{
		dnsRecord("rec", "CNAME", "example.com"),
		{ID: "zone-1", Type: "dns_zone", Domain: "example.com"},
	})
	require.Empty(t, DNSPointsTo{}.Correlate(g))
}

// TestDNSPointsTo_IgnoresTypesOutsideItsOwnTargetSet is the regression guard
// for the dormant label-promotion landmine: NewGraph's byPublicIP/byDomain
// index is NOT restricted to InterestedIn's type list — ANY non-DNS-name
// asset with a PublicIP or Domain gets indexed, promoted Ladybug node label or
// not — so if this rule emitted every match unfiltered, a future promoted
// type (K8sWorkload, SSOGroup, ...) that starts carrying either field would
// become a silent Ladybug-load drop the moment it matches a DNS record's value
// (DnsPointsTo's Rel is plain Asset→Asset with no reroute). k8s_pod is
// already promoted today (to K8sWorkload) — using it here proves the filter
// works against a REAL promoted type, not a hypothetical one.
func TestDNSPointsTo_IgnoresTypesOutsideItsOwnTargetSet(t *testing.T) {
	g := NewGraph([]asset.Asset{
		dnsRecord("rec", "A", "1.2.3.4"),
		{ID: "pod-1", Type: "k8s_pod", PublicIP: "1.2.3.4"},
		{ID: "i-1", Type: "ec2_instance", PublicIP: "1.2.3.4"},
	})
	edges := DNSPointsTo{}.Correlate(g)
	require.Len(t, edges, 1, "only the in-scope ec2_instance target should get an edge")
	require.Equal(t, "i-1", edges[0].DstID)
	require.Equal(t, "ec2_instance", edges[0].DstType)
}

// Some collectors write ALL of an asset's public IPs into public_ip as one
// comma-joined string; each must be its own index key or the value is
// unmatchable and the whole string becomes a junk key.
func TestDNSPointsTo_MatchesEachOfSeveralPublicIPs(t *testing.T) {
	g := NewGraph([]asset.Asset{
		dnsRecord("rec", "A", "203.0.113.10"),
		{ID: "arn:nlb", Type: "load_balancer", PublicIP: "203.0.113.10,203.0.113.11,203.0.113.12"},
	})

	edges := DNSPointsTo{}.Correlate(g)
	require.Len(t, edges, 1)
	require.Equal(t, "arn:nlb", edges[0].DstID)
	require.Empty(t, g.AssetsByPublicIP("203.0.113.10,203.0.113.11,203.0.113.12"),
		"the comma-joined string must not itself be an index key")
}

// The maxDNSTargetsPerValue cap sorts by ID and truncates, so junk targets could
// crowd the one real asset out of a shared value's target list.
func TestDNSPointsTo_RecordsDoNotCrowdOutRealTargetsUnderTheCap(t *testing.T) {
	assets := []asset.Asset{dnsRecord("rec", "A", "1.2.3.4")}
	for i := range maxDNSTargetsPerValue + 10 {
		assets = append(assets, asset.Asset{
			ID: fmt.Sprintf("aaa-rec-%03d", i), Type: "dns_record", PublicIP: "1.2.3.4",
			Metadata: map[string]string{"type": "A", "values": "1.2.3.4"},
		})
	}
	// Lexically last, so under the old index it was always the truncated tail.
	assets = append(assets, asset.Asset{ID: "zzz-instance", Type: "ec2_instance", PublicIP: "1.2.3.4"})

	edges := DNSPointsTo{}.Correlate(NewGraph(assets))
	require.Len(t, edges, maxDNSTargetsPerValue+11,
		"one edge per record (each finds the instance), plus the seed record's own")
	for _, e := range edges {
		require.Equal(t, "zzz-instance", e.DstID)
	}
}
