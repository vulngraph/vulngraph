package correlate

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// publicEC2 is an instance with a public IP behind a world-open SG; inSubnet
// is the collector's in_public_subnet fact ("" leaves the key absent).
func publicEC2(id, inSubnet string) asset.Asset {
	meta := map[string]string{"security_groups": "sg-open"}
	if inSubnet != "" {
		meta["in_public_subnet"] = inSubnet
	}
	return asset.Asset{ID: id, Type: "ec2_instance", PublicIP: "1.2.3.4", Metadata: meta}
}

func publicRDS(id, inSubnet string) asset.Asset {
	meta := map[string]string{"publicly_accessible": "true"}
	if inSubnet != "" {
		meta["in_public_subnet"] = inSubnet
	}
	return asset.Asset{ID: id, Type: "rds_instance", Metadata: meta}
}

func TestInternetReachability_SubnetRoutingGatesPublicIPExposure(t *testing.T) {
	g := NewGraph([]asset.Asset{
		sg("sg-open", `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`),
		publicEC2("i-routed", "true"),
		publicEC2("i-private", "false"),
		publicEC2("i-unknown", ""),
		publicRDS("db-routed", "true"),
		publicRDS("db-private", "false"),
		publicRDS("db-unknown", ""),
		// An internet-facing LB fronting a private-subnet target keeps its own
		// edge: the target's subnet never governs exposure through the LB.
		{ID: "lb-1", Type: "load_balancer", Metadata: map[string]string{"public": "true"}},
	})

	r := InternetReachability{}
	basis := map[string]string{}
	for _, e := range r.Correlate(g) {
		basis[e.SrcID] = e.Properties["exposure_basis"]
	}
	require.Equal(t, map[string]string{
		"i-routed":  basisRouteConfirmed,
		"i-unknown": basisRouteUnknown,
		"db-routed": basisRouteConfirmed,
		// Unknown routing keeps the exposure exactly as before routes were collected.
		"db-unknown": basisRouteUnknown,
		"lb-1":       "",
	}, basis)

	require.ElementsMatch(t, []Demotion{
		{AssetID: "i-private", AssetType: "ec2_instance", Reason: demotedPrivateSubnet},
		{AssetID: "db-private", AssetType: "rds_instance", Reason: demotedPrivateSubnet},
	}, r.Demotions(g), "every withheld exposure is reported, never dropped silently")
}

func TestInternetReachability_PrivateSubnetWithoutOpenSGIsNotADemotion(t *testing.T) {
	// No world-open SG means no exposure to begin with — nothing was demoted.
	g := NewGraph([]asset.Asset{
		sg("sg-open", `[{"protocol":"tcp","from_port":443,"to_port":443,"sg_refs":["sg-lb"]}]`),
		publicEC2("i-private", "false"),
	})
	require.Empty(t, InternetReachability{}.Correlate(g))
	require.Empty(t, InternetReachability{}.Demotions(g))
}

func TestLogDemotions_OneLinePerReasonWithBoundedSample(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)
	var demoted []Demotion
	for i := 0; i < demotionLogSample+5; i++ {
		demoted = append(demoted, Demotion{AssetID: "i-" + string(rune('a'+i)), AssetType: "ec2_instance", Reason: demotedPrivateSubnet})
	}
	logDemotions(&logger, "internet_reachability", demoted)

	var line struct {
		Rule    string   `json:"rule"`
		Reason  string   `json:"reason"`
		Demoted int      `json:"demoted"`
		Sample  []string `json:"sample_asset_ids"`
	}
	require.NoError(t, json.Unmarshal(buf.Bytes(), &line))
	require.Equal(t, "internet_reachability", line.Rule)
	require.Equal(t, demotedPrivateSubnet, line.Reason)
	require.Equal(t, demotionLogSample+5, line.Demoted)
	require.Len(t, line.Sample, demotionLogSample)

	buf.Reset()
	logDemotions(&logger, "internet_reachability", nil)
	require.Empty(t, buf.String())
}
