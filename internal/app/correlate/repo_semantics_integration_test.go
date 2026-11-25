//go:build integration

package correlate

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/db"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// Requires the existing integration ClickHouse database and applied migrations.
// These tests use the production asset writer, SQL projections, correlation,
// and edge reader; a mock database cannot validate the nested JSON seam.
func TestCHRepoSemantics_OrganizationProjectionAndApplicability(t *testing.T) {
	runID := uuid.New()
	suffix := runID.String()
	account := fmt.Sprintf("%012d", binary.BigEndian.Uint64(runID[:8])%1_000_000_000_000)
	management := fmt.Sprintf("%012d", binary.BigEndian.Uint64(runID[8:])%1_000_000_000_000)
	if management == account {
		management = fmt.Sprintf("%012d", (binary.BigEndian.Uint64(runID[8:])%1_000_000_000_000+1)%1_000_000_000_000)
	}
	now := time.Now()
	const full = `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	const deny = `{"Statement":[{"Effect":"Deny","Action":["iam:PassRole","secretsmanager:GetSecretValue"],"Resource":"*"}]}`
	orgContext := semanticsJSON(t, ciem.AWSOrganizationEvidence{
		AccountID: account, ManagementAccountID: management, ObservedAt: now, RootID: "r-integration", RootSCPStatus: "enabled", Applicability: "member", Complete: true,
		Levels: []ciem.SCPLevel{
			{TargetID: account, ParentID: "r-integration", Complete: true, Policies: []ciem.SCPPolicyDocument{{Name: "FullAWSAccess", Document: full}, {Name: "DenyPassAndSecrets", Document: deny}}},
			{TargetID: "r-integration", Complete: true, Policies: []ciem.SCPPolicyDocument{{Name: "FullAWSAccess", Document: full}}},
		},
	})
	membership := semanticsJSON(t, ciem.AWSOrganizationEvidence{AccountID: account, ManagementAccountID: management, ObservedAt: now})
	secret := "arn:aws:secretsmanager:eu-west-1:" + account + ":secret:integration-" + suffix
	// SecretAccess deliberately collapses wildcard grants into secret:*. Use a
	// concrete secret grant here so each projected role must target only this ARN.
	document := fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":["iam:PassRole","ec2:RunInstances"],"Resource":"*"},{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":%q}]}`, secret)
	policies := semanticsJSON(t, []ciem.Policy{{Name: "inline", Type: ciem.PolicyIdentity, Document: document}})
	ordinary := "arn:aws:iam::" + account + ":role/app-" + suffix
	linked := "arn:aws:iam::" + account + ":role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling_" + suffix
	moved := "arn:aws:iam::" + account + ":role/moved-" + suffix
	makeRole := func(id, witness string) asset.Asset {
		return asset.Asset{ID: id, Name: id, Type: "iam_role", Provider: asset.ProviderAWS, AccountID: account,
			Metadata: map[string]string{"policies": policies, "permission_boundary_complete": "true", ciem.MetaAWSOrganizationMembership: witness, "integration_unprojected_sentinel": "must be dropped"}}
	}
	rows := []asset.Asset{
		makeRole(ordinary, membership), makeRole(linked, membership),
		makeRole(moved, semanticsJSON(t, ciem.AWSOrganizationEvidence{AccountID: account, ManagementAccountID: "888888888888", ObservedAt: now})),
		{ID: "aws_scp:" + account, Name: "SCP context", Type: "aws_scp_set", Provider: asset.ProviderAWS, AccountID: account, Metadata: map[string]string{ciem.MetaAWSOrganization: orgContext}},
		{ID: secret, Name: "test secret", Type: "secretsmanager_secret", Provider: asset.ProviderAWS, AccountID: account},
		{ID: secret + "-ungranted", Name: "ungranted secret", Type: "secretsmanager_secret", Provider: asset.ProviderAWS, AccountID: account},
	}
	repo, stored, ids := semanticsStore(t, rows)
	for _, mode := range []string{"full", "types", "by IDs"} {
		t.Run(mode, func(t *testing.T) {
			loaded := semanticsLoad(t, repo, mode, rows, ids)
			byID := semanticsAssetMap(loaded)
			require.Equal(t, orgContext, byID["aws_scp:"+account].Metadata[ciem.MetaAWSOrganization], "nested policy JSON must survive server-side Map(String,String) projection")
			require.Equal(t, membership, byID[ordinary].Metadata[ciem.MetaAWSOrganizationMembership])
			require.Equal(t, policies, byID[ordinary].Metadata["policies"])
			require.NotContains(t, byID[ordinary].Metadata, "integration_unprojected_sentinel", "test must execute the projected SQL rather than a full-row substitute")
			graph := NewGraph(loaded)
			actions := IAMEffectivePermissions{}.Correlate(graph)
			passRoleSources := map[string]bool{}
			for _, edge := range actions {
				if edge.Properties["category"] == "iam-passrole" {
					passRoleSources[edge.SrcID] = true
				}
			}
			require.Equal(t, map[string]bool{linked: true, moved: true}, passRoleSources, "ordinary member is capped; reserved role is exempt; contradictory membership retains an uncertain candidate")
			accesses := SecretAccess{}.Correlate(graph)
			secretSources := map[string]bool{}
			for _, edge := range accesses {
				require.Equal(t, secret, edge.DstID)
				secretSources[edge.SrcID] = true
			}
			require.Equal(t, map[string]bool{linked: true, moved: true}, secretSources, "both permission consumers must use identical applicability evidence")
		})
	}
	// CIEM receives full persisted rows, unlike correlation's minimal view.
	fullRows, err := stored.ByIDs(t.Context(), ids)
	require.NoError(t, err)
	analysis := ciem.AnalyzeIAMAssets(t.Context(), fullRows)
	require.False(t, analysis.OrganizationPolicyCoverage[moved])
	require.Equal(t, ciem.TierUnknown, analysis.Tiers[moved].Tier)
	passRoleCandidates := map[string]bool{}
	for _, path := range analysis.Paths {
		if path.Rule.ID == "aws-privesc-11" {
			passRoleCandidates[path.SourcePrincipal] = true
		}
	}
	require.Equal(t, map[string]bool{linked: true, moved: true}, passRoleCandidates)
}

func TestCHRepoSemantics_NetworkProjectionAndEdgeProperties(t *testing.T) {
	prefix := "it-network-" + uuid.NewString() + "-"
	project := prefix + "project"
	network := prefix + "vpc"
	nics := `[{"network":"` + network + `","private_ipv4":"10.23.1.10","public_ipv4":"34.1.2.3"}]`
	gce := func(id, complete string) asset.Asset {
		return asset.Asset{ID: id, Name: id, Type: "gce_instance", Provider: asset.ProviderGCP, AccountID: project, PublicIP: "34.1.2.3", PrivateIP: "10.23.1.10", Tags: map[string]string{"integration": prefix}, Metadata: map[string]string{"network": network, "network_interfaces": nics, "firewall_rules_complete": complete, "integration_unprojected_sentinel": "drop"}}
	}
	firewall := func(id, priority, source, allow, deny, destination string) asset.Asset {
		return asset.Asset{ID: id, Name: id, Type: "gcp_firewall", Provider: asset.ProviderGCP, AccountID: project, Metadata: map[string]string{"network": network, "direction": "INGRESS", "priority": priority, "source_ranges": source, "allowed": allow, "denied": deny, "destination_ranges": destination}}
	}
	const azureRules = `[{"protocol":"tcp","from_port":443,"to_port":443,"cidrs":["Internet"],"destinations":["10.0.0.10"],"source_ports":["*"],"access":"deny","priority":100},{"protocol":"tcp","from_port":443,"to_port":443,"cidrs":["Internet"],"destinations":["*"],"source_ports":["*"],"access":"allow","priority":200}]`
	nsg := prefix + "nsg"
	azure := func(id, private string) asset.Asset {
		return asset.Asset{ID: id, Name: id, Type: "azure_vm", Provider: asset.ProviderAzure, AccountID: prefix + "subscription", PublicIP: "20.0.0.1", PrivateIP: private, Metadata: map[string]string{"direct_public_ip": "true", "network_interfaces_complete": "true", "nic_nsgs": `[{"public":true,"nsg_ids":["` + nsg + `"]}]`}}
	}
	awsSG := prefix + "aws-sg"
	awsInstance := func(id, route string) asset.Asset {
		metadata := map[string]string{"security_groups": awsSG}
		if route != "" {
			metadata["in_public_subnet"] = route
		}
		return asset.Asset{ID: id, Name: id, Type: "ec2_instance", Provider: asset.ProviderAWS, AccountID: prefix + "aws", PublicIP: "3.4.5.6", PrivateIP: "10.1.0.5", Metadata: metadata}
	}
	rows := []asset.Asset{
		gce(prefix+"gce-confirmed", "true"), gce(prefix+"gce-incomplete", "false"),
		awsInstance(prefix+"aws-confirmed", "true"), awsInstance(prefix+"aws-route-unknown", ""),
		{ID: awsSG, Name: awsSG, Type: "security_group", Provider: asset.ProviderAWS, AccountID: prefix + "aws", Metadata: map[string]string{"ingress": `[{"protocol":"tcp","from_port":22,"to_port":22,"cidrs":["0.0.0.0/0"]}]`}},
		firewall(prefix+"allow", "200", "0.0.0.0/0", "tcp:22,443", "", "10.23.1.0/24"),
		firewall(prefix+"narrow-deny", "100", "0.0.0.0/1", "", "tcp:22", "10.23.1.0/24"),
		firewall(prefix+"unrelated-deny", "50", "0.0.0.0/0", "", "tcp:443", "10.23.2.0/24"),
		azure(prefix+"azure-blocked", "10.0.0.10"), azure(prefix+"azure-open", "10.0.0.11"),
		{ID: nsg, Name: nsg, Type: "security_group", Provider: asset.ProviderAzure, AccountID: prefix + "subscription", Metadata: map[string]string{"ingress": azureRules, "nsg_rules_complete": "true"}},
		{ID: prefix + "azure-unread-nics", Name: "unread NICs", Type: "azure_vm", Provider: asset.ProviderAzure, AccountID: prefix + "subscription", Metadata: map[string]string{"nic_nsgs": "[]", "network_interfaces_complete": "false"}},
	}
	repo, stored, ids := semanticsStore(t, rows)
	for _, mode := range []string{"full", "types", "by IDs"} {
		t.Run(mode, func(t *testing.T) {
			loaded := semanticsLoad(t, repo, mode, rows, ids)
			byID := semanticsAssetMap(loaded)
			require.Equal(t, "10.0.0.10", byID[prefix+"azure-blocked"].PrivateIP, "private_ip SELECT/Scan must agree on both loaders")
			require.Equal(t, "10.23.1.10", byID[prefix+"gce-confirmed"].PrivateIP)
			require.Equal(t, nics, byID[prefix+"gce-confirmed"].Metadata["network_interfaces"])
			require.Equal(t, "false", byID[prefix+"gce-incomplete"].Metadata["firewall_rules_complete"])
			require.Equal(t, "10.23.2.0/24", byID[prefix+"unrelated-deny"].Metadata["destination_ranges"])
			require.Equal(t, "true", byID[nsg].Metadata["nsg_rules_complete"])
			require.Equal(t, "false", byID[prefix+"azure-unread-nics"].Metadata["network_interfaces_complete"])
			require.Equal(t, prefix, byID[prefix+"gce-confirmed"].Tags["integration"])
			require.NotContains(t, byID[prefix+"gce-confirmed"].Metadata, "integration_unprojected_sentinel")
			edges := InternetReachability{}.Correlate(NewGraph(loaded))
			bySource := map[string]asset.Edge{}
			for _, edge := range edges {
				require.NotContains(t, bySource, edge.SrcID)
				bySource[edge.SrcID] = edge
			}
			require.Len(t, bySource, 6)
			require.NotContains(t, bySource, prefix+"azure-blocked", "a real matching destination deny closes the private-IP fallback endpoint")
			confirmed := bySource[prefix+"gce-confirmed"]
			require.Equal(t, asset.PublicAccessConfirmed, confirmed.Properties[asset.EdgePropPublicAccess])
			require.Equal(t, "tcp:443", confirmed.Properties["ports"])
			require.Equal(t, "tcp:22", confirmed.Properties["possible_ports"], "narrow source deny keeps port 22 uncertain without demoting unrelated 443")
			require.Equal(t, asset.PublicAccessPossible, bySource[prefix+"gce-incomplete"].Properties[asset.EdgePropPublicAccess])
			require.Equal(t, asset.PublicAccessConfirmed, bySource[prefix+"aws-confirmed"].Properties[asset.EdgePropPublicAccess])
			require.Equal(t, asset.PublicAccessPossible, bySource[prefix+"aws-route-unknown"].Properties[asset.EdgePropPublicAccess])
			require.Equal(t, "route_unknown", bySource[prefix+"aws-route-unknown"].Properties["exposure_basis"])
			require.Equal(t, asset.PublicAccessConfirmed, bySource[prefix+"azure-open"].Properties[asset.EdgePropPublicAccess])
			require.Equal(t, asset.PublicAccessPossible, bySource[prefix+"azure-unread-nics"].Properties[asset.EdgePropPublicAccess])
			require.NoError(t, stored.IngestEdges(t.Context(), edges))
			persisted, err := stored.EdgesFrom(t.Context(), ids)
			require.NoError(t, err)
			require.ElementsMatch(t, edges, persisted, "edge properties including possible_ports must round-trip through actual graph_edges JSON storage")
		})
	}
}

func semanticsJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	return string(raw)
}

// Each fixture is namespaced and cleanup targets its explicit IDs only. There
// is no truncate, schema recreation, service startup, or ambient-row mutation.
func semanticsStore(t *testing.T, rows []asset.Asset) (*CHRepo, *asset.Service, []string) {
	t.Helper()
	ctx := t.Context()
	ch, err := db.NewCH(ctx, "clickhouse://graph:graph@localhost:9000/graph", 0)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ch.Close()) })
	ids := make([]string, 0, len(rows))
	now := time.Now()
	for i := range rows {
		rows[i].DiscoveredAt = now
		rows[i].LastSeen = now
		ids = append(ids, rows[i].ID)
	}
	placeholders, args := dbutil.CHIn(ids)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		require.NoError(t, ch.Exec(cleanup, fmt.Sprintf("ALTER TABLE graph_edges DELETE WHERE src_id IN (%s) SETTINGS mutations_sync = 1", placeholders), args...))
		require.NoError(t, ch.Exec(cleanup, fmt.Sprintf("ALTER TABLE assets DELETE WHERE id IN (%s) SETTINGS mutations_sync = 1", placeholders), args...))
	})
	stored := asset.NewService(asset.NewCHRepo(ch))
	require.NoError(t, stored.IngestAssets(ctx, rows))
	return NewCHRepo(ch), stored, ids
}

func semanticsLoad(t *testing.T, repo *CHRepo, mode string, seed []asset.Asset, ids []string) []asset.Asset {
	t.Helper()
	var loaded []asset.Asset
	var truncated bool
	var err error
	switch mode {
	case "full":
		loaded, truncated, err = repo.LoadView(t.Context())
	case "types":
		seen := map[string]bool{}
		var types []string
		for _, a := range seed {
			if !seen[a.Type] {
				seen[a.Type] = true
				types = append(types, a.Type)
			}
		}
		loaded, truncated, err = repo.LoadViewForTypes(t.Context(), types)
	case "by IDs":
		loaded, err = repo.LoadByIDs(t.Context(), ids)
	default:
		t.Fatalf("unknown loader %s", mode)
	}
	require.NoError(t, err)
	require.False(t, truncated)
	// Full/type queries can see unrelated integration fixtures. Only feed this
	// test's own rows into the rule, while asserting that every expected row came
	// back from the actual production query.
	wanted := map[string]bool{}
	for _, id := range ids {
		wanted[id] = true
	}
	var own []asset.Asset
	for _, a := range loaded {
		if wanted[a.ID] {
			own = append(own, a)
		}
	}
	require.Len(t, own, len(ids))
	return own
}

func semanticsAssetMap(rows []asset.Asset) map[string]asset.Asset {
	out := map[string]asset.Asset{}
	for _, a := range rows {
		out[a.ID] = a
	}
	return out
}
