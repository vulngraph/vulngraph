package gcp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	cloudfunctions "google.golang.org/api/cloudfunctions/v1"
	compute "google.golang.org/api/compute/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
)

func TestMergeProjectSettings(t *testing.T) {
	now := time.Now()
	assets := []asset.Asset{{ID: "gcp:p", Type: "cloud_account", Metadata: map[string]string{"consumer_account_members": ""}}}
	assets = mergeProjectSettings(assets, "p", map[string]string{"log_alerts_missing": "route_changes"}, now)
	require.Len(t, assets, 1, "settings land on the ONE project asset")
	require.Equal(t, "route_changes", assets[0].Metadata["log_alerts_missing"])
	require.Equal(t, "", assets[0].Metadata["consumer_account_members"])

	bare := mergeProjectSettings(nil, "p", map[string]string{"cloud_asset_api_enabled": "false"}, now)
	require.Len(t, bare, 1)
	require.Equal(t, "cloud_account", bare[0].Type)
	require.NotContains(t, bare[0].Metadata, "consumer_account_members", "IAM keys stay absent when IAM was not read")
	require.Empty(t, mergeProjectSettings(nil, "p", nil, now))
}

func TestAnnotateGKENodeSAs(t *testing.T) {
	assets := []asset.Asset{
		{Type: "gcp_service_account", Name: "nodes@p.iam.gserviceaccount.com", Metadata: map[string]string{"roles": "roles/container.defaultNodeServiceAccount"}},
		{Type: "gcp_service_account", Name: "ci@p.iam.gserviceaccount.com", Metadata: map[string]string{"roles": "roles/logging.logWriter,roles/storage.admin"}},
		{Type: "gke_cluster", Metadata: map[string]string{"node_pool_service_accounts": "a=nodes@p.iam.gserviceaccount.com,b=ci@p.iam.gserviceaccount.com"}},
		{Type: "gke_cluster", Metadata: map[string]string{"node_pool_service_accounts": "a=nodes@p.iam.gserviceaccount.com,x=shared@host.iam.gserviceaccount.com"}},
		{Type: "gke_cluster", Metadata: map[string]string{"node_pool_service_accounts": ""}},
	}
	annotateGKENodeSAs(assets)
	require.Equal(t, "b", assets[2].Metadata["node_pools_privileged_sa"])
	require.NotContains(t, assets[3].Metadata, "node_pools_privileged_sa", "an account from another project is unknown")
	require.Equal(t, "", assets[4].Metadata["node_pools_privileged_sa"], "no dedicated account to grade")
}

func TestAnnotateProxyCerts(t *testing.T) {
	assets := []asset.Asset{
		{Type: "gcp_ssl_certificate", Metadata: map[string]string{"self_link": "https://x/sslCertificates/self", "type": "SELF_MANAGED"}},
		{Type: "gcp_ssl_certificate", Metadata: map[string]string{"self_link": "https://x/sslCertificates/managed", "type": "MANAGED"}},
		{Type: "gcp_target_proxy", Metadata: map[string]string{"certificate_links": "https://x/sslCertificates/self,https://x/sslCertificates/managed"}},
		{Type: "gcp_target_proxy", Metadata: map[string]string{"certificate_links": "https://x/sslCertificates/managed,https://x/sslCertificates/gone"}},
		{Type: "gcp_target_proxy", Metadata: map[string]string{"certificate_links": "https://x/sslCertificates/managed"}},
	}
	annotateProxyCerts(assets)
	require.Equal(t, "self", assets[2].Metadata["self_managed_certificates"])
	require.NotContains(t, assets[3].Metadata, "self_managed_certificates", "an unread certificate is unknown")
	require.Equal(t, "", assets[4].Metadata["self_managed_certificates"])
}

func TestAnnotateIAPBypass(t *testing.T) {
	fw := func(name string, md map[string]string) asset.Asset {
		base := map[string]string{"disabled": "false", "direction": "INGRESS", "allowed": "tcp:80", "network": "prod",
			"source_ranges": "", "source_tags": "", "target_tags": "", "target_sas": ""}
		for k, v := range md {
			base[k] = v
		}
		return asset.Asset{Name: name, Type: "gcp_firewall", Metadata: base}
	}
	inst := asset.Asset{ID: "p/z/web-1", Type: "gce_instance", Metadata: map[string]string{
		"network": "prod", "network_tags": "web", "exec_role": "serviceAccount:web@p.iam.gserviceaccount.com"}}
	backend := func() asset.Asset {
		return asset.Asset{Type: "gcp_backend_service", Metadata: map[string]string{"iap_backend_instances": "p/z/web-1"}}
	}
	assets := []asset.Asset{
		inst, backend(),
		fw("gclb", map[string]string{"source_ranges": "35.191.0.0/16,130.211.0.0/22", "target_tags": "web"}),
		fw("internal", map[string]string{"source_ranges": "10.128.0.0/9"}),
		fw("by-sa", map[string]string{"source_ranges": "0.0.0.0/0", "target_sas": "web@p.iam.gserviceaccount.com"}),
		fw("other-tag", map[string]string{"source_ranges": "0.0.0.0/0", "target_tags": "db"}),
		fw("tagged-src", map[string]string{"source_tags": "bastion", "target_tags": "web"}),
		fw("deny-only", map[string]string{"allowed": "", "source_ranges": "0.0.0.0/0"}),
		fw("other-net", map[string]string{"network": "dev", "source_ranges": "0.0.0.0/0"}),
	}
	annotateIAPBypass(assets, true)
	require.Equal(t, "by-sa,internal,tagged-src", assets[1].Metadata["iap_bypass_firewall_rules"])

	unknown := []asset.Asset{backend(), fw("gclb", map[string]string{"source_ranges": "35.191.0.0/16"})}
	annotateIAPBypass(unknown, true)
	require.NotContains(t, unknown[0].Metadata, "iap_bypass_firewall_rules", "an instance missing from the sweep is unknown")
	clean := []asset.Asset{inst, backend()}
	annotateIAPBypass(clean, false)
	require.NotContains(t, clean[1].Metadata, "iap_bypass_firewall_rules", "unread firewalls are unknown")
}

func TestApplyPostureJoins_VMsWithoutCSEK(t *testing.T) {
	r := &collect.Result{Assets: []asset.Asset{
		{Name: "csek", Type: "gce_instance", Metadata: map[string]string{"disks_without_csek": ""}},
		{Name: "plain", Type: "gce_instance", Metadata: map[string]string{"disks_without_csek": "boot"}},
		{Name: "node", Type: "gce_instance", Tags: map[string]string{"goog-gke-node": ""}, Metadata: map[string]string{"disks_without_csek": "boot"}},
	}}
	applyPostureJoins(r, "p", emptySettings(), joinInputs{firewalls: true, instances: true}, time.Now())
	require.Equal(t, "plain", r.Assets[len(r.Assets)-1].Metadata["vms_without_csek"], "GKE nodes are left out")

	r = &collect.Result{Assets: []asset.Asset{{Name: "plain", Type: "gce_instance", Metadata: map[string]string{"disks_without_csek": "boot"}}}}
	applyPostureJoins(r, "p", emptySettings(), joinInputs{firewalls: true}, time.Now())
	require.Len(t, r.Assets, 1, "an incomplete instance listing grades nothing")
}

func TestToNeutral_ExternalIPAndCSEK(t *testing.T) {
	g := toNeutral(&compute.Instance{
		Name: "vm", Status: "TERMINATED",
		NetworkInterfaces: []*compute.NetworkInterface{
			{Network: "global/networks/prod"},
			{Network: "global/networks/dmz", AccessConfigs: []*compute.AccessConfig{{Type: "ONE_TO_ONE_NAT"}}},
		},
		Disks: []*compute.AttachedDisk{
			{DeviceName: "boot", DiskEncryptionKey: &compute.CustomerEncryptionKey{Sha256: "abc="}},
			{DeviceName: "data", DiskEncryptionKey: &compute.CustomerEncryptionKey{KmsKeyName: "k"}},
			{DeviceName: "scratch"},
		},
	})
	require.True(t, g.ExternalIPConfigured, "a secondary NIC's access config counts, even with no address on a stopped VM")
	require.Empty(t, g.PublicIP)
	require.Equal(t, []string{"data", "scratch"}, g.DisksWithoutCSEK, "CMEK is not a customer-supplied key")
	md := gceMetadata(g, nil, false)
	require.Equal(t, "true", md["external_ip_configured"])
	require.Equal(t, "data,scratch", md["disks_without_csek"])

	require.Equal(t, "false", gceMetadata(toNeutral(&compute.Instance{Name: "private", NetworkInterfaces: []*compute.NetworkInterface{{Network: "default", NetworkIP: "10.0.0.1"}}}), nil, false)["external_ip_configured"])
}

func TestFunctionSecretEnv(t *testing.T) {
	got := functionSecretEnv(&cloudfunctions.CloudFunction{
		EnvironmentVariables: map[string]string{
			"DB_PASSWORD":         "hunter2hunter2",
			"API_TOKEN_SECRET_ID": "projects/p/secrets/token",
			"STRIPE_SECRET":       "projects/p/secrets/stripe/versions/latest",
			"SHORT_TOKEN":         "abc",
			"LOG_LEVEL":           "debug-verbose",
		},
		BuildEnvironmentVariables: map[string]string{"NPM_TOKEN": "npm_abcdefghijk"},
	})
	require.Equal(t, []string{"DB_PASSWORD", "build:NPM_TOKEN"}, got)
}

func emptySettings() postureSettings {
	return postureSettings{project: map[string]string{}, org: orgSettings{md: map[string]string{}}}
}

// Organization-wide settings land on ONE organization asset, keyed by the
// organization, whichever project's sweep emits it.
func TestApplyPostureJoins_OrgSettingsAsset(t *testing.T) {
	s := emptySettings()
	s.add(map[string]string{"cloud_asset_api_enabled": "true"}, orgSettings{org: "organizations/42", md: map[string]string{"log_catch_all_sink": "false"}})
	s.add(nil, orgSettings{org: "organizations/42", md: map[string]string{"essential_contacts_missing": "LEGAL"}})
	r := &collect.Result{}
	applyPostureJoins(r, "p", s, joinInputs{}, time.Now())
	byType := map[string]asset.Asset{}
	for _, a := range r.Assets {
		byType[a.Type] = a
	}
	org := byType["gcp_organization"]
	require.Equal(t, "gcp-org:42", org.ID)
	require.Equal(t, "false", org.Metadata["log_catch_all_sink"])
	require.Equal(t, "LEGAL", org.Metadata["essential_contacts_missing"])
	require.Equal(t, "true", byType["cloud_account"].Metadata["cloud_asset_api_enabled"])

	r = &collect.Result{}
	applyPostureJoins(r, "p", emptySettings(), joinInputs{}, time.Now())
	require.Empty(t, r.Assets, "no settings, no assets")
}

// A GKE node is exempt from the per-VM checks only when its cluster was
// read whole and carries the node-pool verdicts.
func TestAnnotateGKENodes(t *testing.T) {
	node := func(cluster, zone string) asset.Asset {
		return asset.Asset{Type: "gce_instance", Region: zone, Metadata: map[string]string{},
			Tags: map[string]string{"goog-gke-node": "", "goog-k8s-cluster-name": cluster}}
	}
	assets := []asset.Asset{
		{Type: "gke_cluster", Name: "regional", Region: "europe-west4", Metadata: map[string]string{"node_pools_default_sa": "", "node_pools_public_nodes": ""}},
		{Type: "gke_cluster", Name: "unread", Region: "europe-west4-a", Metadata: map[string]string{"node_pools_public_nodes": ""}},
		node("regional", "europe-west4-b"), node("unread", "europe-west4-a"), node("absent", "europe-west4-a"),
		node("regional", "us-east1-b"),
	}
	annotateGKENodes(assets, true)
	require.Equal(t, "true", assets[2].Metadata["gke_node_pool_graded"])
	require.NotContains(t, assets[3].Metadata, "gke_node_pool_graded", "pool service accounts unread")
	require.NotContains(t, assets[4].Metadata, "gke_node_pool_graded", "cluster not in the sweep")
	require.NotContains(t, assets[5].Metadata, "gke_node_pool_graded", "a same-named cluster elsewhere is not this node's")

	partial := []asset.Asset{assets[0], node("regional", "europe-west4-b")}
	annotateGKENodes(partial, false)
	require.NotContains(t, partial[1].Metadata, "gke_node_pool_graded", "a partial cluster listing exempts nobody")
}
