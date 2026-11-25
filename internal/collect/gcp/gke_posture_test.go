package gcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	container "google.golang.org/api/container/v1"
)

func hardenedPool(name string) *container.NodePool {
	return &container.NodePool{
		Name:       name,
		Management: &container.NodeManagement{AutoUpgrade: true, AutoRepair: true},
		Config: &container.NodeConfig{
			ImageType:              "COS_CONTAINERD",
			ServiceAccount:         "gke-nodes@p.iam.gserviceaccount.com",
			OauthScopes:            []string{cloudPlatformScope},
			BootDiskKmsKey:         "projects/p/locations/l/keyRings/r/cryptoKeys/k",
			WorkloadMetadataConfig: &container.WorkloadMetadataConfig{Mode: "GKE_METADATA"},
			ShieldedInstanceConfig: &container.ShieldedInstanceConfig{EnableSecureBoot: true, EnableIntegrityMonitoring: true},
		},
	}
}

func TestGKEPosture_Hardened(t *testing.T) {
	md := gkePosture(&container.Cluster{
		WorkloadIdentityConfig: &container.WorkloadIdentityConfig{WorkloadPool: "p.svc.id.goog"},
		ReleaseChannel:         &container.ReleaseChannel{Channel: "REGULAR"},
		BinaryAuthorization:    &container.BinaryAuthorization{EvaluationMode: "PROJECT_SINGLETON_POLICY_ENFORCE"},
		MasterAuth:             &container.MasterAuth{ClusterCaCertificate: "ca"},
		DatabaseEncryption:     &container.DatabaseEncryption{State: "ENCRYPTED", KeyName: "k"},
		NetworkConfig:          &container.NetworkConfig{DatapathProvider: "ADVANCED_DATAPATH", EnableIntraNodeVisibility: true},
		PrivateClusterConfig:   &container.PrivateClusterConfig{EnablePrivateNodes: true},
		LoggingService:         "logging.googleapis.com/kubernetes",
		MonitoringService:      "monitoring.googleapis.com/kubernetes",
		IpAllocationPolicy:     &container.IPAllocationPolicy{UseIpAliases: true},
		AuthenticatorGroupsConfig: &container.AuthenticatorGroupsConfig{Enabled: true,
			SecurityGroup: "gke-security-groups@example.com"},
		SecurityPostureConfig: &container.SecurityPostureConfig{Mode: "BASIC", VulnerabilityMode: "VULNERABILITY_BASIC"},
		NodePools:             []*container.NodePool{hardenedPool("a"), hardenedPool("b")},
	}, nil)
	require.Equal(t, map[string]string{
		"workload_identity":                  "true",
		"release_channel":                    "REGULAR",
		"binary_authorization":               "PROJECT_SINGLETON_POLICY_ENFORCE",
		"ip_endpoints_enabled":               "true",
		"vpc_native":                         "true",
		"google_groups_rbac":                 "true",
		"kubernetes_alpha":                   "false",
		"security_posture_mode":              "BASIC",
		"node_pools_default_sa":              "",
		"node_pools_default_sa_full_scope":   "",
		"node_pools_no_boot_disk_cmek":       "",
		"node_pool_service_accounts":         "a=gke-nodes@p.iam.gserviceaccount.com,b=gke-nodes@p.iam.gserviceaccount.com",
		"client_certificate_issued":          "false",
		"basic_auth":                         "false",
		"secrets_encryption":                 "ENCRYPTED",
		"datapath_provider":                  "ADVANCED_DATAPATH",
		"intranode_visibility":               "true",
		"logging_service":                    "logging.googleapis.com/kubernetes",
		"monitoring_service":                 "monitoring.googleapis.com/kubernetes",
		"node_pools_no_gke_metadata":         "",
		"node_pools_no_auto_upgrade":         "",
		"node_pools_no_auto_repair":          "",
		"node_pools_no_secure_boot":          "",
		"node_pools_no_integrity_monitoring": "",
		"node_pools_not_cos":                 "",
		"node_pools_public_nodes":            "",
	}, md)
}

func TestGKEPosture_Weak(t *testing.T) {
	weak := &container.NodePool{
		Name:   "legacy",
		Config: &container.NodeConfig{ImageType: "UBUNTU_CONTAINERD", ShieldedInstanceConfig: &container.ShieldedInstanceConfig{}},
	}
	md := gkePosture(&container.Cluster{
		MasterAuth:          &container.MasterAuth{ClientCertificate: "cert", Username: "admin", Password: "pw"},
		BinaryAuthorization: &container.BinaryAuthorization{},
		ReleaseChannel:      &container.ReleaseChannel{Channel: "UNSPECIFIED"},
		DatabaseEncryption:  &container.DatabaseEncryption{State: "DECRYPTED"},
		NetworkConfig:       &container.NetworkConfig{},
		LoggingService:      "none",
		// Kept from the API: an explicitly disabled posture and an alpha cluster.
		SecurityPostureConfig: &container.SecurityPostureConfig{Mode: "DISABLED"},
		EnableKubernetesAlpha: true,
		NodePools:             []*container.NodePool{hardenedPool("good"), weak},
	}, nil)
	require.Equal(t, "false", md["vpc_native"], "no ipAllocationPolicy is a routes-based cluster")
	require.Equal(t, "false", md["google_groups_rbac"])
	require.Equal(t, "true", md["kubernetes_alpha"])
	require.Equal(t, "DISABLED", md["security_posture_mode"])
	require.Equal(t, "legacy", md["node_pools_default_sa"], "an unset node service account is the Compute default")
	require.Equal(t, "", md["node_pools_default_sa_full_scope"], "the default account without cloud-platform scope")
	require.Equal(t, "legacy", md["node_pools_no_boot_disk_cmek"])
	require.Equal(t, "good=gke-nodes@p.iam.gserviceaccount.com", md["node_pool_service_accounts"])
	require.Equal(t, "false", md["workload_identity"])
	require.Equal(t, "", md["release_channel"])
	require.Equal(t, "DISABLED", md["binary_authorization"])
	require.Equal(t, "true", md["client_certificate_issued"])
	require.Equal(t, "true", md["basic_auth"])
	require.Equal(t, "DECRYPTED", md["secrets_encryption"])
	require.Equal(t, "", md["datapath_provider"])
	require.Equal(t, "false", md["intranode_visibility"])
	require.Equal(t, "none", md["logging_service"])
	require.NotContains(t, md, "monitoring_service")
	for _, k := range []string{"node_pools_no_gke_metadata", "node_pools_no_auto_upgrade", "node_pools_no_auto_repair",
		"node_pools_no_secure_boot", "node_pools_no_integrity_monitoring", "node_pools_not_cos"} {
		require.Equal(t, "legacy", md[k], k)
	}
	require.Equal(t, "good,legacy", md["node_pools_public_nodes"], "no private-nodes config anywhere")
	for _, v := range md {
		require.NotContains(t, []string{"cert", "pw", "admin"}, v, "master-auth credentials never reach metadata")
	}
}

// An omitted sub-object whose default is ambiguous leaves the key absent: a
// pool with no shieldedInstanceConfig is not proof that integrity monitoring
// (default on) is off. A pool that DOES violate still surfaces.
func TestGKEPosture_UnknownStaysAbsent(t *testing.T) {
	md := gkePosture(&container.Cluster{NodePools: []*container.NodePool{{Name: "bare", Management: &container.NodeManagement{AutoUpgrade: true, AutoRepair: true}}}}, nil)
	for _, k := range []string{"client_certificate_issued", "basic_auth", "secrets_encryption", "datapath_provider",
		"intranode_visibility", "logging_service", "monitoring_service",
		"node_pools_no_gke_metadata", "node_pools_no_secure_boot", "node_pools_no_integrity_monitoring", "node_pools_not_cos"} {
		require.NotContains(t, md, k, k)
	}
	require.Equal(t, "", md["node_pools_no_auto_upgrade"])

	mixed := gkePosture(&container.Cluster{NodePools: []*container.NodePool{{Name: "bare"}, {Name: "ubuntu", Config: &container.NodeConfig{ImageType: "UBUNTU"}}}}, nil)
	require.Equal(t, "ubuntu", mixed["node_pools_not_cos"], "a positive observation stands beside an unread pool")
}

func TestGKEPosture_PoolPrivateNodesOverride(t *testing.T) {
	md := gkePosture(&container.Cluster{NodePools: []*container.NodePool{
		{Name: "private", NetworkConfig: &container.NodeNetworkConfig{EnablePrivateNodes: true}},
		{Name: "public"},
	}}, nil)
	require.Equal(t, "public", md["node_pools_public_nodes"])
	md = gkePosture(&container.Cluster{
		NetworkConfig: &container.NetworkConfig{DefaultEnablePrivateNodes: true},
		NodePools:     []*container.NodePool{{Name: "inherits"}, {Name: "opted-out"}},
	}, map[string]bool{"opted-out": false})
	require.Equal(t, "opted-out", md["node_pools_public_nodes"], "an explicit opt-out on a private cluster is public")
}

func TestGKEPosture_DefaultSAFullScope(t *testing.T) {
	md := gkePosture(&container.Cluster{NodePools: []*container.NodePool{
		{Name: "default", Config: &container.NodeConfig{ServiceAccount: "default", OauthScopes: []string{cloudPlatformScope}}},
		{Name: "explicit-default", Config: &container.NodeConfig{ServiceAccount: "123-compute@developer.gserviceaccount.com"}},
	}}, nil)
	require.Equal(t, "default,explicit-default", md["node_pools_default_sa"])
	require.Equal(t, "default", md["node_pools_default_sa_full_scope"])
	require.Equal(t, "", md["node_pool_service_accounts"])
	require.NotContains(t, gkePosture(&container.Cluster{NodePools: []*container.NodePool{{Name: "unread"}}}, nil),
		"node_pool_service_accounts", "a pool without its config leaves the account list unknown")
}

// The raw clusters.list body is the fixture: the SDK flattens
// enablePrivateNodes to a plain bool, so only the raw decode can see a pool
// opting out of a private cluster.
func TestDecodeClusters_ExplicitPoolOptOutAndMissingZones(t *testing.T) {
	body := []byte(`{
	  "clusters": [{
	    "name": "prod", "location": "europe-west4",
	    "networkConfig": {"defaultEnablePrivateNodes": true, "subnetwork": "projects/p/regions/europe-west4/subnetworks/nodes"},
	    "nodePools": [
	      {"name": "inherit", "config": {"serviceAccount": "default"}},
	      {"name": "optout", "config": {"serviceAccount": "default"}, "networkConfig": {"enablePrivateNodes": false}}
	    ]
	  }],
	  "missingZones": ["us-central1-a"]
	}`)
	got, err := decodeClusters(body)
	require.Error(t, err, "missingZones is a partial listing")
	require.Len(t, got, 1, "the clusters that were read are kept")
	require.Equal(t, "optout", got[0].Posture["node_pools_public_nodes"])
	require.Equal(t, "projects/p/regions/europe-west4/subnetworks/nodes", got[0].Subnetwork)

	got, err = decodeClusters([]byte(`{}`))
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestCollectGKE_PartialListingKeepsClusters(t *testing.T) {
	got, err := collectGKE(context.Background(), fakeContainer{clusters: []gkeCluster{{Name: "c", Location: "l"}}, err: errors.New("missing zones")},
		"p", time.Now())
	require.Error(t, err)
	require.Len(t, got, 1)
}

func TestBinaryAuthorizationMode(t *testing.T) {
	require.Equal(t, "DISABLED", binaryAuthorizationMode(nil))
	require.Equal(t, "PROJECT_SINGLETON_POLICY_ENFORCE", binaryAuthorizationMode(&container.BinaryAuthorization{Enabled: true}))
	require.Equal(t, "DISABLED", binaryAuthorizationMode(&container.BinaryAuthorization{Enabled: true, EvaluationMode: "DISABLED"}),
		"the deprecated flag is ignored once a mode is set")
	require.Equal(t, "POLICY_BINDINGS", binaryAuthorizationMode(&container.BinaryAuthorization{EvaluationMode: "POLICY_BINDINGS"}))
}

// A DNS-endpoint-only cluster has IP endpoints disabled: reading only the
// legacy privateClusterConfig reported its control plane as public.
func TestControlPlaneAccess(t *testing.T) {
	public, _ := controlPlaneAccess(&container.Cluster{})
	require.True(t, public, "no private config is the public default")

	public, _ = controlPlaneAccess(&container.Cluster{PrivateClusterConfig: &container.PrivateClusterConfig{EnablePrivateEndpoint: true}})
	require.False(t, public)

	public, _ = controlPlaneAccess(&container.Cluster{ControlPlaneEndpointsConfig: &container.ControlPlaneEndpointsConfig{
		IpEndpointsConfig: &container.IPEndpointsConfig{Enabled: false},
	}})
	require.False(t, public, "IP endpoints disabled: DNS endpoint only")

	public, _ = controlPlaneAccess(&container.Cluster{ControlPlaneEndpointsConfig: &container.ControlPlaneEndpointsConfig{
		IpEndpointsConfig: &container.IPEndpointsConfig{Enabled: false, EnablePublicEndpoint: true},
	}})
	require.False(t, public, "a public-endpoint flag on disabled IP endpoints exposes nothing")
	require.Equal(t, "false", gkePosture(&container.Cluster{ControlPlaneEndpointsConfig: &container.ControlPlaneEndpointsConfig{
		IpEndpointsConfig: &container.IPEndpointsConfig{Enabled: false},
	}}, nil)["ip_endpoints_enabled"])

	public, an := controlPlaneAccess(&container.Cluster{ControlPlaneEndpointsConfig: &container.ControlPlaneEndpointsConfig{
		IpEndpointsConfig: &container.IPEndpointsConfig{Enabled: true, EnablePublicEndpoint: true,
			AuthorizedNetworksConfig: &container.MasterAuthorizedNetworksConfig{Enabled: true}},
	}})
	require.True(t, public)
	require.NotNil(t, an, "authorized networks read from the new location when the legacy one is absent")
}

func TestCollectGKE_WorldAuthorizedNetworkIsNoAllowlist(t *testing.T) {
	g := toNeutralGKE(&container.Cluster{Name: "c", Location: "l", MasterAuthorizedNetworksConfig: &container.MasterAuthorizedNetworksConfig{
		Enabled: true, CidrBlocks: []*container.CidrBlock{{CidrBlock: "10.0.0.0/8"}, {CidrBlock: "0.0.0.0/0"}},
	}}, nil)
	require.True(t, g.AuthorizedNets)
	require.True(t, g.AuthorizedNetsWorld)

	got, err := collectGKE(context.Background(), fakeContainer{clusters: []gkeCluster{g}}, "p", time.Now())
	require.NoError(t, err)
	md := got[0].Metadata
	require.Equal(t, "true", md["authorized_networks_world"])
	require.Equal(t, "possible", md["public_access"], "an allowlist admitting 0.0.0.0/0 restricts nothing")
	require.Equal(t, "false", md["workload_identity"], "posture keys reach the asset")
}
