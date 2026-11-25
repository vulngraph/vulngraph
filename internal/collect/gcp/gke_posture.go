package gcp

import (
	"slices"
	"strconv"
	"strings"

	container "google.golang.org/api/container/v1"
)

// gkePosture extracts the CIS GKE cluster and node-pool settings from the
// clusters.list response the collector already fetches.
//
// Known-ness: these come from a cluster object the API returned, and the API
// omits a sub-object whose fields are all at their defaults (a cluster with no
// release channel has no releaseChannel; binary authorization off has no
// binaryAuthorization). So an omitted sub-object of a cluster that was read is
// an observation of the default, and is stamped as such where the default is
// unambiguous. Where it is not — masterAuth, databaseEncryption, the node
// pools' shieldedInstanceConfig (integrity monitoring defaults ON) — an omitted
// sub-object leaves the key absent rather than inventing the default.
//
// explicitPrivate holds the node pools whose networkConfig.enablePrivateNodes
// the API returned explicitly, keyed by pool name: the SDK's plain bool cannot
// tell an explicit false (a pool opting out of a private cluster) from unset
// (inheriting the cluster), so the raw response is decoded for it
// (decodeClusters).
func gkePosture(c *container.Cluster, explicitPrivate map[string]bool) map[string]string {
	md := map[string]string{
		"workload_identity":    strconv.FormatBool(c.WorkloadIdentityConfig != nil && c.WorkloadIdentityConfig.WorkloadPool != ""),
		"release_channel":      releaseChannel(c.ReleaseChannel),
		"binary_authorization": binaryAuthorizationMode(c.BinaryAuthorization),
		// false only for a cluster reachable solely through its DNS endpoint;
		// a cluster without controlPlaneEndpointsConfig has IP endpoints.
		"ip_endpoints_enabled": strconv.FormatBool(c.ControlPlaneEndpointsConfig == nil ||
			c.ControlPlaneEndpointsConfig.IpEndpointsConfig == nil || c.ControlPlaneEndpointsConfig.IpEndpointsConfig.Enabled),
		// A cluster without ipAllocationPolicy is routes-based, not VPC-native.
		"vpc_native":         strconv.FormatBool(c.IpAllocationPolicy != nil && c.IpAllocationPolicy.UseIpAliases),
		"google_groups_rbac": strconv.FormatBool(c.AuthenticatorGroupsConfig != nil && c.AuthenticatorGroupsConfig.Enabled),
		"kubernetes_alpha":   strconv.FormatBool(c.EnableKubernetesAlpha),
	}
	// Security posture defaults to BASIC on current clusters but was absent on
	// older ones, so an omitted config is not graded.
	if sp := c.SecurityPostureConfig; sp != nil && sp.Mode != "" && sp.Mode != "MODE_UNSPECIFIED" {
		md["security_posture_mode"] = sp.Mode
	}
	if c.MasterAuth != nil {
		ma := c.MasterAuth
		// Only booleans: clientCertificate and password are credentials and
		// never leave this function.
		md["client_certificate_issued"] = strconv.FormatBool(ma.ClientCertificate != "" ||
			(ma.ClientCertificateConfig != nil && ma.ClientCertificateConfig.IssueClientCertificate))
		md["basic_auth"] = strconv.FormatBool(ma.Username != "" || ma.Password != "")
	}
	if c.DatabaseEncryption != nil && c.DatabaseEncryption.State != "" {
		md["secrets_encryption"] = c.DatabaseEncryption.State
	}
	if n := c.NetworkConfig; n != nil {
		// "" is the legacy datapath; ADVANCED_DATAPATH (Dataplane V2) enforces
		// NetworkPolicy itself while reporting the networkPolicy addon disabled.
		md["datapath_provider"] = n.DatapathProvider
		md["intranode_visibility"] = strconv.FormatBool(n.EnableIntraNodeVisibility)
	}
	if c.LoggingService != "" {
		md["logging_service"] = c.LoggingService
	}
	if c.MonitoringService != "" {
		md["monitoring_service"] = c.MonitoringService
	}

	clusterPrivate := (c.PrivateClusterConfig != nil && c.PrivateClusterConfig.EnablePrivateNodes) ||
		(c.NetworkConfig != nil && c.NetworkConfig.DefaultEnablePrivateNodes)
	pools := []struct {
		key string
		// bad reports whether the pool violates the setting; known is false
		// when the pool did not carry the sub-object the setting lives in.
		bad func(*container.NodePool) (bad, known bool)
	}{
		{"node_pools_no_gke_metadata", func(p *container.NodePool) (bool, bool) {
			if p.Config == nil {
				return false, false
			}
			w := p.Config.WorkloadMetadataConfig
			return w == nil || w.Mode != "GKE_METADATA", true
		}},
		{"node_pools_no_auto_upgrade", func(p *container.NodePool) (bool, bool) {
			return p.Management == nil || !p.Management.AutoUpgrade, true
		}},
		{"node_pools_no_auto_repair", func(p *container.NodePool) (bool, bool) {
			return p.Management == nil || !p.Management.AutoRepair, true
		}},
		{"node_pools_no_secure_boot", func(p *container.NodePool) (bool, bool) {
			if p.Config == nil || p.Config.ShieldedInstanceConfig == nil {
				return false, false
			}
			return !p.Config.ShieldedInstanceConfig.EnableSecureBoot, true
		}},
		{"node_pools_no_integrity_monitoring", func(p *container.NodePool) (bool, bool) {
			if p.Config == nil || p.Config.ShieldedInstanceConfig == nil {
				return false, false
			}
			return !p.Config.ShieldedInstanceConfig.EnableIntegrityMonitoring, true
		}},
		{"node_pools_not_cos", func(p *container.NodePool) (bool, bool) {
			if p.Config == nil || p.Config.ImageType == "" {
				return false, false
			}
			return !strings.EqualFold(p.Config.ImageType, "COS_CONTAINERD"), true
		}},
		{"node_pools_public_nodes", func(p *container.NodePool) (bool, bool) {
			// A pool's explicit setting overrides the cluster default either
			// way; without one it inherits the cluster.
			// A true in the SDK struct is unambiguous; only false needs the
			// raw response to tell opt-out from unset.
			if v, ok := explicitPrivate[p.Name]; ok {
				return !v, true
			}
			if p.NetworkConfig != nil && p.NetworkConfig.EnablePrivateNodes {
				return false, true
			}
			return !clusterPrivate, true
		}},
		{"node_pools_default_sa", func(p *container.NodePool) (bool, bool) {
			if p.Config == nil {
				return false, false
			}
			return gkeDefaultNodeSA(p.Config.ServiceAccount), true
		}},
		{"node_pools_default_sa_full_scope", func(p *container.NodePool) (bool, bool) {
			if p.Config == nil {
				return false, false
			}
			return gkeDefaultNodeSA(p.Config.ServiceAccount) && slices.Contains(p.Config.OauthScopes, cloudPlatformScope), true
		}},
		{"node_pools_no_boot_disk_cmek", func(p *container.NodePool) (bool, bool) {
			if p.Config == nil {
				return false, false
			}
			return p.Config.BootDiskKmsKey == "", true
		}},
	}
	for _, s := range pools {
		if v, ok := poolsWhere(c.NodePools, s.bad); ok {
			md[s.key] = v
		}
	}
	if v, ok := customNodeSAs(c.NodePools); ok {
		md["node_pool_service_accounts"] = v
	}
	return md
}

// gkeDefaultNodeSA reports whether a node pool runs as the project's default
// Compute Engine account: GKE reports it as "default" (or leaves it empty)
// when no account was chosen at creation.
func gkeDefaultNodeSA(email string) bool {
	return email == "" || email == "default" || strings.HasSuffix(email, "-compute@developer.gserviceaccount.com")
}

// customNodeSAs lists "pool=email" for every pool running as a dedicated
// service account, the input to annotateGKENodeSAs' role check. Unknown when
// a pool's config was not returned.
func customNodeSAs(pools []*container.NodePool) (string, bool) {
	var out []string
	for _, p := range pools {
		if p == nil {
			continue
		}
		if p.Config == nil {
			return "", false
		}
		if !gkeDefaultNodeSA(p.Config.ServiceAccount) {
			out = append(out, p.Name+"="+p.Config.ServiceAccount)
		}
	}
	return strings.Join(out, ","), true
}

// poolsWhere returns the comma-joined names of the node pools violating a
// setting, "" when every pool was read and none does. A pool that did not
// carry the setting makes the answer unknown unless another pool already
// violates — a positive observation stands, but silence from an unread pool
// proves nothing.
func poolsWhere(pools []*container.NodePool, bad func(*container.NodePool) (bool, bool)) (string, bool) {
	var names []string
	unknown := false
	for _, p := range pools {
		if p == nil {
			continue
		}
		b, known := bad(p)
		switch {
		case !known:
			unknown = true
		case b:
			names = append(names, p.Name)
		}
	}
	if len(names) == 0 && unknown {
		return "", false
	}
	return strings.Join(names, ","), true
}

func releaseChannel(rc *container.ReleaseChannel) string {
	if rc == nil || rc.Channel == "UNSPECIFIED" {
		return ""
	}
	return rc.Channel
}

// binaryAuthorizationMode resolves the cluster's Binary Authorization
// evaluation mode. The deprecated enabled flag only counts when no mode is set,
// and an unset mode defaults to DISABLED.
func binaryAuthorizationMode(b *container.BinaryAuthorization) string {
	if b == nil {
		return "DISABLED"
	}
	if b.EvaluationMode != "" && b.EvaluationMode != "EVALUATION_MODE_UNSPECIFIED" {
		return b.EvaluationMode
	}
	if b.Enabled {
		return "PROJECT_SINGLETON_POLICY_ENFORCE"
	}
	return "DISABLED"
}

// controlPlaneAccess resolves whether the control plane has a public IP
// endpoint and which authorized networks guard it. Clusters now report this
// under controlPlaneEndpointsConfig.ipEndpointsConfig (a DNS-endpoint-only
// cluster has IP endpoints disabled entirely); the legacy
// privateClusterConfig / masterAuthorizedNetworksConfig fields are the
// fallback when that block is absent.
func controlPlaneAccess(c *container.Cluster) (public bool, an *container.MasterAuthorizedNetworksConfig) {
	an = c.MasterAuthorizedNetworksConfig
	if cp := c.ControlPlaneEndpointsConfig; cp != nil && cp.IpEndpointsConfig != nil {
		ip := cp.IpEndpointsConfig
		if an == nil {
			an = ip.AuthorizedNetworksConfig
		}
		return ip.Enabled && ip.EnablePublicEndpoint, an
	}
	// Default (no PrivateClusterConfig) is a public endpoint.
	return c.PrivateClusterConfig == nil || !c.PrivateClusterConfig.EnablePrivateEndpoint, an
}

// worldAuthorizedCIDR reports whether an authorized-networks allowlist admits
// the whole internet, which makes it no allowlist at all.
func worldAuthorizedCIDR(an *container.MasterAuthorizedNetworksConfig) bool {
	if an == nil {
		return false
	}
	var cidrs []string
	for _, b := range an.CidrBlocks {
		if b != nil {
			cidrs = append(cidrs, b.CidrBlock)
		}
	}
	return worldAuthorizedNetwork(cidrs)
}
