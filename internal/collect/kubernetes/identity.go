package kubernetes

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// identity.go answers "which cluster is this?" from the cluster itself, rather
// than trusting cfg["cluster_name"] (the operator-typed prefix on every
// Kubernetes asset ID) to match the cloud provider's real cluster name — it
// often doesn't, which silently breaks any join keyed on that name (cloud
// cluster inventory reconciliation, the GuardDuty EKS container join).
//
// The cluster's API server states its identity in its OpenID discovery
// document, and that same string is already emitted on the cloud side:
//
//	EKS: https://oidc.eks.<region>.amazonaws.com/id/<id>
//	     == eks_cluster.metadata["oidc_issuer"] (collect/aws/eks.go)
//	GKE: https://container.googleapis.com/v1/projects/<p>/locations/<l>/clusters/<c>
//	     -> "<p>/gke/<l>/<c>" == the gke_cluster asset ID (collect/gcp/gke.go)
//
// so the issuer becomes a join key no misconfiguration can break, while the
// operator-supplied name is kept beside it as what it actually is: a label.
//
// Asset IDs deliberately keep using the configured name, not the discovered
// one — re-keying would make every existing Kubernetes asset look deleted and
// recreated on each rename. Identity is published as a property to join on,
// not promoted to a primary key.
const openIDConfigurationPath = "/.well-known/openid-configuration"

// clusterIdentity is what one collected cluster asserts about itself, plus the
// name the connector was configured with. Every field is "" when not observed —
// omitted, never guessed.
type clusterIdentity struct {
	// Configured is cfg["cluster_name"] (or the "in-cluster" default): the
	// string every other Kubernetes asset ID in this sweep is prefixed with.
	Configured string
	// Issuer is the API server's service-account issuer.
	Issuer string
	// KubeSystemUID is the kube-system namespace UID — the de-facto stable
	// cluster identifier, unchanged by renames and unique across clusters.
	KubeSystemUID string
}

// cloudProvider, discoveredName and cloudClusterID decode the issuer.
// A shape we do not recognise yields "" for all three: an unknown issuer is
// unknown, not a parse to force.
func (c clusterIdentity) cloudProvider() string {
	switch {
	case strings.HasPrefix(c.Issuer, gkeIssuerPrefix):
		return "gcp"
	case isEKSIssuer(c.Issuer):
		return "aws"
	case isAKSIssuer(c.Issuer):
		return "azure"
	}
	return ""
}

// isAKSIssuer reports whether issuer is an AKS OIDC issuer:
// https://<region>.oic.prod-aks.azure.com/<tenant>/<cluster>/. Only clusters
// created with --enable-oidc-issuer publish one; others report the in-cluster
// default issuer and their provider stays unknown.
func isAKSIssuer(issuer string) bool {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Port() != "" {
		return false
	}
	return strings.HasSuffix(u.Hostname(), ".oic.prod-aks.azure.com")
}

// isEKSIssuer reports whether issuer is an EKS OIDC issuer:
// https://oidc.eks.<region>.amazonaws.com[.cn]/id/<id>. The host must END in
// an AWS domain as well as start with oidc.eks., since the provider read off
// it decides which distribution's RBAC counts as stock.
func isEKSIssuer(issuer string) bool {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Port() != "" {
		return false
	}
	host := u.Hostname()
	return strings.HasPrefix(host, "oidc.eks.") &&
		(strings.HasSuffix(host, ".amazonaws.com") || strings.HasSuffix(host, ".amazonaws.com.cn"))
}

// gkeIssuerPrefix is the fixed prefix of a GKE cluster's service-account issuer.
const gkeIssuerPrefix = "https://container.googleapis.com/v1/projects/"

// gkeIssuerParts splits a GKE issuer into (project, location, cluster).
// Returns ok=false for any other shape.
func gkeIssuerParts(issuer string) (project, location, cluster string, ok bool) {
	rest, found := strings.CutPrefix(issuer, gkeIssuerPrefix)
	if !found {
		return "", "", "", false
	}
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	// <project>/locations/<location>/clusters/<cluster>
	if len(parts) != 5 || parts[1] != "locations" || parts[3] != "clusters" {
		return "", "", "", false
	}
	if parts[0] == "" || parts[2] == "" || parts[4] == "" {
		return "", "", "", false
	}
	return parts[0], parts[2], parts[4], true
}

// discoveredName is the cluster's real name as the cloud provider knows it, or
// "" when the issuer does not carry one. Only GKE issuers do; an EKS issuer
// identifies the cluster by an opaque id, so the EKS name stays unknown here
// rather than being invented from the configured value.
func (c clusterIdentity) discoveredName() string {
	if _, _, cluster, ok := gkeIssuerParts(c.Issuer); ok {
		return cluster
	}
	return ""
}

// cloudClusterID is the ID of the cloud-side asset for this cluster, when the
// issuer determines it. GKE: exactly collect/gcp/gke.go's asset ID.
func (c clusterIdentity) cloudClusterID() string {
	if project, location, cluster, ok := gkeIssuerParts(c.Issuer); ok {
		return fmt.Sprintf("%s/gke/%s/%s", project, location, cluster)
	}
	return ""
}

// nameMismatch reports whether the cluster's own name disagrees with the
// configured one — the silent join-breaker. False when the name was not
// discovered: unknown is not disagreement.
func (c clusterIdentity) nameMismatch() bool {
	d := c.discoveredName()
	return d != "" && d != c.Configured
}

// clusterAssetID is the k8s_cluster asset's ID. "<cluster>/cluster" rather than
// the bare prefix so it cannot collide with a differently-typed asset whose ID
// is a bare name (an s3_bucket, say), and so it reads like every other
// Kubernetes asset ID.
func clusterAssetID(cluster string) string { return cluster + "/cluster" }

// clusterAsset publishes the cluster's identity as an asset. Keys follow the
// collector convention the checks rely on: a key is present only when the value
// was OBSERVED, so a check reading it can tell "not this" from "not known".
func (c clusterIdentity) asset(now time.Time) asset.Asset {
	meta := map[string]string{
		// Always observed: it is the connector's own configuration, and it is
		// the prefix of every other asset ID in this sweep.
		"configured_name": c.Configured,
	}
	if c.Issuer != "" {
		meta["oidc_issuer"] = c.Issuer
	}
	if c.KubeSystemUID != "" {
		meta["kube_system_uid"] = c.KubeSystemUID
	}
	if p := c.cloudProvider(); p != "" {
		meta["cloud_provider"] = p
	}
	if n := c.discoveredName(); n != "" {
		meta["discovered_name"] = n
	}
	if id := c.cloudClusterID(); id != "" {
		meta["cloud_cluster_id"] = id
	}
	name := c.discoveredName()
	if name == "" {
		name = c.Configured
	}
	return asset.Asset{
		ID:           clusterAssetID(c.Configured),
		Name:         name,
		Type:         "k8s_cluster",
		Provider:     asset.ProviderKubernetes,
		Region:       c.Configured,
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}
}

// kubeSystemUID pulls the kube-system namespace UID out of the namespace list
// the collector already fetched — no extra API call.
func kubeSystemUID(namespaces []corev1.Namespace) string {
	for _, ns := range namespaces {
		if ns.Name == "kube-system" {
			return string(ns.UID)
		}
	}
	return ""
}
