package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	container "google.golang.org/api/container/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	htransport "google.golang.org/api/transport/http"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// gkeCluster is a provider-neutral view of a GKE cluster's security posture.
type gkeCluster struct {
	Name           string
	Location       string
	Endpoint       string // public control-plane endpoint ("" when private)
	MasterVersion  string
	PublicEndpoint bool // control plane reachable from the internet
	AuthorizedNets bool // master authorized networks configured
	// AuthorizedNetsWorld: the authorized-networks allowlist itself contains
	// 0.0.0.0/0 or ::/0, so it restricts nothing.
	AuthorizedNetsWorld bool
	LegacyABAC          bool // legacy attribute-based access control still on
	NetworkPolicy       bool // NetworkPolicy enforcement enabled
	ShieldedNodes       bool
	Status              string // cluster lifecycle state ("RUNNING", "STOPPING", …)
	WorkloadPool        string // Workload Identity pool ("<project>.svc.id.goog"), "" when disabled
	// Subnetwork is networkConfig.subnetwork, the nodes' subnet
	// ("projects/P/regions/R/subnetworks/S"), evidence for the subnet's own
	// flow-log finding (CIS GKE 5.6.1 is graded on the gcp_subnetwork asset).
	Subnetwork string
	// Posture holds the CIS GKE cluster and node-pool settings (gkePosture),
	// already in asset-metadata form.
	Posture map[string]string
}

// containerAPI is the slice of the GKE Container API the collector needs.
type containerAPI interface {
	// ListClusters returns the clusters it could read; a non-nil error with a
	// non-empty list is a partial listing (unreachable zones).
	ListClusters(ctx context.Context, projectID string) ([]gkeCluster, error)
}

// collectGKE lists the project's GKE clusters and their security posture — the
// control-plane exposure, legacy ABAC, and NetworkPolicy signals (GKE parity
// with EKS/AKS). Best-effort per the caller;
// on a partial listing the clusters read are returned beside the error.
func collectGKE(ctx context.Context, client containerAPI, projectID string, now time.Time) ([]asset.Asset, error) {
	clusters, listErr := client.ListClusters(ctx, projectID)
	if listErr != nil && len(clusters) == 0 {
		return nil, fmt.Errorf("collectGKE: %w", listErr)
	}
	assets := make([]asset.Asset, 0, len(clusters))
	for _, c := range clusters {
		meta := map[string]string{
			"location":                  c.Location,
			"master_version":            c.MasterVersion,
			"public_endpoint":           strconv.FormatBool(c.PublicEndpoint),
			"authorized_networks":       strconv.FormatBool(c.AuthorizedNets),
			"authorized_networks_world": strconv.FormatBool(c.AuthorizedNetsWorld),
			"legacy_abac":               strconv.FormatBool(c.LegacyABAC),
			"network_policy":            strconv.FormatBool(c.NetworkPolicy),
			"shielded_nodes":            strconv.FormatBool(c.ShieldedNodes),
		}
		// Lifecycle state separates "no workload inventory because collection is
		// blind" from "cluster is being torn down" for inventory reconciliation.
		if c.Status != "" {
			meta["status"] = c.Status
		}
		// The Workload Identity pool is the GKE analogue of the EKS OIDC issuer:
		// it is the join key from a k8s_service_account to the GCP service account
		// it can impersonate. Omitted when Workload Identity is off — which is
		// itself the observation that no such binding can exist.
		if c.WorkloadPool != "" {
			meta["workload_identity_pool"] = c.WorkloadPool
		}
		if c.Subnetwork != "" {
			meta["subnetwork"] = c.Subnetwork
		}
		maps.Copy(meta, c.Posture)
		// A public control-plane endpoint with no authorized-networks allowlist
		// (or one admitting 0.0.0.0/0) is reachable from the whole internet — the
		// possible tier (kubeconfig auth still required), surfaced by exposure
		// scoring at a lower severity.
		if c.PublicEndpoint && (!c.AuthorizedNets || c.AuthorizedNetsWorld) {
			meta["public_access"] = asset.PublicAccessPossible
		}
		assets = append(assets, asset.Asset{
			ID:           fmt.Sprintf("%s/gke/%s/%s", projectID, c.Location, c.Name),
			Name:         c.Name,
			Type:         "gke_cluster",
			Provider:     asset.ProviderGCP,
			Region:       c.Location,
			AccountID:    projectID,
			Endpoint:     c.Endpoint,
			Metadata:     meta,
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	if listErr != nil {
		return assets, fmt.Errorf("collectGKE: %w", listErr)
	}
	return assets, nil
}

// containerEndpoint is the Container API v1 base URL.
const containerEndpoint = "https://container.googleapis.com/v1/"

// newContainerClient builds a real containerAPI via ADC. It calls the REST
// endpoint with an authorized client rather than through the generated
// Service so the raw response body can be decoded twice (decodeClusters).
func newContainerClient(ctx context.Context) (containerAPI, error) {
	hc, _, err := htransport.NewClient(ctx, option.WithScopes(container.CloudPlatformScope))
	if err != nil {
		return nil, fmt.Errorf("newContainerClient: %w", err)
	}
	return &realContainer{hc: hc}, nil
}

type realContainer struct{ hc *http.Client }

func (r *realContainer) ListClusters(ctx context.Context, projectID string) ([]gkeCluster, error) {
	// "-" location lists clusters across all locations in one call.
	u := containerEndpoint + "projects/" + url.PathEscape(projectID) + "/locations/-/clusters"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("ListClusters: %w", err)
	}
	resp, err := r.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ListClusters: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ListClusters: %w", err)
	}
	// A *googleapi.Error, so bestEffort still recognises SERVICE_DISABLED.
	if err := googleapi.CheckResponseWithBody(resp, body); err != nil {
		return nil, fmt.Errorf("ListClusters: %w", err)
	}
	return decodeClusters(body)
}

// decodeClusters maps a clusters.list response body. It is decoded twice:
// once into the SDK's ListClustersResponse, and once for the one field whose
// SDK type loses information, nodePools[].networkConfig.enablePrivateNodes —
// a proto3 optional the SDK flattens to a plain bool, so a pool opting OUT of
// a private cluster (explicit false) would read as inheriting it. A response
// naming missingZones is a partial listing: the clusters it returned are
// kept and the error flags the sweep partial.
func decodeClusters(body []byte) ([]gkeCluster, error) {
	var resp container.ListClustersResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decodeClusters: %w", err)
	}
	var explicit struct {
		Clusters []struct {
			Name      string `json:"name"`
			Location  string `json:"location"`
			NodePools []struct {
				Name          string `json:"name"`
				NetworkConfig *struct {
					EnablePrivateNodes *bool `json:"enablePrivateNodes"`
				} `json:"networkConfig"`
			} `json:"nodePools"`
		} `json:"clusters"`
	}
	if err := json.Unmarshal(body, &explicit); err != nil {
		return nil, fmt.Errorf("decodeClusters: %w", err)
	}
	private := map[string]map[string]bool{}
	for _, c := range explicit.Clusters {
		key := c.Location + "/" + c.Name
		for _, p := range c.NodePools {
			if p.NetworkConfig == nil || p.NetworkConfig.EnablePrivateNodes == nil {
				continue
			}
			if private[key] == nil {
				private[key] = map[string]bool{}
			}
			private[key][p.Name] = *p.NetworkConfig.EnablePrivateNodes
		}
	}
	out := make([]gkeCluster, 0, len(resp.Clusters))
	for _, c := range resp.Clusters {
		if c != nil {
			out = append(out, toNeutralGKE(c, private[c.Location+"/"+c.Name]))
		}
	}
	if len(resp.MissingZones) > 0 {
		return out, fmt.Errorf("decodeClusters: clusters.list did not reach zones %s", strings.Join(resp.MissingZones, ","))
	}
	return out, nil
}

func toNeutralGKE(c *container.Cluster, explicitPrivate map[string]bool) gkeCluster {
	public, an := controlPlaneAccess(c)
	g := gkeCluster{
		Name:           c.Name,
		Location:       c.Location,
		Endpoint:       c.Endpoint,
		MasterVersion:  c.CurrentMasterVersion,
		Status:         c.Status,
		PublicEndpoint: public,
		Posture:        gkePosture(c, explicitPrivate),
	}
	if c.NetworkConfig != nil {
		g.Subnetwork = c.NetworkConfig.Subnetwork
	}
	if an != nil {
		g.AuthorizedNets = an.Enabled
		g.AuthorizedNetsWorld = an.Enabled && worldAuthorizedCIDR(an)
	}
	if c.LegacyAbac != nil {
		g.LegacyABAC = c.LegacyAbac.Enabled
	}
	if c.NetworkPolicy != nil {
		g.NetworkPolicy = c.NetworkPolicy.Enabled
	}
	if c.ShieldedNodes != nil {
		g.ShieldedNodes = c.ShieldedNodes.Enabled
	}
	if c.WorkloadIdentityConfig != nil {
		g.WorkloadPool = c.WorkloadIdentityConfig.WorkloadPool
	}
	return g
}
