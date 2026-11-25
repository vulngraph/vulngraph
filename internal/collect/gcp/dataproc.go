package gcp

import (
	"context"
	"fmt"
	"sync"
	"time"

	compute "google.golang.org/api/compute/v1"
	dataproc "google.golang.org/api/dataproc/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// dataprocAPI is the slice of Dataproc (and the Compute region list it is
// scoped by) the cluster encryption posture needs (CIS GCP 8.1).
type dataprocAPI interface {
	Regions(ctx context.Context, projectID string) ([]string, error)
	Clusters(ctx context.Context, projectID, region string) ([]*dataproc.Cluster, error)
}

// collectDataproc lists every region's Dataproc clusters with the key
// encrypting their persistent disks. Dataproc has no cross-region listing,
// so the first region is read alone: a project that never enabled the API
// answers SERVICE_DISABLED there, and is not fanned out across every region.
func collectDataproc(ctx context.Context, client dataprocAPI, projectID string, now time.Time) ([]asset.Asset, error) {
	regions, err := client.Regions(ctx, projectID)
	if err != nil || len(regions) == 0 {
		return nil, err
	}
	var (
		mu     sync.Mutex
		assets []asset.Asset
	)
	read := func(region string) error {
		clusters, err := client.Clusters(ctx, projectID, region)
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		for _, c := range clusters {
			if c == nil || c.ClusterName == "" {
				continue
			}
			key := ""
			if c.Config != nil && c.Config.EncryptionConfig != nil {
				key = c.Config.EncryptionConfig.GcePdKmsKeyName
			}
			assets = append(assets, asset.Asset{
				ID:   projectID + "/dataproc/" + region + "/" + c.ClusterName,
				Name: c.ClusterName, Type: "gcp_dataproc_cluster", Provider: asset.ProviderGCP,
				Region: region, AccountID: projectID, Tags: c.Labels,
				Metadata:     map[string]string{"disk_cmek": key},
				DiscoveredAt: now, LastSeen: now,
			})
		}
		return nil
	}
	if err := read(regions[0]); err != nil {
		return nil, fmt.Errorf("collectDataproc: %w", err)
	}
	if err := fanOut(ctx, "gcp dataproc region", regions[1:], read); err != nil {
		return assets, fmt.Errorf("collectDataproc: %w", err)
	}
	return assets, nil
}

// newDataprocClient builds the real dataprocAPI via ADC.
func newDataprocClient(ctx context.Context) (dataprocAPI, error) {
	c, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newDataprocClient: %w", err)
	}
	d, err := dataproc.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newDataprocClient: %w", err)
	}
	return &realDataproc{compute: c, dataproc: d}, nil
}

type realDataproc struct {
	compute  *compute.Service
	dataproc *dataproc.Service
}

func (r *realDataproc) Regions(ctx context.Context, projectID string) ([]string, error) {
	var out []string
	if err := r.compute.Regions.List(projectID).Pages(ctx, func(p *compute.RegionList) error {
		for _, reg := range p.Items {
			if reg != nil {
				out = append(out, reg.Name)
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("Regions: %w", err)
	}
	return out, nil
}

func (r *realDataproc) Clusters(ctx context.Context, projectID, region string) ([]*dataproc.Cluster, error) {
	var out []*dataproc.Cluster
	if err := r.dataproc.Projects.Regions.Clusters.List(projectID, region).Pages(ctx, func(p *dataproc.ListClustersResponse) error {
		out = append(out, p.Clusters...)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("Clusters %s: %w", region, err)
	}
	return out, nil
}
