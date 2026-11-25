package gcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	compute "google.golang.org/api/compute/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// computeImageAPI is the slice of the Compute API the image/snapshot exfil
// collector uses — narrow enough to fake in tests (matches cloudSQLAPI/cloudRunAPI).
// A GCP image or disk snapshot is "public" when its IAM policy grants a role to
// allUsers or allAuthenticatedUsers — anyone can then create a disk from it and
// read the source, the GCP analogue of a public EBS snapshot.
type computeImageAPI interface {
	listImages(ctx context.Context, project string) ([]*compute.Image, error)
	listSnapshots(ctx context.Context, project string) ([]*compute.Snapshot, error)
	imagePublic(ctx context.Context, project, name string) (bool, error)
	snapshotPublic(ctx context.Context, project, name string) (bool, error)
}

// collectGCPImagesSnapshots emits the project's own images and disk snapshots,
// flagging any shared with allUsers/allAuthenticatedUsers. Best-effort per
// resource: a failed IAM read omits the "public" key and writes
// public_access=unknown, so the public-image and public-snapshot checks stay
// unevaluated rather than reading it as private.
func collectGCPImagesSnapshots(ctx context.Context, api computeImageAPI, projectID string, now time.Time) ([]asset.Asset, error) {
	var assets []asset.Asset

	images, err := api.listImages(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("collectGCPImagesSnapshots: images: %w", err)
	}
	for _, img := range images {
		assets = append(assets, asset.Asset{
			ID:        fmt.Sprintf("%s/image/%s", projectID, img.Name),
			Name:      img.Name,
			Type:      "gcp_image",
			Provider:  asset.ProviderGCP,
			Region:    "global",
			AccountID: projectID,
			Metadata: publicMetadata(ctx, "image", img.Name, img.SelfLink, img.Status,
				func() (bool, error) { return api.imagePublic(ctx, projectID, img.Name) }),
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}

	snaps, err := api.listSnapshots(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("collectGCPImagesSnapshots: snapshots: %w", err)
	}
	for _, s := range snaps {
		assets = append(assets, asset.Asset{
			ID:        fmt.Sprintf("%s/snapshot/%s", projectID, s.Name),
			Name:      s.Name,
			Type:      "gcp_disk_snapshot",
			Provider:  asset.ProviderGCP,
			Region:    "global",
			AccountID: projectID,
			Metadata: publicMetadata(ctx, "snapshot", s.Name, s.SelfLink, s.Status,
				func() (bool, error) { return api.snapshotPublic(ctx, projectID, s.Name) }),
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	return assets, nil
}

// publicMetadata builds an image or snapshot's metadata, writing "public" only
// when the IAM policy was read and public_access=unknown when it was not.
func publicMetadata(ctx context.Context, kind, name, selfLink, status string, public func() (bool, error)) map[string]string {
	md := map[string]string{"self_link": selfLink, "status": status}
	p, err := public()
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str(kind, name).
			Msg("gcp: IAM policy unreadable; public exposure unknown this sweep")
		md["public_access"] = publicAccessUnknown
		return md
	}
	md["public"] = fmt.Sprintf("%t", p)
	return md
}

// realComputeImageAPI wraps the concrete Compute service. Its IAM reads request
// policy version 3 so a resource with IAM Conditions returns its conditional
// bindings instead of failing the read every sweep.
type realComputeImageAPI struct{ svc *compute.Service }

func (r realComputeImageAPI) listImages(ctx context.Context, project string) ([]*compute.Image, error) {
	var out []*compute.Image
	err := r.svc.Images.List(project).Context(ctx).Pages(ctx, func(page *compute.ImageList) error {
		out = append(out, page.Items...)
		return nil
	})
	return out, err
}

func (r realComputeImageAPI) listSnapshots(ctx context.Context, project string) ([]*compute.Snapshot, error) {
	var out []*compute.Snapshot
	err := r.svc.Snapshots.List(project).Context(ctx).Pages(ctx, func(page *compute.SnapshotList) error {
		out = append(out, page.Items...)
		return nil
	})
	return out, err
}

func (r realComputeImageAPI) imagePublic(ctx context.Context, project, name string) (bool, error) {
	p, err := r.svc.Images.GetIamPolicy(project, name).OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		return false, fmt.Errorf("imagePublic %s: %w", name, err)
	}
	return policyHasPublicMember(p)
}

func (r realComputeImageAPI) snapshotPublic(ctx context.Context, project, name string) (bool, error) {
	p, err := r.svc.Snapshots.GetIamPolicy(project, name).OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		return false, fmt.Errorf("snapshotPublic %s: %w", name, err)
	}
	return policyHasPublicMember(p)
}

// policyHasPublicMember reports whether any binding grants a role to allUsers or
// allAuthenticatedUsers — the GCP "public" signal. A nil policy is no
// observation, so it is an error rather than "not public".
func policyHasPublicMember(p *compute.Policy) (bool, error) {
	if p == nil {
		return false, errors.New("policyHasPublicMember: empty IAM policy response")
	}
	for _, b := range p.Bindings {
		for _, m := range b.Members {
			if m == "allUsers" || m == "allAuthenticatedUsers" {
				return true, nil
			}
		}
	}
	return false, nil
}
