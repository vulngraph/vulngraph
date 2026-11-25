package gcp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	artifactregistry "google.golang.org/api/artifactregistry/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// artifactRegistryAPI is the slice of Artifact Registry the repository
// posture needs (CIS GKE 5.1.1, 5.1.2).
type artifactRegistryAPI interface {
	Locations(ctx context.Context, projectID string) ([]string, error)
	Repositories(ctx context.Context, projectID, location string) ([]*artifactregistry.Repository, error)
	// PublicGrants returns "member=role" for every allUsers or
	// allAuthenticatedUsers binding on the repository's IAM policy.
	PublicGrants(ctx context.Context, repo string) ([]string, error)
}

// collectArtifactRegistry inventories the project's repositories with their
// vulnerability-scanning state and public grants. A location that fails to
// list returns what was read beside the error; an unreadable repository
// policy leaves public_grants absent.
func collectArtifactRegistry(ctx context.Context, client artifactRegistryAPI, projectID string, now time.Time) ([]asset.Asset, error) {
	locations, err := client.Locations(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("collectArtifactRegistry: %w", err)
	}
	var (
		mu     sync.Mutex
		assets []asset.Asset
	)
	err = fanOut(ctx, "gcp artifact registry location", locations, func(loc string) error {
		repos, err := client.Repositories(ctx, projectID, loc)
		if err != nil {
			return err
		}
		var policyErr error
		for _, r := range repos {
			if r == nil || r.Name == "" {
				continue
			}
			md := map[string]string{"format": r.Format, "mode": r.Mode}
			// SCANNING_UNSUPPORTED formats have no setting to grade.
			if c := r.VulnerabilityScanningConfig; c != nil && c.EnablementState != "" &&
				c.EnablementState != "ENABLEMENT_STATE_UNSPECIFIED" && c.EnablementState != "SCANNING_UNSUPPORTED" {
				md["scanning_state"] = c.EnablementState
				md["scanning_state_reason"] = c.EnablementStateReason
			}
			if grants, err := client.PublicGrants(ctx, r.Name); err == nil {
				md["public_grants"] = strings.Join(grants, ",")
			} else {
				policyErr = err
			}
			a := asset.Asset{
				ID: r.Name, Name: lastSegment(r.Name), Type: "gcp_artifact_repository", Provider: asset.ProviderGCP,
				Region: loc, AccountID: projectID, Tags: r.Labels, Metadata: md, DiscoveredAt: now, LastSeen: now,
			}
			mu.Lock()
			assets = append(assets, a)
			mu.Unlock()
		}
		return policyErr
	})
	if err != nil {
		return assets, fmt.Errorf("collectArtifactRegistry: %w", err)
	}
	return assets, nil
}

// newArtifactRegistryClient builds the real artifactRegistryAPI via ADC.
func newArtifactRegistryClient(ctx context.Context) (artifactRegistryAPI, error) {
	svc, err := artifactregistry.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newArtifactRegistryClient: %w", err)
	}
	return &realArtifactRegistry{svc: svc}, nil
}

type realArtifactRegistry struct{ svc *artifactregistry.Service }

func (r *realArtifactRegistry) Locations(ctx context.Context, projectID string) ([]string, error) {
	var out []string
	if err := r.svc.Projects.Locations.List("projects/"+projectID).Pages(ctx, func(p *artifactregistry.ListLocationsResponse) error {
		for _, l := range p.Locations {
			if l != nil {
				out = append(out, l.LocationId)
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("Locations: %w", err)
	}
	return out, nil
}

func (r *realArtifactRegistry) Repositories(ctx context.Context, projectID, location string) ([]*artifactregistry.Repository, error) {
	var out []*artifactregistry.Repository
	parent := "projects/" + projectID + "/locations/" + location
	if err := r.svc.Projects.Locations.Repositories.List(parent).Pages(ctx, func(p *artifactregistry.ListRepositoriesResponse) error {
		out = append(out, p.Repositories...)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("Repositories %s: %w", location, err)
	}
	return out, nil
}

func (r *realArtifactRegistry) PublicGrants(ctx context.Context, repo string) ([]string, error) {
	p, err := r.svc.Projects.Locations.Repositories.GetIamPolicy(repo).OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("PublicGrants %s: %w", repo, err)
	}
	var out []string
	for _, b := range p.Bindings {
		if b == nil {
			continue
		}
		for _, m := range b.Members {
			if m == "allUsers" || m == "allAuthenticatedUsers" {
				out = append(out, m+"="+b.Role)
			}
		}
	}
	return out, nil
}
