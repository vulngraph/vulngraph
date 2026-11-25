package gcp

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	secretmanager "google.golang.org/api/secretmanager/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// gcpSecret is a provider-neutral view of a Secret Manager secret.
type gcpSecret struct {
	Name        string
	HasRotation bool
}

// secretsAPI is the slice of Secret Manager the collector needs.
type secretsAPI interface {
	ListSecrets(ctx context.Context, projectID string) ([]gcpSecret, error)
	// GetSecretAccessors returns service account IDs that have
	// roles/secretmanager.secretAccessor on the given secret resource, and an
	// error when its IAM policy cannot be read.
	GetSecretAccessors(ctx context.Context, secretResource string) ([]string, error)
}

// collectSecrets maps Secret Manager secrets to assets and emits
// accesses_secret edges for every service account that can read each secret.
// A secret whose IAM policy could not be read is still emitted, with
// accessors_known=false (asset.DependentsUnread): its missing edges mean "not
// observed", not "nobody can read it".
func collectSecrets(ctx context.Context, client secretsAPI, projectID string, now time.Time) ([]asset.Asset, []asset.Edge, error) {
	secrets, err := client.ListSecrets(ctx, projectID)
	if err != nil {
		return nil, nil, fmt.Errorf("collectSecrets: %w", err)
	}
	var assets []asset.Asset
	var edges []asset.Edge
	for _, s := range secrets {
		if s.Name == "" {
			continue
		}
		secretID := projectID + "/secret/" + s.Name
		secretResource := "projects/" + projectID + "/secrets/" + s.Name
		accessors, aErr := client.GetSecretAccessors(ctx, secretResource)
		if aErr != nil {
			log.FromContext(ctx).Warn().Err(aErr).Str("secret", secretResource).
				Msg("gcp secret IAM policy unreadable; who can access it is unknown this sweep")
		}
		assets = append(assets, asset.Asset{
			ID:        secretID,
			Name:      s.Name,
			Type:      "gcp_secret",
			Provider:  asset.ProviderGCP,
			AccountID: projectID,
			Metadata: map[string]string{
				"rotation":               fmt.Sprintf("%t", s.HasRotation),
				asset.MetaAccessorsKnown: fmt.Sprintf("%t", aErr == nil),
			},
			DiscoveredAt: now,
			LastSeen:     now,
		})
		for _, saID := range accessors {
			edges = append(edges, asset.Edge{
				SrcID:    saID,
				SrcType:  "gcp_service_account",
				DstID:    secretID,
				DstType:  "gcp_secret",
				EdgeType: "accesses_secret",
			})
		}
	}
	return assets, edges, nil
}

// newSecretsClient builds a real Secret Manager-backed client via ADC.
func newSecretsClient(ctx context.Context) (secretsAPI, error) {
	svc, err := secretmanager.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newSecretsClient: %w", err)
	}
	return &realSecrets{svc: svc}, nil
}

type realSecrets struct {
	svc *secretmanager.Service
}

func (r *realSecrets) ListSecrets(ctx context.Context, projectID string) ([]gcpSecret, error) {
	var out []gcpSecret
	parent := "projects/" + projectID
	err := r.svc.Projects.Secrets.List(parent).Pages(ctx, func(page *secretmanager.ListSecretsResponse) error {
		for _, s := range page.Secrets {
			out = append(out, gcpSecret{
				Name:        path.Base(s.Name),
				HasRotation: s.Rotation != nil && s.Rotation.RotationPeriod != "",
			})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ListSecrets: %w", err)
	}
	return out, nil
}

// GetSecretAccessors requests policy version 3 so a secret with IAM
// Conditions returns its conditional bindings instead of failing the read
// every sweep.
func (r *realSecrets) GetSecretAccessors(ctx context.Context, secretResource string) ([]string, error) {
	policy, err := r.svc.Projects.Secrets.GetIamPolicy(secretResource).OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("GetSecretAccessors %s: %w", secretResource, err)
	}
	var accessors []string
	for _, binding := range policy.Bindings {
		if binding.Role != "roles/secretmanager.secretAccessor" &&
			binding.Role != "roles/secretmanager.admin" &&
			binding.Role != "roles/owner" {
			continue
		}
		for _, member := range binding.Members {
			// member format: "serviceAccount:sa@project.iam.gserviceaccount.com"
			if after, ok := strings.CutPrefix(member, "serviceAccount:"); ok {
				accessors = append(accessors, after)
			}
		}
	}
	return accessors, nil
}
