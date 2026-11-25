package gcp

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
	orgpolicy "google.golang.org/api/orgpolicy/v2"
	storage "google.golang.org/api/storage/v1"
	htransport "google.golang.org/api/transport/http"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// gcsBucket is a provider-neutral view of a Cloud Storage bucket, so the
// asset-mapping stays independent of the GCP SDK shapes (mirrors gceInstance).
type gcsBucket struct {
	Name                   string
	Location               string
	PublicAccessPrevention string
	EffectivePrevention    string
	UniformAccess          bool
	Versioning             bool
	LogBucket              string
	Public                 bool
	// PublicKnown is false when effective prevention or IAM could not be read: Public is
	// then not an observation, and the bucket is written without a "public"
	// key so gcp-gcs-public-bucket stays unevaluated instead of compliant,
	// and with public_access=unknown so DSPM shows it as unobserved rather
	// than private.
	PublicKnown bool
}

// gcsAPI is the slice of Cloud Storage the collector needs — small enough to fake.
type gcsAPI interface {
	ListBuckets(ctx context.Context, projectID string) ([]gcsBucket, error)
}

// collectGCS lists the project's buckets and maps each to a gcs_bucket asset,
// flagging public exposure — the GCP counterpart to the AWS S3 collector.
// Public buckets get an exposed_to_internet edge to the internet sentinel; a
// bucket whose exposure is unknown gets neither the edge nor a "public" key,
// and is tagged public_access=unknown instead.
func collectGCS(ctx context.Context, client gcsAPI, projectID string, now time.Time) ([]asset.Asset, []asset.Edge, error) {
	buckets, err := client.ListBuckets(ctx, projectID)
	if err != nil {
		return nil, nil, fmt.Errorf("collectGCS: %w", err)
	}

	var assets []asset.Asset
	var edges []asset.Edge
	for _, b := range buckets {
		if b.Name == "" {
			continue
		}
		md := map[string]string{
			"public_access_prevention": b.PublicAccessPrevention,
			"uniform_access":           fmt.Sprintf("%t", b.UniformAccess),
			"versioning":               fmt.Sprintf("%t", b.Versioning),
			// logging_bucket, not "logging": on s3_bucket the same key name is an
			// enabled/disabled ENUM, here it is the destination log bucket's NAME.
			// Both readers happen to be AssetType-scoped today, so nothing is
			// cross-wired — but one shared key with two incompatible value spaces
			// is a check away from firing on the wrong one.
			"logging_bucket": b.LogBucket,
		}
		if b.EffectivePrevention != "" {
			md["public_access_prevention_effective"] = b.EffectivePrevention
		}
		if b.PublicKnown {
			md["public"] = fmt.Sprintf("%t", b.Public)
		} else {
			md["public_access"] = publicAccessUnknown
		}
		assets = append(assets, asset.Asset{
			ID:           b.Name, // GCS bucket names are globally unique
			Name:         b.Name,
			Type:         "gcs_bucket",
			Provider:     asset.ProviderGCP,
			Region:       strings.ToLower(b.Location),
			AccountID:    projectID,
			Domain:       b.Name + ".storage.googleapis.com",
			Metadata:     md,
			DiscoveredAt: now,
			LastSeen:     now,
		})
		if b.PublicKnown && b.Public {
			edges = append(edges, asset.Edge{
				SrcID: b.Name, SrcType: "gcs_bucket",
				DstID: "internet", DstType: "internet",
				EdgeType: "exposed_to_internet",
			})
		}
	}
	return assets, edges, nil
}

// newGCSClient builds a real Cloud Storage-backed gcsAPI via Application Default
// Credentials — the same OIDC/Workload-Identity path as the compute
// client; no key on the connector.
func newGCSClient(ctx context.Context) (gcsAPI, error) {
	svc, err := storage.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newGCSClient: %w", err)
	}
	policies, _, err := htransport.NewClient(ctx, option.WithScopes(orgpolicy.CloudPlatformScope))
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).
			Msg("gcs: organization policy client unavailable; inherited prevention unknown")
	}
	rm, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).
			Msg("gcs: project ancestry client unavailable; ancestor prevention unknown")
	}
	return &realGCS{svc: svc, policies: policies, rm: rm}, nil
}

// realGCS adapts the Storage SDK to the provider-neutral gcsAPI.
type realGCS struct {
	svc      *storage.Service
	policies *http.Client
	rm       *cloudresourcemanager.Service
}

func (r *realGCS) ListBuckets(ctx context.Context, projectID string) ([]gcsBucket, error) {
	var out []gcsBucket
	var inheritedPrevention string
	preventionRead := false
	err := r.svc.Buckets.List(projectID).Pages(ctx, func(page *storage.Buckets) error {
		for _, b := range page.Items {
			if !preventionRead && (b.IamConfiguration == nil || b.IamConfiguration.PublicAccessPrevention != "enforced") {
				inheritedPrevention = r.projectPublicAccessPrevention(ctx, projectID)
				preventionRead = true
			}
			out = append(out, bucketToNeutral(ctx, b, r.bucketPolicy, inheritedPrevention))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ListBuckets: %w", err)
	}
	return out, nil
}

// bucketPolicy requests policy version 3 so a bucket with IAM Conditions
// returns its conditional bindings instead of failing the read every sweep.
func (r *realGCS) bucketPolicy(ctx context.Context, bucket string) (*storage.Policy, error) {
	p, err := r.svc.Buckets.GetIamPolicy(bucket).OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("bucketPolicy %s: %w", bucket, err)
	}
	return p, nil
}

// bucketToNeutral maps a bucket and resolves its public exposure. A bucket is
// public if its IAM policy grants any role to allUsers / allAuthenticatedUsers.
// Effective prevention overrides retained public bindings. Unknown prevention
// leaves exposure unknown: a public binding alone does not prove public access.
func bucketToNeutral(ctx context.Context, b *storage.Bucket, policyOf func(context.Context, string) (*storage.Policy, error), inheritedPrevention string) gcsBucket {
	g := gcsBucket{Name: b.Name, Location: b.Location}

	if b.IamConfiguration != nil {
		g.PublicAccessPrevention = b.IamConfiguration.PublicAccessPrevention
		if b.IamConfiguration.UniformBucketLevelAccess != nil {
			g.UniformAccess = b.IamConfiguration.UniformBucketLevelAccess.Enabled
		}
	}

	if b.Versioning != nil {
		g.Versioning = b.Versioning.Enabled
	}

	if b.Logging != nil {
		g.LogBucket = b.Logging.LogBucket
	}

	if g.PublicAccessPrevention == "enforced" || inheritedPrevention == "enforced" {
		g.EffectivePrevention = "enforced"
		g.PublicKnown = true
		return g
	}
	if g.PublicAccessPrevention != "inherited" || inheritedPrevention != "not_enforced" {
		return g
	}
	g.EffectivePrevention = "not_enforced"

	policy, err := policyOf(ctx, b.Name)
	if err == nil && policy == nil {
		err = fmt.Errorf("bucketToNeutral %s: empty IAM policy response", b.Name)
	}
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("bucket", b.Name).
			Msg("gcs: bucket IAM policy unreadable; public exposure unknown this sweep")
		return g
	}
	g.PublicKnown = true
	for _, binding := range policy.Bindings {
		for _, m := range binding.Members {
			if m == "allUsers" || m == "allAuthenticatedUsers" {
				g.Public = true
				return g
			}
		}
	}
	return g
}
