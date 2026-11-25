package gcp

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	cloudkms "google.golang.org/api/cloudkms/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// kmsAPI is the slice of Cloud KMS the key posture needs.
type kmsAPI interface {
	Locations(ctx context.Context, projectID string) ([]string, error)
	KeyRings(ctx context.Context, projectID, location string) ([]string, error)
	CryptoKeys(ctx context.Context, keyRing string) ([]*cloudkms.CryptoKey, error)
	// PublicGrants returns "member=role" for every allUsers or
	// allAuthenticatedUsers binding on a key ring or key IAM policy.
	PublicGrants(ctx context.Context, resource string) ([]string, error)
}

// rotationLimit is the longest rotation period CIS GCP 1.11 allows.
const rotationLimit = 90 * 24 * time.Hour

// collectKMS inventories the project's Cloud KMS keys (CIS GCP 1.10, 1.11):
// every location's key rings and their keys, with the public grants on the
// ring (inherited by its keys) and on the key itself. A location or ring that
// fails to list returns what was read beside the error; an unreadable IAM
// policy leaves public_grants absent.
func collectKMS(ctx context.Context, client kmsAPI, projectID string, now time.Time) ([]asset.Asset, error) {
	locations, err := client.Locations(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("collectKMS: %w", err)
	}
	var (
		mu     sync.Mutex
		assets []asset.Asset
	)
	err = fanOut(ctx, "gcp kms location", locations, func(loc string) error {
		rings, err := client.KeyRings(ctx, projectID, loc)
		if err != nil {
			return err
		}
		var errs []error
		for _, ring := range rings {
			ringGrants, ringErr := client.PublicGrants(ctx, ring)
			errs = append(errs, ringErr)
			keys, err := client.CryptoKeys(ctx, ring)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			for _, k := range keys {
				if k == nil || k.Name == "" {
					continue
				}
				md := kmsKeyMetadata(k)
				keyGrants, keyErr := client.PublicGrants(ctx, k.Name)
				errs = append(errs, keyErr)
				if ringErr == nil && keyErr == nil {
					md["public_grants"] = strings.Join(append(append([]string{}, ringGrants...), keyGrants...), ",")
				}
				a := asset.Asset{
					ID: k.Name, Name: lastSegment(k.Name), Type: "gcp_kms_key", Provider: asset.ProviderGCP,
					Region: loc, AccountID: projectID, Tags: k.Labels, Metadata: md, DiscoveredAt: now, LastSeen: now,
				}
				mu.Lock()
				assets = append(assets, a)
				mu.Unlock()
			}
		}
		return errors.Join(errs...)
	})
	if err != nil {
		return assets, fmt.Errorf("collectKMS: %w", err)
	}
	return assets, nil
}

// kmsKeyMetadata records a key's purpose, primary-version state and
// rotation schedule. rotation_period_days is "" when no automatic rotation
// is configured, which is an observation (the API omits rotationPeriod).
func kmsKeyMetadata(k *cloudkms.CryptoKey) map[string]string {
	md := map[string]string{
		"key_ring":             strings.Split(k.Name, "/cryptoKeys/")[0],
		"purpose":              k.Purpose,
		"import_only":          strconv.FormatBool(k.ImportOnly),
		"next_rotation":        strconv.FormatBool(k.NextRotationTime != ""),
		"rotation_period_days": "",
	}
	if k.Primary != nil {
		md["primary_state"] = k.Primary.State
	}
	if k.VersionTemplate != nil {
		md["protection_level"] = k.VersionTemplate.ProtectionLevel
	}
	if d, err := time.ParseDuration(k.RotationPeriod); err == nil && k.RotationPeriod != "" {
		md["rotation_period_days"] = strconv.Itoa(int(d / (24 * time.Hour)))
		md["rotation_within_90_days"] = strconv.FormatBool(d <= rotationLimit)
	} else {
		md["rotation_within_90_days"] = "false"
	}
	return md
}

// newKMSClient builds the real Cloud KMS-backed kmsAPI via ADC.
func newKMSClient(ctx context.Context) (kmsAPI, error) {
	svc, err := cloudkms.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newKMSClient: %w", err)
	}
	return &realKMS{svc: svc}, nil
}

type realKMS struct{ svc *cloudkms.Service }

func (r *realKMS) Locations(ctx context.Context, projectID string) ([]string, error) {
	var out []string
	if err := r.svc.Projects.Locations.List("projects/"+projectID).Pages(ctx, func(p *cloudkms.ListLocationsResponse) error {
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

func (r *realKMS) KeyRings(ctx context.Context, projectID, location string) ([]string, error) {
	var out []string
	parent := "projects/" + projectID + "/locations/" + location
	if err := r.svc.Projects.Locations.KeyRings.List(parent).Pages(ctx, func(p *cloudkms.ListKeyRingsResponse) error {
		for _, k := range p.KeyRings {
			if k != nil {
				out = append(out, k.Name)
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("KeyRings %s: %w", location, err)
	}
	return out, nil
}

func (r *realKMS) CryptoKeys(ctx context.Context, keyRing string) ([]*cloudkms.CryptoKey, error) {
	var out []*cloudkms.CryptoKey
	if err := r.svc.Projects.Locations.KeyRings.CryptoKeys.List(keyRing).Pages(ctx, func(p *cloudkms.ListCryptoKeysResponse) error {
		out = append(out, p.CryptoKeys...)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("CryptoKeys %s: %w", keyRing, err)
	}
	return out, nil
}

func (r *realKMS) PublicGrants(ctx context.Context, resource string) ([]string, error) {
	var (
		p   *cloudkms.Policy
		err error
	)
	if strings.Contains(resource, "/cryptoKeys/") {
		p, err = r.svc.Projects.Locations.KeyRings.CryptoKeys.GetIamPolicy(resource).
			OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	} else {
		p, err = r.svc.Projects.Locations.KeyRings.GetIamPolicy(resource).
			OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	}
	if err != nil {
		return nil, fmt.Errorf("PublicGrants %s: %w", resource, err)
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
