package gcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	compute "google.golang.org/api/compute/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// collectGCPSSLCerts fetches all GCP Compute SSL certificates (global +
// regional) for a project. These cover managed certs attached to load
// balancers. Certificate Manager (the newer API) is a separate service not
// yet covered here.
func collectGCPSSLCerts(ctx context.Context, svc *compute.Service, projectID string, now time.Time) ([]asset.Asset, error) {
	var assets []asset.Asset

	// AggregatedList covers both global and regional SSL certificates.
	err := svc.SslCertificates.AggregatedList(projectID).Context(ctx).Pages(ctx,
		func(page *compute.SslCertificateAggregatedList) error {
			for scopeKey, scoped := range page.Items {
				for _, cert := range scoped.SslCertificates {
					region := lastSegment(scopeKey)
					if region == "" || region == scopeKey {
						region = "global"
					}
					a := gcpSSLCertAsset(cert, projectID, region, now)
					assets = append(assets, a)
				}
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("collectGCPSSLCerts: %w", err)
	}
	return assets, nil
}

func gcpSSLCertAsset(cert *compute.SslCertificate, projectID, region string, now time.Time) asset.Asset {
	id := projectID + "/ssl-certificate/" + cert.Name

	meta := map[string]string{
		"type":      cert.Type,
		"self_link": cert.SelfLink,
		"source":    "gcp-compute",
	}

	var domain string
	var expiresAt time.Time

	switch cert.Type {
	case "MANAGED":
		if cert.Managed != nil {
			meta["status"] = cert.Managed.Status
			domains := cert.Managed.Domains
			if len(domains) > 0 {
				domain = domains[0]
				meta["domains"] = strings.Join(domains, ",")
			}
			// domain_status: "example.com": "ACTIVE"
			var statuses []string
			for d, s := range cert.Managed.DomainStatus {
				statuses = append(statuses, d+"="+s)
			}
			if len(statuses) > 0 {
				meta["domain_status"] = strings.Join(statuses, ",")
			}
		}
	case "SELF_MANAGED":
		if cert.SelfManaged != nil {
			// Don't store the PEM — but parse SANs if we can
			meta["has_private_key"] = fmt.Sprintf("%t", cert.SelfManaged.PrivateKey != "")
		}
	}

	// SubjectAlternativeNames available for all types after GCP parses them.
	if len(cert.SubjectAlternativeNames) > 0 {
		meta["san"] = strings.Join(cert.SubjectAlternativeNames, ",")
		if domain == "" {
			domain = cert.SubjectAlternativeNames[0]
		}
	}

	// ExpireTime is RFC3339, available for both managed and self-managed.
	if cert.ExpireTime != "" {
		if t, err := time.Parse(time.RFC3339, cert.ExpireTime); err == nil {
			expiresAt = t
			meta["expires_at"] = t.UTC().Format(time.RFC3339)
			days := int(time.Until(t).Hours() / 24)
			meta["days_until_expiry"] = fmt.Sprintf("%d", days)
			// Both outcomes recorded, so an absent key means only that ExpireTime
			// was unreadable. See the note in collect/aws/acm.go.
			meta["expiring_soon"] = fmt.Sprintf("%t", days <= 30)
		}
	}

	_ = expiresAt // used for future checks

	name := cert.Name
	if domain != "" && domain != cert.Name {
		name = cert.Name + " (" + domain + ")"
	}

	return asset.Asset{
		ID:           id,
		Name:         name,
		Type:         "gcp_ssl_certificate",
		Provider:     asset.ProviderGCP,
		Region:       region,
		AccountID:    projectID,
		Domain:       domain,
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}
}
