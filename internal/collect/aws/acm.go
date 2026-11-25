package aws

import (
	"context"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// collectACM lists all ACM certificates in a region and maps them to assets.
// Certificates are a key security surface: expiry, mis-issuance, and weak
// domain coverage all show up here before they become incidents.
func collectACM(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectACM: %w", err)
	}
	return collectACMCerts(ctx, acm.NewFromConfig(awsCfg), region, accountID, now)
}

type acmAPI interface {
	ListCertificates(context.Context, *acm.ListCertificatesInput, ...func(*acm.Options)) (*acm.ListCertificatesOutput, error)
	DescribeCertificate(context.Context, *acm.DescribeCertificateInput, ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
}

func collectACMCerts(ctx context.Context, client acmAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		assets      []asset.Asset
		nextToken   *string
		undescribed int
	)
	for {
		out, err := client.ListCertificates(ctx, &acm.ListCertificatesInput{
			NextToken: nextToken,
			// Include all statuses — expired certs are still important to track.
			// KeyTypes must be listed: without it ListCertificates returns only
			// RSA_2048 certificates, hiding exactly the RSA_1024 ones the
			// key-length check exists for (and every EC certificate).
			Includes: &acmtypes.Filters{
				KeyUsage: []acmtypes.KeyUsageName{
					acmtypes.KeyUsageNameDigitalSignature,
					acmtypes.KeyUsageNameKeyEncipherment,
				},
				KeyTypes: acmtypes.KeyAlgorithm("").Values(),
			},
		})
		if err != nil {
			return nil, fmt.Errorf("collectACMCerts: list: %w", err)
		}
		for _, summary := range out.CertificateSummaryList {
			arn := awssdk.ToString(summary.CertificateArn)

			// Describe gives expiry, issuer, SANs — worth one extra call per cert
			// since the list only gives domain + status.
			desc, err := client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
				CertificateArn: summary.CertificateArn,
			})
			if err != nil {
				// Best-effort: a describe failure still yields an asset, from the
				// list summary alone — but that asset carries NO expiry metadata,
				// so acm-cert-expiring-soon silently passes on it. Counted and
				// reported below rather than skipped quietly: a role without
				// acm:DescribeCertificate would otherwise look exactly like an
				// estate whose certificates all have plenty of time left.
				undescribed++
				a := acmSummaryAsset(arn, summary, region, accountID, now)
				assets = append(assets, a)
				continue
			}
			a := acmDetailAsset(arn, desc.Certificate, region, accountID, now)
			assets = append(assets, a)
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	if undescribed > 0 {
		log.FromContext(ctx).Warn().Int("undescribed", undescribed).Int("certificates", len(assets)).
			Str("region", region).
			Msg("acm: certificate detail unreadable; expiry metadata omitted (check the collector role's acm:DescribeCertificate)")
	}
	return assets, nil
}

// acmDetailAsset maps a fully-described ACM certificate to an asset.
func acmDetailAsset(arn string, cert *acmtypes.CertificateDetail, region, accountID string, now time.Time) asset.Asset {
	if cert == nil {
		return asset.Asset{ID: arn, Type: "acm_certificate", Provider: asset.ProviderAWS, Region: region, AccountID: accountID, DiscoveredAt: now, LastSeen: now}
	}

	domain := awssdk.ToString(cert.DomainName)
	name := domain
	if name == "" {
		name = arn
	}

	meta := map[string]string{
		"status": string(cert.Status),
		"type":   string(cert.Type),
		"source": "acm",
	}
	if cert.Issuer != nil {
		meta["issuer"] = awssdk.ToString(cert.Issuer)
	}
	if cert.Subject != nil {
		meta["subject"] = awssdk.ToString(cert.Subject)
	}
	if cert.KeyAlgorithm != "" {
		meta["key_algorithm"] = string(cert.KeyAlgorithm)
	}
	sans := cert.SubjectAlternativeNames
	if len(sans) > 0 {
		meta["san"] = strings.Join(sans, ",")
	}

	var expiryDays int
	if cert.NotAfter != nil {
		meta["expires_at"] = cert.NotAfter.UTC().Format(time.RFC3339)
		expiryDays = int(time.Until(*cert.NotAfter).Hours() / 24)
		meta["days_until_expiry"] = fmt.Sprintf("%d", expiryDays)
		// Written on BOTH outcomes. Writing it only when true would make "this
		// certificate has months left" identical to "this certificate has no
		// expiry date we could read" — and acm-cert-expiring-soon reads exactly
		// this key, so it would pass on both. Absent means only that NotAfter was
		// unavailable (a PENDING_VALIDATION or FAILED certificate has none), which
		// is genuinely unknown rather than fine.
		meta["expiring_soon"] = fmt.Sprintf("%t", expiryDays <= 30)
	}
	if cert.IssuedAt != nil {
		meta["issued_at"] = cert.IssuedAt.UTC().Format(time.RFC3339)
	}
	if cert.RenewalEligibility != "" {
		meta["renewal_eligibility"] = string(cert.RenewalEligibility)
	}
	if len(cert.InUseBy) > 0 {
		meta["in_use_by"] = strings.Join(cert.InUseBy, ",")
	}

	return asset.Asset{
		ID:           arn,
		Name:         name,
		Type:         "acm_certificate",
		Provider:     asset.ProviderAWS,
		Region:       region,
		AccountID:    accountID,
		Domain:       domain,
		Tags:         map[string]string{},
		Metadata:     meta,
		DiscoveredAt: now,
		LastSeen:     now,
	}
}

// acmSummaryAsset is used when DescribeCertificate fails — builds from the list summary only.
func acmSummaryAsset(arn string, s acmtypes.CertificateSummary, region, accountID string, now time.Time) asset.Asset {
	domain := awssdk.ToString(s.DomainName)
	return asset.Asset{
		ID:           arn,
		Name:         domain,
		Type:         "acm_certificate",
		Provider:     asset.ProviderAWS,
		Region:       region,
		AccountID:    accountID,
		Domain:       domain,
		Metadata:     map[string]string{"status": string(s.Status), "source": "acm"},
		DiscoveredAt: now,
		LastSeen:     now,
	}
}
