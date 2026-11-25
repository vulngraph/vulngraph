package aws

import (
	"context"
	"fmt"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	pcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// privateCAType is one AWS Private CA certificate authority (FSBP PCA.1).
const privateCAType = "acmpca_certificate_authority"

type acmPCAAPI interface {
	ListCertificateAuthorities(context.Context, *acmpca.ListCertificateAuthoritiesInput, ...func(*acmpca.Options)) (*acmpca.ListCertificateAuthoritiesOutput, error)
}

func collectPrivateCA(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectPrivateCA: %w", err)
	}
	return readPrivateCAs(ctx, acmpca.NewFromConfig(awsCfg), region, accountID, now)
}

// readPrivateCAs lists the CAs this account owns. The listing carries type and
// status, so there is no per-CA read; a deleted CA (in its restore window) is
// skipped — it issues nothing.
func readPrivateCAs(ctx context.Context, client acmPCAAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out  []asset.Asset
		next *string
	)
	for {
		page, err := client.ListCertificateAuthorities(ctx, &acmpca.ListCertificateAuthoritiesInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("readPrivateCAs: acm-pca:ListCertificateAuthorities: %w", err)
		}
		for _, ca := range page.CertificateAuthorities {
			if ca.Status == pcatypes.CertificateAuthorityStatusDeleted {
				continue
			}
			arn := awssdk.ToString(ca.Arn)
			name := arn
			if c := ca.CertificateAuthorityConfiguration; c != nil && c.Subject != nil && awssdk.ToString(c.Subject.CommonName) != "" {
				name = awssdk.ToString(c.Subject.CommonName)
			}
			out = append(out, asset.Asset{
				ID:        arn,
				Name:      name,
				Type:      privateCAType,
				Provider:  asset.ProviderAWS,
				Region:    region,
				AccountID: accountID,
				Metadata: map[string]string{
					"ca_type":   string(ca.Type),
					"ca_status": string(ca.Status),
				},
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if page.NextToken == nil {
			return out, nil
		}
		next = page.NextToken
	}
}
