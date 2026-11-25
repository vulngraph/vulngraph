package aws

import (
	"context"
	"fmt"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/stretchr/testify/require"
)

// expiring_soon must be an observation on BOTH outcomes. Writing it only when
// true made "this certificate has months left" identical to "this certificate
// has no expiry date we could read", and acm-cert-expiring-soon reads exactly
// this key — so its silence was scored as a pass in both cases.
func TestACMDetailAsset_ExpiringSoonIsRecordedOnBothOutcomes(t *testing.T) {
	now := time.Now()
	far := now.Add(200 * 24 * time.Hour)
	a := acmDetailAsset("arn:far", &acmtypes.CertificateDetail{
		DomainName: awssdk.String("far.example.com"),
		NotAfter:   &far,
	}, "eu-west-1", "123456789012", now)
	require.Equal(t, "false", a.Metadata["expiring_soon"],
		"a certificate with 200 days left WAS observed, and must say so")

	soon := now.Add(5 * 24 * time.Hour)
	b := acmDetailAsset("arn:soon", &acmtypes.CertificateDetail{
		DomainName: awssdk.String("soon.example.com"),
		NotAfter:   &soon,
	}, "eu-west-1", "123456789012", now)
	require.Equal(t, "true", b.Metadata["expiring_soon"])
}

// A certificate with no NotAfter — PENDING_VALIDATION or FAILED — carries no
// key at all, so an absent key means "unknown" and nothing else.
func TestACMDetailAsset_NoExpiryDateOmitsTheKey(t *testing.T) {
	a := acmDetailAsset("arn:pending", &acmtypes.CertificateDetail{
		DomainName: awssdk.String("pending.example.com"),
		Status:     acmtypes.CertificateStatusPendingValidation,
	}, "eu-west-1", "123456789012", time.Now())
	require.NotContains(t, a.Metadata, "expiring_soon")
	require.NotContains(t, a.Metadata, "days_until_expiry")
}

// acmFake lists certificates and describes only those in `described`; any other
// describe is refused the way a role without acm:DescribeCertificate refuses it.
type acmFake struct {
	arns      []string
	described map[string]time.Time
}

func (f acmFake) ListCertificates(context.Context, *acm.ListCertificatesInput, ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
	out := &acm.ListCertificatesOutput{}
	for _, arn := range f.arns {
		out.CertificateSummaryList = append(out.CertificateSummaryList, acmtypes.CertificateSummary{
			CertificateArn: awssdk.String(arn),
			DomainName:     awssdk.String(arn + ".example.com"),
			Status:         acmtypes.CertificateStatusIssued,
		})
	}
	return out, nil
}

func (f acmFake) DescribeCertificate(_ context.Context, in *acm.DescribeCertificateInput, _ ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
	arn := awssdk.ToString(in.CertificateArn)
	notAfter, ok := f.described[arn]
	if !ok {
		return nil, fmt.Errorf("AccessDeniedException: not authorized to perform acm:DescribeCertificate")
	}
	return &acm.DescribeCertificateOutput{Certificate: &acmtypes.CertificateDetail{
		DomainName: awssdk.String(arn + ".example.com"),
		NotAfter:   &notAfter,
	}}, nil
}

var _ acmAPI = acmFake{}

// A certificate whose detail could not be read still becomes an asset, but must
// carry NO expiry metadata — so the check sees missing data rather than a clean
// result. This is the other half of the same gap: the describe-failure
// path produces a summary-only asset, and did so without a word in the logs.
func TestCollectACMCerts_UndescribedCertificateCarriesNoExpiry(t *testing.T) {
	now := time.Now()
	assets, err := collectACMCerts(context.Background(), acmFake{
		arns:      []string{"arn:ok", "arn:denied"},
		described: map[string]time.Time{"arn:ok": now.Add(200 * 24 * time.Hour)},
	}, "eu-west-1", "123456789012", now)
	require.NoError(t, err)
	require.Len(t, assets, 2)

	byID := map[string]map[string]string{}
	for _, a := range assets {
		byID[a.ID] = a.Metadata
	}
	require.Equal(t, "false", byID["arn:ok"]["expiring_soon"])
	require.NotContains(t, byID["arn:denied"], "expiring_soon",
		"a certificate the collector could not describe must not read as 'not expiring soon'")
}
