package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	pcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	"github.com/stretchr/testify/require"
)

type fakeACMPCA struct {
	pages []*acmpca.ListCertificateAuthoritiesOutput
	calls int
	err   error
}

func (f *fakeACMPCA) ListCertificateAuthorities(_ context.Context, _ *acmpca.ListCertificateAuthoritiesInput, _ ...func(*acmpca.Options)) (*acmpca.ListCertificateAuthoritiesOutput, error) {
	if f.calls == len(f.pages) {
		return nil, f.err
	}
	p := f.pages[f.calls]
	f.calls++
	return p, nil
}

func TestReadPrivateCAs(t *testing.T) {
	client := &fakeACMPCA{pages: []*acmpca.ListCertificateAuthoritiesOutput{
		{CertificateAuthorities: []pcatypes.CertificateAuthority{
			{Arn: awssdk.String("arn:root"), Type: pcatypes.CertificateAuthorityTypeRoot, Status: pcatypes.CertificateAuthorityStatusActive,
				CertificateAuthorityConfiguration: &pcatypes.CertificateAuthorityConfiguration{Subject: &pcatypes.ASN1Subject{CommonName: awssdk.String("Corp Root")}}},
			{Arn: awssdk.String("arn:deleted"), Type: pcatypes.CertificateAuthorityTypeRoot, Status: pcatypes.CertificateAuthorityStatusDeleted},
		}, NextToken: awssdk.String("p2")},
		{CertificateAuthorities: []pcatypes.CertificateAuthority{
			{Arn: awssdk.String("arn:sub"), Type: pcatypes.CertificateAuthorityTypeSubordinate, Status: pcatypes.CertificateAuthorityStatusActive},
		}},
	}}
	got, err := readPrivateCAs(context.Background(), client, "us-east-1", "1", time.Now())
	require.NoError(t, err)
	m := indexAssetsByID(got)
	require.Len(t, m, 2, "a deleted CA is not emitted")
	require.Equal(t, "ROOT", m["arn:root"].Metadata["ca_type"])
	require.Equal(t, "ACTIVE", m["arn:root"].Metadata["ca_status"])
	require.Equal(t, "Corp Root", m["arn:root"].Name)
	require.Equal(t, "SUBORDINATE", m["arn:sub"].Metadata["ca_type"])

	_, err = readPrivateCAs(context.Background(), &fakeACMPCA{pages: client.pages[:1], err: errors.New("throttled")}, "us-east-1", "1", time.Now())
	require.Error(t, err)
}
