package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sestypes "github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/stretchr/testify/require"
)

type fakeSES struct {
	pages []*sesv2.ListConfigurationSetsOutput
	calls int
	err   error
	sets  map[string]*sesv2.GetConfigurationSetOutput
}

func (f *fakeSES) ListConfigurationSets(_ context.Context, _ *sesv2.ListConfigurationSetsInput, _ ...func(*sesv2.Options)) (*sesv2.ListConfigurationSetsOutput, error) {
	if f.calls == len(f.pages) {
		return nil, f.err
	}
	p := f.pages[f.calls]
	f.calls++
	return p, nil
}

func (f *fakeSES) GetConfigurationSet(_ context.Context, in *sesv2.GetConfigurationSetInput, _ ...func(*sesv2.Options)) (*sesv2.GetConfigurationSetOutput, error) {
	d, ok := f.sets[awssdk.ToString(in.ConfigurationSetName)]
	if !ok {
		return nil, errors.New("AccessDeniedException")
	}
	return d, nil
}

func TestReadSESConfigurationSets(t *testing.T) {
	client := &fakeSES{
		pages: []*sesv2.ListConfigurationSetsOutput{
			{ConfigurationSets: []string{"strict"}, NextToken: awssdk.String("p2")},
			{ConfigurationSets: []string{"lax", "default", "denied"}},
		},
		sets: map[string]*sesv2.GetConfigurationSetOutput{
			"strict":  {DeliveryOptions: &sestypes.DeliveryOptions{TlsPolicy: sestypes.TlsPolicyRequire}},
			"lax":     {DeliveryOptions: &sestypes.DeliveryOptions{TlsPolicy: sestypes.TlsPolicyOptional}},
			"default": {},
		},
	}
	got, err := readSESConfigurationSets(context.Background(), client, "eu-west-1", "1", time.Now())
	require.NoError(t, err)
	m := indexAssetsByID(got)
	require.Len(t, m, 4)
	arn := func(n string) string { return "arn:aws:ses:eu-west-1:1:configuration-set/" + n }
	require.Equal(t, "REQUIRE", m[arn("strict")].Metadata["tls_policy"])
	require.Equal(t, "OPTIONAL", m[arn("lax")].Metadata["tls_policy"])
	require.Equal(t, "OPTIONAL", m[arn("default")].Metadata["tls_policy"], "no delivery options is SES's OPTIONAL default")
	require.NotContains(t, m[arn("denied")].Metadata, "tls_policy")

	_, err = readSESConfigurationSets(context.Background(), &fakeSES{pages: client.pages[:1], err: errors.New("throttled"), sets: client.sets}, "eu-west-1", "1", time.Now())
	require.Error(t, err)
}
