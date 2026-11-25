package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/servicecatalog"
	sctypes "github.com/aws/aws-sdk-go-v2/service/servicecatalog/types"
	"github.com/stretchr/testify/require"
)

type fakeServiceCatalog struct {
	portfolios *servicecatalog.ListPortfoliosOutput
	listErr    error
	// access maps portfolio id → pages of account ids; a missing id is denied.
	access map[string][][]string
}

func (f *fakeServiceCatalog) ListPortfolios(_ context.Context, _ *servicecatalog.ListPortfoliosInput, _ ...func(*servicecatalog.Options)) (*servicecatalog.ListPortfoliosOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.portfolios, nil
}

func (f *fakeServiceCatalog) ListPortfolioAccess(_ context.Context, in *servicecatalog.ListPortfolioAccessInput, _ ...func(*servicecatalog.Options)) (*servicecatalog.ListPortfolioAccessOutput, error) {
	pages, ok := f.access[awssdk.ToString(in.PortfolioId)]
	if !ok {
		return nil, errors.New("AccessDeniedException")
	}
	if in.OrganizationParentId != nil {
		return nil, errors.New("organization shares must not be read as account shares")
	}
	i := 0
	if in.PageToken != nil {
		i = 1
	}
	out := &servicecatalog.ListPortfolioAccessOutput{AccountIds: pages[i]}
	if i+1 < len(pages) {
		out.NextPageToken = awssdk.String("next")
	}
	return out, nil
}

func scPortfolio(id string) sctypes.PortfolioDetail {
	return sctypes.PortfolioDetail{Id: awssdk.String(id), ARN: awssdk.String("arn:" + id), DisplayName: awssdk.String(id)}
}

func TestReadServiceCatalogPortfolios(t *testing.T) {
	client := &fakeServiceCatalog{
		portfolios: &servicecatalog.ListPortfoliosOutput{PortfolioDetails: []sctypes.PortfolioDetail{
			scPortfolio("shared"), scPortfolio("private"), scPortfolio("denied"),
		}},
		access: map[string][][]string{
			"shared":  {{"333333333333"}, {"222222222222"}},
			"private": {{}},
		},
	}
	got, err := readServiceCatalogPortfolios(context.Background(), client, "us-east-1", "1", time.Now())
	require.NoError(t, err)
	m := indexAssetsByID(got)
	require.Len(t, m, 3)
	require.Equal(t, "222222222222,333333333333", m["arn:shared"].Metadata["account_shares"], "every access page is read")
	v, ok := m["arn:private"].Metadata["account_shares"]
	require.True(t, ok)
	require.Empty(t, v, "no direct share is observed as empty")
	require.NotContains(t, m["arn:denied"].Metadata, "account_shares")

	_, err = readServiceCatalogPortfolios(context.Background(), &fakeServiceCatalog{listErr: errors.New("throttled")}, "us-east-1", "1", time.Now())
	require.Error(t, err)
}
