package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/servicecatalog"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// serviceCatalogPortfolioType is one Service Catalog portfolio this account
// owns (FSBP ServiceCatalog.1).
const serviceCatalogPortfolioType = "servicecatalog_portfolio"

type serviceCatalogAPI interface {
	ListPortfolios(context.Context, *servicecatalog.ListPortfoliosInput, ...func(*servicecatalog.Options)) (*servicecatalog.ListPortfoliosOutput, error)
	ListPortfolioAccess(context.Context, *servicecatalog.ListPortfolioAccessInput, ...func(*servicecatalog.Options)) (*servicecatalog.ListPortfolioAccessOutput, error)
}

func collectServiceCatalog(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectServiceCatalog: %w", err)
	}
	return readServiceCatalogPortfolios(ctx, servicecatalog.NewFromConfig(awsCfg), region, accountID, now)
}

// readServiceCatalogPortfolios lists the account's own portfolios and, for
// each, the accounts it is shared with directly. ListPortfolioAccess without
// an OrganizationParentId returns exactly the ACCOUNT-type shares — the share
// type ServiceCatalog.1 fails; organization and OU shares are not in it.
// (servicecatalog:DescribePortfolioShares would name the share types directly
// but neither SecurityAudit nor ViewOnlyAccess grants it; List* is granted.)
func readServiceCatalogPortfolios(ctx context.Context, client serviceCatalogAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out     []asset.Asset
		next    *string
		readErr []error
	)
	for {
		page, err := client.ListPortfolios(ctx, &servicecatalog.ListPortfoliosInput{PageToken: next})
		if err != nil {
			return nil, fmt.Errorf("readServiceCatalogPortfolios: servicecatalog:ListPortfolios: %w", err)
		}
		for _, p := range page.PortfolioDetails {
			id := awssdk.ToString(p.Id)
			meta := map[string]string{"portfolio_id": id}
			if accounts, err := portfolioAccountShares(ctx, client, p.Id); err == nil {
				meta["account_shares"] = strings.Join(accounts, ",")
			} else {
				readErr = append(readErr, fmt.Errorf("%s: %w", id, err))
			}
			name := awssdk.ToString(p.DisplayName)
			if name == "" {
				name = id
			}
			out = append(out, asset.Asset{
				ID:           awssdk.ToString(p.ARN),
				Name:         name,
				Type:         serviceCatalogPortfolioType,
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if page.NextPageToken == nil {
			break
		}
		next = page.NextPageToken
	}
	if len(readErr) > 0 {
		log.FromContext(ctx).Warn().Err(errors.Join(readErr...)).Str("region", region).
			Msg("servicecatalog: portfolio access unreadable (check servicecatalog:ListPortfolioAccess); sharing unknown for those portfolios this sweep")
	}
	return out, nil
}

// portfolioAccountShares returns the sorted account IDs a portfolio is shared
// with directly. Any page failing fails the read: a short list would hide a share.
func portfolioAccountShares(ctx context.Context, client serviceCatalogAPI, portfolioID *string) ([]string, error) {
	var (
		accounts []string
		next     *string
	)
	for {
		page, err := client.ListPortfolioAccess(ctx, &servicecatalog.ListPortfolioAccessInput{PortfolioId: portfolioID, PageToken: next})
		if err != nil {
			return nil, fmt.Errorf("servicecatalog:ListPortfolioAccess: %w", err)
		}
		accounts = append(accounts, page.AccountIds...)
		if page.NextPageToken == nil {
			sort.Strings(accounts)
			return accounts, nil
		}
		next = page.NextPageToken
	}
}
