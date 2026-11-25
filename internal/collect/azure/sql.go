package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// collectSQL pulls Azure SQL Servers and their databases. SQL servers with a
// public network access policy of "Enabled" are flagged public=true.
func collectSQL(ctx context.Context, cred azcore.TokenCredential, subscriptionID string, now time.Time) ([]asset.Asset, []asset.Edge, error) {
	serverClient, err := armsql.NewServersClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, nil, fmt.Errorf("collectSQL: server client: %w", err)
	}
	dbClient, err := armsql.NewDatabasesClient(subscriptionID, cred, readOnlyARM())
	if err != nil {
		return nil, nil, fmt.Errorf("collectSQL: db client: %w", err)
	}

	var assets []asset.Asset
	var edges []asset.Edge

	pager := serverClient.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("collectSQL: list servers: %w", err)
		}
		for _, srv := range page.Value {
			if srv.ID == nil {
				continue
			}
			fqdn := ""
			if srv.Properties != nil {
				fqdn = strVal(srv.Properties.FullyQualifiedDomainName)
			}
			srvAsset := asset.Asset{
				ID:           *srv.ID,
				Name:         strVal(srv.Name),
				Type:         "azure_sql_server",
				Provider:     asset.ProviderAzure,
				Region:       strVal(srv.Location),
				AccountID:    subscriptionID,
				Domain:       fqdn,
				Endpoint:     httpsURL(fqdn),
				Tags:         azTags(srv.Tags),
				Metadata:     sqlServerExposure(srv),
				DiscoveredAt: now,
				LastSeen:     now,
			}
			assets = append(assets, srvAsset)

			// Databases (best-effort — a permission error on one server skips its DBs).
			// This break swallows the page error instead of propagating it, so a nil
			// error from collectSQL as a whole does NOT prove every server's database
			// list was read completely. azure.go's collectAll therefore claims
			// completeness for azure_sql_server only, never azure_sql_database.
			rg := resourceGroup(*srv.ID)
			dbPager := dbClient.NewListByServerPager(rg, strVal(srv.Name), nil)
			for dbPager.More() {
				dbPage, err := dbPager.NextPage(ctx)
				if err != nil {
					break
				}
				for _, db := range dbPage.Value {
					if db.ID == nil {
						continue
					}
					assets = append(assets, asset.Asset{
						ID:        *db.ID,
						Name:      strVal(db.Name),
						Type:      "azure_sql_database",
						Provider:  asset.ProviderAzure,
						Region:    strVal(db.Location),
						AccountID: subscriptionID,
						Metadata: map[string]string{
							"sku": dbSKU(db),
						},
						DiscoveredAt: now,
						LastSeen:     now,
					})
					edges = append(edges, asset.Edge{
						SrcID: *db.ID, SrcType: "azure_sql_database",
						DstID: *srv.ID, DstType: "azure_sql_server",
						EdgeType: "runs_in",
					})
				}
			}
		}
	}
	return assets, edges, nil
}

// sqlServerExposure writes the server's version and public exposure. The
// public-network toggle is reachability only — server firewall rules and
// SQL/AAD auth still gate access, so exposure is possible, never confirmed. A
// server returned without properties has no observed exposure: "public" is
// left out and the tier is unknown.
func sqlServerExposure(srv *armsql.Server) map[string]string {
	meta := map[string]string{"version": sqlVersion(srv)}
	if srv.Properties == nil {
		meta["public_access"] = publicAccessUnknown
		return meta
	}
	isPublic := srv.Properties.PublicNetworkAccess == nil ||
		*srv.Properties.PublicNetworkAccess == armsql.ServerNetworkAccessFlagEnabled
	meta["public"] = boolStr(isPublic)
	meta["public_access"] = publicPossibleIf(isPublic)
	return meta
}

func sqlVersion(srv *armsql.Server) string {
	if srv.Properties == nil || srv.Properties.Version == nil {
		return ""
	}
	return *srv.Properties.Version
}

func dbSKU(db *armsql.Database) string {
	if db.SKU == nil || db.SKU.Name == nil {
		return ""
	}
	return *db.SKU.Name
}
