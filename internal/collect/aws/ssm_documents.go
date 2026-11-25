package aws

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Systems Manager documents the account owns, and whether each is shared with
// every AWS account (AWS FSBP SSM.4): DescribeDocumentPermission lists the
// accounts a document is shared with, and the literal "all" means public.
// Plus the two regional SSM service settings FSBP grades (SSM.6, SSM.7), read
// onto aws_region_settings by readRegionSettings.

const ssmDocumentType = "ssm_document"

// ssmDocumentConcurrency bounds DescribeDocumentPermission calls.
const ssmDocumentConcurrency = 4

// ssmPublicShareAccount is the AccountIds entry meaning "shared with everyone".
const ssmPublicShareAccount = "all"

// SSM service settings read per region.
const (
	ssmSettingPublicSharing   = "/ssm/documents/console/public-sharing-permission"
	ssmSettingAutomationLogTo = "/ssm/automation/customer-script-log-destination"
)

type ssmDocumentsAPI interface {
	ListDocuments(context.Context, *ssm.ListDocumentsInput, ...func(*ssm.Options)) (*ssm.ListDocumentsOutput, error)
	DescribeDocumentPermission(context.Context, *ssm.DescribeDocumentPermissionInput, ...func(*ssm.Options)) (*ssm.DescribeDocumentPermissionOutput, error)
}

type ssmServiceSettingsAPI interface {
	GetServiceSetting(context.Context, *ssm.GetServiceSettingInput, ...func(*ssm.Options)) (*ssm.GetServiceSettingOutput, error)
}

func collectSSMDocuments(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectSSMDocuments: %w", err)
	}
	return readSSMDocuments(ctx, ssm.NewFromConfig(awsCfg), region, accountID, now)
}

func readSSMDocuments(ctx context.Context, client ssmDocumentsAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	docs, err := listOwnedDocuments(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("readSSMDocuments: %w", err)
	}
	assets := make([]asset.Asset, len(docs))
	var (
		mu     sync.Mutex
		failed int
		last   error
	)
	_ = forEachBounded(len(docs), ssmDocumentConcurrency, func(i int) error {
		a, err := ssmDocumentAsset(ctx, client, docs[i], region, accountID, now)
		assets[i] = a
		if err != nil {
			mu.Lock()
			failed++
			last = err
			mu.Unlock()
		}
		return nil
	})
	if failed > 0 {
		log.FromContext(ctx).Warn().Err(last).Str("region", region).Int("failed", failed).
			Msg("ssm document permission read failed; those documents' sharing is unknown this sweep")
	}
	return assets, nil
}

// listOwnedDocuments lists the documents this account owns (Owner=Self): only
// those can be shared by it, and AWS- or third-party-owned documents are
// public by design.
func listOwnedDocuments(ctx context.Context, client ssmDocumentsAPI) ([]ssmtypes.DocumentIdentifier, error) {
	var (
		out   []ssmtypes.DocumentIdentifier
		token *string
	)
	for {
		page, err := client.ListDocuments(ctx, &ssm.ListDocumentsInput{
			Filters:   []ssmtypes.DocumentKeyValuesFilter{{Key: awssdk.String("Owner"), Values: []string{"Self"}}},
			NextToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("listOwnedDocuments: %w", err)
		}
		for _, d := range page.DocumentIdentifiers {
			if awssdk.ToString(d.Name) != "" {
				out = append(out, d)
			}
		}
		if page.NextToken == nil {
			return out, nil
		}
		token = page.NextToken
	}
}

// ssmDocumentAsset builds the document's asset; publicly_shared and
// shared_account_count are written only when every permission page was read.
func ssmDocumentAsset(ctx context.Context, client ssmDocumentsAPI, d ssmtypes.DocumentIdentifier, region, accountID string, now time.Time) (asset.Asset, error) {
	name := awssdk.ToString(d.Name)
	a := asset.Asset{
		ID:        "arn:" + partitionFor(region) + ":ssm:" + region + ":" + accountID + ":document/" + name,
		Name:      name,
		Type:      ssmDocumentType,
		Provider:  asset.ProviderAWS,
		Region:    region,
		AccountID: accountID,
		Metadata: map[string]string{
			"document_type": string(d.DocumentType),
		},
		DiscoveredAt: now,
		LastSeen:     now,
	}
	var (
		accounts []string
		token    *string
	)
	for {
		out, err := client.DescribeDocumentPermission(ctx, &ssm.DescribeDocumentPermissionInput{
			Name: d.Name, PermissionType: ssmtypes.DocumentPermissionTypeShare, NextToken: token,
		})
		if err != nil {
			return a, fmt.Errorf("ssmDocumentAsset %s: %w", name, err)
		}
		accounts = append(accounts, out.AccountIds...)
		if out.NextToken == nil {
			break
		}
		token = out.NextToken
	}
	public := slices.ContainsFunc(accounts, func(id string) bool { return strings.EqualFold(strings.TrimSpace(id), ssmPublicShareAccount) })
	a.Metadata["publicly_shared"] = strconv.FormatBool(public)
	a.Metadata["shared_account_count"] = strconv.Itoa(len(accounts))
	if public {
		a.Metadata["public_access"] = asset.PublicAccessConfirmed
	}
	return a, nil
}

// ssmServiceSettingsReader is readRegionSettings' extra reader for the two SSM
// service settings: the keys it read and the reads that failed. A setting AWS
// reports as not provisioned (ServiceSettingNotFound) is unknown, not a
// default, so its key stays absent like any other failed read.
func ssmServiceSettingsReader(client ssmServiceSettingsAPI) func(context.Context) (map[string]string, []error) {
	return func(ctx context.Context) (map[string]string, []error) {
		meta := map[string]string{}
		var errs []error
		for key, id := range map[string]string{
			"ssm_document_public_sharing":    ssmSettingPublicSharing,
			"ssm_automation_log_destination": ssmSettingAutomationLogTo,
		} {
			out, err := client.GetServiceSetting(ctx, &ssm.GetServiceSettingInput{SettingId: awssdk.String(id)})
			if err != nil || out == nil || out.ServiceSetting == nil || out.ServiceSetting.SettingValue == nil {
				errs = append(errs, fmt.Errorf("GetServiceSetting %s: %w", id, orEmpty(err)))
				continue
			}
			meta[key] = awssdk.ToString(out.ServiceSetting.SettingValue)
		}
		return meta, errs
	}
}
