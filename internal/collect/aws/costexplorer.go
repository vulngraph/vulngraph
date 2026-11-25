package aws

import (
	"context"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"
)

// CostEntry is one (service, date, cost) triple returned by the Cost Explorer API.
type CostEntry struct {
	Service string
	CostUSD float64
	Date    time.Time
}

// ceAPI is the slice of the Cost Explorer SDK the collector uses.
type ceAPI interface {
	GetCostAndUsage(context.Context, *costexplorer.GetCostAndUsageInput, ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error)
}

// FetchCostByService queries AWS Cost Explorer for daily UnblendedCost grouped
// by SERVICE for the last N days. Only "Usage" record types are included so
// credits, refunds, and taxes do not distort the numbers.
func FetchCostByService(ctx context.Context, cfg awssdk.Config, days int) ([]CostEntry, error) {
	if days < 1 {
		days = 7
	}

	now := time.Now().UTC()
	start := now.AddDate(0, 0, -days).Format("2006-01-02")
	end := now.Format("2006-01-02")

	client := costexplorer.NewFromConfig(cfg)
	return fetchCostByService(ctx, client, start, end)
}

func fetchCostByService(ctx context.Context, client ceAPI, start, end string) ([]CostEntry, error) {
	input := &costexplorer.GetCostAndUsageInput{
		TimePeriod: &cetypes.DateInterval{
			Start: awssdk.String(start),
			End:   awssdk.String(end),
		},
		Granularity: cetypes.GranularityDaily,
		GroupBy: []cetypes.GroupDefinition{
			{Type: cetypes.GroupDefinitionTypeDimension, Key: awssdk.String("SERVICE")},
		},
		Metrics: []string{"UnblendedCost"},
		Filter: &cetypes.Expression{
			Dimensions: &cetypes.DimensionValues{
				Key:    cetypes.DimensionRecordType,
				Values: []string{"Usage"},
			},
		},
	}

	var entries []CostEntry
	// Paginate: SERVICE × daily can exceed one page, and results past page 1
	// would otherwise be silently dropped from the cost totals.
	for {
		out, err := client.GetCostAndUsage(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("FetchCostByService: GetCostAndUsage: %w", err)
		}
		for _, result := range out.ResultsByTime {
			if result.TimePeriod == nil {
				continue
			}
			date, err := time.Parse("2006-01-02", awssdk.ToString(result.TimePeriod.Start))
			if err != nil {
				return nil, fmt.Errorf("FetchCostByService: parse date %q: %w", awssdk.ToString(result.TimePeriod.Start), err)
			}
			for _, group := range result.Groups {
				if len(group.Keys) == 0 {
					continue
				}
				service := group.Keys[0]
				metric, ok := group.Metrics["UnblendedCost"]
				if !ok || metric.Amount == nil {
					continue
				}
				amount, err := strconv.ParseFloat(awssdk.ToString(metric.Amount), 64)
				if err != nil {
					return nil, fmt.Errorf("FetchCostByService: parse amount for %q: %w", service, err)
				}
				entries = append(entries, CostEntry{
					Service: service,
					CostUSD: amount,
					Date:    date,
				})
			}
		}
		if out.NextPageToken == nil || *out.NextPageToken == "" {
			break
		}
		input.NextPageToken = out.NextPageToken
	}
	return entries, nil
}
