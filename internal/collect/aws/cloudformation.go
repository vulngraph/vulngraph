package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// cloudFormationStackType is one CloudFormation stack (FSBP CloudFormation.3/.4).
const cloudFormationStackType = "cloudformation_stack"

type cloudFormationAPI interface {
	DescribeStacks(context.Context, *cloudformation.DescribeStacksInput, ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
}

func collectCloudFormation(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectCloudFormation: %w", err)
	}
	return readCloudFormationStacks(ctx, cloudformation.NewFromConfig(awsCfg), region, accountID, now)
}

// readCloudFormationStacks lists every live stack. DescribeStacks without a
// stack name returns every stack except deleted ones (DELETE_COMPLETE is
// skipped defensively all the same) with RoleARN, but it may leave out
// EnableTerminationProtection — AWS returns that only when one stack is
// described — so a root stack listed without it is described on its own
// (stackTerminationProtection).
func readCloudFormationStacks(ctx context.Context, client cloudFormationAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out  []asset.Asset
		next *string
	)
	for {
		page, err := client.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("readCloudFormationStacks: cloudformation:DescribeStacks: %w", err)
		}
		for _, s := range page.Stacks {
			if s.StackStatus == cfntypes.StackStatusDeleteComplete {
				continue
			}
			meta := map[string]string{
				"stack_status": string(s.StackStatus),
				// A nested stack (ParentId set) takes termination protection and
				// its service role from the root stack; checks grade the root.
				"nested":    strconv.FormatBool(awssdk.ToString(s.ParentId) != ""),
				"role_arn":  awssdk.ToString(s.RoleARN),
				"parent_id": awssdk.ToString(s.ParentId),
				// StackSets name every stack instance "StackSet-<set>-<id>" and
				// deploy it through the StackSet execution role, never the
				// caller's credentials — the role CloudFormation.4 asks for.
				"stackset_instance": strconv.FormatBool(strings.HasPrefix(awssdk.ToString(s.StackName), "StackSet-")),
			}
			if s.EnableTerminationProtection != nil {
				meta["termination_protection"] = strconv.FormatBool(*s.EnableTerminationProtection)
			}
			out = append(out, asset.Asset{
				ID:           awssdk.ToString(s.StackId),
				Name:         awssdk.ToString(s.StackName),
				Type:         cloudFormationStackType,
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if page.NextToken == nil {
			stackTerminationProtection(ctx, client, region, out)
			return out, nil
		}
		next = page.NextToken
	}
}

// cfnDescribeConcurrency bounds the per-stack describes.
const cfnDescribeConcurrency = 4

// stackTerminationProtection fills termination_protection on every root stack
// the listing left it off, with one bounded DescribeStacks per stack. A
// failed describe leaves the key absent (unknown).
func stackTerminationProtection(ctx context.Context, client cloudFormationAPI, region string, stacks []asset.Asset) {
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		failed int
		sem    = make(chan struct{}, cfnDescribeConcurrency)
	)
	for i := range stacks {
		m := stacks[i].Metadata
		if _, ok := m["termination_protection"]; ok || m["nested"] != "false" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(id string, meta map[string]string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					log.FromContext(ctx).Error().Interface("panic", rec).Str("stack", id).Msg("cloudformation: stack describe panicked")
				}
			}()
			out, err := client.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: &id})
			mu.Lock()
			defer mu.Unlock()
			if err != nil || len(out.Stacks) != 1 || out.Stacks[0].EnableTerminationProtection == nil {
				failed++
				return
			}
			meta["termination_protection"] = strconv.FormatBool(*out.Stacks[0].EnableTerminationProtection)
		}(stacks[i].ID, m)
	}
	wg.Wait()
	if failed > 0 {
		log.FromContext(ctx).Warn().Str("region", region).Int("stacks", failed).
			Msg("cloudformation: termination protection unread for some stacks (check cloudformation:DescribeStacks); unknown this sweep")
	}
}
