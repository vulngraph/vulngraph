package aws

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// AWS WAF (v2) web ACLs and rule groups (AWS FSBP WAF.10, WAF.12). REGIONAL
// scope is read in every region; CLOUDFRONT scope exists only in the
// partition's home region and is read once, from the global phase.

const (
	wafWebACLType    = "waf_web_acl"
	wafRuleGroupType = "waf_rule_group"
	// wafConcurrency bounds the per-ACL / per-rule-group Get fan-out.
	wafConcurrency = 4
)

type wafv2API interface {
	ListWebACLs(context.Context, *wafv2.ListWebACLsInput, ...func(*wafv2.Options)) (*wafv2.ListWebACLsOutput, error)
	GetWebACL(context.Context, *wafv2.GetWebACLInput, ...func(*wafv2.Options)) (*wafv2.GetWebACLOutput, error)
	ListRuleGroups(context.Context, *wafv2.ListRuleGroupsInput, ...func(*wafv2.Options)) (*wafv2.ListRuleGroupsOutput, error)
	GetRuleGroup(context.Context, *wafv2.GetRuleGroupInput, ...func(*wafv2.Options)) (*wafv2.GetRuleGroupOutput, error)
}

func collectWAFv2Regional(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectWAFv2Regional: %w", err)
	}
	return readWAFv2(ctx, wafv2.NewFromConfig(awsCfg), wafv2types.ScopeRegional, region, accountID, now)
}

func collectWAFv2CloudFront(ctx context.Context, cfg map[string]string, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectWAFv2CloudFront: %w", err)
	}
	if !cloudFrontPartition(awsCfg.Region) {
		return nil, nil
	}
	awsCfg.Region = globalRegionFor(awsCfg.Region)
	return readWAFv2(ctx, wafv2.NewFromConfig(awsCfg), wafv2types.ScopeCloudfront, "global", accountID, now)
}

// wafv2Summary is one listed web ACL or rule group.
type wafv2Summary struct{ arn, id, name string }

// listWAFv2 pages a wafv2 listing to the end. WAF returns a NextMarker only
// while more items remain; an empty page also ends the listing.
func listWAFv2(ctx context.Context, page func(*string) ([]wafv2Summary, *string, error)) ([]wafv2Summary, error) {
	var (
		out    []wafv2Summary
		marker *string
	)
	for {
		items, next, err := page(marker)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		if awssdk.ToString(next) == "" || len(items) == 0 {
			return out, nil
		}
		marker = next
	}
}

func readWAFv2(ctx context.Context, client wafv2API, scope wafv2types.Scope, region, accountID string, now time.Time) ([]asset.Asset, error) {
	acls, err := listWAFv2(ctx, func(m *string) ([]wafv2Summary, *string, error) {
		out, err := client.ListWebACLs(ctx, &wafv2.ListWebACLsInput{Scope: scope, NextMarker: m})
		if err != nil {
			return nil, nil, err
		}
		items := make([]wafv2Summary, 0, len(out.WebACLs))
		for _, w := range out.WebACLs {
			items = append(items, wafv2Summary{awssdk.ToString(w.ARN), awssdk.ToString(w.Id), awssdk.ToString(w.Name)})
		}
		return items, out.NextMarker, nil
	})
	if err != nil {
		return nil, fmt.Errorf("readWAFv2: ListWebACLs %s: %w", scope, err)
	}
	groups, err := listWAFv2(ctx, func(m *string) ([]wafv2Summary, *string, error) {
		out, err := client.ListRuleGroups(ctx, &wafv2.ListRuleGroupsInput{Scope: scope, NextMarker: m})
		if err != nil {
			return nil, nil, err
		}
		items := make([]wafv2Summary, 0, len(out.RuleGroups))
		for _, g := range out.RuleGroups {
			items = append(items, wafv2Summary{awssdk.ToString(g.ARN), awssdk.ToString(g.Id), awssdk.ToString(g.Name)})
		}
		return items, out.NextMarker, nil
	})
	if err != nil {
		return nil, fmt.Errorf("readWAFv2: ListRuleGroups %s: %w", scope, err)
	}

	assets := make([]asset.Asset, 0, len(acls)+len(groups))
	for _, s := range acls {
		assets = append(assets, wafAsset(s.arn, s.name, wafWebACLType, string(scope), false, region, accountID, now))
	}
	for _, s := range groups {
		assets = append(assets, wafAsset(s.arn, s.name, wafRuleGroupType, string(scope), false, region, accountID, now))
	}
	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		sem = make(chan struct{}, wafConcurrency)
	)
	for i := range assets {
		wg.Add(1)
		sem <- struct{}{}
		go func(a *asset.Asset, s wafv2Summary) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					log.FromContext(ctx).Error().Interface("panic", rec).Str("waf_resource", s.arn).Msg("wafv2 read panicked")
				}
			}()
			rules, err := wafv2Rules(ctx, client, a.Type, scope, s)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// Rule count and metrics stay absent: an unread ACL is unknown, not empty.
				log.FromContext(ctx).Warn().Err(err).Str("waf_resource", s.arn).Msg("wafv2 rule read failed; its rule checks cannot evaluate it this sweep")
				return
			}
			stampWAFv2Rules(a.Metadata, rules)
		}(&assets[i], summaryAt(acls, groups, i))
	}
	wg.Wait()
	return assets, nil
}

func summaryAt(acls, groups []wafv2Summary, i int) wafv2Summary {
	if i < len(acls) {
		return acls[i]
	}
	return groups[i-len(acls)]
}

// wafv2RuleSet is what a web ACL or rule group evaluates: its own rules and,
// for a web ACL, the Firewall Manager rule groups wrapped around them.
type wafv2RuleSet struct {
	rules   []wafv2types.Rule
	fmsRule []wafv2types.FirewallManagerRuleGroup
}

func wafv2Rules(ctx context.Context, client wafv2API, typ string, scope wafv2types.Scope, s wafv2Summary) (wafv2RuleSet, error) {
	if typ == wafWebACLType {
		out, err := client.GetWebACL(ctx, &wafv2.GetWebACLInput{Id: awssdk.String(s.id), Name: awssdk.String(s.name), Scope: scope})
		if err != nil {
			return wafv2RuleSet{}, fmt.Errorf("GetWebACL: %w", err)
		}
		if out.WebACL == nil {
			return wafv2RuleSet{}, fmt.Errorf("GetWebACL: %w", errEmptyResponse)
		}
		w := out.WebACL
		return wafv2RuleSet{rules: w.Rules, fmsRule: append(append([]wafv2types.FirewallManagerRuleGroup(nil), w.PreProcessFirewallManagerRuleGroups...), w.PostProcessFirewallManagerRuleGroups...)}, nil
	}
	out, err := client.GetRuleGroup(ctx, &wafv2.GetRuleGroupInput{Id: awssdk.String(s.id), Name: awssdk.String(s.name), Scope: scope})
	if err != nil {
		return wafv2RuleSet{}, fmt.Errorf("GetRuleGroup: %w", err)
	}
	if out.RuleGroup == nil {
		return wafv2RuleSet{}, fmt.Errorf("GetRuleGroup: %w", errEmptyResponse)
	}
	return wafv2RuleSet{rules: out.RuleGroup.Rules}, nil
}

// stampWAFv2Rules records rule_count (WAF.10) and rules_without_metrics
// (WAF.12): the rules whose visibility config publishes no CloudWatch metric.
// A rule with no visibility config at all publishes none either.
func stampWAFv2Rules(meta map[string]string, rs wafv2RuleSet) {
	meta["rule_count"] = strconv.Itoa(len(rs.rules) + len(rs.fmsRule))
	var dark []string
	for _, r := range rs.rules {
		if r.VisibilityConfig == nil || !r.VisibilityConfig.CloudWatchMetricsEnabled {
			dark = append(dark, awssdk.ToString(r.Name))
		}
	}
	for _, r := range rs.fmsRule {
		if r.VisibilityConfig == nil || !r.VisibilityConfig.CloudWatchMetricsEnabled {
			dark = append(dark, awssdk.ToString(r.Name))
		}
	}
	meta["rules_without_metrics"] = strings.Join(dark, ",")
}

// wafAsset is the shared shape of every WAF asset, v2 and Classic.
func wafAsset(arn, name, typ, scope string, classic bool, region, accountID string, now time.Time) asset.Asset {
	if name == "" {
		name = arn
	}
	return asset.Asset{
		ID:        arn,
		Name:      name,
		Type:      typ,
		Provider:  asset.ProviderAWS,
		Region:    region,
		AccountID: accountID,
		Metadata: map[string]string{
			"scope":   scope,
			"classic": strconv.FormatBool(classic),
		},
		DiscoveredAt: now,
		LastSeen:     now,
	}
}
