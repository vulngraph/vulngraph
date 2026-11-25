package aws

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/waf"
	"github.com/aws/aws-sdk-go-v2/service/wafregional"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// AWS WAF Classic (AWS FSBP WAF.1-4, WAF.6-8): the global (waf, CloudFront)
// and regional (waf-regional) APIs are identical in shape but distinct SDK
// packages, so each is adapted onto wafClassic and graded by one reader.
// Classic was retired on 2025-09-30; most accounts have nothing here, an
// empty listing emits nothing, and a retired API reads as empty
// (classicRetired).

const wafRuleType = "waf_rule"

// classicItem is one listed web ACL, rule or rule group.
type classicItem struct{ id, name string }

type wafClassic interface {
	webACLs(context.Context) ([]classicItem, error)
	// webACL returns the ACL's ARN and how many rules it activates.
	webACL(context.Context, string) (string, int, error)
	rules(context.Context) ([]classicItem, error)
	ruleConditions(context.Context, string) (int, error)
	ruleGroups(context.Context) ([]classicItem, error)
	ruleGroupRules(context.Context, string) (int, error)
}

// pageClassic pages a Classic listing to the end: NextMarker is set only
// while more items remain, and an empty page ends it too.
func pageClassic(page func(*string) ([]classicItem, *string, error)) ([]classicItem, error) {
	var (
		out    []classicItem
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

// classicLimit is the largest page every Classic listing accepts.
const classicLimit = 100

func collectWAFClassicGlobal(ctx context.Context, cfg map[string]string, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectWAFClassicGlobal: %w", err)
	}
	if !cloudFrontPartition(awsCfg.Region) {
		return nil, nil
	}
	awsCfg.Region = globalRegionFor(awsCfg.Region)
	client := waf.NewFromConfig(awsCfg)
	assets, err := readWAFClassic(ctx, wafGlobal{client}, "GLOBAL", "waf", awsCfg.Region, "global", accountID, now)
	if err != nil || len(assets) == 0 {
		return assets, err
	}
	logged, err := classicLoggedACLs(client)(ctx)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("waf classic logging configurations unreadable; web ACL logging is unknown this sweep")
		return assets, nil
	}
	stampClassicLogging(assets, logged)
	return assets, nil
}

func collectWAFClassicRegional(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectWAFClassicRegional: %w", err)
	}
	return readWAFClassic(ctx, wafRegional{wafregional.NewFromConfig(awsCfg)}, "REGIONAL", "waf-regional", region, region, accountID, now)
}

// stampClassicLogging marks each global web ACL logging_enabled (WAF.1).
func stampClassicLogging(assets []asset.Asset, logged map[string]bool) {
	for i := range assets {
		if assets[i].Type == wafWebACLType {
			assets[i].Metadata["logging_enabled"] = strconv.FormatBool(logged[assets[i].ID])
		}
	}
}

// readWAFClassic lists the web ACLs, rules and rule groups and reads each
// one's contents. A listing failure fails the read; a single Get failure
// leaves that resource's count absent (unknown, never "empty").
func readWAFClassic(ctx context.Context, api wafClassic, scope, service, armRegion, region, accountID string, now time.Time) ([]asset.Asset, error) {
	// A retired Classic API (classicRetired) on any listing is an
	// empty account, not a failed read.
	acls, err := api.webACLs(ctx)
	if err != nil {
		if classicRetired(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("readWAFClassic: %s ListWebACLs: %w", service, err)
	}
	rules, err := api.rules(ctx)
	if err != nil {
		if classicRetired(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("readWAFClassic: %s ListRules: %w", service, err)
	}
	groups, err := api.ruleGroups(ctx)
	if err != nil {
		if classicRetired(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("readWAFClassic: %s ListRuleGroups: %w", service, err)
	}
	arnPrefix := "arn:" + partitionFor(armRegion) + ":" + service + ":"
	if service == "waf-regional" {
		arnPrefix += armRegion
	}
	arnPrefix += ":" + accountID + ":"

	type job struct {
		a    asset.Asset
		id   string
		read func(context.Context, string) (int, error)
		key  string
	}
	var jobs []job
	for _, w := range acls {
		jobs = append(jobs, job{a: wafAsset(arnPrefix+"webacl/"+w.id, w.name, wafWebACLType, scope, true, region, accountID, now), id: w.id, key: "rule_count"})
	}
	for _, r := range rules {
		jobs = append(jobs, job{a: wafAsset(arnPrefix+"rule/"+r.id, r.name, wafRuleType, scope, true, region, accountID, now), id: r.id, read: api.ruleConditions, key: "condition_count"})
	}
	for _, g := range groups {
		jobs = append(jobs, job{a: wafAsset(arnPrefix+"rulegroup/"+g.id, g.name, wafRuleGroupType, scope, true, region, accountID, now), id: g.id, read: api.ruleGroupRules, key: "rule_count"})
	}
	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		sem = make(chan struct{}, wafConcurrency)
	)
	for i := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j *job) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					log.FromContext(ctx).Error().Interface("panic", rec).Str("waf_resource", j.a.ID).Msg("waf classic read panicked")
				}
			}()
			var (
				n   int
				arn string
				err error
			)
			if j.read == nil {
				arn, n, err = api.webACL(ctx, j.id)
			} else {
				n, err = j.read(ctx, j.id)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				log.FromContext(ctx).Warn().Err(err).Str("waf_resource", j.a.ID).Msg("waf classic read failed; its checks cannot evaluate it this sweep")
				return
			}
			if arn != "" {
				j.a.ID = arn
			}
			j.a.Metadata[j.key] = strconv.Itoa(n)
		}(&jobs[i])
	}
	wg.Wait()
	out := make([]asset.Asset, len(jobs))
	for i, j := range jobs {
		out[i] = j.a
	}
	return out, nil
}
