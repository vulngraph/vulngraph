package aws

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/waf"
	"github.com/aws/aws-sdk-go-v2/service/wafregional"
)

// The two WAF Classic SDKs adapted onto wafClassic. They are line-for-line
// the same calls; only the package differs.

type wafGlobalAPI interface {
	ListWebACLs(context.Context, *waf.ListWebACLsInput, ...func(*waf.Options)) (*waf.ListWebACLsOutput, error)
	GetWebACL(context.Context, *waf.GetWebACLInput, ...func(*waf.Options)) (*waf.GetWebACLOutput, error)
	ListRules(context.Context, *waf.ListRulesInput, ...func(*waf.Options)) (*waf.ListRulesOutput, error)
	GetRule(context.Context, *waf.GetRuleInput, ...func(*waf.Options)) (*waf.GetRuleOutput, error)
	ListRuleGroups(context.Context, *waf.ListRuleGroupsInput, ...func(*waf.Options)) (*waf.ListRuleGroupsOutput, error)
	ListActivatedRulesInRuleGroup(context.Context, *waf.ListActivatedRulesInRuleGroupInput, ...func(*waf.Options)) (*waf.ListActivatedRulesInRuleGroupOutput, error)
	ListLoggingConfigurations(context.Context, *waf.ListLoggingConfigurationsInput, ...func(*waf.Options)) (*waf.ListLoggingConfigurationsOutput, error)
}

type wafGlobal struct{ c wafGlobalAPI }

func (w wafGlobal) webACLs(ctx context.Context) ([]classicItem, error) {
	return pageClassic(func(m *string) ([]classicItem, *string, error) {
		out, err := w.c.ListWebACLs(ctx, &waf.ListWebACLsInput{Limit: classicLimit, NextMarker: m})
		if err != nil {
			return nil, nil, err
		}
		items := make([]classicItem, 0, len(out.WebACLs))
		for _, a := range out.WebACLs {
			items = append(items, classicItem{awssdk.ToString(a.WebACLId), awssdk.ToString(a.Name)})
		}
		return items, out.NextMarker, nil
	})
}

func (w wafGlobal) webACL(ctx context.Context, id string) (string, int, error) {
	out, err := w.c.GetWebACL(ctx, &waf.GetWebACLInput{WebACLId: awssdk.String(id)})
	if err != nil {
		return "", 0, fmt.Errorf("GetWebACL: %w", err)
	}
	if out.WebACL == nil {
		return "", 0, fmt.Errorf("GetWebACL: %w", errEmptyResponse)
	}
	return awssdk.ToString(out.WebACL.WebACLArn), len(out.WebACL.Rules), nil
}

func (w wafGlobal) rules(ctx context.Context) ([]classicItem, error) {
	return pageClassic(func(m *string) ([]classicItem, *string, error) {
		out, err := w.c.ListRules(ctx, &waf.ListRulesInput{Limit: classicLimit, NextMarker: m})
		if err != nil {
			return nil, nil, err
		}
		items := make([]classicItem, 0, len(out.Rules))
		for _, r := range out.Rules {
			items = append(items, classicItem{awssdk.ToString(r.RuleId), awssdk.ToString(r.Name)})
		}
		return items, out.NextMarker, nil
	})
}

func (w wafGlobal) ruleConditions(ctx context.Context, id string) (int, error) {
	out, err := w.c.GetRule(ctx, &waf.GetRuleInput{RuleId: awssdk.String(id)})
	if err != nil {
		return 0, fmt.Errorf("GetRule: %w", err)
	}
	if out.Rule == nil {
		return 0, fmt.Errorf("GetRule: %w", errEmptyResponse)
	}
	return len(out.Rule.Predicates), nil
}

func (w wafGlobal) ruleGroups(ctx context.Context) ([]classicItem, error) {
	return pageClassic(func(m *string) ([]classicItem, *string, error) {
		out, err := w.c.ListRuleGroups(ctx, &waf.ListRuleGroupsInput{Limit: classicLimit, NextMarker: m})
		if err != nil {
			return nil, nil, err
		}
		items := make([]classicItem, 0, len(out.RuleGroups))
		for _, g := range out.RuleGroups {
			items = append(items, classicItem{awssdk.ToString(g.RuleGroupId), awssdk.ToString(g.Name)})
		}
		return items, out.NextMarker, nil
	})
}

func (w wafGlobal) ruleGroupRules(ctx context.Context, id string) (int, error) {
	n := 0
	_, err := pageClassic(func(m *string) ([]classicItem, *string, error) {
		out, err := w.c.ListActivatedRulesInRuleGroup(ctx, &waf.ListActivatedRulesInRuleGroupInput{RuleGroupId: awssdk.String(id), Limit: classicLimit, NextMarker: m})
		if err != nil {
			return nil, nil, fmt.Errorf("ListActivatedRulesInRuleGroup: %w", err)
		}
		n += len(out.ActivatedRules)
		return make([]classicItem, len(out.ActivatedRules)), out.NextMarker, nil
	})
	return n, err
}

// classicLoggedACLs lists the global web ACL ARNs that have a logging
// configuration (WAF.1).
func classicLoggedACLs(c wafGlobalAPI) func(context.Context) (map[string]bool, error) {
	return func(ctx context.Context) (map[string]bool, error) {
		logged := map[string]bool{}
		var marker *string
		for {
			out, err := c.ListLoggingConfigurations(ctx, &waf.ListLoggingConfigurationsInput{Limit: classicLimit, NextMarker: marker})
			if err != nil {
				return nil, fmt.Errorf("classicLoggedACLs: ListLoggingConfigurations: %w", err)
			}
			for _, l := range out.LoggingConfigurations {
				if len(l.LogDestinationConfigs) > 0 {
					logged[awssdk.ToString(l.ResourceArn)] = true
				}
			}
			if awssdk.ToString(out.NextMarker) == "" || len(out.LoggingConfigurations) == 0 {
				return logged, nil
			}
			marker = out.NextMarker
		}
	}
}

type wafRegionalAPI interface {
	ListWebACLs(context.Context, *wafregional.ListWebACLsInput, ...func(*wafregional.Options)) (*wafregional.ListWebACLsOutput, error)
	GetWebACL(context.Context, *wafregional.GetWebACLInput, ...func(*wafregional.Options)) (*wafregional.GetWebACLOutput, error)
	ListRules(context.Context, *wafregional.ListRulesInput, ...func(*wafregional.Options)) (*wafregional.ListRulesOutput, error)
	GetRule(context.Context, *wafregional.GetRuleInput, ...func(*wafregional.Options)) (*wafregional.GetRuleOutput, error)
	ListRuleGroups(context.Context, *wafregional.ListRuleGroupsInput, ...func(*wafregional.Options)) (*wafregional.ListRuleGroupsOutput, error)
	ListActivatedRulesInRuleGroup(context.Context, *wafregional.ListActivatedRulesInRuleGroupInput, ...func(*wafregional.Options)) (*wafregional.ListActivatedRulesInRuleGroupOutput, error)
}

type wafRegional struct{ c wafRegionalAPI }

func (w wafRegional) webACLs(ctx context.Context) ([]classicItem, error) {
	return pageClassic(func(m *string) ([]classicItem, *string, error) {
		out, err := w.c.ListWebACLs(ctx, &wafregional.ListWebACLsInput{Limit: classicLimit, NextMarker: m})
		if err != nil {
			return nil, nil, err
		}
		items := make([]classicItem, 0, len(out.WebACLs))
		for _, a := range out.WebACLs {
			items = append(items, classicItem{awssdk.ToString(a.WebACLId), awssdk.ToString(a.Name)})
		}
		return items, out.NextMarker, nil
	})
}

func (w wafRegional) webACL(ctx context.Context, id string) (string, int, error) {
	out, err := w.c.GetWebACL(ctx, &wafregional.GetWebACLInput{WebACLId: awssdk.String(id)})
	if err != nil {
		return "", 0, fmt.Errorf("GetWebACL: %w", err)
	}
	if out.WebACL == nil {
		return "", 0, fmt.Errorf("GetWebACL: %w", errEmptyResponse)
	}
	return awssdk.ToString(out.WebACL.WebACLArn), len(out.WebACL.Rules), nil
}

func (w wafRegional) rules(ctx context.Context) ([]classicItem, error) {
	return pageClassic(func(m *string) ([]classicItem, *string, error) {
		out, err := w.c.ListRules(ctx, &wafregional.ListRulesInput{Limit: classicLimit, NextMarker: m})
		if err != nil {
			return nil, nil, err
		}
		items := make([]classicItem, 0, len(out.Rules))
		for _, r := range out.Rules {
			items = append(items, classicItem{awssdk.ToString(r.RuleId), awssdk.ToString(r.Name)})
		}
		return items, out.NextMarker, nil
	})
}

func (w wafRegional) ruleConditions(ctx context.Context, id string) (int, error) {
	out, err := w.c.GetRule(ctx, &wafregional.GetRuleInput{RuleId: awssdk.String(id)})
	if err != nil {
		return 0, fmt.Errorf("GetRule: %w", err)
	}
	if out.Rule == nil {
		return 0, fmt.Errorf("GetRule: %w", errEmptyResponse)
	}
	return len(out.Rule.Predicates), nil
}

func (w wafRegional) ruleGroups(ctx context.Context) ([]classicItem, error) {
	return pageClassic(func(m *string) ([]classicItem, *string, error) {
		out, err := w.c.ListRuleGroups(ctx, &wafregional.ListRuleGroupsInput{Limit: classicLimit, NextMarker: m})
		if err != nil {
			return nil, nil, err
		}
		items := make([]classicItem, 0, len(out.RuleGroups))
		for _, g := range out.RuleGroups {
			items = append(items, classicItem{awssdk.ToString(g.RuleGroupId), awssdk.ToString(g.Name)})
		}
		return items, out.NextMarker, nil
	})
}

func (w wafRegional) ruleGroupRules(ctx context.Context, id string) (int, error) {
	n := 0
	_, err := pageClassic(func(m *string) ([]classicItem, *string, error) {
		out, err := w.c.ListActivatedRulesInRuleGroup(ctx, &wafregional.ListActivatedRulesInRuleGroupInput{RuleGroupId: awssdk.String(id), Limit: classicLimit, NextMarker: m})
		if err != nil {
			return nil, nil, fmt.Errorf("ListActivatedRulesInRuleGroup: %w", err)
		}
		n += len(out.ActivatedRules)
		return make([]classicItem, len(out.ActivatedRules)), out.NextMarker, nil
	})
	return n, err
}
