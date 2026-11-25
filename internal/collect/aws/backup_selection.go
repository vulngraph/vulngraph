package aws

import (
	"context"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
)

// backupPlanLister lists the region's backup plans.
type backupPlanLister interface {
	ListBackupPlans(context.Context, *backup.ListBackupPlansInput, ...func(*backup.Options)) (*backup.ListBackupPlansOutput, error)
}

// backupPlanAPI is the slice of AWS Backup needed to decide whether a
// resource is assigned to a backup plan (FSBP EFS.2): every plan's resource
// assignments plus the region's service opt-in.
type backupPlanAPI interface {
	backupPlanLister
	ListBackupSelections(context.Context, *backup.ListBackupSelectionsInput, ...func(*backup.Options)) (*backup.ListBackupSelectionsOutput, error)
	GetBackupSelection(context.Context, *backup.GetBackupSelectionInput, ...func(*backup.Options)) (*backup.GetBackupSelectionOutput, error)
	DescribeRegionSettings(context.Context, *backup.DescribeRegionSettingsInput, ...func(*backup.Options)) (*backup.DescribeRegionSettingsOutput, error)
}

// backupRule is one backup selection (resource assignment). AWS evaluates it
// like an IAM statement: (Resources OR ListOfTags) AND every Conditions entry,
// minus anything in NotResources.
type backupRule struct {
	resources    []string
	notResources []string
	listOfTags   []backupTagCond
	conditions   []backupTagCond
}

// backupTagCond is one tag test; op is StringEquals, StringNotEquals,
// StringLike or StringNotLike. key is the tag key without aws:ResourceTag/.
type backupTagCond struct {
	op, key, value string
	// unsupported marks a condition key that is not a resource tag: graph
	// cannot evaluate it, so the rule's answer is unknown.
	unsupported bool
}

// backupPlanCoverage is every resource assignment of every backup plan in one
// region, plus the region's per-service opt-in.
type backupPlanCoverage struct {
	rules []backupRule
	optIn map[string]bool
}

// readBackupPlanCoverage reads every plan's selections. Any failed call fails
// the whole read: a partial selection list would report covered resources as
// unprotected.
func readBackupPlanCoverage(ctx context.Context, client backupPlanAPI) (*backupPlanCoverage, error) {
	settings, err := client.DescribeRegionSettings(ctx, &backup.DescribeRegionSettingsInput{})
	if err != nil {
		return nil, fmt.Errorf("readBackupPlanCoverage: DescribeRegionSettings: %w", err)
	}
	cov := &backupPlanCoverage{optIn: settings.ResourceTypeOptInPreference}
	planIDs, err := listBackupPlanIDs(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("readBackupPlanCoverage: %w", err)
	}
	for _, planID := range planIDs {
		var next *string
		for {
			page, err := client.ListBackupSelections(ctx, &backup.ListBackupSelectionsInput{BackupPlanId: awssdk.String(planID), NextToken: next})
			if err != nil {
				return nil, fmt.Errorf("readBackupPlanCoverage: ListBackupSelections: %w", err)
			}
			for _, s := range page.BackupSelectionsList {
				sel, err := client.GetBackupSelection(ctx, &backup.GetBackupSelectionInput{BackupPlanId: awssdk.String(planID), SelectionId: s.SelectionId})
				if err != nil {
					return nil, fmt.Errorf("readBackupPlanCoverage: GetBackupSelection: %w", err)
				}
				if sel.BackupSelection != nil {
					cov.rules = append(cov.rules, backupRuleFrom(*sel.BackupSelection))
				}
			}
			if page.NextToken == nil {
				break
			}
			next = page.NextToken
		}
	}
	return cov, nil
}

// listBackupPlanIDs lists every live backup plan in the region.
func listBackupPlanIDs(ctx context.Context, client backupPlanLister) ([]string, error) {
	var (
		ids  []string
		next *string
	)
	for {
		page, err := client.ListBackupPlans(ctx, &backup.ListBackupPlansInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("listBackupPlanIDs: %w", err)
		}
		for _, p := range page.BackupPlansList {
			if id := awssdk.ToString(p.BackupPlanId); id != "" {
				ids = append(ids, id)
			}
		}
		if page.NextToken == nil {
			return ids, nil
		}
		next = page.NextToken
	}
}

func backupRuleFrom(s backuptypes.BackupSelection) backupRule {
	r := backupRule{resources: s.Resources, notResources: s.NotResources}
	for _, c := range s.ListOfTags {
		r.listOfTags = append(r.listOfTags, backupTagCondFrom("StringEquals", c.ConditionKey, c.ConditionValue, true))
	}
	if c := s.Conditions; c != nil {
		for op, params := range map[string][]backuptypes.ConditionParameter{
			"StringEquals": c.StringEquals, "StringNotEquals": c.StringNotEquals,
			"StringLike": c.StringLike, "StringNotLike": c.StringNotLike,
		} {
			for _, p := range params {
				r.conditions = append(r.conditions, backupTagCondFrom(op, p.ConditionKey, p.ConditionValue, false))
			}
		}
	}
	return r
}

// backupTagCondFrom normalises a condition key. ListOfTags accepts a bare tag
// key or aws:ResourceTag/<key>; Conditions only the prefixed form.
func backupTagCondFrom(op string, key, value *string, bareAllowed bool) backupTagCond {
	k := awssdk.ToString(key)
	c := backupTagCond{op: op, value: awssdk.ToString(value)}
	switch tag, ok := strings.CutPrefix(k, "aws:ResourceTag/"); {
	case ok:
		c.key = tag
	case bareAllowed && !strings.Contains(k, ":"):
		c.key = k
	default:
		c.unsupported = true
	}
	return c
}

// covers reports whether some plan assigns the resource. optInKey is the
// resource type's name in the region's opt-in preferences (e.g. "EFS");
// typeMarker is the ARN fragment that makes a pattern name the resource type
// itself (e.g. "file-system/"), which AWS backs up regardless of opt-in.
// known is false when no rule assigned the resource and at least one could
// not be decided (an unreadable opt-in, a non-tag condition key).
func (c *backupPlanCoverage) covers(arn string, tags map[string]string, optInKey, typeMarker string) (covered, known bool) {
	known = true
	for _, r := range c.rules {
		switch r.assigns(arn, tags, c.optIn, optInKey, typeMarker) {
		case tristateYes:
			return true, true
		case tristateUnknown:
			known = false
		}
	}
	return false, known
}

type tristate int

const (
	tristateNo tristate = iota
	tristateYes
	tristateUnknown
)

func (r backupRule) assigns(arn string, tags map[string]string, optIn map[string]bool, optInKey, typeMarker string) tristate {
	for _, p := range r.notResources {
		if backupGlobMatch(p, arn) {
			return tristateNo
		}
	}
	// A pattern naming the resource type selects it whatever the opt-in; a
	// service-wide pattern ("*", "arn:aws:elasticfilesystem:*") or a tag
	// assignment selects it only when the region has the type opted in.
	scope := tristateNo
	for _, p := range r.resources {
		if !backupGlobMatch(p, arn) {
			continue
		}
		if strings.Contains(p, typeMarker) {
			scope = tristateYes
			break
		}
		scope = maxTristate(scope, optedIn(optIn, optInKey))
	}
	if scope != tristateYes {
		for _, t := range r.listOfTags {
			if t.unsupported {
				scope = maxTristate(scope, tristateUnknown)
				continue
			}
			if v, ok := tags[t.key]; ok && v == t.value {
				scope = maxTristate(scope, optedIn(optIn, optInKey))
			}
		}
	}
	if scope == tristateNo {
		return tristateNo
	}
	for _, cond := range r.conditions {
		switch cond.holds(tags) {
		case tristateNo:
			return tristateNo
		case tristateUnknown:
			scope = tristateUnknown
		}
	}
	return scope
}

// maxTristate prefers a decisive yes, then unknown, over no.
func maxTristate(a, b tristate) tristate {
	if a == tristateYes || b == tristateYes {
		return tristateYes
	}
	if a == tristateUnknown || b == tristateUnknown {
		return tristateUnknown
	}
	return tristateNo
}

func optedIn(optIn map[string]bool, key string) tristate {
	v, ok := optIn[key]
	switch {
	case !ok:
		return tristateUnknown
	case v:
		return tristateYes
	}
	return tristateNo
}

// holds evaluates one tag condition with IAM semantics: the negated operators
// hold when the tag is absent.
func (c backupTagCond) holds(tags map[string]string) tristate {
	if c.unsupported {
		return tristateUnknown
	}
	v, ok := tags[c.key]
	var pass bool
	switch c.op {
	case "StringEquals":
		pass = ok && v == c.value
	case "StringNotEquals":
		pass = !ok || v != c.value
	case "StringLike":
		pass = ok && backupGlobMatch(c.value, v)
	case "StringNotLike":
		pass = !ok || !backupGlobMatch(c.value, v)
	default:
		return tristateUnknown
	}
	if pass {
		return tristateYes
	}
	return tristateNo
}

// backupGlobMatch matches AWS Backup's wildcard: `*` is zero or more
// non-whitespace characters; everything else is literal.
func backupGlobMatch(pattern, s string) bool {
	if pattern == "" {
		return s == ""
	}
	star := strings.IndexByte(pattern, '*')
	if star < 0 {
		return pattern == s
	}
	if !strings.HasPrefix(s, pattern[:star]) {
		return false
	}
	rest, tail := s[star:], pattern[star+1:]
	for i := 0; i <= len(rest); i++ {
		if backupGlobMatch(tail, rest[i:]) {
			return true
		}
		if i < len(rest) && (rest[i] == ' ' || rest[i] == '\t' || rest[i] == '\n') {
			return false
		}
	}
	return false
}
