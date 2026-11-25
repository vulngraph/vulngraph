package executor

import (
	"fmt"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/connector"
)

// Guidance describes, for a person deciding whether to approve a fix, the
// executor action that would carry it out: exactly what it changes, whether it
// can be undone and how, and the cloud CLI command that does the same by hand.
// It is built from a finding alone — no connector, no cloud call — so it can be
// shown next to every proposal. Running it still goes through Execute, with
// its principal, read_write and grant checks.
type Guidance struct {
	Action Action
	// Change is the same describe() text a dry run and an approval grant use,
	// with <placeholders> for parameters the finding does not carry.
	Change string
	// Destructive means Execute needs a grant minted by a second admin.
	Destructive bool
	// Reversible means Rollback undoes the change completely; when false,
	// Rollback says what to save first because nothing can recreate it after.
	Reversible bool
	Rollback   string
	// CLI is the equivalent provider CLI command, with the same placeholders.
	CLI string
	// Params are the action's parameters as derived from the finding, with
	// <placeholders> for the ones it does not carry.
	Params map[string]string
}

// guide is the per-action half of Guidance that the registry in plan.go does
// not already hold.
type guide struct {
	// fits lists the respond action classes this action can carry out. An
	// action outside the proposed class is not offered: stopping an instance
	// isolates it, it does not remediate a vulnerability on it.
	fits map[string]bool
	// params derives what it can from the finding's resource id and region;
	// anything it cannot is filled with a placeholder.
	params     func(resourceID, region string) map[string]string
	reversible bool
	rollback   func(p map[string]string) string
	cli        func(p map[string]string) string
	// confirm is the parameter a person types to confirm the action when it
	// is destructive or irreversible: the name of the thing it changes.
	confirm string
}

var (
	fixClasses     = map[string]bool{"remediate": true, "modify": true}
	isolateClasses = map[string]bool{"isolate": true}
	keyClasses     = map[string]bool{"remediate": true, "modify": true, "isolate": true}
)

var guides = map[Action]guide{
	ActionSGRuleRemove: {
		fits:    fixClasses,
		confirm: ParamGroupID,
		params: func(id, region string) map[string]string {
			return map[string]string{
				ParamGroupID: lastSegment(id), ParamRegion: orPlaceholder(region, "region"),
				ParamProtocol: "<protocol>", ParamFromPort: "<from_port>", ParamToPort: "<to_port>", ParamCIDR: "<cidr>",
			}
		},
		reversible: true,
		rollback: func(p map[string]string) string {
			return "Re-add the same rule (its description, if it had one, is not kept): " +
				sgCommand("authorize-security-group-ingress", p)
		},
		cli: func(p map[string]string) string { return sgCommand("revoke-security-group-ingress", p) },
	},
	ActionIAMKeyDisable: {
		fits:    keyClasses,
		confirm: ParamKeyID,
		params: func(id, region string) map[string]string {
			return map[string]string{
				ParamUsername: lastSegment(id), ParamKeyID: "<access_key_id>", ParamRegion: orPlaceholder(region, "region"),
			}
		},
		reversible: true,
		rollback: func(p map[string]string) string {
			return "Re-enable the key: " + iamKeyCommand(p, "Active")
		},
		cli: func(p map[string]string) string { return iamKeyCommand(p, "Inactive") },
	},
	ActionEC2Stop: {
		fits:    isolateClasses,
		confirm: ParamInstanceID,
		params: func(id, region string) map[string]string {
			return map[string]string{ParamInstanceID: lastSegment(id), ParamRegion: orPlaceholder(region, "region")}
		},
		reversible: true,
		rollback: func(p map[string]string) string {
			return fmt.Sprintf("Start it again: aws ec2 start-instances --region %s --instance-ids %s "+
				"(instance-store data is lost on stop, and a public IP without an Elastic IP changes)",
				p[ParamRegion], p[ParamInstanceID])
		},
		cli: func(p map[string]string) string {
			return fmt.Sprintf("aws ec2 stop-instances --region %s --instance-ids %s", p[ParamRegion], p[ParamInstanceID])
		},
	},
	ActionS3BlockPublic: {
		fits:    fixClasses,
		confirm: ParamBucketName,
		params: func(id, region string) map[string]string {
			return map[string]string{
				ParamBucketName: strings.TrimPrefix(id, "arn:aws:s3:::"), ParamRegion: orPlaceholder(region, "region"),
			}
		},
		reversible: true,
		rollback: func(p map[string]string) string {
			return fmt.Sprintf("Remove the block: aws s3api delete-public-access-block --bucket %s "+
				"(when the execute audit row records a bucket-level block before, re-apply those settings with "+
				"put-public-access-block instead)", p[ParamBucketName])
		},
		cli: func(p map[string]string) string {
			return fmt.Sprintf("aws s3api put-public-access-block --bucket %s --public-access-block-configuration "+
				"BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
				p[ParamBucketName])
		},
	},
	ActionGCPSAKeyDisable: {
		fits:    keyClasses,
		confirm: ParamKeyName,
		params: func(id, _ string) map[string]string {
			return map[string]string{ParamServiceAccount: lastSegment(id), ParamKeyName: "<key_id>"}
		},
		reversible: true,
		rollback: func(p map[string]string) string {
			return fmt.Sprintf("Re-enable the key: gcloud iam service-accounts keys enable %s --iam-account %s",
				p[ParamKeyName], p[ParamServiceAccount])
		},
		cli: func(p map[string]string) string {
			return fmt.Sprintf("gcloud iam service-accounts keys disable %s --iam-account %s",
				p[ParamKeyName], p[ParamServiceAccount])
		},
	},
	ActionGCPFirewallRemove: {
		fits:    fixClasses,
		confirm: ParamFirewallRule,
		params: func(id, _ string) map[string]string {
			return map[string]string{
				ParamFirewallRule: lastSegment(id),
				ParamProject:      orPlaceholder(pathValue(id, "projects"), "project"),
			}
		},
		rollback: func(p map[string]string) string {
			return fmt.Sprintf("Not reversible from the request — save the rule first: gcloud compute firewall-rules "+
				"describe %s --project %s --format=yaml, and recreate it from that with gcloud compute firewall-rules create",
				p[ParamFirewallRule], p[ParamProject])
		},
		cli: func(p map[string]string) string {
			return fmt.Sprintf("gcloud compute firewall-rules delete %s --project %s", p[ParamFirewallRule], p[ParamProject])
		},
	},
	ActionAzureNSGRuleRemove: {
		fits:    fixClasses,
		confirm: ParamRuleName,
		params: func(id, _ string) map[string]string {
			return map[string]string{
				ParamSubscriptionID: orPlaceholder(pathValue(id, "subscriptions"), "subscription_id"),
				ParamResourceGroup:  orPlaceholder(pathValue(id, "resourceGroups"), "resource_group"),
				ParamNSGName:        orPlaceholder(pathValue(id, "networkSecurityGroups"), "nsg_name"),
				ParamRuleName:       "<rule_name>",
			}
		},
		rollback: func(p map[string]string) string {
			return "Not reversible from the request — save the rule first: " + nsgRuleCommand("show", p) +
				" -o json, and recreate it from that with az network nsg rule create"
		},
		cli: func(p map[string]string) string { return nsgRuleCommand("delete", p) },
	},
}

// resourceFixes maps a finding's resource type to the executor actions that can
// change that kind of resource — the single source of truth for which resource
// types have any executor path at all (HasExecutableAction). security_group is
// shared by the AWS and Azure collectors; GuideFor picks by the id's shape.
var resourceFixes = map[string][]Action{
	"security_group":      {ActionSGRuleRemove, ActionAzureNSGRuleRemove},
	"iam_user":            {ActionIAMKeyDisable},
	"ec2_instance":        {ActionEC2Stop},
	"s3_bucket":           {ActionS3BlockPublic},
	"gcp_service_account": {ActionGCPSAKeyDisable},
	"gcp_firewall":        {ActionGCPFirewallRemove},
}

// HasExecutableAction reports whether resourceType has at least one wired
// executor action. respond consumes it (injected at construction, for
// layering) to annotate plans no in-cluster action can carry out.
func HasExecutableAction(resourceType string) bool {
	return len(resourceFixes[resourceType]) > 0
}

// GuideFor returns the guidance for the executor action that would carry out a
// proposed actionClass on the finding's resource, or false when no executor
// action fits — the fix then has to be applied by hand or in IaC.
func GuideFor(resourceType, resourceID, region, actionClass string) (Guidance, bool) {
	azure := strings.HasPrefix(strings.ToLower(resourceID), "/subscriptions/")
	// Finding data is not trusted to be a region: anything else renders as the
	// placeholder rather than reaching the CLI line a person copies.
	if !validAWSRegion(region) {
		region = ""
	}
	for _, action := range resourceFixes[resourceType] {
		spec, g := specs[action], guides[action]
		if (spec.connectorType == connector.TypeAzure) != azure || !g.fits[actionClass] {
			continue
		}
		p := g.params(resourceID, region)
		return Guidance{
			Action:      action,
			Change:      spec.describe(connector.Connector{}, p),
			Destructive: spec.destructive(p),
			Reversible:  g.reversible,
			Rollback:    g.rollback(p),
			CLI:         g.cli(p),
			Params:      p,
		}, true
	}
	return Guidance{}, false
}

func sgCommand(verb string, p map[string]string) string {
	return fmt.Sprintf("aws ec2 %s --region %s --group-id %s --protocol %s --port %s-%s --cidr %s",
		verb, p[ParamRegion], p[ParamGroupID], p[ParamProtocol], p[ParamFromPort], p[ParamToPort], p[ParamCIDR])
}

func iamKeyCommand(p map[string]string, status string) string {
	return fmt.Sprintf("aws iam update-access-key --user-name %s --access-key-id %s --status %s",
		p[ParamUsername], p[ParamKeyID], status)
}

func nsgRuleCommand(verb string, p map[string]string) string {
	return fmt.Sprintf("az network nsg rule %s --subscription %s --resource-group %s --nsg-name %s --name %s",
		verb, p[ParamSubscriptionID], p[ParamResourceGroup], p[ParamNSGName], p[ParamRuleName])
}

// lastSegment is the trailing name of an ARN or resource path
// ("arn:aws:iam::1:user/ops/alice" -> "alice", "sg-1" -> "sg-1").
func lastSegment(id string) string {
	if i := strings.LastIndexAny(id, "/:"); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}

// pathValue returns the segment after key in a slash-separated resource path
// (case-insensitive key), or "" when the path does not carry it.
func pathValue(id, key string) string {
	parts := strings.Split(id, "/")
	for i := 0; i < len(parts)-1; i++ {
		if strings.EqualFold(parts[i], key) {
			return parts[i+1]
		}
	}
	return ""
}

func orPlaceholder(v, name string) string {
	if v == "" {
		return "<" + name + ">"
	}
	return v
}

// isPlaceholder reports whether a guidance parameter is a <placeholder> the
// finding could not fill.
func isPlaceholder(v string) bool {
	return strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">")
}

// confirmText is what a person types to confirm action with resolved params:
// the changed thing's name when the action is destructive or cannot be undone,
// and empty when a click is enough.
func confirmText(action Action, params map[string]string, destructive bool) string {
	g, ok := guides[action]
	if !ok || (!destructive && g.reversible) {
		return ""
	}
	return params[g.confirm]
}
