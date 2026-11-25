package executor

import (
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/connector"
)

// actionSpec declares everything about an action that is decided BEFORE any
// cloud call: which connector type may carry it, how its params resolve, what it
// would change, and whether that change is destructive enough to require a
// second admin's approval.
//
// The registry is the single resolution point. A dry-run, an approval grant and
// a real execution all run the same resolve+describe, so an approval can never
// describe something other than what would execute — the plan text an approver
// reads is byte-identical to the plan the executor binds the grant to.
type actionSpec struct {
	connectorType connector.Type

	// resolve validates params and applies connector-config fallbacks, returning
	// the params every later step uses. Returns ErrBadParams.
	resolve func(c connector.Connector, params map[string]string) (map[string]string, error)

	// describe renders, from resolved params, what the action WOULD change.
	// Present tense, no side effects — this is the dry-run output.
	describe func(c connector.Connector, p map[string]string) string

	// destructive reports whether this specific call (params matter — see
	// iam_key_disable) needs a second admin's approval before it runs.
	destructive func(p map[string]string) bool
}

// never marks an action as not requiring a second admin's approval. Every
// action still needs one admin's explicit request (ADR 087), a read_write
// connector and an execution principal; an API-key request needs a second
// admin's grant for every action (service.go viaAPIKey).
//
// The rule for the second admin, applied to every action below, is exactly
// this: gated when the action (a) destroys state that nothing in the request
// or its audit row can restore — a deleted key or rule, or a stopped
// instance's memory, instance-store data and auto-assigned public IP — or (b)
// undoes a containment, which only ec2_start can. Everything else is not
// gated, because its access settings are restored exactly from the request and
// audit row: sg_rule_remove re-adds the rule from the five params (the rule's
// free-text description is a label, not access, and is not kept), a disabled
// key is set active again, and s3_block_public records the bucket's earlier
// block in its audit row and refuses to run when it cannot read it.
//
// Outage capability is deliberately NOT the criterion. Revoking world ingress
// (sg_rule_remove) can cut a public load balancer, disabling a key
// (iam_key_disable, gcp_sa_key_disable) can break the job that uses it, and
// blocking public access (s3_block_public) can break a public website — and
// these are also the routine remediations. A second approval on every one of
// them trains operators to approve without reading, which is worse than no
// gate at all. Their outage is bounded by the undo the audit row specifies,
// and by what the execution principal's IAM permits.
func never(map[string]string) bool { return false }

// always marks an action as requiring approval regardless of params.
func always(map[string]string) bool { return true }

var specs = map[Action]actionSpec{
	// Revoking a 0.0.0.0/0 or ::/0 ingress rule is the canonical remediation,
	// and the rule being revoked is fully specified in the request — re-adding
	// it is a copy of the same five params. Reversible from the audit row alone.
	// Any other CIDR is refused: this action is not gated, so it must not be a
	// one-admin way to cut an internal rule (10.0.0.0/8 from a production SG).
	ActionSGRuleRemove: {
		connectorType: connector.TypeAWS,
		resolve: func(_ connector.Connector, params map[string]string) (map[string]string, error) {
			p := copyParams(params)
			if err := requireParams(ActionSGRuleRemove, p, ParamGroupID, ParamRegion, ParamProtocol, ParamCIDR); err != nil {
				return nil, err
			}
			if err := checkRegion(p); err != nil {
				return nil, err
			}
			cidr, err := worldOpenCIDR(p[ParamCIDR])
			if err != nil {
				return nil, err
			}
			p[ParamCIDR] = cidr
			if _, err := parsePort(p[ParamFromPort]); err != nil {
				return nil, fmt.Errorf("%w: from_port: %v", ErrBadParams, err)
			}
			if _, err := parsePort(p[ParamToPort]); err != nil {
				return nil, fmt.Errorf("%w: to_port: %v", ErrBadParams, err)
			}
			return p, nil
		},
		describe: func(_ connector.Connector, p map[string]string) string {
			return fmt.Sprintf("revoke ingress rule proto=%s from_port=%s to_port=%s cidr=%s on security group %s in %s",
				p[ParamProtocol], orZero(p[ParamFromPort]), orZero(p[ParamToPort]), p[ParamCIDR], p[ParamGroupID], p[ParamRegion])
		},
		destructive: never,
	},

	// Disabling a key is reversible (UpdateAccessKey back to Active) and loses
	// nothing. DELETING it is not: the key material and the key's existence are
	// gone, which destroys the evidence of what an attacker used — an
	// anti-forensics primitive. Only the delete variant is gated.
	ActionIAMKeyDisable: {
		connectorType: connector.TypeAWS,
		resolve: func(c connector.Connector, params map[string]string) (map[string]string, error) {
			p := copyParams(params)
			// IAM is global; the region only picks the STS/credential endpoint,
			// so it falls back to the connector's configured region.
			fallback(p, ParamRegion, c.Config["region"])
			if err := requireParams(ActionIAMKeyDisable, p, ParamKeyID, ParamUsername, ParamRegion); err != nil {
				return nil, err
			}
			if err := checkRegion(p); err != nil {
				return nil, err
			}
			return p, nil
		},
		describe: func(_ connector.Connector, p map[string]string) string {
			if p[ParamDeleteKey] == "true" {
				return fmt.Sprintf("disable AND DELETE IAM access key %s of user %s (irreversible — the key record is destroyed)",
					p[ParamKeyID], p[ParamUsername])
			}
			return fmt.Sprintf("disable IAM access key %s of user %s (reversible — the key is set Inactive, not removed)",
				p[ParamKeyID], p[ParamUsername])
		},
		destructive: func(p map[string]string) bool { return p[ParamDeleteKey] == "true" },
	},

	// Stopping an instance destroys what starting it again does not restore: its
	// memory (live-forensics evidence on a compromised host), instance-store
	// volumes, and a public IPv4 address that is not an Elastic IP. Gated (rule
	// (a) on never).
	ActionEC2Stop: {
		connectorType: connector.TypeAWS,
		resolve:       awsInstanceParams(ActionEC2Stop),
		describe: func(_ connector.Connector, p map[string]string) string {
			return fmt.Sprintf("stop EC2 instance %s in %s (the workload goes offline)", p[ParamInstanceID], p[ParamRegion])
		},
		destructive: always,
	},

	// Starting an instance destroys nothing, but it is not a remediation: it
	// brings back a workload that may have been stopped to contain it (rule (b)
	// on never). One admin restarting a quarantined host would undo a
	// containment that took two. Gated.
	ActionEC2Start: {
		connectorType: connector.TypeAWS,
		resolve:       awsInstanceParams(ActionEC2Start),
		describe: func(_ connector.Connector, p map[string]string) string {
			return fmt.Sprintf("start EC2 instance %s in %s (the workload comes back online — check it was not stopped to contain it)",
				p[ParamInstanceID], p[ParamRegion])
		},
		destructive: always,
	},

	// Blocking public access is undone from the audit row: the executor reads
	// the bucket's earlier block first and records it (service.go
	// s3BlockPublicAccess), so a partial block is put back, not deleted.
	ActionS3BlockPublic: {
		connectorType: connector.TypeAWS,
		resolve: func(c connector.Connector, params map[string]string) (map[string]string, error) {
			p := copyParams(params)
			fallback(p, ParamRegion, c.Config["region"])
			if err := requireParams(ActionS3BlockPublic, p, ParamBucketName, ParamRegion); err != nil {
				return nil, err
			}
			if err := checkRegion(p); err != nil {
				return nil, err
			}
			return p, nil
		},
		describe: func(_ connector.Connector, p map[string]string) string {
			return fmt.Sprintf("block all public access on S3 bucket %s (%s)", p[ParamBucketName], p[ParamRegion])
		},
		destructive: never,
	},

	// Disabling a service-account key is the GCP mirror of iam_key_disable
	// without the delete: Keys.Disable is reversible via Keys.Enable.
	ActionGCPSAKeyDisable: {
		connectorType: connector.TypeGCP,
		resolve: func(_ connector.Connector, params map[string]string) (map[string]string, error) {
			p := copyParams(params)
			if err := requireParams(ActionGCPSAKeyDisable, p, ParamServiceAccount, ParamKeyName); err != nil {
				return nil, err
			}
			return p, nil
		},
		describe: func(_ connector.Connector, p map[string]string) string {
			return fmt.Sprintf("disable GCP service account key %s on %s (reversible via Keys.Enable)",
				p[ParamKeyName], p[ParamServiceAccount])
		},
		destructive: never,
	},

	// Firewalls.Delete removes the whole rule, and the rule's definition (source
	// ranges, targets, ports) is NOT in the request — only its name is. Nothing
	// in the audit trail is sufficient to recreate it, and deleting an allow rule
	// can partition production. Gated.
	ActionGCPFirewallRemove: {
		connectorType: connector.TypeGCP,
		resolve: func(c connector.Connector, params map[string]string) (map[string]string, error) {
			p := copyParams(params)
			fallback(p, ParamProject, c.Config["project_id"])
			if err := requireParams(ActionGCPFirewallRemove, p, ParamFirewallRule, ParamProject); err != nil {
				return nil, err
			}
			return p, nil
		},
		describe: func(_ connector.Connector, p map[string]string) string {
			return fmt.Sprintf("DELETE GCP firewall rule %s in project %s (irreversible — the rule definition is not recoverable from this request)",
				p[ParamFirewallRule], p[ParamProject])
		},
		destructive: always,
	},

	// Same shape as the GCP firewall delete: the rule is identified by name, its
	// contents are destroyed, and removing an allow rule can partition a subnet.
	ActionAzureNSGRuleRemove: {
		connectorType: connector.TypeAzure,
		resolve: func(c connector.Connector, params map[string]string) (map[string]string, error) {
			p := copyParams(params)
			fallback(p, ParamSubscriptionID, c.Config["subscription_id"])
			if err := requireParams(ActionAzureNSGRuleRemove, p,
				ParamSubscriptionID, ParamResourceGroup, ParamNSGName, ParamRuleName); err != nil {
				return nil, err
			}
			return p, nil
		},
		describe: func(_ connector.Connector, p map[string]string) string {
			return fmt.Sprintf("DELETE Azure NSG rule %s from %s in resource group %s (subscription %s) — irreversible, the rule definition is not recoverable from this request",
				p[ParamRuleName], p[ParamNSGName], p[ParamResourceGroup], p[ParamSubscriptionID])
		},
		destructive: always,
	},
}

// awsInstanceParams is the shared resolver for the two EC2 instance actions.
func awsInstanceParams(action Action) func(connector.Connector, map[string]string) (map[string]string, error) {
	return func(c connector.Connector, params map[string]string) (map[string]string, error) {
		p := copyParams(params)
		fallback(p, ParamRegion, c.Config["region"])
		if err := requireParams(action, p, ParamInstanceID, ParamRegion); err != nil {
			return nil, err
		}
		if err := checkRegion(p); err != nil {
			return nil, err
		}
		return p, nil
	}
}

// awsRegionRE is the shape of every AWS partition's region names
// (us-east-1, us-gov-west-1, cn-north-1, us-isob-east-1, eu-isoe-west-1).
var awsRegionRE = regexp.MustCompile(`^[a-z]{2}(-(gov|iso[a-z]?))?-[a-z]+-[0-9]{1,2}$`)

// validAWSRegion reports whether region is shaped like an AWS region.
func validAWSRegion(region string) bool { return awsRegionRE.MatchString(region) }

// checkRegion refuses a region that is not an AWS region. The SDK builds the
// endpoint the execution role's SIGNED requests go to from it, and it is
// interpolated into the plan and the CLI line a person copies — and it can
// come from finding data, so a value like "eu-west-1.attacker.example" must
// never get that far.
func checkRegion(p map[string]string) error {
	if !validAWSRegion(p[ParamRegion]) {
		return fmt.Errorf("%w: region %q is not an AWS region", ErrBadParams, p[ParamRegion])
	}
	return nil
}

// copyParams returns a copy so a resolver's fallbacks never mutate the caller's
// map — the audit row records the params as SUBMITTED, not as resolved.
func copyParams(params map[string]string) map[string]string {
	out := make(map[string]string, len(params)+2)
	maps.Copy(out, params)
	return out
}

// fallback fills key from the connector config when the caller left it empty.
func fallback(p map[string]string, key, value string) {
	if p[key] == "" {
		p[key] = value
	}
}

// requireParams names every missing key at once, so an operator fixes one
// request instead of discovering the requirements one 400 at a time.
func requireParams(action Action, p map[string]string, keys ...string) error {
	var missing []string
	for _, k := range keys {
		if p[k] == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s requires %s", ErrBadParams, action, strings.Join(missing, ", "))
	}
	return nil
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

// Plan resolves req against the action registry and returns what it WOULD
// change, without contacting any cloud API. It is exported because the approval
// endpoint and the dry-run path both need the plan text before deciding
// anything, and because a caller wanting to show an operator the consequence of
// a request should never have to reach for Execute to find out.
func Plan(c connector.Connector, action Action, params map[string]string) (planned string, destructive bool, err error) {
	spec, ok := specs[action]
	if !ok {
		return "", false, fmt.Errorf("%w: unknown action %q", ErrCapabilityMissing, action)
	}
	if c.Type != spec.connectorType {
		return "", false, fmt.Errorf("%w: %s requires a %s connector, got %s",
			ErrCapabilityMissing, action, spec.connectorType, c.Type)
	}
	p, err := spec.resolve(c, params)
	if err != nil {
		return "", false, err
	}
	return spec.describe(c, p), spec.destructive(p), nil
}

// worldOpenCIDR returns the canonical form of cidr when it is 0.0.0.0/0 or
// ::/0, and ErrBadParams for any other value.
func worldOpenCIDR(cidr string) (string, error) {
	pfx, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || pfx.Bits() != 0 || !pfx.Addr().IsUnspecified() {
		return "", fmt.Errorf("%w: cidr: only 0.0.0.0/0 or ::/0 may be revoked, got %q", ErrBadParams, cidr)
	}
	return pfx.Masked().String(), nil
}
