package mcp

// The tools that reach a real cloud account: execute_action (mutations) and
// the live read tools. Both are gated beyond "authenticated": an MCP client is
// usually an LLM reading attacker-influenceable data, so a mutation needs a
// human's grant and a live read needs the configured role and leaves an audit
// row.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/executor"
)

// Auditor appends to the shared audit trail. *executor.CHAuditRepo implements it.
type Auditor interface {
	RecordAudit(ctx context.Context, e executor.AuditEvent) error
}

// Live read bounds: what one tool call may ask a cloud API for.
const (
	defaultTrailHours = 24
	maxTrailHours     = 72
	defaultTrailLimit = 50
	maxTrailLimit     = 200
)

// auditActionLiveRead is the audit_events action for a live cloud read.
const auditActionLiveRead = "mcp.live_read"

// errGrantRequired is returned when execute_action is asked to mutate without
// a grant. It is surfaced to the client verbatim: it tells the human what to do.
var errGrantRequired = errors.New("execute_action needs an approval_token minted by a different admin " +
	"(POST /api/executor/approvals with \"agent\": true for the exact connector, action and params); " +
	"use dry_run to preview the plan without one")

// WithAudit attaches the audit sink for live cloud reads.
func (h *Handler) WithAudit(a Auditor) *Handler {
	h.audit = a
	return h
}

// WithLiveRole sets the minimum role for the live cloud tools (admin by default).
func (h *Handler) WithLiveRole(r auth.Role) *Handler {
	h.liveRole = r
	return h
}

// allowedLive reports whether the caller may use the live cloud tools.
func (h *Handler) allowedLive(ctx context.Context) (auth.User, bool) {
	u, ok := auth.UserFromContext(ctx)
	if !ok || !u.Role.Valid() {
		return auth.User{}, false
	}
	need := h.liveRole
	if !need.Valid() {
		need = auth.RoleAdmin // fail closed on an unset or unknown role
	}
	return u, u.Role.Privilege() >= need.Privilege()
}

// liveGate checks the role and writes the audit row BEFORE the read. A read
// that cannot be audited is refused: live cloud data is the one thing these
// tools return that the graph does not already hold.
func (h *Handler) liveGate(ctx context.Context, tool, connectorID string, args map[string]any) error {
	u, ok := h.allowedLive(ctx)
	if !ok {
		return errForbidden
	}
	if h.audit == nil {
		return nil
	}
	details, err := json.Marshal(map[string]any{"tool": tool, "args": args, "actor_user_id": u.ID})
	if err != nil {
		return fmt.Errorf("%s: audit: %w", tool, err)
	}
	actor := u.Email
	if actor == "" {
		actor = executor.AuditActorUnknown
	}
	if err := h.audit.RecordAudit(ctx, executor.AuditEvent{
		TS: time.Now().UTC(), Actor: actor, Action: auditActionLiveRead,
		TargetType: executor.AuditTargetConnector, TargetID: connectorID, Details: string(details),
	}); err != nil {
		return fmt.Errorf("%s: audit write failed, read refused: %w", tool, err)
	}
	return nil
}

// clamp bounds v to [lo, hi], using def when v was not given (<= 0).
func clamp(v, def, lo, hi int) int {
	if v <= 0 {
		v = def
	}
	return max(lo, min(v, hi))
}

func (h *Handler) registerExecuteAction(exec ActionExecutor) {
	h.register(tool{
		Name: "execute_action",
		Description: "Execute a cloud remediation action on a connector. Connector must be read_write mode. " +
			"Admin only, and every real execution needs an approval_token minted by a DIFFERENT admin " +
			"(POST /api/executor/approvals with agent=true); without one only dry_run=true is accepted. " +
			"Available actions: " +
			"sg_rule_remove (AWS — revoke SG ingress rule, params: group_id, region, protocol, from_port, to_port, cidr), " +
			"iam_key_disable (AWS — disable IAM key, params: key_id, username, region, delete_key), " +
			"ec2_stop (AWS — stop instance, params: instance_id, region), " +
			"ec2_start (AWS — start instance, params: instance_id, region), " +
			"s3_block_public (AWS — block all public access on bucket, params: bucket_name, region), " +
			"gcp_sa_key_disable (GCP — disable SA key, params: service_account, key_name), " +
			"gcp_firewall_remove (GCP — delete firewall rule, params: firewall_rule, project), " +
			"azure_nsg_rule_remove (Azure — delete NSG rule, params: subscription_id, resource_group, nsg_name, rule_name). " +
			"Always call get_finding_context or investigate_resource FIRST to confirm the issue is real before executing.",
		InputSchema: objSchema(map[string]any{
			"connector_id": strProp("the connector ID to execute the action against"),
			"action":       strProp("the action to perform (see description for list)"),
			"params": map[string]any{
				"type":                 "object",
				"description":          "action-specific parameters (see description for each action's required params)",
				"additionalProperties": map[string]any{"type": "string"},
			},
			"reason":         strProp("why this action is being taken (for the audit trail)"),
			"dry_run":        map[string]any{"type": "boolean", "description": "describe the change without making it; needs no approval"},
			"approval_token": strProp("grant from a different admin for exactly this connector, action and params"),
		}, "connector_id", "action", "reason"),
		handler: func(ctx context.Context, args map[string]any) (any, error) {
			user, ok := auth.UserFromContext(ctx)
			if !ok || user.Role != auth.RoleAdmin {
				return nil, errForbidden
			}
			connID, _ := args["connector_id"].(string)
			action, _ := args["action"].(string)
			reason, _ := args["reason"].(string)
			dryRun, _ := args["dry_run"].(bool)
			token, _ := args["approval_token"].(string)
			rawParams, _ := args["params"].(map[string]any)
			params := make(map[string]string, len(rawParams))
			for k, v := range rawParams {
				if sv, ok := v.(string); ok {
					params[k] = sv
				}
			}
			if connID == "" || action == "" {
				return nil, errors.New("execute_action: connector_id and action are required")
			}
			if reason == "" {
				return nil, errors.New("execute_action: reason is required (audit trail)")
			}
			if !dryRun && token == "" {
				return nil, errGrantRequired
			}
			result, err := exec.Execute(ctx, executor.ExecutionRequest{
				ConnectorID:   connID,
				Action:        executor.Action(action),
				Params:        params,
				DryRun:        dryRun,
				ApprovalToken: token,
				RequireGrant:  true,
				Reason:        reason,
			})
			if errors.Is(err, executor.ErrApprovalRequired) || errors.Is(err, executor.ErrApprovalInvalid) {
				return nil, fmt.Errorf("%w: %v", errGrantRequired, err)
			}
			if err != nil {
				return nil, fmt.Errorf("execute_action: %w", err)
			}
			return map[string]any{
				"connector_id": result.ConnectorID,
				"action":       string(result.Action),
				"detail":       result.Detail,
				"dry_run":      result.DryRun,
				"reason":       reason,
				"actor":        user.Email,
			}, nil
		},
	})
}

func (h *Handler) registerLiveTools(liveAWS LiveAWSCaller, connectors ConnectorLister) {
	if liveAWS != nil {
		h.register(tool{
			Name:        "live_aws_describe",
			Description: "Query AWS live in real-time using a connector's credentials (admin by default; every call is audited). Supports: describe_instance (EC2), describe_security_group, list_role_policies (IAM), list_attached_role_policies, describe_bucket (S3). Returns fresh data, not cached scan results. Use for alert investigation when you need current state — e.g. 'is this SG rule still there?', 'what policies does this role currently have?'",
			InputSchema: objSchema(map[string]any{
				"connector_id": strProp("which AWS connector to use (use list_connectors if unsure)"),
				"resource":     strProp("the resource identifier: instance ID, SG ID, role name, bucket name, or ARN"),
				"action":       strProp("one of: describe_instance, describe_security_group, list_role_policies, list_attached_role_policies, describe_bucket"),
			}, "connector_id", "resource", "action"),
			handler: func(ctx context.Context, args map[string]any) (any, error) {
				connectorID, _ := args["connector_id"].(string)
				resource, _ := args["resource"].(string)
				action, _ := args["action"].(string)
				if connectorID == "" || resource == "" || action == "" {
					return nil, errors.New("live_aws_describe: connector_id, resource, and action are required")
				}
				var call func(context.Context, string, string) (map[string]any, error)
				switch action {
				case "describe_instance":
					call = liveAWS.DescribeEC2Instance
				case "describe_security_group":
					call = liveAWS.DescribeSecurityGroup
				case "list_role_policies", "list_attached_role_policies":
					call = liveAWS.ListRolePolicies
				case "describe_bucket":
					call = liveAWS.DescribeBucket
				default:
					return nil, fmt.Errorf("live_aws_describe: unknown action %q; valid: describe_instance, describe_security_group, list_role_policies, list_attached_role_policies, describe_bucket", action)
				}
				if err := h.liveGate(ctx, "live_aws_describe", connectorID, args); err != nil {
					return nil, err
				}
				return call(ctx, connectorID, resource)
			},
		})

		h.register(tool{
			Name:        "get_cloudtrail_events",
			Description: "Get recent CloudTrail API events for a specific resource or principal (admin by default; every call is audited). Shows what AWS API calls were made by or to this resource in the last N hours, including the caller's source_ip and principal_arn. Critical for GuardDuty alert investigation — tells you what the resource DID after compromise. NOTE: CloudTrail's LookupEvents API cannot filter by source IP; to scope by attacker IP, fetch by principal here and match on the returned source_ip, or query CloudTrail Lake/Athena for a full sweep.",
			InputSchema: objSchema(map[string]any{
				"connector_id": strProp("which AWS connector to use"),
				"resource_id":  strProp("instance ID, role name, role ARN, or user ARN (NOT an IP address — CloudTrail cannot look up by IP)"),
				"hours":        intProp("lookback window in hours (default 24, 1-72)"),
				"limit":        intProp("max events to return (default 50, 1-200)"),
			}, "connector_id", "resource_id"),
			handler: func(ctx context.Context, args map[string]any) (any, error) {
				connectorID, _ := args["connector_id"].(string)
				resourceID, _ := args["resource_id"].(string)
				if connectorID == "" || resourceID == "" {
					return nil, errors.New("get_cloudtrail_events: connector_id and resource_id are required")
				}
				hours := clamp(intArg(args, "hours", 0), defaultTrailHours, 1, maxTrailHours)
				limit := clamp(intArg(args, "limit", 0), defaultTrailLimit, 1, maxTrailLimit)
				if err := h.liveGate(ctx, "get_cloudtrail_events", connectorID, args); err != nil {
					return nil, err
				}
				events, err := liveAWS.LookupCloudTrailEvents(ctx, connectorID, resourceID, hours, limit)
				if err != nil {
					return nil, fmt.Errorf("get_cloudtrail_events: %w", err)
				}
				return map[string]any{"events": events, "count": len(events)}, nil
			},
		})
	}

	if connectors != nil {
		h.register(tool{
			Name:        "list_connectors",
			Description: "List every connector (any provider, enabled or disabled) with its ID, type, enabled flag and sync status (admin by default). Use to find the right connector_id for live_aws_describe or get_cloudtrail_events.",
			InputSchema: objSchema(nil),
			handler: func(ctx context.Context, _ map[string]any) (any, error) {
				if err := h.liveGate(ctx, "list_connectors", "", nil); err != nil {
					return nil, err
				}
				all, err := connectors.List(ctx, false)
				if err != nil {
					return nil, fmt.Errorf("list_connectors: %w", err)
				}
				out := make([]map[string]any, 0, len(all))
				for _, c := range all {
					lastSynced := ""
					if c.LastSyncedAt != nil {
						lastSynced = c.LastSyncedAt.String()
					}
					out = append(out, map[string]any{
						"id":             c.ID,
						"name":           c.Name,
						"type":           string(c.Type),
						"enabled":        c.Enabled,
						"sync_status":    string(c.SyncStatus),
						"last_synced_at": lastSynced,
					})
				}
				return map[string]any{"connectors": out, "count": len(out)}, nil
			},
		})
	}
}
