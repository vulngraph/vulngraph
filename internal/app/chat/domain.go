// Package chat serves a streaming LLM chat endpoint (provider chosen via
// internal/llm). Read-only tools: list_findings, get_asset, get_compliance,
// and, with WithCypher, run_cypher (graphquery.IsReadOnly-validated). With
// WithConnectors it adds list_connectors, and with WithLiveCaller
// live_aws_describe and get_cloudtrail_events, which make live, read-only AWS
// calls with connector credentials; these live tools are offered only at or
// above the live role and each call is audited (see live_gate.go and
// internal/app/mcp/live_aws.go).
package chat

import (
	"context"
	"errors"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/compliance"
	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Message is one turn in a conversation.
type Message struct {
	Role    string `json:"role"` // "user" | "assistant"
	Content string `json:"content"`
}

// ChatRequest is the JSON body accepted by POST /api/chat.
type ChatRequest struct {
	Messages []Message `json:"messages"`
	// Context is an optional, compact description of what the user is currently
	// looking at (a finding, an asset, a graph selection) — set when the chat is
	// opened from a detail view. It is injected as a per-request system block so
	// follow-up questions keep the context without the user re-pasting IDs.
	Context string `json:"context,omitempty"`
}

var ErrEmptyMessages = errors.New("chat: messages must not be empty")

// Tool interfaces — defined here so service.go can depend on them without
// importing concrete types from other domains.

type AssetReader interface {
	Get(ctx context.Context, id string) (asset.Asset, error)
	BlastRadius(ctx context.Context, seedID string, maxDepth int) (asset.BlastRadius, error)
}

type FindingLister interface {
	List(ctx context.Context, f finding.Filter) ([]finding.Finding, error)
}

type ComplianceReader interface {
	// Coverage returns the current CIS control coverage summary.
	Coverage(ctx context.Context) (compliance.Coverage, error)
}

type CypherRunner interface {
	RunCypher(ctx context.Context, query string) (explore.Result, error)
}

// LiveCaller makes real-time API calls to cloud providers using connector credentials.
// Used as a fallback when the graph doesn't have enough context — e.g. "is this
// SG rule still there?" or "what did this role do after the alert fired?".
// mcp.LiveAWSCallerImpl implements this for AWS; a nil value disables live tools.
type LiveCaller interface {
	DescribeEC2Instance(ctx context.Context, connectorID, instanceID string) (map[string]any, error)
	DescribeSecurityGroup(ctx context.Context, connectorID, sgID string) (map[string]any, error)
	ListRolePolicies(ctx context.Context, connectorID, roleName string) (map[string]any, error)
	DescribeBucket(ctx context.Context, connectorID, bucketName string) (map[string]any, error)
	LookupCloudTrailEvents(ctx context.Context, connectorID, resourceID string, hours, limit int) ([]map[string]any, error)
}

// ConnInfo is a minimal connector summary for the list_connectors tool.
type ConnInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	OK   bool   `json:"ok"`
}

// ConnectorLister lists available cloud connectors.
// connector.Service implements this via an adapter in serve.go.
type ConnectorLister interface {
	ListForChat(ctx context.Context) ([]ConnInfo, error)
}
