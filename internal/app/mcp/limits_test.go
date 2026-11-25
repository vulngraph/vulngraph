package mcp

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/llm"
)

const graphQueryCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"graph_query","arguments":{"question":"q"}}}`

// graph_query makes up to two LLM calls per request: it spends from the
// per-user LLM limiter, keyed by user, and a spent bucket is refused before
// the tool runs. Cheap tools are untouched.
func TestGraphQuery_IsLimitedPerUser(t *testing.T) {
	h := NewHandler(fakeAssets{}, fakeFindings{}, fakeFindingCtx{}, fakeCompliance{}, fakeGraph{}, nil, nil, &fakeSuppress{}, nil, nil, nil).
		WithLimits(auth.NewKeyedLimiter(1, 1), unlimited{})

	require.Nil(t, rpcCtx(t, viewerCtx(), h, graphQueryCall).Error)
	resp := rpcCtx(t, viewerCtx(), h, graphQueryCall)
	require.NotNil(t, resp.Error)
	require.Equal(t, codeRateLimited, resp.Error.Code)
	require.Contains(t, resp.Error.Message, "retry in")

	require.Nil(t, rpcCtx(t, adminCtx(), h, graphQueryCall).Error, "another user has their own bucket")
	require.Nil(t, rpcCtx(t, viewerCtx(), h,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_compliance","arguments":{}}}`).Error)
}

func TestAlertContext_IsLimitedPerUser(t *testing.T) {
	h := NewHandler(fakeAssets{}, fakeFindings{}, fakeFindingCtx{}, fakeCompliance{}, fakeGraph{}, nil, nil, &fakeSuppress{}, nil, nil, nil).
		WithAlertContext(&fakeAlertCtx{}).WithLimits(unlimited{}, auth.NewKeyedLimiter(1, 1))
	call := toolCall(t, "get_alert_context", map[string]any{"identifiers": []string{"i-1"}})
	require.Nil(t, rpc(t, h, call).Error)
	resp := rpc(t, h, call)
	require.NotNil(t, resp.Error)
	require.Equal(t, codeRateLimited, resp.Error.Code)
}

// investigate_resource runs the same attribute scan as get_alert_context and
// spends from the same bucket.
func TestInvestigateResource_SharesTheAlertContextLimit(t *testing.T) {
	h := NewHandler(fakeAssets{}, fakeFindings{}, fakeFindingCtx{}, fakeCompliance{}, fakeGraph{}, nil, nil, &fakeSuppress{}, nil, nil, nil).
		WithAlertContext(&fakeAlertCtx{}).WithResourceResolver(fakeResolver{id: "i-1"}, fixedAsset{}, &filterAwareFindings{}).
		WithLimits(unlimited{}, auth.NewKeyedLimiter(1, 1))
	require.Nil(t, rpc(t, h, toolCall(t, "get_alert_context", map[string]any{"identifiers": []string{"i-1"}})).Error)
	resp := rpc(t, h, toolCall(t, "investigate_resource", map[string]any{"identifier": "i-1"}))
	require.NotNil(t, resp.Error)
	require.Equal(t, codeRateLimited, resp.Error.Code)
}

// An unwired limiter disables the tool rather than running it unlimited,
// and a costly tool needs a user to charge.
func TestLimitedTools_FailClosed(t *testing.T) {
	h := NewHandler(fakeAssets{}, fakeFindings{}, fakeFindingCtx{}, fakeCompliance{}, fakeGraph{}, nil, nil, &fakeSuppress{}, nil, nil, nil)
	resp := rpc(t, h, graphQueryCall)
	require.NotNil(t, resp.Error)
	require.Equal(t, codeRateLimited, resp.Error.Code)

	resp = rpcCtx(t, context.Background(), newHandler(), graphQueryCall)
	require.NotNil(t, resp.Error)
	require.Equal(t, codeForbidden, resp.Error.Code)
}

type budgetGraph struct {
	fakeGraph
	err error
}

func (g budgetGraph) Translate(context.Context, string) (explore.GraphQuerySpec, error) {
	return explore.GraphQuerySpec{}, g.err
}

func (g budgetGraph) TranslateAndRunCypher(context.Context, explore.CypherRunner, string, int, int) (explore.Result, string, error) {
	return explore.Result{}, "", g.err
}

// An LLM budget refusal is said plainly, not as "tool execution failed".
func TestGraphQuery_BudgetRefusalIsExplicit(t *testing.T) {
	g := budgetGraph{err: fmt.Errorf("translate: %w", llm.ErrBudgetExceeded)}
	h := NewHandler(fakeAssets{}, fakeFindings{}, fakeFindingCtx{}, fakeCompliance{}, g, &fakeCypher{}, nil, &fakeSuppress{}, nil, nil, nil).
		WithLimits(unlimited{}, unlimited{})
	resp := rpc(t, h, graphQueryCall)
	require.NotNil(t, resp.Error)
	require.Equal(t, codeRateLimited, resp.Error.Code)
	require.Contains(t, resp.Error.Message, "budget")
}
