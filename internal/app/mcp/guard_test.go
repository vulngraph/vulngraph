package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/executor"
	"github.com/vulngraph/vulngraph/internal/app/explore"
)

type fakeCypher struct{ ran []string }

func (f *fakeCypher) RunCypher(_ context.Context, q string, _, _ int) (explore.Result, error) {
	f.ran = append(f.ran, q)
	return explore.Result{}, nil
}

type fakeExecutor struct{ calls int }

func (f *fakeExecutor) Execute(_ context.Context, req executor.ExecutionRequest) (executor.ExecutionResult, error) {
	f.calls++
	return executor.ExecutionResult{ConnectorID: req.ConnectorID, Action: req.Action}, nil
}

func toolCall(t *testing.T, name string, args map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args},
	})
	require.NoError(t, err)
	return string(b)
}

// run_cypher must never hand a write, DDL or IO statement to the engine, for
// any role — including admin.
func TestToolsCall_RunCypher_RejectsWrites(t *testing.T) {
	writes := []string{
		"CREATE (n:Asset {id: 'x'}) RETURN n",
		"MERGE (n:Asset {id: 'x'}) RETURN n",
		"MATCH (n:Asset) DETACH DELETE n",
		"MATCH (n:Asset) SET n.risk_score = 0 RETURN n",
		"MATCH (n:Asset) REMOVE n.name RETURN n",
		"MATCH (n:Asset) RETURN n; CREATE (m:Asset {id: 'y'})",
		"LOAD FROM 'http://evil.example/x.csv' RETURN *",
		"MATCH (`n\\`) DETACH DELETE n RETURN 1",
	}
	for _, q := range writes {
		t.Run(q, func(t *testing.T) {
			cy := &fakeCypher{}
			h := NewHandler(fakeAssets{}, fakeFindings{}, fakeFindingCtx{}, fakeCompliance{}, fakeGraph{}, cy, nil, &fakeSuppress{}, nil, nil, nil).WithCypherLimit(unlimited{})
			resp := rpcCtx(t, adminCtx(), h, toolCall(t, "run_cypher", map[string]any{"query": q}))
			require.NotNil(t, resp.Error, "write query must be rejected")
			require.Empty(t, cy.ran, "write query must not reach the engine")
		})
	}
}

func TestToolsCall_RunCypher_AllowsRead(t *testing.T) {
	cy := &fakeCypher{}
	h := NewHandler(fakeAssets{}, fakeFindings{}, fakeFindingCtx{}, fakeCompliance{}, fakeGraph{}, cy, nil, &fakeSuppress{}, nil, nil, nil).WithCypherLimit(unlimited{})
	q := "MATCH (r:IamRole)-[:CanAssume]->(b:IamRole) RETURN r, b LIMIT 20"
	resp := rpcCtx(t, viewerCtx(), h, toolCall(t, "run_cypher", map[string]any{"query": q}))
	require.Nil(t, resp.Error)
	require.Equal(t, []string{q}, cy.ran)
}

func TestToolsCall_RunCypher_IsRateLimitedPerUser(t *testing.T) {
	cy := &fakeCypher{}
	h := NewHandler(fakeAssets{}, fakeFindings{}, fakeFindingCtx{}, fakeCompliance{}, fakeGraph{}, cy, nil, &fakeSuppress{}, nil, nil, nil).
		WithCypherLimit(auth.NewKeyedLimiter(1, 1))
	call := toolCall(t, "run_cypher", map[string]any{"query": "MATCH (n:Asset) RETURN n LIMIT 1"})
	require.Nil(t, rpcCtx(t, viewerCtx(), h, call).Error)
	resp := rpcCtx(t, viewerCtx(), h, call)
	require.NotNil(t, resp.Error)
	require.Equal(t, codeRateLimited, resp.Error.Code)
	require.Len(t, cy.ran, 1, "the limited call must not reach the engine")
}

func TestToolsCall_RunCypher_DisabledWithoutLimiter(t *testing.T) {
	cy := &fakeCypher{}
	h := NewHandler(fakeAssets{}, fakeFindings{}, fakeFindingCtx{}, fakeCompliance{}, fakeGraph{}, cy, nil, &fakeSuppress{}, nil, nil, nil)
	resp := rpcCtx(t, viewerCtx(), h, toolCall(t, "run_cypher", map[string]any{"query": "MATCH (n:Asset) RETURN n LIMIT 1"}))
	require.NotNil(t, resp.Error)
	require.Equal(t, codeRateLimited, resp.Error.Code)
	require.Empty(t, cy.ran)
}

func TestToolsCall_ExecuteAction_AdminOnly(t *testing.T) {
	args := map[string]any{"connector_id": "c1", "action": "ec2_stop", "reason": "test",
		"params": map[string]any{"instance_id": "i-1", "region": "us-east-1"}}
	for name, ctx := range map[string]context.Context{
		"viewer":          viewerCtx(),
		"unauthenticated": context.Background(),
	} {
		t.Run(name, func(t *testing.T) {
			ex := &fakeExecutor{}
			h := NewHandler(fakeAssets{}, fakeFindings{}, fakeFindingCtx{}, fakeCompliance{}, fakeGraph{}, nil, nil, &fakeSuppress{}, nil, nil, ex)
			resp := rpcCtx(t, ctx, h, toolCall(t, "execute_action", args))
			require.NotNil(t, resp.Error)
			require.Equal(t, codeForbidden, resp.Error.Code)
			require.Zero(t, ex.calls, "executor must not run for a non-admin")
		})
	}

	ex := &fakeExecutor{}
	h := NewHandler(fakeAssets{}, fakeFindings{}, fakeFindingCtx{}, fakeCompliance{}, fakeGraph{}, nil, nil, &fakeSuppress{}, nil, nil, ex)
	args["approval_token"] = "grant-from-another-admin"
	resp := rpcCtx(t, adminCtx(), h, toolCall(t, "execute_action", args))
	require.Nil(t, resp.Error)
	require.Equal(t, 1, ex.calls)
}
