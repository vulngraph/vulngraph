package chat

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/executor"
)

type countingLive struct {
	fakeDeps
	calls        int
	hours, limit int
}

func (c *countingLive) DescribeEC2Instance(context.Context, string, string) (map[string]any, error) {
	c.calls++
	return map[string]any{}, nil
}

func (c *countingLive) LookupCloudTrailEvents(_ context.Context, _, _ string, hours, limit int) ([]map[string]any, error) {
	c.calls++
	c.hours, c.limit = hours, limit
	return nil, nil
}

type auditSink struct {
	events []executor.AuditEvent
	err    error
}

func (a *auditSink) RecordAudit(_ context.Context, e executor.AuditEvent) error {
	a.events = append(a.events, e)
	return a.err
}

func userCtx(role auth.Role) context.Context {
	return auth.ContextWithUser(context.Background(), auth.User{ID: "u-" + string(role), Email: string(role) + "@x.example", Role: role})
}

func liveSvc(live *countingLive, audit *auditSink) *Service {
	return NewService(nil, fakeDeps{}, fakeDeps{}, fakeDeps{}).WithLiveCaller(live).WithConnectors(fakeDeps{}).WithAudit(audit)
}

const describeInput = `{"connector_id":"c1","resource":"i-1","action":"describe_instance"}`

func TestLiveTools_AdminOnlyByDefault(t *testing.T) {
	live, audit := &countingLive{}, &auditSink{}
	svc := liveSvc(live, audit)
	for _, ctx := range []context.Context{userCtx(auth.RoleViewer), userCtx(auth.RoleAnalyst), context.Background()} {
		for name, input := range map[string]string{
			"live_aws_describe": describeInput, "get_cloudtrail_events": `{"connector_id":"c1","resource_id":"i-1"}`, "list_connectors": `{}`,
		} {
			_, isErr := svc.callTool(ctx, name, input)
			require.True(t, isErr, name)
		}
		for _, tool := range svc.toolsFor(ctx) {
			require.False(t, liveTools[tool.Name], "%s is not offered to a non-admin", tool.Name)
		}
	}
	require.Zero(t, live.calls)
	require.Empty(t, audit.events)

	_, isErr := svc.callTool(userCtx(auth.RoleAdmin), "live_aws_describe", describeInput)
	require.False(t, isErr)
	require.Equal(t, 1, live.calls)
	require.Len(t, svc.toolsFor(userCtx(auth.RoleAdmin)), len(svc.toolDefs()))
}

func TestLiveTools_RoleIsConfigurable(t *testing.T) {
	live := &countingLive{}
	svc := liveSvc(live, &auditSink{}).WithLiveRole(auth.RoleAnalyst)
	_, isErr := svc.callTool(userCtx(auth.RoleAnalyst), "live_aws_describe", describeInput)
	require.False(t, isErr)
	_, isErr = svc.callTool(userCtx(auth.RoleViewer), "live_aws_describe", describeInput)
	require.True(t, isErr)
}

func TestLiveTools_AuditedBeforeTheRead(t *testing.T) {
	live, audit := &countingLive{}, &auditSink{}
	svc := liveSvc(live, audit)
	_, isErr := svc.callTool(userCtx(auth.RoleAdmin), "live_aws_describe", describeInput)
	require.False(t, isErr)
	require.Len(t, audit.events, 1)
	e := audit.events[0]
	require.Equal(t, auditActionLiveRead, e.Action)
	require.Equal(t, "c1", e.TargetID)
	var d map[string]any
	require.NoError(t, json.Unmarshal([]byte(e.Details), &d))
	require.Equal(t, "u-admin", d["actor_user_id"])

	audit.err = errors.New("clickhouse down")
	_, isErr = svc.callTool(userCtx(auth.RoleAdmin), "live_aws_describe", describeInput)
	require.True(t, isErr)
	require.Equal(t, 1, live.calls, "an unaudited read is refused")
}

func TestCloudTrail_BoundsHoursAndLimit(t *testing.T) {
	live := &countingLive{}
	svc := liveSvc(live, &auditSink{})
	_, isErr := svc.callTool(userCtx(auth.RoleAdmin), "get_cloudtrail_events", `{"connector_id":"c1","resource_id":"i-1","hours":-3,"limit":100000}`)
	require.False(t, isErr)
	require.Equal(t, 24, live.hours)
	require.Equal(t, 200, live.limit)

	_, _ = svc.callTool(userCtx(auth.RoleAdmin), "get_cloudtrail_events", `{"connector_id":"c1","resource_id":"i-1","hours":500,"limit":1}`)
	require.Equal(t, 72, live.hours)
	require.Equal(t, 1, live.limit)
}
