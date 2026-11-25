package executor

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/connector"
)

func rwConnector(t connector.Type, cfg map[string]string) connector.Connector {
	return connector.Connector{ID: "conn-1", Type: t, Mode: connector.ModeReadWrite, Config: cfg}
}

// allActions is every Action the domain declares. A new action that forgets a
// spec is unreachable AND unclassified — it would have no dry-run, no approval
// decision and no connector-type check.
var allActions = []Action{
	ActionSGRuleRemove, ActionIAMKeyDisable, ActionEC2Stop, ActionEC2Start,
	ActionS3BlockPublic, ActionGCPSAKeyDisable, ActionGCPFirewallRemove, ActionAzureNSGRuleRemove,
}

func TestRegistry_CoversEveryDeclaredAction(t *testing.T) {
	for _, a := range allActions {
		spec, ok := specs[a]
		require.Truef(t, ok, "action %q has no actionSpec — it can never run", a)
		require.NotNil(t, spec.resolve, "%s has no resolver", a)
		require.NotNil(t, spec.describe, "%s has no description", a)
		require.NotNil(t, spec.destructive, "%s has no destructiveness decision", a)
	}
	require.Len(t, specs, len(allActions), "specs and allActions have drifted")
}

// The destructive set is a deliberate minority, and every row applies the one
// rule on plan.go's never: gated when the action destroys state nothing in the
// request or audit row restores, or undoes a containment — never because it can
// cause an outage. Pinned by name in both directions so widening it (approval
// fatigue) or narrowing it (a silent un-gating of ec2_stop) is a test change
// someone has to justify.
func TestDestructiveSubset_IsExactlyTheIrreversibleActions(t *testing.T) {
	cases := []struct {
		action Action
		params map[string]string
		want   bool
		why    string
	}{
		{ActionSGRuleRemove, nil, false, "can cut a public load balancer, but the revoked rule's access is fully specified in the request — re-adding it is a copy (its description is not kept)"},
		{ActionIAMKeyDisable, nil, false, "can break the job using the key, but UpdateAccessKey Active restores it exactly"},
		{ActionIAMKeyDisable, map[string]string{ParamDeleteKey: "true"}, true, "delete destroys the key record — anti-forensics"},
		{ActionEC2Stop, nil, true, "destroys memory, instance-store data and an auto-assigned public IP that a start does not restore"},
		{ActionEC2Start, nil, true, "undoes a containment: brings back a host that may have been stopped to contain it"},
		{ActionS3BlockPublic, nil, false, "can break a public website, but the audit row records the earlier bucket-level block, and re-applying (or deleting) it restores it exactly"},
		{ActionGCPSAKeyDisable, nil, false, "can break the job using the key, but Keys.Enable restores it exactly"},
		{ActionGCPFirewallRemove, nil, true, "the rule definition is destroyed and is not in the request"},
		{ActionAzureNSGRuleRemove, nil, true, "the rule definition is destroyed and is not in the request"},
	}
	require.Len(t, cases, len(allActions)+1, "every action must have a stated destructiveness")

	for _, tc := range cases {
		got := specs[tc.action].destructive(tc.params)
		require.Equalf(t, tc.want, got, "%s destructive=%v, want %v — %s", tc.action, got, tc.want, tc.why)
	}
}

func TestPlan_RejectsWrongConnectorType(t *testing.T) {
	_, _, err := Plan(rwConnector(connector.TypeGCP, nil), ActionEC2Stop, map[string]string{
		ParamInstanceID: "i-1", ParamRegion: "eu-west-1",
	})
	require.ErrorIs(t, err, ErrCapabilityMissing)
}

func TestPlan_RejectsUnknownAction(t *testing.T) {
	_, _, err := Plan(rwConnector(connector.TypeAWS, nil), Action("rm_-rf"), nil)
	require.ErrorIs(t, err, ErrCapabilityMissing)
}

func TestPlan_NamesEveryMissingParamAtOnce(t *testing.T) {
	_, _, err := Plan(rwConnector(connector.TypeAWS, nil), ActionSGRuleRemove, map[string]string{
		ParamGroupID: "sg-1",
	})
	require.ErrorIs(t, err, ErrBadParams)
	for _, want := range []string{ParamRegion, ParamProtocol, ParamCIDR} {
		require.Contains(t, err.Error(), want)
	}
}

func TestPlan_AppliesConnectorConfigFallbacksWithoutMutatingTheRequest(t *testing.T) {
	params := map[string]string{ParamInstanceID: "i-abc"}
	planned, _, err := Plan(rwConnector(connector.TypeAWS, map[string]string{"region": "eu-west-1"}), ActionEC2Stop, params)
	require.NoError(t, err)
	require.Contains(t, planned, "eu-west-1")

	// The audit row records what was SUBMITTED; a resolver that wrote back into
	// the caller's map would silently rewrite the evidence.
	require.Equal(t, map[string]string{ParamInstanceID: "i-abc"}, params)
}

func TestPlan_DescribesIrreversibilityForTheDeleteVariant(t *testing.T) {
	c := rwConnector(connector.TypeAWS, map[string]string{"region": "eu-west-1"})
	base := map[string]string{ParamKeyID: "AKIA1", ParamUsername: "deploy"}

	disable, destructive, err := Plan(c, ActionIAMKeyDisable, base)
	require.NoError(t, err)
	require.False(t, destructive)
	require.Contains(t, disable, "reversible")

	del := map[string]string{ParamKeyID: "AKIA1", ParamUsername: "deploy", ParamDeleteKey: "true"}
	deleted, destructive, err := Plan(c, ActionIAMKeyDisable, del)
	require.NoError(t, err)
	require.True(t, destructive)
	require.Contains(t, deleted, "DELETE")
	require.NotEqual(t, disable, deleted, "the two variants must not share a plan — a grant for one would authorise the other")
}

// ---- dry run ----

// The whole point: a dry run resolves the entire chain and reports the change
// without touching the cloud. The connector below has NO execution role, so any
// real call fails at credential build — a dry run that succeeds here proves it
// never got that far.
func TestExecute_DryRunReportsThePlanAndChangesNothing(t *testing.T) {
	audit := &fakeAuditor{}
	svc := NewService(&fakeConnectors{c: rwConnector(connector.TypeAWS, map[string]string{"region": "eu-west-1"})}).
		WithAudit(audit)

	res, err := svc.Execute(adminCtx("ops@example.com"), ExecutionRequest{
		ConnectorID: "conn-1",
		Action:      ActionSGRuleRemove,
		Params: map[string]string{
			ParamGroupID: "sg-1", ParamRegion: "eu-west-1",
			ParamProtocol: "tcp", ParamFromPort: "22", ParamToPort: "22", ParamCIDR: "0.0.0.0/0",
		},
		DryRun: true,
	})
	require.NoError(t, err)
	require.True(t, res.DryRun)
	require.False(t, res.Destructive)
	require.True(t, strings.HasPrefix(res.Detail, "DRY RUN — nothing was changed."),
		"the response must say up front that nothing changed, got %q", res.Detail)
	require.Contains(t, res.Detail, "sg-1")
	require.Contains(t, res.Detail, "0.0.0.0/0")

	require.Len(t, audit.events, 1)
	require.Equal(t, AuditActionDryRun, audit.events[0].Action,
		"a dry run must not be recorded as an execution")
}

// A dry run of a destructive action must succeed (that is how an operator finds
// out what it does) and must say the approval is coming.
func TestExecute_DryRunOfDestructiveActionNeedsNoApprovalButSaysSo(t *testing.T) {
	svc := NewService(&fakeConnectors{c: rwConnector(connector.TypeAWS, map[string]string{"region": "eu-west-1"})})

	res, err := svc.Execute(adminCtx("ops@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionEC2Stop,
		Params: map[string]string{ParamInstanceID: "i-abc"},
		DryRun: true,
	})
	require.NoError(t, err)
	require.True(t, res.DryRun)
	require.True(t, res.Destructive)
	require.Contains(t, res.Detail, "approval grant from a second admin")
}

func TestExecute_DryRunStillRejectsBadParams(t *testing.T) {
	svc := NewService(&fakeConnectors{c: rwConnector(connector.TypeAWS, nil)})
	_, err := svc.Execute(adminCtx("ops@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionEC2Stop, DryRun: true,
	})
	require.ErrorIs(t, err, ErrBadParams)
}

func TestExecute_DryRunAuditRecordsTheSubmittedParams(t *testing.T) {
	audit := &fakeAuditor{}
	svc := NewService(&fakeConnectors{c: rwConnector(connector.TypeAWS, map[string]string{"region": "eu-west-1"})}).
		WithAudit(audit)
	_, err := svc.Execute(adminCtx("ops@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionEC2Stop,
		Params: map[string]string{ParamInstanceID: "i-abc"},
		DryRun: true,
	})
	require.NoError(t, err)

	var details map[string]any
	require.NoError(t, json.Unmarshal([]byte(audit.events[0].Details), &details))
	require.Equal(t, map[string]any{ParamInstanceID: "i-abc"}, details["params"])
}

// The region picks the endpoint the execution role's signed requests go to
// and is interpolated into the plan and the CLI line a person copies. It can
// come from finding data, so anything that is not an AWS region is refused.
func TestValidAWSRegion(t *testing.T) {
	for _, ok := range []string{"us-east-1", "eu-west-1", "ap-southeast-4", "us-gov-west-1", "cn-north-1",
		"il-central-1", "us-iso-east-1", "us-isob-east-1", "eu-isoe-west-1", "us-isof-south-1"} {
		require.Truef(t, validAWSRegion(ok), "%q is an AWS region", ok)
	}
	for _, bad := range []string{"", "eu-west", "EU-WEST-1", "eu-west-1.evil.com", "evil.com/eu-west-1",
		"eu-west-1 ", "eu-west-1;id", "eu-west-1#", "westeurope", "europe-west1", "us-east-1a", "eu-west-123"} {
		require.Falsef(t, validAWSRegion(bad), "%q must not pass as an AWS region", bad)
	}
}

func TestPlan_RejectsMalformedRegionOnEveryAWSAction(t *testing.T) {
	params := map[Action]map[string]string{
		ActionSGRuleRemove:  {ParamGroupID: "sg-1", ParamProtocol: "tcp", ParamCIDR: "0.0.0.0/0"},
		ActionIAMKeyDisable: {ParamKeyID: "AKIA1", ParamUsername: "u"},
		ActionEC2Stop:       {ParamInstanceID: "i-1"},
		ActionEC2Start:      {ParamInstanceID: "i-1"},
		ActionS3BlockPublic: {ParamBucketName: "b"},
	}
	for _, a := range allActions {
		if specs[a].connectorType != connector.TypeAWS {
			continue
		}
		p, ok := params[a]
		require.Truef(t, ok, "%s is an AWS action with no region case here", a)
		p[ParamRegion] = "eu-west-1.attacker.example"
		_, _, err := Plan(rwConnector(connector.TypeAWS, nil), a, p)
		require.ErrorIsf(t, err, ErrBadParams, "%s accepted a malformed region", a)

		delete(p, ParamRegion)
		_, _, err = Plan(rwConnector(connector.TypeAWS, map[string]string{"region": "x/../y"}), a, p)
		require.ErrorIsf(t, err, ErrBadParams, "%s accepted a malformed connector-default region", a)

		p[ParamRegion] = "eu-west-1"
		_, _, err = Plan(rwConnector(connector.TypeAWS, nil), a, p)
		require.NoErrorf(t, err, "%s refused a valid region", a)
	}
}

// sg_rule_remove is not gated, so it may only revoke a world-open rule: any
// narrower CIDR is refused before a dry run or execution can describe it.
func TestPlan_SGRuleRemoveOnlyRevokesWorldOpenRules(t *testing.T) {
	c := rwConnector(connector.TypeAWS, map[string]string{"region": "eu-west-1"})
	base := map[string]string{
		ParamGroupID: "sg-1", ParamRegion: "eu-west-1",
		ParamProtocol: "tcp", ParamFromPort: "22", ParamToPort: "22",
	}
	for _, ok := range []string{"0.0.0.0/0", "::/0", " 0.0.0.0/0 "} {
		p := copyParams(base)
		p[ParamCIDR] = ok
		got, err := specs[ActionSGRuleRemove].resolve(c, p)
		require.NoErrorf(t, err, "%q is world-open", ok)
		require.Contains(t, []string{"0.0.0.0/0", "::/0"}, got[ParamCIDR])
	}
	for _, bad := range []string{"10.0.0.0/8", "0.0.0.0/1", "203.0.113.7/32", "::/1", "2001:db8::/32", "0.0.0.0", "any"} {
		p := copyParams(base)
		p[ParamCIDR] = bad
		_, err := specs[ActionSGRuleRemove].resolve(c, p)
		require.ErrorIsf(t, err, ErrBadParams, "%q must be refused", bad)
	}
}
