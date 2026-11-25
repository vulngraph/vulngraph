package connector

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/diskscan"
)

var (
	adminActor = DiskScanActor{ID: "u-admin", Admin: true}

	awsDiskCfg = map[string]string{
		"role_arn": "arn:aws:iam::1:role/collect", "readonly_role_arn": "arn:aws:iam::1:role/ro",
		"execute_role_arn": "arn:aws:iam::1:role/exec", "region": "eu-west-1",
		ConfigDiskScanRoleARN: "arn:aws:iam::1:role/disk",
	}
)

func withCfg(base map[string]string, kv ...string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == "" {
			delete(out, kv[i])
		} else {
			out[kv[i]] = kv[i+1]
		}
	}
	return out
}

func TestSetDiskScanMode_Refusals(t *testing.T) {
	tests := []struct {
		name  string
		typ   Type
		cfg   map[string]string
		mode  diskscan.DiskScanMode
		conf  string
		actor DiskScanActor
		want  error
	}{
		{"analyst", TypeAWS, awsDiskCfg, diskscan.DiskScanModeCreateSnapshots, DiskScanConfirmation, DiskScanActor{ID: "u", Admin: false}, ErrDiskScanForbidden},
		{"admin via api key", TypeAWS, awsDiskCfg, diskscan.DiskScanModeCreateSnapshots, DiskScanConfirmation, DiskScanActor{ID: "u", Admin: true, ViaAPIKey: true}, ErrDiskScanForbidden},
		{"api key may not even turn it off", TypeAWS, awsDiskCfg, diskscan.DiskScanModeOff, "", DiskScanActor{ID: "u", Admin: true, ViaAPIKey: true}, ErrDiskScanForbidden},
		{"zero actor", TypeAWS, awsDiskCfg, diskscan.DiskScanModeExistingSnapshots, DiskScanConfirmation, DiskScanActor{}, ErrDiskScanForbidden},
		{"bogus mode", TypeAWS, awsDiskCfg, "bogus", DiskScanConfirmation, adminActor, ErrDiskScanInvalidMode},
		{"no confirmation", TypeAWS, awsDiskCfg, diskscan.DiskScanModeCreateSnapshots, "", adminActor, ErrDiskScanConfirmation},
		{"wrong confirmation", TypeAWS, awsDiskCfg, diskscan.DiskScanModeExistingSnapshots, "yes", adminActor, ErrDiskScanConfirmation},
		{"empty role", TypeAWS, withCfg(awsDiskCfg, ConfigDiskScanRoleARN, ""), diskscan.DiskScanModeCreateSnapshots, DiskScanConfirmation, adminActor, ErrDiskScanRoleMissing},
		{"role equals role_arn", TypeAWS, withCfg(awsDiskCfg, ConfigDiskScanRoleARN, "arn:aws:iam::1:role/collect"), diskscan.DiskScanModeCreateSnapshots, DiskScanConfirmation, adminActor, ErrDiskScanRoleShared},
		{"role equals readonly_role_arn", TypeAWS, withCfg(awsDiskCfg, ConfigDiskScanRoleARN, "arn:aws:iam::1:role/ro"), diskscan.DiskScanModeCreateSnapshots, DiskScanConfirmation, adminActor, ErrDiskScanRoleShared},
		{"role equals execute_role_arn", TypeAWS, withCfg(awsDiskCfg, ConfigDiskScanRoleARN, "arn:aws:iam::1:role/exec"), diskscan.DiskScanModeCreateSnapshots, DiskScanConfirmation, adminActor, ErrDiskScanRoleShared},
		{"shared role refused even for existing_snapshots", TypeAWS, withCfg(awsDiskCfg, ConfigDiskScanRoleARN, "arn:aws:iam::1:role/exec"), diskscan.DiskScanModeExistingSnapshots, DiskScanConfirmation, adminActor, ErrDiskScanRoleShared},
		{"azure existing_snapshots needs the principal", TypeAzure, map[string]string{"subscription_id": "s", "client_id": "c1"}, diskscan.DiskScanModeExistingSnapshots, DiskScanConfirmation, adminActor, ErrDiskScanRoleMissing},
		{"azure existing_snapshots principal shared", TypeAzure, map[string]string{"subscription_id": "s", "client_id": "c1", ConfigDiskScanClientID: "c1"}, diskscan.DiskScanModeExistingSnapshots, DiskScanConfirmation, adminActor, ErrDiskScanRoleShared},
		{"azure client id shared", TypeAzure, map[string]string{"subscription_id": "s", "client_id": "c1", ConfigDiskScanClientID: "c1"}, diskscan.DiskScanModeCreateSnapshots, DiskScanConfirmation, adminActor, ErrDiskScanRoleShared},
		{"azure execute client shared", TypeAzure, map[string]string{"subscription_id": "s", "execute_client_id": "c2", ConfigDiskScanClientID: "c2"}, diskscan.DiskScanModeCreateSnapshots, DiskScanConfirmation, adminActor, ErrDiskScanRoleShared},
		{"gcp execute sa shared", TypeGCP, map[string]string{"project_id": "p", "execute_service_account": "sa@p", ConfigDiskScanServiceAccount: "sa@p"}, diskscan.DiskScanModeCreateSnapshots, DiskScanConfirmation, adminActor, ErrDiskScanRoleShared},
		{"unsupported type", TypeKubernetes, map[string]string{}, diskscan.DiskScanModeExistingSnapshots, DiskScanConfirmation, adminActor, ErrDiskScanUnsupported},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, a := newAuditedService(t)
			ctx := context.Background()
			c, err := svc.Create(ctx, tc.typ, "c", tc.cfg, "")
			require.NoError(t, err)
			a.rows = nil

			err = svc.SetDiskScanMode(ctx, c.ID, tc.mode, tc.conf, tc.actor)
			require.ErrorIs(t, err, tc.want)
			require.Empty(t, a.rows, "a refused change writes no audit row")
			got, err := svc.Get(ctx, c.ID)
			require.NoError(t, err)
			require.Equal(t, diskscan.DiskScanModeOff, got.DiskScanMode, "a refusal leaves the mode off")
		})
	}
}

func TestSetDiskScanMode_UnknownConnector(t *testing.T) {
	svc, _ := newAuditedService(t)
	err := svc.SetDiskScanMode(context.Background(), "nope", diskscan.DiskScanModeOff, "", adminActor)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestSetDiskScanMode_ExistingSnapshotsNeedsNoRole(t *testing.T) {
	svc, _ := newAuditedService(t)
	ctx := context.Background()
	c, err := svc.Create(ctx, TypeAWS, "c", withCfg(awsDiskCfg, ConfigDiskScanRoleARN, ""), "")
	require.NoError(t, err)
	require.NoError(t, svc.SetDiskScanMode(ctx, c.ID, diskscan.DiskScanModeExistingSnapshots, DiskScanConfirmation, adminActor))
}

// Only Azure's existing_snapshots needs the principal: AWS and GCP read existing
// snapshots with the collection role; an Azure connector with one may enable it.
func TestSetDiskScanMode_ExistingSnapshotsRoleRule(t *testing.T) {
	svc, _ := newAuditedService(t)
	ctx := context.Background()
	gcp, err := svc.Create(ctx, TypeGCP, "g", map[string]string{"project_id": "p"}, "")
	require.NoError(t, err)
	require.NoError(t, svc.SetDiskScanMode(ctx, gcp.ID, diskscan.DiskScanModeExistingSnapshots, DiskScanConfirmation, adminActor))
	az, err := svc.Create(ctx, TypeAzure, "a", map[string]string{"subscription_id": "s", "client_id": "c1", ConfigDiskScanClientID: "c2"}, "")
	require.NoError(t, err)
	require.NoError(t, svc.SetDiskScanMode(ctx, az.ID, diskscan.DiskScanModeExistingSnapshots, DiskScanConfirmation, adminActor))
}

func TestSetDiskScanMode_IsAuditedWithBeforeAfterRoleActor(t *testing.T) {
	svc, a := newAuditedService(t)
	ctx := context.Background()
	c, err := svc.Create(ctx, TypeAWS, "c", awsDiskCfg, "")
	require.NoError(t, err)
	a.rows = nil

	require.NoError(t, svc.SetDiskScanMode(ctx, c.ID, diskscan.DiskScanModeCreateSnapshots, DiskScanConfirmation, adminActor))
	got, err := svc.Get(ctx, c.ID)
	require.NoError(t, err)
	require.Equal(t, diskscan.DiskScanModeCreateSnapshots, got.DiskScanMode)
	require.Equal(t, "u-admin", got.DiskScanEnabledBy)
	require.NotNil(t, got.DiskScanEnabledAt)

	require.NoError(t, svc.SetDiskScanMode(ctx, c.ID, diskscan.DiskScanModeOff, "", adminActor))
	got, err = svc.Get(ctx, c.ID)
	require.NoError(t, err)
	require.Equal(t, diskscan.DiskScanModeOff, got.DiskScanMode)
	require.Empty(t, got.DiskScanEnabledBy)
	require.Nil(t, got.DiskScanEnabledAt)

	require.Len(t, a.rows, 2)
	for i, want := range []struct{ before, after string }{{"off", "create_snapshots"}, {"create_snapshots", "off"}} {
		row := a.rows[i]
		require.Equal(t, AuditActionDiskScanChange, row.action)
		require.Equal(t, AuditTargetConnector, row.targetType)
		require.Equal(t, c.ID, row.targetID)
		require.Equal(t, want.before, row.details["before"])
		require.Equal(t, want.after, row.details["after"])
		require.Equal(t, "arn:aws:iam::1:role/disk", row.details["role"])
		require.Equal(t, "u-admin", row.details["actor"])
		require.NotEmpty(t, row.details["at"])
	}
}

func TestDiskScanEnabled_ListsOnlyEnabledSupported(t *testing.T) {
	svc, _ := newAuditedService(t)
	ctx := context.Background()
	on, err := svc.Create(ctx, TypeAWS, "on", awsDiskCfg, "")
	require.NoError(t, err)
	_, err = svc.Create(ctx, TypeAWS, "off", awsDiskCfg, "")
	require.NoError(t, err)
	require.NoError(t, svc.SetDiskScanMode(ctx, on.ID, diskscan.DiskScanModeCreateSnapshots, DiskScanConfirmation, adminActor))

	got, err := svc.DiskScanEnabled(ctx)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, on.ID, got[0].ConnectorID)
	require.Equal(t, diskscan.DiskScanModeCreateSnapshots, got[0].Mode)
	require.Equal(t, "arn:aws:iam::1:role/disk", got[0].Role)
	require.ElementsMatch(t, []string{"arn:aws:iam::1:role/collect", "arn:aws:iam::1:role/ro", "arn:aws:iam::1:role/exec"}, got[0].OtherRoles)

	one, err := svc.DiskScanSettings(ctx, on.ID)
	require.NoError(t, err)
	require.Equal(t, got[0], one)
}

func TestDiskScanRoles(t *testing.T) {
	tests := []struct {
		name   string
		typ    Type
		cfg    map[string]string
		role   string
		others []string
	}{
		{"aws", TypeAWS, map[string]string{"role_arn": "a", ConfigDiskScanRoleARN: "d"}, "d", []string{"a"}},
		{"aws none", TypeAWS, map[string]string{"role_arn": "a"}, "", []string{"a"}},
		{"azure", TypeAzure, map[string]string{"client_id": "c", ConfigDiskScanClientID: "d"}, "d", []string{"c"}},
		{"gcp", TypeGCP, map[string]string{ConfigDiskScanServiceAccount: "d"}, "d", nil},
		{"github", TypeGitHub, map[string]string{ConfigDiskScanRoleARN: "d"}, "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			role, others := DiskScanRoles(tc.typ, tc.cfg)
			require.Equal(t, tc.role, role)
			require.Equal(t, tc.others, others)
		})
	}
}
