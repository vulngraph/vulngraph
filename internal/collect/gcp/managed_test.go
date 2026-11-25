package gcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	sqladmin "google.golang.org/api/sqladmin/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

var now = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

type fakeCloudSQL struct{ items []cloudSQLInstance }

func (f *fakeCloudSQL) ListInstances(context.Context, string) ([]cloudSQLInstance, error) {
	return f.items, nil
}

func TestCollectCloudSQL(t *testing.T) {
	assets, err := collectCloudSQL(context.Background(), &fakeCloudSQL{items: []cloudSQLInstance{
		{Name: "db1", Region: "europe-west1", Version: "POSTGRES_15", PublicIP: "34.1.2.3", HasPublic: true, RequireSSL: false, Backups: true,
			SettingsObserved: true, BackupObserved: true, IPConfigObserved: true},
		{Name: ""}, // skipped
	}}, "proj", now)
	require.NoError(t, err)
	require.Len(t, assets, 1)
	require.Equal(t, "proj/cloudsql/db1", assets[0].ID)
	require.Equal(t, "cloudsql_instance", assets[0].Type)
	require.Equal(t, "34.1.2.3", assets[0].PublicIP)
	require.Equal(t, "true", assets[0].Metadata["public"])
	require.Equal(t, "false", assets[0].Metadata["require_ssl"])
	require.Equal(t, "true", assets[0].Metadata["backups"])
	require.Equal(t, "possible", assets[0].Metadata["public_access"],
		"a public IPv4 is network reachability only — never confirmed")
}

// TestCloudSQLPublicTier pins the three-state grading. Before this, an instance
// whose ipConfiguration the API never returned reported public_access="" —
// indistinguishable from an observed-private instance — so the DSPM public tile
// counted a measurement gap as a fact.
func TestCloudSQLPublicTier(t *testing.T) {
	require.Equal(t, "possible", cloudSQLPublicTier(cloudSQLInstance{
		SettingsObserved: true, IPConfigObserved: true, HasPublic: true,
	}))
	require.Equal(t, "none", cloudSQLPublicTier(cloudSQLInstance{
		SettingsObserved: true, IPConfigObserved: true, HasPublic: false,
	}), "read the ipConfiguration, no public IP → an observation, not silence")
	require.Equal(t, "unknown", cloudSQLPublicTier(cloudSQLInstance{
		SettingsObserved: true, IPConfigObserved: false,
	}), "no ipConfiguration returned → unobserved, not private")
	require.Equal(t, "unknown", cloudSQLPublicTier(cloudSQLInstance{}),
		"nil Settings → unobserved")
}

// TestCollectCloudSQL_UnobservedIPConfig is the end-to-end shape: unknown tier,
// and `public` still false so no exposure edge or public count is invented.
func TestCollectCloudSQL_UnobservedIPConfig(t *testing.T) {
	assets, err := collectCloudSQL(context.Background(), &fakeCloudSQL{items: []cloudSQLInstance{
		{Name: "blind", Region: "europe-west1", SettingsObserved: true},
	}}, "proj", now)
	require.NoError(t, err)
	require.Len(t, assets, 1)
	require.Equal(t, "unknown", assets[0].Metadata["public_access"])
	require.Equal(t, "false", assets[0].Metadata["public"],
		"an unobserved instance must not be reported as public")
}

type fakeSecrets struct {
	items     []gcpSecret
	accessors map[string][]string // by secret resource; absent = policy unreadable
}

func (f *fakeSecrets) ListSecrets(context.Context, string) ([]gcpSecret, error) { return f.items, nil }
func (f *fakeSecrets) GetSecretAccessors(_ context.Context, resource string) ([]string, error) {
	if f.accessors == nil {
		return nil, nil
	}
	got, ok := f.accessors[resource]
	if !ok {
		return nil, errors.New("googleapi: Error 403: Permission denied")
	}
	return got, nil
}

func TestCollectSecrets(t *testing.T) {
	assets, edges, err := collectSecrets(context.Background(), &fakeSecrets{items: []gcpSecret{
		{Name: "api-key", HasRotation: false},
		{Name: "rotated", HasRotation: true},
	}}, "proj", now)
	require.NoError(t, err)
	require.Len(t, assets, 2)
	require.Empty(t, edges)
	require.Equal(t, "gcp_secret", assets[0].Type)
	require.Equal(t, "false", assets[0].Metadata["rotation"])
	require.Equal(t, "true", assets[1].Metadata["rotation"])
	require.Equal(t, "true", assets[0].Metadata["accessors_known"])
}

// A secret whose IAM policy could not be read is still emitted, marked
// accessors_known=false, so its missing accesses_secret edges are not read as
// "no service account can access it".
func TestCollectSecrets_UnreadPolicyIsUnknownAccess(t *testing.T) {
	assets, edges, err := collectSecrets(context.Background(), &fakeSecrets{
		items: []gcpSecret{{Name: "read"}, {Name: "denied"}},
		accessors: map[string][]string{
			"projects/proj/secrets/read": {"app@proj.iam.gserviceaccount.com"},
		},
	}, "proj", now)
	require.NoError(t, err)
	require.Len(t, assets, 2)
	require.Equal(t, "true", assets[0].Metadata["accessors_known"])
	require.Equal(t, "false", assets[1].Metadata["accessors_known"])
	require.Equal(t, []asset.Edge{{
		SrcID: "app@proj.iam.gserviceaccount.com", SrcType: "gcp_service_account",
		DstID: "proj/secret/read", DstType: "gcp_secret", EdgeType: "accesses_secret",
	}}, edges)
}

type fakeFunctions struct{ items []cloudFunction }

func (f *fakeFunctions) ListFunctions(context.Context, string) ([]cloudFunction, error) {
	return f.items, nil
}

func TestCollectFunctions(t *testing.T) {
	assets, err := collectFunctions(context.Background(), &fakeFunctions{items: []cloudFunction{
		{Name: "fn", Region: "europe-west1", Runtime: "go121", URL: "https://fn.example", PublicNet: true},
	}}, "proj", now)
	require.NoError(t, err)
	require.Len(t, assets, 1)
	require.Equal(t, "cloud_function", assets[0].Type)
	require.Equal(t, "true", assets[0].Metadata["public"])
}

// toNeutralCloudSQL must record WHETHER it read each settings sub-object, not
// just what it read. Every posture flag on cloudSQLInstance is a plain bool, so
// a nil Settings or nil BackupConfiguration collapses to `false` — and `false`
// is exactly the value gcp-cloudsql-no-backup and
// gcp-cloudsql-deletion-protection-disabled fire on. Without the observed flags
// the collector hands those checks the violation they were narrowed to demand
// evidence for, defeating the narrowing entirely.
func TestToNeutralCloudSQL_ObservedFlags(t *testing.T) {
	autoResize := true
	cases := []struct {
		name             string
		in               *sqladmin.DatabaseInstance
		wantSettings     bool
		wantBackup       bool
		wantBackups      bool
		wantBinaryLog    bool
		wantRequireSSL   bool
		wantDeletionProt bool
	}{
		{
			name: "no settings at all",
			in:   &sqladmin.DatabaseInstance{Name: "db"},
		},
		{
			name:         "settings without a backup configuration",
			in:           &sqladmin.DatabaseInstance{Name: "db", Settings: &sqladmin.Settings{DeletionProtectionEnabled: true}},
			wantSettings: true, wantDeletionProt: true,
		},
		{
			name: "full settings",
			in: &sqladmin.DatabaseInstance{Name: "db", Settings: &sqladmin.Settings{
				IpConfiguration:           &sqladmin.IpConfiguration{RequireSsl: true},
				BackupConfiguration:       &sqladmin.BackupConfiguration{Enabled: true, BinaryLogEnabled: true},
				DeletionProtectionEnabled: true,
				StorageAutoResize:         &autoResize,
			}},
			wantSettings: true, wantBackup: true, wantBackups: true,
			wantBinaryLog: true, wantRequireSSL: true, wantDeletionProt: true,
		},
		{
			name: "backups genuinely off",
			in: &sqladmin.DatabaseInstance{Name: "db", Settings: &sqladmin.Settings{
				BackupConfiguration: &sqladmin.BackupConfiguration{Enabled: false},
			}},
			wantSettings: true, wantBackup: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := toNeutralCloudSQL(tc.in)
			require.Equal(t, tc.wantSettings, got.SettingsObserved)
			require.Equal(t, tc.wantBackup, got.BackupObserved)
			require.Equal(t, tc.wantBackups, got.Backups)
			require.Equal(t, tc.wantBinaryLog, got.BinaryLogEnabled)
			require.Equal(t, tc.wantRequireSSL, got.RequireSSL)
			require.Equal(t, tc.wantDeletionProt, got.DeletionProtectionEnabled)
		})
	}
}

// …and collectCloudSQL must omit the keys, not write the zero values.
func TestCollectCloudSQL_UnobservedSettingsOmitted(t *testing.T) {
	assets, err := collectCloudSQL(context.Background(), &fakeCloudSQL{items: []cloudSQLInstance{
		{Name: "unknown", Version: "MYSQL_8_0"},
		{Name: "settings-only", Version: "MYSQL_8_0", SettingsObserved: true},
		{Name: "observed-off", Version: "MYSQL_8_0", SettingsObserved: true, BackupObserved: true},
		{Name: "observed-on", Version: "MYSQL_8_0", SettingsObserved: true, BackupObserved: true,
			Backups: true, BinaryLogEnabled: true},
	}}, "proj", now)
	require.NoError(t, err)

	md := map[string]map[string]string{}
	for _, a := range assets {
		md[a.Name] = a.Metadata
	}

	for _, k := range []string{"backups", "log_bin", "require_ssl", "deletion_protection_enabled", "storage_auto_resize"} {
		require.NotContains(t, md["unknown"], k, "an unread Settings must not become an observed negative")
	}
	// Settings read, BackupConfiguration absent: the settings-level flags are
	// evidence, the backup-level ones are not.
	require.Equal(t, "false", md["settings-only"]["deletion_protection_enabled"])
	require.NotContains(t, md["settings-only"], "backups")
	require.NotContains(t, md["settings-only"], "log_bin")

	// A genuinely-disabled backup config must still produce the finding.
	require.Equal(t, "false", md["observed-off"]["backups"])
	require.Contains(t, md["observed-off"], "log_bin")
	require.Equal(t, "", md["observed-off"]["log_bin"], "present-and-empty is what observedNone requires")

	require.Equal(t, "true", md["observed-on"]["backups"])
	require.Equal(t, "true", md["observed-on"]["log_bin"])

	// public/public_access stay unconditional — an unknown instance reads as not
	// public, which suppresses an exposure edge rather than inventing one.
	require.Equal(t, "false", md["unknown"]["public"])
}
