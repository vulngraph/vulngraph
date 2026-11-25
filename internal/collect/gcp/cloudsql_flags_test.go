package gcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	sqladmin "google.golang.org/api/sqladmin/v1"
)

// require_ssl is read from ipConfiguration, so it is evidence only when
// ipConfiguration came back. It used to be stamped whenever Settings did, and a
// Settings with no ipConfiguration wrote the Go zero value "false" — exactly
// what gcp-cloudsql-no-ssl fires on.
func TestCollectCloudSQL_RequireSSLNeedsIPConfig(t *testing.T) {
	assets, err := collectCloudSQL(context.Background(), &fakeCloudSQL{items: []cloudSQLInstance{
		{Name: "settings-only", Version: "POSTGRES_15", SettingsObserved: true},
		{Name: "ipconfig", Version: "POSTGRES_15", SettingsObserved: true, IPConfigObserved: true,
			SSLMode: "ENCRYPTED_ONLY"},
	}}, "proj", now)
	require.NoError(t, err)
	md := map[string]map[string]string{}
	for _, a := range assets {
		md[a.Name] = a.Metadata
	}
	for _, k := range []string{"require_ssl", "ssl_mode", "authorized_networks", "authorized_networks_world"} {
		require.NotContains(t, md["settings-only"], k, "an unread ipConfiguration is not an observed negative")
	}
	require.Equal(t, "false", md["ipconfig"]["require_ssl"])
	require.Equal(t, "ENCRYPTED_ONLY", md["ipconfig"]["ssl_mode"])
	require.Equal(t, "false", md["ipconfig"]["authorized_networks_world"])
	require.Equal(t, "", md["ipconfig"]["authorized_networks"])
}

func TestToNeutralCloudSQL_IPConfigAndFlags(t *testing.T) {
	in := &sqladmin.DatabaseInstance{Name: "db", DatabaseVersion: "POSTGRES_15", Settings: &sqladmin.Settings{
		IpConfiguration: &sqladmin.IpConfiguration{
			Ipv4Enabled: true,
			SslMode:     "ALLOW_UNENCRYPTED_AND_ENCRYPTED",
			AuthorizedNetworks: []*sqladmin.AclEntry{
				{Value: "10.0.0.0/8"}, nil, {Value: " 0.0.0.0/0 "},
			},
		},
		DatabaseFlags: []*sqladmin.DatabaseFlags{
			{Name: "log_connections", Value: "ON"},
			{Name: "cloudsql.enable_pgaudit", Value: "on"},
			nil,
		},
	}}
	got := toNeutralCloudSQL(in)
	require.Equal(t, "ALLOW_UNENCRYPTED_AND_ENCRYPTED", got.SSLMode)
	require.Equal(t, []string{"10.0.0.0/8", "0.0.0.0/0"}, got.AuthorizedNetworks)
	require.Equal(t, map[string]string{"log_connections": "on", "cloudsql.enable_pgaudit": "on"}, got.Flags)
}

func TestCloudSQLWorldAuthorizedNetwork(t *testing.T) {
	require.True(t, worldAuthorizedNetwork([]string{"10.0.0.0/8", "0.0.0.0/0"}))
	require.True(t, worldAuthorizedNetwork([]string{"::/0"}))
	require.False(t, worldAuthorizedNetwork([]string{"10.0.0.0/8", "0.0.0.0/8"}))
	require.False(t, worldAuthorizedNetwork(nil))
}

// Every CIS-graded flag of the instance's engine is stamped once Settings was
// read: "" for a flag left at its default, which the checks distinguish from a
// missing key (Settings unread). Other engines' flags are never stamped.
func TestDBFlagMetadata(t *testing.T) {
	pg := dbFlagMetadata("POSTGRES_15", map[string]string{"log_connections": "on", "cloudsql.iam_authentication": "on"})
	require.Equal(t, "on", pg["db_flag_log_connections"])
	require.Equal(t, "on", pg["db_flag_cloudsql_iam_authentication"])
	require.Contains(t, pg, "db_flag_log_disconnections")
	require.Equal(t, "", pg["db_flag_log_disconnections"], "unset flag is observed default, present and empty")
	require.NotContains(t, pg, "db_flag_local_infile", "a MySQL flag on a Postgres instance")

	my := dbFlagMetadata("MYSQL_8_0", map[string]string{"cloudsql_iam_authentication": "on", "local_infile": "on"})
	require.Equal(t, "on", my["db_flag_cloudsql_iam_authentication"])
	require.Equal(t, "on", my["db_flag_local_infile"])
	require.Equal(t, "", my["db_flag_skip_show_database"])

	ss := dbFlagMetadata("SQLSERVER_2019_STANDARD", map[string]string{"3625": "on", "remote access": "off"})
	require.Equal(t, "on", ss["db_flag_3625"])
	require.Equal(t, "off", ss["db_flag_remote_access"])
	require.Equal(t, "", ss["db_flag_external_scripts_enabled"])

	require.Empty(t, dbFlagMetadata("", nil), "an unknown engine stamps nothing")
}

func TestCollectCloudSQL_FlagsOnlyWhenSettingsObserved(t *testing.T) {
	assets, err := collectCloudSQL(context.Background(), &fakeCloudSQL{items: []cloudSQLInstance{
		{Name: "unread", Version: "POSTGRES_15"},
		{Name: "read", Version: "POSTGRES_15", SettingsObserved: true},
	}}, "proj", now)
	require.NoError(t, err)
	md := map[string]map[string]string{}
	for _, a := range assets {
		md[a.Name] = a.Metadata
	}
	require.NotContains(t, md["unread"], "db_flag_log_connections")
	require.Contains(t, md["read"], "db_flag_log_connections")
}
