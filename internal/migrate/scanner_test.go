package migrate

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var scannerGrantTarget = regexp.MustCompile(`^GRANT [A-Z, ]+ ON (SEQUENCE )?([a-z_, ]+) TO graph_scanner$`)

// Every object scannerGrants names exists: an app table the Postgres
// migrations create, or one of the River and goose tables the scanner's job
// client and readiness wait use. A renamed table would otherwise fail every
// migrate run. No app table outside the scan workers' three and the disk scan's is granted, and connectors never.
func TestScannerGrantsNameRealObjects(t *testing.T) {
	appTables := migrationTables(t, "postgres")
	require.True(t, appTables["users"], "the table scan is broken")

	others := map[string]bool{
		"goose_db_version": true, "river_migration": true, "river_job": true,
		"river_leader": true, "river_queue": true, "river_job_id_seq": true,
	}
	var granted []string
	for _, g := range scannerGrants {
		m := scannerGrantTarget.FindStringSubmatch(g)
		require.NotNil(t, m, "unparsed grant %q", g)
		for _, name := range strings.Split(m[2], ",") {
			name = strings.TrimSpace(name)
			require.True(t, appTables[name] || others[name], "%q grants on %s, which no migration creates", g, name)
			if appTables[name] {
				granted = append(granted, name)
			}
		}
	}
	require.ElementsMatch(t, []string{
		"disk_scan_runs", "disk_scan_volumes", "disk_scan_snapshots", "disk_scan_cache", "disk_scan_packages",
		"disk_scan_connector_modes",
	}, granted,
		"the scanner touches only the disk-scan tables and the connector-mode view; "+
			"anything else (users, api_keys, connectors) is an escalation path")
}
