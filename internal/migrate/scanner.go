package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// ScannerRole is the Postgres role the scanner pod connects as. It owns
// nothing: migrate, connected as the owner of the tables, grants it
// scannerGrants after every run, because those tables (River's among them)
// exist only once the migrations have created them. The bundled Postgres
// creates the role (files/postgres-init.sql); on an external one the operator
// does, and without it there is nothing to grant.
const ScannerRole = "graph_scanner"

// scannerGrants is everything the scanner process does on Postgres:
//   - goose_db_version, river_migration: the readiness wait (migrate.Status).
//   - river_job, river_leader, river_queue: River's client. The scanner works
//     queueScan, enqueues enrich jobs, and as the elected leader enqueues the
//     periodic jobs and runs River's maintenance (rescue, cleanup, scheduling).
//     The reindexer, which needs the owner, is off (jobs.reindexerSchedule).
//   - scan_profiles, scan_runs, scan_findings: the scan workers, which read a
//     profile and record runs and their per-target findings.
//   - disk_scan_*: the disk scan's volume jobs record their results, packages,
//     snapshot registry rows and cache. The runs table is read and updated so the
//     last volume of a run can close it. A connector is visible only through the
//     disk_scan_connector_modes view (id and disk-scan mode): the volume job
//     checks the opt-in is still on without a grant on connectors, whose config
//     column holds every credential. The credentials a job needs travel sealed in
//     its args (internal/app/diskscan/envelope).
//
// Nothing on users, sessions, API keys, connectors or any other table.
var scannerGrants = []string{
	"GRANT SELECT ON goose_db_version, river_migration TO " + ScannerRole,
	"GRANT SELECT, INSERT, UPDATE, DELETE ON river_job, river_leader, river_queue TO " + ScannerRole,
	"GRANT USAGE ON SEQUENCE river_job_id_seq TO " + ScannerRole,
	"GRANT SELECT ON scan_profiles TO " + ScannerRole,
	"GRANT SELECT, INSERT, UPDATE ON scan_runs, scan_findings TO " + ScannerRole,
	"GRANT SELECT, UPDATE ON disk_scan_runs TO " + ScannerRole,
	"GRANT SELECT, INSERT, UPDATE ON disk_scan_volumes, disk_scan_snapshots, disk_scan_cache, disk_scan_packages TO " + ScannerRole,
	"GRANT SELECT ON disk_scan_connector_modes TO " + ScannerRole,
}

// scannerRevokes run before scannerGrants, in the same transaction, so the
// role ends each run with exactly scannerGrants.
var scannerRevokes = []string{
	"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM " + ScannerRole,
	"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM " + ScannerRole,
}

// scannerEscapes lists what would let ScannerRole act beyond scannerGrants:
//   - CREATE on a schema or on the database. With CREATE in a schema on
//     graph's search_path (PUBLIC holds it on public before Postgres 15, and a
//     schema named graph would come first) the scanner could plant a function
//     or operator that graph's own queries resolve to, and run code as the
//     owner of every table.
//   - Membership in any role, which REVOKE ... FROM ScannerRole leaves in
//     place: the role migrate runs as, pg_read_all_data or pg_write_all_data,
//     pg_execute_server_program, a provider's admin role.
//   - SUPERUSER, CREATEROLE (which grants roles) or REPLICATION (which streams
//     every row of the cluster).
//   - A privilege on a table or sequence migrate's role owns that is not
//     ScannerRole's own grant, so came from PUBLIC (a grant or a default
//     privilege) or a role: on users or api_keys it is the privilege
//     scannerGrants withholds. The system catalogs and extension objects are
//     left out: they hold no Vulngraph data, yet migrate's role owns all of
//     them when it is the cluster's bootstrap superuser (the dev compose's
//     graph, or postgres on an external server), and Postgres grants PUBLIC
//     reads of most.
const scannerEscapes = `
SELECT 'CREATE on schema ' || nspname FROM pg_namespace WHERE has_schema_privilege($1::name, oid, 'CREATE')
UNION ALL
SELECT 'CREATE on database ' || current_database() WHERE has_database_privilege($1::name, current_database(), 'CREATE')
UNION ALL
SELECT 'membership in ' || rolname FROM pg_roles WHERE rolname <> $1 AND pg_has_role($1::name, oid, 'MEMBER')
UNION ALL
SELECT attr FROM pg_roles r, LATERAL (VALUES ('SUPERUSER', r.rolsuper), ('CREATEROLE', r.rolcreaterole),
	('REPLICATION', r.rolreplication)) AS a(attr, held)
WHERE r.rolname = $1 AND held
UNION ALL
SELECT p.priv || ' on ' || c.oid::regclass::text || ' through PUBLIC or a role'
FROM pg_class c
CROSS JOIN LATERAL unnest(CASE WHEN c.relkind = 'S' THEN ARRAY['SELECT', 'UPDATE', 'USAGE']
	ELSE ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'] END) AS p(priv)
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
	AND c.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
	AND n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\_%'
	AND NOT EXISTS (SELECT 1 FROM pg_depend d
		WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
	AND CASE WHEN c.relkind = 'S' THEN has_sequence_privilege($1::name, c.oid, p.priv)
		WHEN p.priv IN ('DELETE', 'TRUNCATE', 'TRIGGER') THEN has_table_privilege($1::name, c.oid, p.priv)
		ELSE has_any_column_privilege($1::name, c.oid, p.priv) END
	AND NOT EXISTS (SELECT 1 FROM aclexplode(c.relacl) a
		WHERE a.grantee = (SELECT oid FROM pg_roles WHERE rolname = $1) AND a.privilege_type = p.priv)`

// grantScanner applies scannerGrants when ScannerRole exists, and fails
// while the role holds any of scannerEscapes: a scanner role that can create
// objects graph runs, or holds rights that do not come from its own grants,
// is not confined, however few those grants. A missing role
// is not an error: an external Postgres may run the scanner as another role
// its operator chose.
func grantScanner(ctx context.Context, pgDSN string) error {
	db, err := sql.Open("pgx", pgDSN)
	if err != nil {
		return fmt.Errorf("grantScanner: open: %w", err)
	}
	defer func() { _ = db.Close() }()

	var exists bool
	if err := db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, ScannerRole).Scan(&exists); err != nil {
		return fmt.Errorf("grantScanner: look up role: %w", err)
	}
	if !exists {
		log.FromContext(ctx).Info().Str("role", ScannerRole).
			Msg("migrate: no scanner role, so no scanner grants (deploy/README.md, External datastores)")
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("grantScanner: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, stmt := range append(append([]string{}, scannerRevokes...), scannerGrants...) {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("grantScanner: %s: %w", stmt, err)
		}
	}
	escapes, err := scannerEscapesOf(ctx, tx)
	if err != nil {
		return err
	}
	if len(escapes) > 0 {
		return fmt.Errorf("grantScanner: %s holds %s; revoke it (deploy/README.md, External datastores)",
			ScannerRole, strings.Join(escapes, ", "))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("grantScanner: commit: %w", err)
	}
	return nil
}

func scannerEscapesOf(ctx context.Context, tx *sql.Tx) ([]string, error) {
	rows, err := tx.QueryContext(ctx, scannerEscapes, ScannerRole)
	if err != nil {
		return nil, fmt.Errorf("grantScanner: check confinement: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, fmt.Errorf("grantScanner: check confinement: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("grantScanner: check confinement: %w", err)
	}
	return out, nil
}
