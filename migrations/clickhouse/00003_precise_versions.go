// Package clickhouse contains Goose migrations requiring a verified data copy.
package clickhouse

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
)

const versionMarker = "vulngraph:precise-versions:3:"

var versionColumns = []struct{ table, column string }{
	{"assets", "synced_at"}, {"graph_edges", "synced_at"},
	{"sync_state", "updated_at"}, {"findings", "synced_at"},
	{"signals", "synced_at"}, {"beliefs", "created_at"},
	{"phishing_candidates", "synced_at"},
}

// PreciseVersions is registered explicitly on the ClickHouse provider only.
func PreciseVersions() *goose.Migration {
	m := goose.NewGoMigration(3,
		&goose.GoFunc{RunDB: func(ctx context.Context, db *sql.DB) error { return rebuildVersions(ctx, db, "DateTime64(9)") }},
		&goose.GoFunc{RunDB: func(ctx context.Context, db *sql.DB) error { return rebuildVersions(ctx, db, "DateTime") }})
	m.Source = "00003_precise_versions.go"
	return m
}

type copyMarker struct {
	Table, Column, Target, SourceUUID, CopyUUID, Comment string
}

type tableInfo struct{ uuid, comment, ddl, engine string }

func table(ctx context.Context, db *sql.DB, name string) (tableInfo, error) {
	var t tableInfo
	err := db.QueryRowContext(ctx, `SELECT toString(uuid), comment, create_table_query, engine
		FROM system.tables WHERE database=currentDatabase() AND name=?`, name).Scan(&t.uuid, &t.comment, &t.ddl, &t.engine)
	if err == nil {
		err = db.QueryRowContext(ctx, "SHOW CREATE TABLE "+ident(name)+" SETTINGS show_table_uuid_in_table_create_query_if_not_nil=0").Scan(&t.ddl)
	}
	return t, err
}

func ident(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }
func literal(s string) string {
	return "'" + strings.NewReplacer("\\", "\\\\", "'", "\\'").Replace(s) + "'"
}

func exec(ctx context.Context, db *sql.DB, query string) error {
	if _, err := db.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("precise versions: %s: %w", strings.SplitN(query, "\n", 2)[0], err)
	}
	return nil
}

func rebuildVersions(ctx context.Context, db *sql.DB, target string) error {
	var engine string
	if err := db.QueryRowContext(ctx, `SELECT engine FROM system.databases WHERE name=currentDatabase()`).Scan(&engine); err != nil {
		return fmt.Errorf("precise versions: database engine: %w", err)
	}
	if engine != "Atomic" {
		return fmt.Errorf("precise versions requires an Atomic database, got %s", engine)
	}
	for _, c := range versionColumns {
		if err := rebuildVersion(ctx, db, c.table, c.column, target); err != nil {
			return fmt.Errorf("rebuild %s: %w", c.table, err)
		}
	}
	return nil
}

func decodeMarker(t tableInfo, name, column, target string) (copyMarker, error) {
	var m copyMarker
	if !strings.HasPrefix(t.comment, versionMarker) {
		return m, errors.New("intermediate table is not owned by migration 3; refusing to modify it")
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(t.comment, versionMarker)), &m); err != nil {
		return m, fmt.Errorf("migration marker: %w", err)
	}
	if m.Table != name || m.Column != column || m.Target != target || m.SourceUUID != t.uuid {
		return m, errors.New("intermediate table ownership or migration direction differs; resume the original direction first")
	}
	if _, err := uuid.Parse(m.CopyUUID); err != nil {
		return m, fmt.Errorf("copy UUID: %w", err)
	}
	return m, nil
}

func markerComment(m copyMarker) string {
	b, _ := json.Marshal(m) // only strings
	return versionMarker + string(b)
}

func rebuildVersion(ctx context.Context, db *sql.DB, name, column, target string) error {
	source, dest := "_vg_m3_"+name+"_source", "_vg_m3_"+name+"_copy"
	// A process may die after permanent detach. ATTACH is reversible and does
	// not change data; ownership must still match before copying or dropping.
	var detached uint64
	if err := db.QueryRowContext(ctx, `SELECT count() FROM system.detached_tables WHERE database=currentDatabase() AND table=?`, source).Scan(&detached); err != nil {
		return err
	}
	if detached > 0 {
		if err := exec(ctx, db, "ATTACH TABLE "+ident(source)); err != nil {
			return err
		}
	}
	backup, err := table(ctx, db, source)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var m copyMarker
	if errors.Is(err, sql.ErrNoRows) {
		current, err := table(ctx, db, name)
		if err != nil {
			return fmt.Errorf("read source: %w", err)
		}
		// Never overwrite a pre-existing staging table, even on an empty install.
		if _, err := table(ctx, db, dest); !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("unexpected staging table %s (lookup: %v)", dest, err)
		}
		var typ string
		if err := db.QueryRowContext(ctx, `SELECT type FROM system.columns WHERE database=currentDatabase() AND table=? AND name=?`, name, column).Scan(&typ); err != nil {
			return err
		}
		if typ == target && !strings.HasPrefix(current.comment, versionMarker) {
			return nil
		}
		if strings.HasPrefix(current.comment, versionMarker) {
			m, err = decodeMarker(current, name, column, target)
			if err != nil {
				return err
			}
		} else {
			m = copyMarker{name, column, target, current.uuid, uuid.NewString(), current.comment}
		}
		if current.engine != "ReplacingMergeTree" {
			return fmt.Errorf("unsupported engine %s", current.engine)
		}
		var dependencies uint64
		if err := db.QueryRowContext(ctx, `SELECT toUInt64(length(dependencies_table)+length(loading_dependent_table)) FROM system.tables WHERE database=currentDatabase() AND name=?`, name).Scan(&dependencies); err != nil {
			return err
		}
		if dependencies != 0 {
			return errors.New("custom dependent views must be removed and recreated around this migration")
		}
		// Validate the complete DDL before taking away the application table.
		if _, err := copyDDL(current.ddl, dest, m); err != nil {
			return err
		}
		var busy uint64
		if err := db.QueryRowContext(ctx, `SELECT count() FROM system.mutations WHERE database=currentDatabase() AND table=? AND NOT is_done`, name).Scan(&busy); err != nil {
			return err
		}
		if busy != 0 {
			return errors.New("pending mutations; wait for them before migrating")
		}
		if err := exec(ctx, db, "ALTER TABLE "+ident(name)+" MODIFY COMMENT "+literal(markerComment(m))); err != nil {
			return err
		}
		if err := exec(ctx, db, "RENAME TABLE "+ident(name)+" TO "+ident(source)); err != nil {
			return err
		}
	} else {
		m, err = decodeMarker(backup, name, column, target)
		if err != nil {
			return err
		}
	}
	if current, err := table(ctx, db, name); err == nil {
		if current.uuid != m.CopyUUID {
			return errors.New("public table is not the verified migration copy")
		}
		return finishCopy(ctx, db, name, source, m)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	// RENAME alone does not wait for in-flight inserts. Synchronous detach
	// drains storage users; the public name is absent throughout the copy.
	if err := exec(ctx, db, "DETACH TABLE "+ident(source)+" PERMANENTLY SYNC"); err != nil {
		return err
	}
	if err := exec(ctx, db, "ATTACH TABLE "+ident(source)); err != nil {
		return err
	}
	if err := exec(ctx, db, "SYSTEM STOP MERGES "+ident(source)); err != nil {
		return err
	}
	backup, err = table(ctx, db, source)
	if err != nil {
		return err
	}
	if _, err := decodeMarker(backup, name, column, target); err != nil {
		return err
	}
	if staged, err := table(ctx, db, dest); err == nil {
		if staged.uuid != m.CopyUUID || staged.comment != markerComment(m) {
			return errors.New("staging table ownership mismatch")
		}
		if err := exec(ctx, db, "DROP TABLE "+ident(dest)+" SYNC"); err != nil {
			return err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	ddl, err := copyDDL(backup.ddl, dest, m)
	if err != nil {
		return err
	}
	if err := exec(ctx, db, ddl); err != nil {
		return err
	}
	if err := exec(ctx, db, "SYSTEM STOP MERGES "+ident(dest)); err != nil {
		return err
	}
	columns, projected, err := copyColumns(ctx, db, source, m)
	if err != nil {
		return err
	}
	if err := exec(ctx, db, "INSERT INTO "+ident(dest)+" ("+columns+") SELECT "+projected+" FROM "+ident(source)+" FINAL SETTINGS max_threads=2"); err != nil {
		return err
	}
	left, err := copyDigest(ctx, db, source, projected)
	if err != nil {
		return err
	}
	right, err := copyDigest(ctx, db, dest, columns)
	if err != nil {
		return err
	}
	if left != right {
		return fmt.Errorf("copy verification failed: source=%v copy=%v; source retained", left, right)
	}
	if err := exec(ctx, db, "RENAME TABLE "+ident(dest)+" TO "+ident(name)); err != nil {
		return err
	}
	return finishCopy(ctx, db, name, source, m)
}

func finishCopy(ctx context.Context, db *sql.DB, name, source string, m copyMarker) error {
	if err := exec(ctx, db, "ALTER TABLE "+ident(name)+" MODIFY COMMENT "+literal(m.Comment)); err != nil {
		return err
	}
	if err := exec(ctx, db, "SYSTEM START MERGES "+ident(name)); err != nil {
		return err
	}
	return exec(ctx, db, "DROP TABLE "+ident(source)+" SYNC")
}

func copyDDL(ddl, dest string, m copyMarker) (string, error) {
	start := strings.Index(ddl, "\n(")
	if start < 0 {
		return "", errors.New("unrecognized CREATE TABLE shape")
	}
	body := ddl[start:]
	if i := strings.LastIndex(body, "\nCOMMENT "); i >= 0 {
		body = body[:i]
	}
	from := "DateTime"
	if m.Target == "DateTime" {
		from = "DateTime64(9)"
	}
	prefix := "    " + ident(m.Column) + " "
	lines := strings.Split(body, "\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) {
			rest := strings.TrimPrefix(line, prefix)
			if rest != from && !strings.HasPrefix(rest, from+",") && !strings.HasPrefix(rest, from+" DEFAULT ") {
				return "", fmt.Errorf("unsupported version column: %s", line)
			}
			rest = m.Target + strings.TrimPrefix(rest, from)
			if m.Target == "DateTime" {
				rest = strings.ReplaceAll(rest, "now64(9)", "now()")
			} else {
				rest = strings.ReplaceAll(rest, "now()", "now64(9)")
			}
			lines[i], found = prefix+rest, true
		}
		if strings.HasPrefix(line, "TTL "+m.Column+" + ") {
			lines[i] = strings.Replace(line, "TTL "+m.Column, "TTL toDateTime("+m.Column+")", 1)
		}
	}
	if !found {
		return "", errors.New("version column not found")
	}
	return "CREATE TABLE " + ident(dest) + " UUID " + literal(m.CopyUUID) + strings.Join(lines, "\n") + "\nCOMMENT " + literal(markerComment(m)), nil
}

func copyColumns(ctx context.Context, db *sql.DB, source string, m copyMarker) (string, string, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM system.columns WHERE database=currentDatabase() AND table=? AND default_kind NOT IN ('ALIAS','MATERIALIZED') ORDER BY position`, source)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = rows.Close() }()
	var columns, projection []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return "", "", err
		}
		columns = append(columns, ident(name))
		value := ident(name)
		if name == m.Column {
			value = "CAST(" + value + " AS " + m.Target + ")"
		}
		projection = append(projection, value)
	}
	if err := rows.Err(); err != nil {
		return "", "", err
	}
	return strings.Join(columns, ","), strings.Join(projection, ","), nil
}

// Count and two independent commutative checks cover every stored field,
// including metadata and relationship properties, without sorting all rows.
func copyDigest(ctx context.Context, db *sql.DB, name, columns string) ([3]uint64, error) {
	var d [3]uint64
	err := db.QueryRowContext(ctx, "SELECT count(), sumWithOverflow(cityHash64(tuple("+columns+"))), groupBitXor(sipHash64(tuple("+columns+"))) FROM "+ident(name)+" FINAL SETTINGS max_threads=2").Scan(&d[0], &d[1], &d[2])
	return d, err
}
