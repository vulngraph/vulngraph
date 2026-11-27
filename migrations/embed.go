// Package migrations embeds the goose migration files for both databases so
// the single binary can migrate itself.
package migrations

import (
	"embed"

	"github.com/pressly/goose/v3"
	"github.com/vulngraph/vulngraph/migrations/clickhouse"
)

//go:embed postgres/*.sql clickhouse/*.sql clickhouse/[0-9]*.go
var FS embed.FS

// ProviderOptions keeps migration execution and readiness on the same registry.
// Go migrations must never use Goose's global registry: Postgres and ClickHouse
// have independent version sequences inside the same process.
func ProviderOptions(dialect goose.Dialect) goose.ProviderOption {
	if dialect == goose.DialectClickHouse {
		return goose.WithGoMigrations(clickhouse.PreciseVersions())
	}
	return goose.WithGoMigrations()
}
