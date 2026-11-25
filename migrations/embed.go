// Package migrations embeds the goose migration files for both databases so
// the single binary can migrate itself.
package migrations

import "embed"

//go:embed postgres/*.sql clickhouse/*.sql
var FS embed.FS
