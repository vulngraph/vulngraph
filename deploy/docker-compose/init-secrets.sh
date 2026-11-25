#!/bin/sh
# Generates this stack's secrets on its first start (the init service in
# docker-compose.yml). One env file per consumer, each in its own volume, so
# no container holds a credential it does not use. The app file is written
# last: once it exists, a later start changes nothing.
set -eu

root=${SECRETS_DIR:-/secrets}
[ -s "$root/app/env" ] && exit 0

hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

pg_superuser=$(hex 24) pg_app=$(hex 24) pg_scanner=$(hex 24)
ch_app=$(hex 24) ch_migrate=$(hex 24) ch_scanner=$(hex 24)
secret_key=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
rpc_secret=$(hex 32)

pg_url="postgres://graph:$pg_app@postgres:5432/graph?sslmode=disable"

# write DIR: the env file for DIR from stdin, world-readable inside its volume
# because the consumers run as different users.
write() {
	cat >"$root/$1/env.tmp"
	chmod 0444 "$root/$1/env.tmp"
	mv "$root/$1/env.tmp" "$root/$1/env"
}

write postgres <<EOT
POSTGRES_PASSWORD=$pg_superuser
GRAPH_DB_PASSWORD=$pg_app
GRAPH_SCANNER_DB_PASSWORD=$pg_scanner
EOT

# CLICKHOUSE_USER (graph_migrate) is set in docker-compose.yml: the image
# creates the database as that user, so it needs that user's password.
write clickhouse <<EOT
CLICKHOUSE_PASSWORD=$ch_migrate
GRAPH_CH_APP_PASSWORD=$ch_app
GRAPH_CH_MIGRATE_PASSWORD=$ch_migrate
GRAPH_CH_SCANNER_PASSWORD=$ch_scanner
EOT

write migrate <<EOT
DATABASE_URL=$pg_url
CLICKHOUSE_URL=clickhouse://graph_migrate:$ch_migrate@clickhouse:9000/graph
EOT

write app <<EOT
DATABASE_URL=$pg_url
CLICKHOUSE_URL=clickhouse://graph:$ch_app@clickhouse:9000/graph
GRAPH_SECRET_KEY=$secret_key
LADYBUG_RPC_SECRET=$rpc_secret
EOT
