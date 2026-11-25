# Docker Compose

The batteries-included way to run Vulngraph: Postgres, ClickHouse, `serve`, and
`worker` (with the in-memory graph engine), all from one image — no Go or bun
toolchain, no Kubernetes.

`docker compose up` builds the image from this checkout and tags it
`vulngraph:local`, never a published name. To run a published release image
instead, see [Running a published release](#running-a-published-release).

Requires **Docker Compose v2.24 or newer** (`docker compose version`): the
compose files use the long `env_file` syntax (`path:` / `required: false`) and
`!reset`, which older releases reject.

Run every command below from this directory:

```sh
cd deploy/docker-compose
cp app.env.example app.env         # optional: LLM provider, SMTP, other settings
docker compose up -d               # builds this checkout
docker compose exec serve /graph user create --email you@example.com --role admin
```

The first build takes several minutes; later ones reuse the build cache, and
every `up` rebuilds from the checkout.

`user create` prints the generated password. Open http://localhost:8080 and
sign in with it. Prefer it to `--password`, which leaves the password in shell
history and process listings.

**Safari on `http://localhost`:** Safari refuses the session cookie's `Secure`
attribute over plain http, so sign-in loops back to the login page. Chrome and
Firefox are fine. For local Safari use, set `COOKIE_INSECURE=true` in `app.env` and
`docker compose up -d` again. Never set it behind a real hostname.

**Sizing.** The compose stack sets no memory or CPU limits. For the same
components (serve, the worker with nuclei inside it, Postgres and ClickHouse)
the Helm chart's defaults request about 5 GiB of memory and 2.25 CPUs and cap
them at 13 GiB and 7 CPUs, so give Docker at least 6 GB and 4 CPUs; the worker
alone reserves 1280 MiB for the graph engine's buffer pool. On a small machine,
set `IMAGE_SCAN_DISABLED=true` (no container-image sweep),
`SCAN_WORKER_DISABLED=true` (no nuclei scans at all, since Compose has no
scanner pod) or a lower `LADYBUG_BUFFER_MB` in `app.env`.

## What runs

| service | role |
|---|---|
| `init` | generates the stack's secrets on the first start, then exits ([Secrets](#secrets)) |
| `postgres`, `clickhouse` | datastores (named volumes `vulngraph_pgdata`, `vulngraph_chdata`) |
| `migrate` | applies schema migrations, then exits; `serve`/`worker` start after it |
| `serve` | UI + API on `127.0.0.1:8080` (loopback only) |
| `worker` | connector syncs, enrichment, and the graph engine. `serve` reaches the engine at `worker:8090` on the compose network, authenticated with `LADYBUG_RPC_SECRET`; its snapshot lives in the `vulngraph_ladybug` volume |

Settings live in two optional files:

- `.env` is read by Compose only, to fill in `docker-compose.yml`. It holds
  `GRAPH_VERSION` / `GRAPH_IMAGE` (for `docker-compose.release.yml`) and, during
  a key rotation, `GRAPH_RETIRED_SECRET_KEYS`; see `.env.example`.
- `app.env` is passed whole to `serve` and `worker`, so any setting in
  [`docs/configuration.md`](../../docs/configuration.md) can go there: the LLM
  provider, SMTP approvals, `COOKIE_INSECURE`. Never put the datastore
  passwords in it. For a local Ollama on the host, use
  `LLM_BASE_URL=http://host.docker.internal:11434/v1`; `serve` and `worker` map
  that name to the host on Linux too. On Linux, start Ollama with
  `OLLAMA_HOST=0.0.0.0`: by default it listens on 127.0.0.1 only, which the
  containers cannot reach. `SMTP_ALLOW_PLAINTEXT=true` is dangerous (approval links
  travel unencrypted); leave it unset unless the relay is local or on a trusted
  private link.

**No app container is a datastore admin** ([Datastore users](#datastore-users)).

ClickHouse gets the same cache ceilings, system-log TTLs and
`max_execution_time` backstop as the Helm chart, from `clickhouse/*.xml`.

The UI is published on loopback only. To reach it from other machines, put a
TLS-terminating reverse proxy in front of it rather than publishing plain http
on `0.0.0.0`.

## Secrets

Nothing to set up: on the first start the `init` service generates the
credential encryption key (`GRAPH_SECRET_KEY`, which seals every stored
connector credential), the internal RPC secret and all six datastore passwords,
each with `/dev/urandom`. It writes one file per consumer into its own named
volume (`vulngraph_secrets-postgres`, `-clickhouse`, `-migrate`, `-app`), so
a container only sees what it uses, and later starts leave them alone. `serve`,
`worker` and `migrate` read theirs through `GRAPH_ENV_FILE`; the datastore
containers source theirs in their entrypoint.

- **They live with the data.** `docker compose down -v` deletes the data
  volumes and the secrets together, which is a clean slate. Deleting only the
  secrets volumes while keeping the data volumes strands the data: the
  databases keep the old passwords, and the encryption key that sealed the
  stored credentials is gone.
- **To back them up,** copy the contents of `vulngraph_secrets-app` apart from
  the database backups: `docker compose exec serve cat /secrets/env`.
- **To use your own values** for `GRAPH_SECRET_KEY` or `LADYBUG_RPC_SECRET`, set
  them in `app.env`: an environment variable outranks the generated file. The
  datastore passwords are fixed when the data volumes are created.
- This is an evaluation convenience. For production use the Helm chart, where you
  supply every secret ([production checklist](../../docs/production-checklist.md)).

## Datastore users

The stack sets up its datastore users from the same files the Helm chart uses
(Postgres on the first start of an empty volume, ClickHouse on every start),
and no app container holds an admin password:

| datastore | user | used by | rights |
|---|---|---|---|
| Postgres | `graph` | `migrate`, `serve`, `worker` | owns the `graph` database, so it applies the schema and River's job tables; not a superuser, so no `COPY ... TO PROGRAM`, no server files, no new roles or databases ([`postgres-init.sql`](../helm-chart/graph/files/postgres-init.sql)) |
| Postgres | `postgres` | the `postgres` container only | the image's bootstrap superuser |
| ClickHouse | `graph` | `serve`, `worker` | `SELECT` and `INSERT` on the `graph` database, `ALTER DELETE` on `assets` and `graph_edges` (connector purge), `OPTIMIZE` on five tables, and reads of `system.parts` and `system.projection_parts` for its size guard; no DDL, no `DROP` or `TRUNCATE`, nothing that rewrites `audit_events` ([`clickhouse-users.xml`](../helm-chart/graph/files/clickhouse-users.xml)) |
| ClickHouse | `graph_migrate` | `migrate`, and the image's creation of the `graph` database | every right on the `graph` database, none outside it |
| both | `graph_scanner` | nothing in this stack | the Helm chart's scanner users: River's job tables and the scan tables on Postgres, reads of assets and findings and inserts of findings on ClickHouse |

ClickHouse has no other user: the image's passwordless `default` admin is
removed. To open a client as `graph_migrate`:

```sh
docker compose exec clickhouse sh -c '. /secrets/env; clickhouse-client --password "$CLICKHOUSE_PASSWORD"'
```

The `graph` users can still write the rows the app itself writes, users and API
keys included, so their credentials are still Vulngraph admin access
([Credential isolation](../../docs/security-hardening.md#credential-isolation)).
This stack has no scanner container: nuclei runs in the worker, as `graph`. The
Postgres users exist from the first start on, with the passwords the `init`
service generated; to change one later, `ALTER ROLE graph PASSWORD '...'`
(`docker compose exec postgres psql -U postgres -d graph`) and update the
generated file to match. ClickHouse reads its three passwords on every start.

## Upgrading

`git pull`, then `docker compose up -d`: the image is rebuilt from the
checkout. Migrations run automatically on every start via the `migrate`
service, before `serve`/`worker` start. `docker compose exec serve /graph
version` prints the running build.

## Running a published release

`.github/workflows/release.yaml` publishes a multi-arch image to
`ghcr.io/vulngraph/vulngraph` for every release tag; the root
[`CHANGELOG.md`](../../CHANGELOG.md) lists the releases. Set `GRAPH_VERSION`
in `.env` to the tag (for example `v0.1.0`) and add
`docker-compose.release.yml`:

```sh
docker compose -f docker-compose.yml -f docker-compose.release.yml pull
docker compose -f docker-compose.yml -f docker-compose.release.yml up -d
```

Set `COMPOSE_FILE=docker-compose.yml:docker-compose.release.yml` in `.env` to
make every `docker compose` command in this directory use it.
`GRAPH_VERSION` has no default: without it, Compose stops with an error naming
it. The release file drops the build, so a failed pull is an error, never a
local build under the release's name. `GRAPH_IMAGE` runs a fork's published
image. `GRAPH_VERSION=edge` runs the rolling build of `main` instead: it is
unversioned and has no upgrade guarantees from one build to the next.

To upgrade, bump `GRAPH_VERSION`, then `pull` and `up -d` again.

### Pinning and verifying the image

A tag can be moved; a digest cannot. Append the digest to `GRAPH_VERSION`
(`GRAPH_VERSION=v0.1.0@sha256:<digest>`), and Compose pulls exactly that image.
How to look up the digest and check its signature and provenance is in
[`deploy/README.md`](../README.md#verifying-a-release-image).

## This vs. the root `docker-compose.yml`

The root `docker-compose.yml` only starts Postgres + ClickHouse — it's for
building from source and running `go run ./cmd/graph serve` yourself (see
[`CONTRIBUTING.md`](../../CONTRIBUTING.md)), and the integration tests run
against it. It keeps one admin user per datastore (`graph`/`graph`, published
on loopback only), because the tests need it. This one runs the whole thing
from the image instead, with the users above.
