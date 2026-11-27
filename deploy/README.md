# Deploy

Vulngraph deploys as one image (`serve` / `worker` / `scanner` / `migrate` run modes)
into any Kubernetes cluster via the Helm chart in `deploy/helm-chart/graph`.
Nothing here assumes a particular cloud, ingress controller, or auth proxy —
override the pieces that don't match your stack via `deploy/helm-values/example.yaml`.

For production, layer [`deploy/helm-values/hardened.yaml`](helm-values/hardened.yaml)
under your values. It sets `hardened: true`, which fails the render until you have
supplied every value only you know (image digest, host, network ranges, datastore
certificates). Then work through
[docs/production-checklist.md](../docs/production-checklist.md), which also covers what the
chart cannot do: backups, rotation, upgrades, monitoring and IAM.

## Quickstart

The chart's default image is this project's own multi-arch (amd64 + arm64)
image, which `.github/workflows/release.yaml` publishes to
`ghcr.io/vulngraph/vulngraph` on every tagged release (`vX.Y.Z`). The chart
pulls the tag named by its `appVersion` (`0.1.0` in `Chart.yaml`), so the chart
at a release tag runs that release's image. The fastest path is:

```sh
cp deploy/helm-values/example.yaml deploy/helm-values/my-values.yaml
# Required secrets — the render fails without them. Keep them out of git:
# pass them on the command line (as here) or in an untracked values file.
SECRETS="secret.secretKey=$(openssl rand -base64 32)"
SECRETS="$SECRETS,secret.postgresPassword=$(openssl rand -hex 24)"
SECRETS="$SECRETS,secret.postgresSuperuserPassword=$(openssl rand -hex 24)"
SECRETS="$SECRETS,secret.postgresScannerPassword=$(openssl rand -hex 24)"
SECRETS="$SECRETS,secret.clickhousePassword=$(openssl rand -hex 24)"
SECRETS="$SECRETS,secret.clickhouseMigratePassword=$(openssl rand -hex 24)"
SECRETS="$SECRETS,secret.clickhouseScannerPassword=$(openssl rand -hex 24)"
helm template graph deploy/helm-chart/graph -f deploy/helm-values/my-values.yaml \
  --set-string "$SECRETS"
helm upgrade --install graph deploy/helm-chart/graph \
  -n graph --create-namespace \
  -f deploy/helm-values/my-values.yaml --set-string "$SECRETS"
```

Generate the secrets once and store them (a password manager, your secret
store): re-running `openssl rand` on a later upgrade would rotate the database
passwords out from under the existing data volumes. See
[Secrets](#secrets-generate-your-own-never-commit-them) below, and
[Datastore users](#datastore-users) for what each password opens.

Install **one release per namespace**: the objects in the release namespace
have fixed names (`graph-serve`, `graph-worker`, `graph`, `graph-secrets`, ...).
The objects outside it, the ClusterRoles and their bindings and the `VMRule` in
`alerts.namespace` (when `alerts.enabled`), are prefixed with
`<namespace>-<release>-`, so installs in different namespaces do not collide.

### First admin and access

The chart creates no user. Once the serve pod is ready, create the first admin
inside it; the command prints the generated password (prefer it to `--password`,
which leaves the password in shell history and process listings):

```sh
kubectl -n graph rollout status deploy/graph-serve
kubectl -n graph exec deploy/graph-serve -c serve -- \
  /graph user create --email you@example.com --role admin
```

Without an ingress, reach the UI through the `graph` Service:

```sh
kubectl -n graph port-forward svc/graph 8080:8080
# open http://localhost:8080
```

Safari refuses the `Secure` session cookie over plain `http://localhost`; use
another browser for the port-forward, or see `COOKIE_INSECURE` in
[docs/security-hardening.md](../docs/security-hardening.md) (local only). With
SSO configured (`sso.*`, `config.oauth2Proxy`, `config.iapAudience`), name the
first admins in `config.adminEmails` instead.

`kubectl -n graph exec deploy/graph-serve -c serve -- /graph version` prints the
running release.

### Building the image yourself

To run a commit that has no release, or a change of your own, build the image
and point the chart at it:

```sh
docker build --build-arg VERSION=dev -t vulngraph:dev .
kind load docker-image vulngraph:dev          # kind; for minikube: minikube image load
helm upgrade --install graph deploy/helm-chart/graph -n graph --create-namespace \
  -f deploy/helm-values/my-values.yaml --set-string "$SECRETS" \
  --set image.repository=vulngraph --set image.tag=dev --set image.pullPolicy=Never
```

For a remote cluster, push the build to a registry it can pull from instead of
`kind load`, and drop `pullPolicy=Never`. The workflow also pushes `edge`, the
rolling build of `main` (linux/amd64 only), on every push to `main`: it is unversioned and has no
upgrade guarantees from one build to the next, and with the default
`pullPolicy: IfNotPresent` pods on different nodes can run different builds of
it, so pin it with `image.digest` if you run it at all.

### Publishing releases (maintainers)

Tag `vX.Y.Z` on a commit whose `deploy/helm-chart/graph/Chart.yaml` has
`appVersion: "X.Y.Z"`; the release workflow refuses a tag that does not match.
It pushes `vX.Y.Z`, `X.Y.Z` (what the chart pulls by default) and `latest`, and
cuts a GitHub Release. GHCR creates a new package as private: right after the
first release, open the package's settings on GitHub
(`github.com/orgs/<owner>/packages/container/<repo>/settings`) and change its
visibility to public, once.

### Verifying a release image

The release workflow (`.github/workflows/release.yaml`) signs each image it
pushes with keyless cosign and attaches a GitHub build-provenance attestation,
both bound to the image digest. It does both only while the repository is
public.

1. Look up the digest of the tag you want (the `Digest:` line, the multi-arch
   index the workflow signs):

   ```sh
   docker buildx imagetools inspect ghcr.io/vulngraph/vulngraph:vX.Y.Z
   ```

2. Check the signature. The certificate identity is the release workflow at
   the tag that built the image (`refs/heads/main` for an `edge` build):

   ```sh
   cosign verify ghcr.io/vulngraph/vulngraph@sha256:<digest> \
     --certificate-identity https://github.com/vulngraph/vulngraph/.github/workflows/release.yaml@refs/tags/vX.Y.Z \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com
   ```

3. Check the provenance:

   ```sh
   gh attestation verify oci://ghcr.io/vulngraph/vulngraph@sha256:<digest> \
     --repo vulngraph/vulngraph \
     --signer-workflow vulngraph/vulngraph/.github/workflows/release.yaml
   ```

4. Deploy that digest, so the image cannot change under the tag: Helm
   `image.digest: sha256:<digest>` (every graph container then runs
   `repository@digest`; `image.tag` is ignored), Compose
   `GRAPH_VERSION=vX.Y.Z@sha256:<digest>` with `docker-compose.release.yml`.

A fork's images are signed by its own workflow: replace `vulngraph/vulngraph`
with the fork's owner and repository in both commands.

### Upgrading

`image.tag` is empty by default, which means the deployment templates fall
back to `.Chart.AppVersion` — the same convention most published Helm charts
use. Concretely: pull this chart at a newer release tag and `helm upgrade` —
the image moves with it automatically, no separate `--set image.tag=...`
needed. Pin a specific
version regardless of chart changes with `image.tag: v0.1.0` in your values
file, or track the rolling main-branch build with `image.tag: edge`. Every
release is tagged both `vX.Y.Z` and `X.Y.Z`.

Running your own fork, or want a specific commit? Build your own image —
it's self-contained, no external registry dependency (it downloads the pinned,
checksum-verified LadybugDB release instead of compiling a graph engine):

```sh
SHA=$(git rev-parse --short HEAD)
docker build --build-arg VERSION="$SHA" -t <your-registry>/vulngraph:"$SHA" .
docker push <your-registry>/vulngraph:"$SHA"   # skip if using a local/kind cluster
```

Then point the chart at it: add `image.repository`/`image.tag` to your values
file, or `--set image.repository=<your-registry>/vulngraph --set image.tag=<sha>`.
A fork's own release workflow publishes to `ghcr.io/<owner>/<repo>`.

`ENTRYPOINT graph`, `CMD serve`. The worker Deployment runs `worker`.
The isolated disk reader runs `scanner` only when `config.diskScanEnabled`
and `scanner.enabled` are both true. Disk scanning is off by default and
requires each connector to opt in. Keep `scanner.enabled: true` to separate
disk parsing from the worker and its application credentials.

The disk reader receives its own `graph_scanner` database credentials and a
dedicated disk-job envelope key. It receives no `GRAPH_SECRET_KEY`, LLM key,
signing secrets, chart-wide extra environment, or cloud workload identity.
Its service account has no mounted Kubernetes token. It can modify River
jobs and disk results, so these restrictions do not make it a complete sandbox.
See [Credential isolation](../docs/security-hardening.md#credential-isolation).

Migrations run as an init container with `migrate` in the serve pod.

Renders: serve Deployment (migrate init container, ClusterIP by default —
`ingress.yaml` is rendered when `ingress.enabled`), worker Deployment (River
jobs, gated on `worker.enabled`), scanner Deployment (isolated disk reader, gated on both `scanner.enabled` and `config.diskScanEnabled`),
Service, Secret, ServiceAccount, plus `ladybug-internal-svc.yaml` and
`ladybug-pvc.yaml`, the volume for Ladybug's warm-start snapshot (the graph
itself is in memory and is rebuilt from ClickHouse; the snapshot only speeds up
a restart). Every value has a
default in `deploy/helm-chart/graph/values.yaml`, documented inline — that
file is the source of truth for what's configurable.

Don't want Kubernetes at all? [`deploy/docker-compose/`](docker-compose)
runs the full stack (Postgres + ClickHouse + serve + worker) with one
`docker compose up -d` — no Go/bun toolchain. It builds the image from the
checkout; `docker-compose.release.yml` runs a release image at the version
pinned in `GRAPH_VERSION` instead (see
[`deploy/docker-compose/README.md`](docker-compose/README.md)). Running from
source instead: `docker compose up -d` (root
`docker-compose.yml`, datastores only) plus `go run ./cmd/graph serve` (see
CONTRIBUTING.md's [Dev setup](../CONTRIBUTING.md#dev-setup)).

## Datastores — in-cluster (default)

Postgres + ClickHouse ship as StatefulSets in the chart (`postgres.enabled` /
`clickhouse.enabled`, default true) — self-contained, no managed-service
dependency, marginal cost ≈ just the PVCs. There is nothing to wire: the chart
builds the DSNs itself from the passwords in `secret.*`, pointing at the
headless Services (`graph-postgres:5432`, `graph-clickhouse:9000`).

Both run as their images' own non-root users (uid 70 and 101) with a
RuntimeDefault seccomp profile and every capability dropped, so the namespace
can enforce the PodSecurity `restricted` level. If you swap
`postgres.image` for a Debian-based one, set `postgres.podSecurityContext`'s ids
to 999.

**Transport.** By default the bundled servers have no certificate, so the
graph pods reach them in plaintext on the pod network: the Postgres DSN carries
`sslmode=prefer`, which falls back to plaintext, and ClickHouse is the native
protocol on 9000. The [NetworkPolicy](#network-policy) limits who can
connect, not who can read the traffic. To encrypt it, give each server a `kubernetes.io/tls` Secret whose
certificate covers its Service name (`graph-postgres`, `graph-clickhouse`;
cert-manager writes this shape):

```yaml
postgres:
  tlsSecret: graph-postgres-tls
  sslMode: require        # or verify-ca / verify-full
clickhouse:
  tlsSecret: graph-clickhouse-tls
  secure: true            # DSN on :9440 with secure=true
```

`require` encrypts without checking the certificate. `verify-ca` and
`verify-full` also check it against the Secret's `ca.crt` (cert-manager writes
one for a CA issuer), which the chart then mounts into the graph pods and names
in the DSN's `sslrootcert`; `verify-full` also checks the name
`graph-postgres`. ClickHouse's `secure` encrypts without checking the
certificate (`skip_verify=true`): its client checks only against the system CA
bundle, which a certificate for `graph-clickhouse` does not chain to. The
render fails if `sslMode` is `require` or a verify mode, or `secure` is on,
without the matching `tlsSecret`.

### Datastore users

No graph pod connects as a datastore admin. The bundled Postgres creates its
roles on the first start of an empty volume (`files/postgres-init.sql` in the
chart), and the bundled ClickHouse loads its users from
`files/clickhouse-users.xml` on every start:

| datastore | user (password) | used by | rights |
|---|---|---|---|
| Postgres | `graph` (`secret.postgresPassword`) | migrate, serve, worker | owns the `graph` database, so it applies the schema and River's job tables (River's reindexing needs the owner); not a superuser and none of the `pg_*_server_*` roles, so no `COPY ... TO PROGRAM`, no server files, no new roles or databases |
| Postgres | `graph_scanner` (`secret.postgresScannerPassword`) | scanner | owns nothing; after every run migrate grants it River's job tables, the schema version, disk result tables and the connector-mode view (`internal/migrate/scanner.go`); nothing on users, sessions, API keys or connectors |
| Postgres | `postgres` (`secret.postgresSuperuserPassword`) | only the Postgres StatefulSet | the image's bootstrap superuser |
| ClickHouse | `graph` (`secret.clickhousePassword`) | serve, worker | `SELECT` and `INSERT` on `graph.*`, `ALTER DELETE` on `assets` and `graph_edges` (connector purge), `OPTIMIZE` on five tables and `SELECT` on `system.parts` and `system.projection_parts` (part compaction); no DDL, no `DROP` or `TRUNCATE`, nothing that rewrites `audit_events` |
| ClickHouse | `graph_scanner` (`secret.clickhouseScannerPassword`) | scanner | `SELECT` on `goose_db_version`; nothing else |
| ClickHouse | `graph_migrate` (`secret.clickhouseMigratePassword`) | the migrate init container, and the image's bootstrap of the `graph` database | `ALL` on `graph.*`; `SELECT` on `system.detached_tables` and `system.mutations` for resumable migration checks |

The bundled ClickHouse has no other user: the image's passwordless `default`
admin is removed. `kubectl -n graph exec -it graph-clickhouse-0 --
clickhouse-client` connects as `graph_migrate` (the container's
`CLICKHOUSE_USER` and `CLICKHOUSE_PASSWORD`), which can read and change the
`graph` database and read migration metadata, but cannot manage users or change other databases.

The render fails without any of the six passwords, or when one equals another
user's. Postgres sets its passwords once: changing `secret.postgresPassword`
later also needs `ALTER ROLE graph PASSWORD '...'` (`kubectl -n graph exec
graph-postgres-0 -- psql -U postgres -d graph`), and likewise for
`graph_scanner`; the bootstrap stops instead of creating a role without a
password if a value is missing. ClickHouse reads its three passwords from the
Secret on every start and takes an empty value as an empty password, so with
`secret.create: false` keep `clickhouse-password`, `clickhouse-migrate-password`
and `clickhouse-scanner-password` non-empty (the chart's own Secret refuses to
render without them). The app users still write every row the app writes, users
and API keys included; the scanner's do not
([Credential isolation](../docs/security-hardening.md#credential-isolation)).

### External datastores

Set `postgres.enabled=false` / `clickhouse.enabled=false` and give the full DSNs
— the only datastore settings the app reads:

```yaml
postgres: { enabled: false }
clickhouse: { enabled: false }
secret:
  databaseUrl: postgres://graph:<pw>@db.example.internal:5432/graph?sslmode=require
  clickhouseUrl: clickhouse://graph:<pw>@ch.example.internal:9440/graph?secure=true
  # migrate's user; empty = clickhouseUrl
  clickhouseMigrateUrl: clickhouse://graph_migrate:<pw>@ch.example.internal:9440/graph?secure=true
  # the scanner's users; required while scanner.enabled
  scannerDatabaseUrl: postgres://graph_scanner:<pw>@db.example.internal:5432/graph?sslmode=require
  scannerClickhouseUrl: clickhouse://graph_scanner:<pw>@ch.example.internal:9440/graph?secure=true
```

With `scanner.enabled` (the default) the render fails until both scanner URLs
are set. To run the scanner as the app users instead, set them to the values of
`databaseUrl` and `clickhouseUrl`: the scanner then holds every row the app
writes, users and API keys included.

Give them the same users as the bundled datastores. On Postgres, as an admin
(on a managed service, its master user):

```sql
CREATE ROLE graph LOGIN PASSWORD '<pw>' NOSUPERUSER NOCREATEDB NOCREATEROLE;
-- A master user that is not a superuser (RDS, Cloud SQL, Postgres 16+) may only
-- create a database owned by a role it can SET ROLE to.
GRANT graph TO CURRENT_USER;
CREATE DATABASE graph OWNER graph;
REVOKE graph FROM CURRENT_USER;
```

The app role must own the database and be able to create tables in its
`public` schema: migrate creates the schema and River's job tables as it, and
River's periodic `REINDEX` needs the owner. On Postgres 15 and later the
database owner can, and nobody else. On Postgres 14 and older every role can
create in `public` through `PUBLIC`, so take that away and give it to `graph`
alone, connected to the `graph` database as the same admin:

```sql
-- Postgres 14 and older only.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CREATE ON SCHEMA public TO graph;
```

Do not grant `graph` superuser, `rds_superuser`/`cloudsqlsuperuser`, or the
`pg_*_server_*` roles; it needs none of them.

The scanner's role owns nothing and needs no grants from you: whenever it
exists, migrate (as `graph`, the tables' owner) grants it River's job tables and
the scan tables at the end of every run. Create it as the same admin:

```sql
CREATE ROLE graph_scanner LOGIN PASSWORD '<pw>' NOSUPERUSER NOCREATEDB NOCREATEROLE;
```

Migrate grants only while it runs, as serve's init container, so create the
role before the install, or restart serve after creating it (`kubectl -n graph
rollout restart deploy/graph-serve`); until then the scanner's queries fail with
`permission denied`. Without the role, migrate grants nothing and logs that it
skipped the step. Migrate fails, naming what to revoke, while `graph_scanner`
holds any of these, which its grants do not give it and revoking them does not
take away:

- `CREATE` on a schema or on the database. An object it creates where
  `graph`'s queries look up names (a function or operator in `public`, which
  every role can create in on Postgres 14 and older unless revoked as above)
  would run with `graph`'s rights.
- Membership in any role: `graph`, `pg_read_all_data`, `pg_write_all_data`,
  `pg_execute_server_program`, or a provider's admin role. A user created
  through a provider's console or API rather than with the statement above
  may get one (Cloud SQL makes such users members of `cloudsqlsuperuser`).
- `SUPERUSER`, `CREATEROLE` or `REPLICATION`.
- A privilege on a table or sequence `graph` owns that comes from `PUBLIC` (a
  grant, or default privileges) or from a role, rather than from migrate's
  grants. The system catalogs and extension objects do not count: they hold
  no Vulngraph data, and when migrate runs as the server's bootstrap superuser
  it owns all of them.

On ClickHouse, as a user with access management:

```sql
CREATE DATABASE graph;
CREATE USER graph_migrate IDENTIFIED WITH sha256_password BY '<pw>' DEFAULT DATABASE graph;
GRANT ALL ON graph.* TO graph_migrate;
GRANT SELECT ON system.detached_tables TO graph_migrate;
GRANT SELECT ON system.mutations TO graph_migrate;
CREATE USER graph IDENTIFIED WITH sha256_password BY '<pw>' DEFAULT DATABASE graph;
GRANT SELECT, INSERT ON graph.* TO graph;
GRANT ALTER DELETE ON graph.assets TO graph;
GRANT ALTER DELETE ON graph.graph_edges TO graph;
GRANT OPTIMIZE ON graph.graph_edges TO graph;
GRANT OPTIMIZE ON graph.signals TO graph;
GRANT OPTIMIZE ON graph.beliefs TO graph;
GRANT OPTIMIZE ON graph.findings TO graph;
GRANT OPTIMIZE ON graph.assets TO graph;
GRANT SELECT ON system.parts TO graph;
GRANT SELECT ON system.projection_parts TO graph;
CREATE USER graph_scanner IDENTIFIED WITH sha256_password BY '<pw>' DEFAULT DATABASE graph;
GRANT SELECT ON graph.goose_db_version TO graph_scanner;
```

These are the grants of `files/clickhouse-users.xml`. `cmd/graph/chart_chgrants_test.go`
derives `graph`'s from the statements in the code and fails on a statement kind
it recognises and has no grant for; it reads SQL written as string literals,
`+` concatenations of them and `Sprintf` templates, with the verb and table in
the literal (a statement assembled with `strings.Builder` or `strings.Join`, or
whose verb is a `%s`, is not seen), and DDL, `TRUNCATE`, `SYSTEM`, `KILL` and
`GRANT` in upper case only. `internal/migrate/scanner_reach_test.go` walks the
code the scanner pod can run and derives `graph_scanner`'s grants, on both
datastores, from the statements it reaches. Keep `graph` and `graph_scanner` on
a settings profile with `readonly=0`: queries set per-query `SETTINGS` such as
`max_execution_time`.

The chart passes these URLs through unchanged, so the transport is whatever
they say: keep `sslmode=require` or stronger (`verify-full` needs the server's
CA in the system bundle, or an `sslrootcert` file in the pods) and ClickHouse's
secure port with `secure=true`.

An external ClickHouse should carry the same server settings the in-chart one
gets from `templates/clickhouse-config.yaml`: cache ceilings, system-log TTLs,
and a `max_execution_time` of at least 600s (each query's Go timeout is the
real bound; a lower server default kills the long bulk reads).

### Sizing

ClickHouse holds the inventory, findings and graph edges; Postgres holds users,
connectors and jobs and stays small. Set the volume sizes before the first
install — growing a bound PVC later needs a storage class with
`allowVolumeExpansion`. Keep `clickhouse.storage` and `postgres.storage` the
same on every later `helm upgrade`: a StatefulSet's volume claim template cannot
change, so the upgrade would be rejected. The rows are starting points, not measurements: watch
the ClickHouse volume and the worker's memory after the first full sync and
adjust.

| estate | assets | `clickhouse.storage` | `clickhouse.resources.limits` | `worker.resources.limits` | `postgres.storage` |
|---|---|---|---|---|---|
| small | up to ~10k | 50Gi (default) | 2 CPU / 4Gi (default) | 1 CPU / 4Gi (default) | 20Gi (default) |
| medium | ~10k–100k | 150Gi | 4 CPU / 8Gi | 2 CPU / 6Gi | 20Gi |
| large | 100k+ | 500Gi+ | 8 CPU / 16Gi | 4 CPU / 8Gi | 50Gi |

When you raise `clickhouse.resources.limits`, raise `clickhouse.tuning` with it
(`maxThreads` ≈ CPU limit, `maxServerMemoryBytes` ≈ 75% and `maxMemoryBytes` ≈
50% of the memory limit — see the comments in `values.yaml`). For a large
graph, raise `ladybug.bufferPoolMB` alongside the worker's memory limit.

## Network policy

`networkPolicy.enabled` is on by default and renders one NetworkPolicy per
component (`templates/networkpolicy.yaml`). Ingress only: egress stays open,
because the collectors call cloud APIs.

| pod | accepts |
|---|---|
| Postgres | 5432 from serve (with its migrate init container), the worker and the scanner |
| ClickHouse | 9000 (and 9440 with `clickhouse.tlsSecret`) from the same three; not 8123, its HTTP SQL interface |
| worker | the graph RPC (8090) from serve |
| scanner | nothing |
| serve | its API port (`service.port`) from every source, until you set `networkPolicy.ingressNamespace` |

With `metrics.enabled`, each pod with a metrics port also accepts it, from
`networkPolicy.metricsNamespace` or, while that is empty, from every source.

None of this needs your cluster's details, so it cannot break an install: only
serve probes over HTTP, and its port stays open. Tighten serve to the ingress
controller once you know its namespace and your node address ranges:

```yaml
networkPolicy:
  ingressNamespace: ingress-nginx
  nodeCIDRs: ["10.0.0.0/16"]   # kubelet probes come from the node address
```

If your load balancer sends traffic straight to pod IPs (the AWS Load
Balancer Controller in IP target mode, GKE container-native load balancing),
its connections and health checks come from the load balancer's own
addresses, not from a pod in any namespace: add its subnets or health-check
ranges to `nodeCIDRs` as well, or serve is cut off from it.

The render fails with `ingressNamespace` and no `nodeCIDRs` (serve's probes
would be blocked), with `nodeCIDRs` and no `ingressNamespace` (the CIDRs would
restrict nothing), and `config.oauth2Proxy` refuses to render without
`ingressNamespace`. A CNI that does not enforce NetworkPolicy (Calico and
Cilium do; not every CNI does) ignores the objects. They are additive: to let
something else in, such as a backup job reaching Postgres, add a NetworkPolicy
of your own that admits it.

## Secrets (generate your own, never commit them)

The chart renders a Secret named `graph-secrets` with keys: `database-url`,
`clickhouse-url`, `clickhouse-migrate-url` (read only by the migrate init
container), `secret-key` (32-byte base64; encrypts connector credentials
and alert-channel secrets at rest and signs second-admin approval grants),
`llm-api-key` (the LLM provider key, from `secret.llmApiKey`, or the deprecated
`secret.anthropicApiKey`), `ladybug-rpc-secret` (shared-secret auth on the internal Ladybug
RPC port, read as `LADYBUG_RPC_SECRET`), plus `postgres-password`,
`postgres-superuser-password`, `postgres-scanner-password`,
`clickhouse-password`, `clickhouse-migrate-password` and
`clickhouse-scanner-password` for the in-cluster datastores. Set
only when the matching feature is on: `scanner-database-url` and
`scanner-clickhouse-url` (read only by the scanner pod), `google-client-secret`,
`okta-client-secret`, `decision-webhook-secret`, `approval-webhook-secret`,
`approval-token-secret`, `oauth2-proxy-shared-secret`, and
`retired-secret-keys` during a [key rotation](#rotating-graph_secret_key). A Secret managed out of
band (`secret.create: false`) must carry the same keys; the pods also read an
`anthropic-api-key` key from it when present. Wire
these from your own secrets manager / CI secret store — `helm upgrade
--set-string secret.secretKey=$(head -c32 /dev/urandom | base64) ...`, a
templated values file that's never committed, or `secret.create: false` plus a
Secret you manage out of band. `imagePullSecrets` is empty by default; add one
only if `image.repository` is a private registry.

## Sign-in, ingress and extra settings

- **Ingress.** `ingress.enabled`, `ingress.host`, `ingress.className` (empty =
  the cluster default class), `ingress.annotations`. TLS is on by default with
  the certificate in `ingress.tlsSecret`; set `ingress.tls: false` only when TLS
  ends in front of the ingress.
- **Google / Okta sign-in.** `sso.google.clientId` / `sso.okta.clientId` (plus
  `sso.okta.domain`) turn a provider on; the client secret goes in
  `secret.googleClientSecret` / `secret.oktaClientSecret`, and
  `sso.<provider>.allowedDomains` is required (the render fails without it,
  since an empty list refuses every sign-in). `sso.<provider>.redirectUrl` is
  required too: set it to `https://<host>/api/auth/<google|okta>/callback` and
  register the same URI with the provider (the render fails without it).
- **Anything else.** Settings from [docs/configuration.md](../docs/configuration.md)
  without a first-class value go in `extraEnv` / `extraEnvFrom` (serve, migrate
  and worker; never the scanner) or `serve.extraEnv`, `worker.extraEnv`,
  `scanner.extraEnv` (and the matching `extraEnvFrom`) for one component. An `extraEnv` entry replaces a
  variable the chart sets under the same name, so the pod spec carries one
  value per name. `hardened: true` refuses such an entry and any
  `extraEnvFrom` list ([production checklist](../docs/production-checklist.md#5-fill-in-the-overlay)).
- **Approval email over plaintext SMTP.** `config.smtpAllowPlaintext: true`
  (`SMTP_ALLOW_PLAINTEXT`) is dangerous: approval emails, whose approve/deny
  links are bearer credentials, go out unencrypted when the server offers no
  STARTTLS. Only for a relay on the same node or a trusted private link.

## Kubernetes connector RBAC

The in-cluster Kubernetes connector reads the cluster through the worker's
service account (`serviceAccount.name`); every Kubernetes grant the chart makes
is bound to that account alone. serve runs with
`automountServiceAccountToken: false`, so it holds none of them even when it
shares the account, and the scanner and the node posture reader run as
accounts of their own with no token. Set `kubernetesRBAC.collectorRead: true`
to grant it: a ClusterRole
with `list` on namespaces, pods, services, service accounts, config maps,
deployments, stateful sets, daemon sets, jobs, RBAC objects, ingresses, network
policies and cert-manager certificates, plus `get` on the OIDC discovery
document — never Secrets, never a write verb
(`templates/kubernetes-collector-rbac.yaml`). Without it the connector's sync
fails with `Forbidden`. `kubernetesRBAC.policyEngineRead` (on by default) adds
the admission-policy reads for CIS 5.2.1.

## Cloud auth: OIDC

AWS and GCP connectors can run with no stored cloud secret: the worker (and
serve, for the connector "Test" button) authenticates by federating its
Kubernetes identity. AWS also accepts static access keys (per connector, or once
on an `aws_org` hub with `hub_auth=access_key`, which assumes the hub role named
by `hub_role_arn`), for clusters without workload
identity; they are encrypted at rest. Prefer the ambient identity. This is wired in the chart; the
cloud-side trust below is provisioned once, out of band (needs cloud-admin), then
the two values are set.

Other connectors do store credentials — an Azure service-principal client
secret, a GitHub App private key, Okta and Google Workspace tokens, executor
credentials such as `execute_client_secret` — and so do alert channels (Slack bot tokens, webhook
URLs). Those are encrypted at rest under `secret-key`; see
[Connector credential encryption](#connector-credential-encryption). Grant
those credentials only the permissions listed in
[docs/iam/identity-and-code-connectors.md](../docs/iam/identity-and-code-connectors.md).

### GCP — Workload Identity

The worker uses Application Default Credentials from a bound GCP service account.

The full permission map (every API call and the role that grants it) is in
[docs/iam/gcp-cspm-permissions.md](../docs/iam/gcp-cspm-permissions.md).

```sh
# 1. A collector SA with Viewer + Security Reviewer on each target project
#    (or once on the folder / organization above them). For a narrower grant
#    than Viewer, use the graphCollectorReader custom role from
#    docs/iam/gcp-cspm-permissions.md in its place.
gcloud iam service-accounts create graph-collector --project <PROJECT>
for role in roles/viewer roles/iam.securityReviewer; do
  gcloud projects add-iam-policy-binding <TARGET_PROJECT> \
    --member "serviceAccount:graph-collector@<PROJECT>.iam.gserviceaccount.com" \
    --role "$role"
done

# 1b. Optional, for the organization-level CIS controls (org domain, VPC
#     Service Controls, org contacts / Access Approval, aggregated sinks):
#     the custom organization role defined in docs/iam/gcp-cspm-permissions.md.
gcloud organizations add-iam-policy-binding <ORG_ID> \
  --member "serviceAccount:graph-collector@<PROJECT>.iam.gserviceaccount.com" \
  --role organizations/<ORG_ID>/roles/graphCspmOrgReader

# 2. Bind the in-cluster k8s SA (namespace/graph) to it.
gcloud iam service-accounts add-iam-policy-binding \
  graph-collector@<PROJECT>.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:<PROJECT>.svc.id.goog[<NAMESPACE>/graph]"
```

Then set `serviceAccount.gcpServiceAccount: graph-collector@<PROJECT>.iam.gserviceaccount.com`.

### AWS — OIDC web-identity federation

The worker and serve pods project a service-account token (audience
`sts.amazonaws.com`) and the AWS SDK exchanges it via STS
`AssumeRoleWithWebIdentity` for a base role, which then assumes each
connector's `role_arn` cross-account. (serve needs it for the connector "Test"
button.) On EKS you can use IRSA instead: leave `aws.enabled` off and set
`serviceAccount.annotations: {eks.amazonaws.com/role-arn: <role arn>}`.
Azure Workload Identity works the same way: annotate the ServiceAccount with
`azure.workload.identity/client-id` (`serviceAccount.annotations`) and set
`serviceAccount.azureWorkloadIdentity: true`, which labels only the serve and
worker pods `azure.workload.identity/use: "true"`. Do not set that label through
`extraLabels`: it reaches every pod, including the datastores and node-posture.

```sh
# Cluster OIDC issuer (the projected token's `iss`):
ISSUER=$(kubectl get --raw /.well-known/openid-configuration | jq -r .issuer)

# 1. Register that issuer as an AWS IAM OIDC provider, audience sts.amazonaws.com.
aws iam create-open-id-connect-provider \
  --url "$ISSUER" --client-id-list sts.amazonaws.com

# 2. Base role trusting it, scoped to the namespace/graph SA subject:
#    Condition: "<issuer-host>:sub" = "system:serviceaccount:<NAMESPACE>:graph",
#               "<issuer-host>:aud" = "sts.amazonaws.com".
# 3. Each target-account role trusts this base role (cross-account sts:AssumeRole).
```

Then set `aws.enabled: true` and `aws.roleArn: arn:aws:iam::<ACCT>:role/graph-collector`.
Until both clouds are provisioned, leave the values empty/disabled — the worker
runs but a connector whose cloud lacks a bound identity will fail to sync unless
it carries static AWS access keys.

## Monitoring: how metrics leave the pod and how alerts come back

The binary exposes a Prometheus registry on `METRICS_PORT` (off by default —
turn it on with `metrics.enabled: true`). Getting something to actually scrape
it is a separate step, and the mechanism depends entirely on what runs your
metrics pipeline:

- **Prometheus Operator** (ServiceMonitor/PodMonitor): this chart doesn't render
  either CRD. If that's your setup, add your own ServiceMonitor selecting the
  `graph` pods, or open a PR — it's a small addition.
- **Annotation-based scraping** (a Prometheus/vmagent whose scrape config keys
  off `prometheus.io/scrape`, `prometheus.io/port`, `prometheus.io/path`): this
  is what `metrics.enabled` wires up. It sets those three pod annotations, a
  named `metrics` containerPort (some scrape configs drop targets with no
  declared container port even if the annotation is present — check yours),
  and plain `app`/`component` pod labels so a `component="worker"` selector
  works regardless of what your job's labelmap keeps from
  `app.kubernetes.io/*`. The serve pod reports a structural
  `graph_ladybug_node_count` of 0 unless `serveLadybug.enabled`, so any rule on that
  series (or others the worker alone populates) needs to pin `component="worker"`
  or it silently averages against the zero.

Alerting (`alerts.enabled`, off by default) targets **VictoriaMetrics**
specifically: it renders a `VMRule` CR from `helm-chart/graph/alerts/rules.yaml`,
evaluated by `vmalert` against whatever `ruleSelector`/`ruleNamespaceSelector`
your `vmalert` config uses — set `alerts.namespace` and `alerts.ruleLabels` to
match it, or the CR is accepted, stored, and silently never evaluated. Each rule
carries only `severity` (`warning`, or `critical` for the two outage rules);
`alerts.labels` adds your Alertmanager routing labels to every alert (empty by
default, so alerts route on severity alone). The `graph-intel-scc` group, which
alerts when the GCP Security Command Center feed has never refreshed, renders
only when `config.sccOrgId` is set, since the feed does not run otherwise. Running
Prometheus/Alertmanager instead? Treat `rules.yaml` as a reference for which
`graph_*` series matter and port the expressions to your own rule format —
`internal/obs/alerts_test.go` keeps every metric name in it honest against what
the binary actually emits, which is the useful part to keep either way.

Inspect what would be applied without applying it:

```sh
helm template graph deploy/helm-chart/graph -f deploy/helm-values/my-values.yaml \
  --show-only templates/vmrule.yaml
```

## Container hardening

The serve, worker and scanner deployments run with `runAsNonRoot`, `runAsUser: 65532`, dropped
capabilities, `seccompProfile: RuntimeDefault` and a read-only root filesystem
(`securityContext.*` in `values.yaml`). The image sets `USER nonroot` too; the
manifest settings are what make the cluster enforce it.

The one setting with a runtime failure mode is `readOnlyRootFilesystem`. The
binary genuinely writes outside its volumes:

| path | writer | volume |
|---|---|---|
| `/tmp` | Ladybug COPY CSV staging when `/dev/shm` has no headroom (`graphstore/copy_load.go`) | `emptyDir`, `securityContext.tmpSizeLimit` (default 2Gi) |
| `/home/nonroot` (`$HOME`) | runtime libraries that require a writable home directory | `emptyDir`, `securityContext.homeSizeLimit` (default 1Gi) |
| `/dev/shm` | Ladybug COPY staging | provided by the runtime, unaffected |
| `/data/ladybug`, `/data/serve-ladybug` | Ladybug snapshots | PVCs, group-writable via `fsGroup` |

The serve (including its migrate init container), worker and scanner
deployments mount both `emptyDir`s. The in-cluster Postgres and ClickHouse
StatefulSets use their own `containerSecurityContext` values and are not
covered by this table. If a writer turns up that this
table missed, set `securityContext.readOnlyRootFilesystem: false` — that keeps
`runAsNonRoot` and the dropped capabilities, which are the settings with no
runtime risk. Do not disable `securityContext.enabled` for it.

The first symptom of a missed writer is not a crashing pod — the pod starts
fine. It is an `EROFS` in the worker's correlate sweep hours later. Watch the
first graph rebuild after you change any of these settings.

## Connector credential encryption

Connector config, the alert-channel secrets in `alert_channels` (Slack bot
tokens, webhook URLs) and users' TOTP seeds are stored under envelope
encryption: a per-row data key, wrapped by the key-encryption key, which is
`GRAPH_SECRET_KEY` itself. There is one such key for all of them: whoever holds
it and the database opens every row
([Encryption key](../docs/security-hardening.md#encryption-key)). Every one of them also binds the row's id (connector,
alert channel or user) in as additional authenticated data, so a ciphertext
cannot be replayed onto another row. Every write seals; a read refuses a value
that is not sealed.

`graph keys rewrap` re-seals every row under the current key. It is idempotent
(a row already sealed under the current key is skipped) and it refuses to
overwrite a row it could not first open: an unreadable credential is reported
by id and left alone rather than destroyed. Its main use is
[key rotation](#rotating-graph_secret_key).

`graph keys rewrap` runs inside a pod that already has the database and key
environment:

```sh
# Kubernetes
kubectl -n <namespace> exec deploy/graph-serve -c serve -- /graph keys rewrap
# Docker Compose (from deploy/docker-compose)
docker compose exec serve /graph keys rewrap
```

It prints one line per table (`connectors`, `alert channels`, `totp secrets`)
with how many rows it re-sealed. Re-running it is safe; a clean second run
reports `0` for each.

### Rotating GRAPH_SECRET_KEY

Envelopes name the key that sealed them, which is what makes rotation possible.
`GRAPH_RETIRED_SECRET_KEYS` (comma-separated) holds previous keys that are
trusted for decryption only; every write uses `GRAPH_SECRET_KEY`.

1. Set the new key and retire the old one, then restart serve and worker so
   they pick both up (a Secret change alone does not restart pods):
   - Helm: `secret.secretKey=<new>`, `secret.retiredSecretKeys=<old>` (or the
     `secret-key` / `retired-secret-keys` keys of a Secret you manage), then
     `kubectl -n <namespace> rollout restart deploy/graph-serve deploy/graph-worker`.
     Helm's `--set` splits on commas, so a list of several retired keys goes in
     a values file (`retiredSecretKeys: "<old1>,<old2>"`) or is escaped as
     `--set secret.retiredSecretKeys=<old1>\,<old2>`.
   - Compose: read the current key (`docker compose exec serve grep
     ^GRAPH_SECRET_KEY= /secrets/env`), then set `GRAPH_SECRET_KEY=<new>` in
     `app.env` (it outranks the generated file) and
     `GRAPH_RETIRED_SECRET_KEYS=<old>` in `.env`, then `docker compose up -d` (with the
     same `-f` files you started the stack with, or `COMPOSE_FILE` set in
     `.env`: a release run without `docker-compose.release.yml` rebuilds
     from the checkout instead).
2. Run `graph keys rewrap` (commands above). Every connector, alert-channel and
   TOTP seed row is re-sealed under the new key.
3. Clear the retired key (`secret.retiredSecretKeys=""` /
   `GRAPH_RETIRED_SECRET_KEYS=`) and restart serve and worker again.

Between steps 1 and 3 every row stays readable. If step 2 stops on a row, the
error names it and the key it is sealed under; fix the key list and run it again.
Do not do step 3 until a rewrap run has finished without an error: a row still
sealed under a key that is no longer configured cannot be opened.

Two other things change with the key:

- `ladybug-rpc-secret` is derived from `secret.secretKey` unless
  `secret.ladybugRpcSecret` is set, so the serve-to-worker RPC secret rotates
  too. Restart both pods together (step 1 does): until both have restarted,
  the worker refuses serve's graph-engine calls.
- Second-admin approval grants are signed with a key derived from
  `GRAPH_SECRET_KEY`. A grant minted before the restart no longer verifies;
  have the second admin approve again (grants only live 10 minutes anyway).

## Executor: execution roles

The executor mutates cloud resources with a principal that is **separate from
the collection credential**, and fails closed without one. Per connector:

| provider | config keys |
|---|---|
| AWS | `execute_role_arn` (required), `execute_external_id` (optional) |
| GCP | `execute_service_account` (required — impersonated) |
| Azure | `execute_client_id`, `execute_client_secret` (required), `execute_tenant_id` (falls back to `tenant_id`) |

The AWS execution role is assumed from the pod's ambient workload identity, not
from `role_arn` and not from any static keys the connector carries, and it is
rejected if it equals `role_arn` or `readonly_role_arn`. That ambient identity
is the same hub role the collectors use, so the separation from the collection
credential is enforced by Vulngraph, not by IAM, unless you hold the execution
path to serve's own ServiceAccount (EKS Pod Identity, `ExecutorServiceAccount`;
see [Credential isolation](../docs/security-hardening.md#credential-isolation)). Scope it to
the actions the connector is expected to perform — that policy, not the
collector's, is now the executor's ceiling.

Until these keys are set, a real `POST /api/executor/*` call returns 400
naming the missing key and makes no cloud call. It fails only after the
approval check and after its `executor.execute_intent` audit row is written,
so a missing key still leaves an intent row (and may have consumed a grant).
`dry_run: true` reports the planned change without contacting the cloud, but
it does not check these keys: a dry run succeeds on a connector that has no
execution principal configured. Check the keys above before minting a grant.

