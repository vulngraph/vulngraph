# Production checklist

A production install of the Helm chart, in order. Steps 1 to 6 happen before
or during `helm install` and use the hardened overlay,
[`deploy/helm-values/hardened.yaml`](../deploy/helm-values/hardened.yaml).
Steps 7 to 14 cover what the chart cannot do for you. Each step names the
setting and gives a command that shows it is done. The commands assume the
release `graph` in namespace `graph` and host `graph.example.com`.

The overlay sets `hardened: true`. With it, the render fails until every value
the operator has to supply is set and every check in
`templates/checks/hardened.yaml` holds, and the error lists every gap at once. Running `helm template` with the overlay and no
values of your own is a quick way to see what is left to do.

## 1. A dedicated namespace at PodSecurity `restricted`

Every pod the chart renders passes the `restricted` level. The exception is
`nodePosture.enabled`, whose hostPath mounts need `privileged`.

```sh
kubectl create namespace graph
kubectl label namespace graph pod-security.kubernetes.io/enforce=restricted
```

Verify after the install. The first command prints `restricted`. PodSecurity
admission refuses a pod before it exists, so a refused pod shows up as a
`FailedCreate` event (`violates PodSecurity`) and a workload short of its
replicas: the second command prints no events (they are kept for about an
hour), and the third shows every workload at full READY count.

```sh
kubectl get namespace graph -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}{"\n"}'
kubectl -n graph get events --field-selector reason=FailedCreate
kubectl -n graph get deployments,statefulsets
```

## 2. Generate the secrets once and keep them in a secret manager

Generate `secret.secretKey` (`openssl rand -base64 32`) and the four datastore
passwords (`openssl rand -hex 24` each, all different) once, and keep them
outside git. Regenerating them on a later upgrade locks the app out of its own
data volumes. Store `GRAPH_SECRET_KEY` apart from the database backups (step
9): together they open every connector credential
([Encryption key](security-hardening.md#encryption-key)). The overlay keeps
`secret.create: true` so the chart can check the datastore DSNs it builds,
and hardened refuses `secret.create: false`, so a Secret that External
Secrets, Sealed Secrets or a CSI driver writes cannot replace `graph-secrets`.
Pass the values with `--set-string` or a values file that your secret manager
templates.

Helm stores the values it is given, and the rendered `graph-secrets`, in a
release Secret per revision (`sh.helm.release.v1.graph.v<N>`). `helm upgrade`
keeps `--history-max` of them, 10 by default. Anyone who can read Secrets in
the namespace can read every key and password in that history, including
those you have since rotated (step 10). Keep Secret reads in the namespace to
the people who administer the install. In CI, keep command tracing
(`set -x`) off around `helm`, or pass the values in a values file, so that
they do not reach a job log.

Verify: `helm template` renders with them. The chart rejects a key that is not
base64 of 32 bytes and a datastore password reused between two users.

## 3. Pin the image by digest

Look up the release's digest and check its signature and provenance
([Verifying a release image](../deploy/README.md#verifying-a-release-image)),
then set `image.digest: sha256:<digest>`. Every graph container then runs
`repository@digest`. The bundled Postgres and ClickHouse images are pinned by
digest in `values.yaml` already.

Verify that only digests are running:

```sh
kubectl -n graph get pods -o jsonpath='{range .items[*]}{range .spec.initContainers[*]}{.image}{"\n"}{end}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | sort -u
```

## 4. Certificates for the datastores

Create a `kubernetes.io/tls` Secret for each bundled datastore whose
certificate covers its Service name, then set `postgres.tlsSecret` and
`clickhouse.tlsSecret`. A cert-manager CA issuer also writes `ca.crt`, which
the overlay's `postgres.sslMode: verify-full` needs:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: { name: graph-postgres-tls, namespace: graph }
spec:
  secretName: graph-postgres-tls
  dnsNames: [graph-postgres, graph-postgres.graph.svc, graph-postgres.graph.svc.cluster.local]
  issuerRef: { name: <your CA issuer>, kind: ClusterIssuer }
# and the same for graph-clickhouse (secretName graph-clickhouse-tls)
```

ClickHouse encrypts on port 9440 but does not check the certificate
(`skip_verify=true`; see
[Datastores](../deploy/README.md#datastores--in-cluster-default)). External
datastores need `secret.databaseUrl` (and `secret.scannerDatabaseUrl`) as a
`postgres://` (or `postgresql://`) URL whose `sslmode` is `require`, `verify-ca`
or `verify-full`, and `secure=true` in `secret.clickhouseUrl` (and in
`secret.clickhouseMigrateUrl` and `secret.scannerClickhouseUrl`).
The hardened checks refuse anything else: a missing parameter, a second one
with another value, a percent-escaped key, and a keyword/value Postgres
string.

Verify the DSNs the pods read, with passwords masked, and the live Postgres
sessions:

```sh
for k in database-url clickhouse-url clickhouse-migrate-url; do
  kubectl -n graph get secret graph-secrets -o "jsonpath={.data.$k}" | base64 -d | sed 's#//[^@]*@#//***@#'; echo
done
kubectl -n graph exec -i graph-postgres-0 -- sh -c \
  'PGPASSWORD="$POSTGRES_PASSWORD" psql -h 127.0.0.1 -U postgres -d graph -At' <<'SQL'
SELECT a.usename, s.ssl FROM pg_stat_ssl s JOIN pg_stat_activity a USING (pid) WHERE a.usename = 'graph';
SQL
kubectl -n graph exec graph-clickhouse-0 -c clickhouse -- \
  clickhouse-client --secure --port 9440 --accept-invalid-certificate -q 'SELECT 1'
```

Every `graph` row shows `t`, and the ClickHouse URLs name `:9440` with
`secure=true`.

## 5. Fill in the overlay

Put the values marked REQUIRED in the overlay into your own values file, and
layer that file after the overlay. A later `-f` replaces lists (such as
`nodeCIDRs`) rather than merging into them.

```yaml
# my-values.yaml
image: { digest: sha256:<digest> }
ingress: { host: graph.example.com }       # certificate in ingress.tlsSecret (graph-tls)
networkPolicy:
  ingressNamespace: ingress-nginx          # the ingress controller's namespace
  nodeCIDRs: ["10.0.0.0/16"]               # node ranges, plus any LB that targets pod IPs
  metricsNamespace: monitoring             # the metrics scraper's namespace
config:
  trustedProxyCidrs: "10.244.0.0/16"       # the ingress controller's pod range
postgres: { tlsSecret: graph-postgres-tls }
clickhouse: { tlsSecret: graph-clickhouse-tls }
```

```sh
helm template graph deploy/helm-chart/graph -f deploy/helm-values/hardened.yaml \
  -f my-values.yaml --set-string "$SECRETS" > /dev/null
helm upgrade --install graph deploy/helm-chart/graph -n graph \
  -f deploy/helm-values/hardened.yaml -f my-values.yaml --set-string "$SECRETS"
```

The overlay also turns on admin TOTP (`config.requireAdminTotp`), HSTS behind
the ingress (`config.tlsProxy`), the real client address
(`config.clientIpHeader`, `X-Forwarded-For`; use your controller's header),
metrics and `avoidSpotNodes`. Its spot label is GKE's. On EKS, Karpenter or
AKS set `avoidSpotNodeLabelKey` to that cloud's key (`values.yaml` lists
them) and the chart uses its spot value. For any other key also set
`avoidSpotNodeLabelValues`, or the render fails. Check that
`kubectl get nodes -L <key>` shows a listed value on exactly your spot nodes.
It keeps the scanner pod, the read-only root filesystem and the NetworkPolicy
on, and hardened refuses a range in `networkPolicy.nodeCIDRs` or
`config.trustedProxyCidrs` wider than `/8` for IPv4 or `/32` for IPv6 (`/7`
inside the unique-local `fc00::/7`). An IPv4-mapped range counts as
the IPv4 range serve reads it as, so `::ffff:0:0/96` is `0.0.0.0/0`. Under `hardened: true` the chart also refuses
every dangerous flag in [the table](security-hardening.md#dangerous-flags),
whether it is a chart value or an `extraEnv` entry. That includes `PASSWORD_LOGIN_BREAK_GLASS`:
behind IAP or oauth2-proxy it lets every local password sign in past the
proxy's MFA, and `config.requireAdminTotp` holds only admins to TOTP. If the
IdP is down and you need it, set it for the outage with `hardened=false` on
that one upgrade (the checks render no object, so that changes nothing else),
and undo both afterwards.

An `extraEnv` entry replaces a variable of the same name the chart sets, so
hardened also refuses an entry, in any `extraEnv` list, of a name the chart
sets on a pod that list reaches. It refuses the sign-in, datastore, proxy and
approval variables whose chart values it checks (`OAUTH2_PROXY`,
`IAP_AUDIENCE`, `GOOGLE_CLIENT_ID`, `ADMIN_EMAILS`, `DATABASE_URL`,
`TRUSTED_PROXY_CIDRS`, `DECISION_WEBHOOK_URL` and the rest) even where this
install does not set them. Set those through their chart values. It refuses
every `extraEnvFrom` list, whose variables it cannot see. List each variable
in `extraEnv` instead, with `valueFrom.secretKeyRef` for one held in a Secret.
Any other `extraEnv` entry renders unchecked, including a tuning variable
that loosens a default, such as `LOGIN_RATE_LIMIT_PER_IP=0`,
`LOGIN_RATE_LIMIT_PER_ACCOUNT=0`, `EXECUTOR_APPROVER_MIN_ACCOUNT_AGE=0s` or
`ALLOWED_ORIGINS` ([configuration](configuration.md)). Review each one.

Verify that serve's port turns away a pod outside the ingress namespace
(this needs a CNI that enforces NetworkPolicy), and that serve sends HSTS
(a port-forward reaches serve directly, without an auth proxy in the way):

```sh
kubectl -n default run np-probe --rm -i --restart=Never --image=busybox:1.37 -- \
  wget -q -T 5 -O /dev/null http://graph.graph.svc:8080/healthz && echo "OPEN: fix the NetworkPolicy"
kubectl -n graph port-forward svc/graph 8080:8080 &
curl -sI http://localhost:8080/healthz | grep -i strict-transport-security
```

## 6. Sign-in

Password login with TOTP needs nothing more than the overlay. To sign in
through your IdP, configure `sso.google`, `sso.okta`, `config.iapAudience` or
`config.oauth2Proxy` (see [deploy/README.md](../deploy/README.md#sign-in-ingress-and-extra-settings)
and [oauth2-proxy](security-hardening.md#oauth2-proxy)), and require MFA in
the IdP: Vulngraph does not ask SSO sign-ins for TOTP
([Admin MFA](security-hardening.md#admin-mfa)). With SSO configured, hardened
also requires the following:

- `config.adminEmails`, `config.oidcAdminGroups` or
  `config.oidcAnalystGroups`. With none of them set, the first allowlisted
  sign-in becomes admin. With only analyst groups, SSO makes no admin: create
  one as in step 7.
- an `https://` redirect URL.
- for oauth2-proxy, ID-token verification (`config.oauth2ProxyOidcIssuer` and
  `config.oauth2ProxyOidcAudience`) rather than the shared secret alone.

Set `config.oidcRequiredGroups` to admit only members of a group.

hardened can only check what the chart renders, not what an admission
webhook or a hand edit adds to a pod later. Verify that no dangerous flag is
set in a running pod. This prints variable names only:

```sh
for c in serve worker scanner; do
  kubectl -n graph exec deploy/graph-$c -c $c -- env | cut -d= -f1 | grep -xE \
    'BYPASS_AUTH.*|COOKIE_INSECURE|LADYBUG_RPC_INSECURE|SCAN_ALLOW_INTERNAL_TARGETS|OAUTH_REDIRECT_FROM_HOST|.*_ALLOW_ANY_DOMAIN|.*_ALLOW_UNSIGNED|SMTP_ALLOW_PLAINTEXT|OAUTH2_PROXY_TRUST_GROUPS|OAUTH2_PROXY_OIDC_ALLOW_UNVERIFIED_EMAIL|PPROF_PORT|PASSWORD_LOGIN_BREAK_GLASS'
done
kubectl -n graph logs deploy/graph-serve -c serve | grep 'SECURITY:'
```

Serve and the worker log a `SECURITY:` line at startup for most of these
flags. Some `SECURITY:` lines are refusals of a single request (a refused
sign-in), not configuration.

## 7. The first admin, with TOTP

The chart creates no user. With SSO, the admins come from
`config.adminEmails` or `config.oidcAdminGroups` (step 6). Otherwise, create
one admin and enroll TOTP for it:

```sh
kubectl -n graph exec deploy/graph-serve -c serve -- /graph user create --email you@example.com --role admin
kubectl -n graph exec deploy/graph-serve -c serve -- /graph user totp --email you@example.com
```

The first command prints a generated password. The second prints an
`otpauth://` URL to add to an authenticator app. That URL is the TOTP secret,
so do not paste it anywhere else. Running `user totp` again replaces the
secret.

Verify that every enabled admin who signs in with a password has TOTP. This
prints no rows when they all do. Behind IAP or oauth2-proxy password login is
off, so there is nothing to check. With direct Google or Okta sign-in, the
query leaves out accounts bound to the IdP (`oidc_issuer` set), which sign in
there. An account SSO created has a random password nobody holds, and
`config.requireAdminTotp` refuses a password sign-in by any admin without TOTP.

```sh
kubectl -n graph exec -i graph-postgres-0 -- sh -c \
  'PGPASSWORD="$POSTGRES_PASSWORD" psql -h 127.0.0.1 -U postgres -d graph -At' <<'SQL'
SELECT email FROM users WHERE role = 'admin' AND disabled_at IS NULL AND totp_secret IS NULL AND oidc_issuer IS NULL;
SQL
```

## 8. Connectors with least-privilege credentials

Give each connector the read-only grants in [`docs/iam/`](iam), not a broad
viewer or admin role. For a whole AWS Organization, follow
[onboarding-aws-org.md](onboarding-aws-org.md). Prefer keyless workload
identity ([Cloud auth: OIDC](../deploy/README.md#cloud-auth-oidc)) to stored
keys. A connector that may run approved fixes needs its own execution
principal, scoped to the actions you expect it to take
([Executor: execution roles](../deploy/README.md#executor-execution-roles)).
To keep that path off the worker, set `serviceAccount.serveName` and grant the
execution role to serve's ServiceAccount alone (EKS Pod Identity; see
[Credential isolation](security-hardening.md#credential-isolation)). Leave
`kubernetesRBAC.collectorRead` off unless you add a Kubernetes connector.

Verify: each connector's Test button (Settings → Connectors, or
`POST /api/connectors/{id}/test`) passes, and its first sync reports no
`Forbidden` or `AccessDenied` errors.

## 9. Backups, and a restore test

The chart backs up nothing. Postgres holds users, connectors (sealed under
`GRAPH_SECRET_KEY`) and jobs. ClickHouse holds the inventory, findings, graph
edges and the audit trail. The Ladybug graph is rebuilt from ClickHouse and
needs no backup. Back up both datastores on a schedule, for example with CSI
`VolumeSnapshot`s of `data-graph-postgres-0` and `data-graph-clickhouse-0`, or
with the tools below. Keep a copy of the `graph-secrets` values with the
backups, but not in the same place.

```sh
# Postgres: a custom-format dump to your machine
kubectl -n graph exec graph-postgres-0 -- sh -c \
  'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -h 127.0.0.1 -U postgres -Fc graph' > graph-$(date +%F).dump
# ClickHouse: as the in-pod default user, to object storage
kubectl -n graph exec graph-clickhouse-0 -c clickhouse -- clickhouse-client -q \
  "BACKUP DATABASE graph TO S3('https://<bucket>.s3.amazonaws.com/graph/$(date +%F)', '<key id>', '<secret>')"
```

Run a restore test before you rely on the backups, and after every upgrade.
Restore into a scratch database next to the live one, compare the row counts,
and then drop it:

```sh
kubectl -n graph exec -i graph-postgres-0 -- sh -c 'export PGPASSWORD="$POSTGRES_PASSWORD";
  createdb -h 127.0.0.1 -U postgres graph_restore &&
  pg_restore -h 127.0.0.1 -U postgres -d graph_restore --no-owner &&
  psql -h 127.0.0.1 -U postgres -d graph_restore -Atc "SELECT count(*) FROM users" &&
  dropdb -h 127.0.0.1 -U postgres graph_restore' < graph-<date>.dump
CH="kubectl -n graph exec graph-clickhouse-0 -c clickhouse -- clickhouse-client -q"
$CH "RESTORE DATABASE graph AS graph_restore FROM S3('https://<bucket>.s3.amazonaws.com/graph/<date>', '<key id>', '<secret>')"
$CH "SELECT count() FROM graph_restore.audit_events"   # compare with graph.audit_events
$CH "DROP DATABASE graph_restore SYNC"
```

## 10. Secret rotation

- `GRAPH_SECRET_KEY`. Set the new key in `secret.secretKey` and the old one
  in `secret.retiredSecretKeys` (`GRAPH_RETIRED_SECRET_KEYS`, read-only), and
  restart serve and the worker. Then run `graph keys rewrap`, clear
  `retiredSecretKeys` and restart again
  ([Rotating GRAPH_SECRET_KEY](../deploy/README.md#rotating-graph_secret_key)).
  Verify that a second `kubectl -n graph exec deploy/graph-serve -c serve --
  /graph keys rewrap` reports `0` for every table. Rotating the key re-seals
  stored credentials but revokes nothing, so after a suspected leak rotate
  the connector credentials themselves too.
- The old values in Helm's release history. Each earlier revision Secret
  (step 2) still holds the retired key and the old passwords, whatever its
  status: superseded, failed or pending-*. Once the rotation is done and
  `helm rollback` to a revision before it is no longer wanted, delete every
  revision but the deployed one, while no `helm` command runs against the
  release:
  `kubectl -n graph delete secret -l 'owner=helm,name=graph,status!=deployed'`.
- Datastore passwords. ClickHouse reads its two passwords from the Secret on
  every start. Change them with `helm upgrade`, then run
  `kubectl -n graph rollout restart statefulset/graph-clickhouse deploy/graph-serve deploy/graph-worker deploy/graph-scanner`.
  Postgres sets its users' passwords only when the volume is first created, so
  run `ALTER ROLE graph PASSWORD '...'` (and the same for `postgres`) in
  `graph-postgres-0` first, then upgrade and restart the same way.
- API keys expire after `API_KEY_MAX_LIFETIME_DAYS` (90 by default). Offboard
  people as in [Offboarding](security-hardening.md#offboarding): an IdP removal
  does not end their API keys.

## 11. Upgrades

1. Read [`CHANGELOG.md`](../CHANGELOG.md) for every release in between.
   Vulngraph is pre-1.0, so config keys can change.
2. Take the backups from step 9.
3. Look up and verify the new release's digest (step 3), and set it in
   `image.digest`. With a digest set, a newer chart does not move the image by
   itself.
4. Compare `helm template ... -f deploy/helm-values/hardened.yaml -f my-values.yaml`
   at the new chart with `helm get manifest graph -n graph`. Keep
   `clickhouse.storage` and `postgres.storage` unchanged: a StatefulSet's
   volume claim cannot change.
5. Run `helm upgrade` with the same values files and secrets. Migrations run
   in serve's `migrate` init container before the new serve starts.

Verify:

```sh
kubectl -n graph rollout status deploy/graph-serve
kubectl -n graph logs deploy/graph-serve -c migrate --tail 20
kubectl -n graph exec deploy/graph-serve -c serve -- /graph version
```

`helm rollback` restores the previous manifests but not the database schema.
To go back, restore the backups you took in step 2.

## 12. Monitoring and alerts

The overlay turns on `metrics.enabled`, which serves `/metrics` and adds the
`prometheus.io/*` scrape annotations ([Monitoring](../deploy/README.md#monitoring-how-metrics-leave-the-pod-and-how-alerts-come-back)).
With the VictoriaMetrics operator, set `alerts.enabled: true` together with
`alerts.namespace`, `alerts.ruleLabels` and `alerts.labels`, so that vmalert
evaluates the rules and Alertmanager routes them. With Prometheus, port
[`alerts/rules.yaml`](../deploy/helm-chart/graph/alerts/rules.yaml) to your
rule format. Route at least these alerts to a person:

- `GraphServeNotReady` and `GraphWorkerOrScannerNotReady` (critical).
- `GraphMetricsPipelineDown`. Every other rule evaluates to nothing while it
  fires.
- `GraphMigrationPending`, `GraphConnectorStale`, `GraphIntelFeedStale` and
  `GraphJobQueueWedged`.

Also alert on `SECURITY:` lines in the graph pods' logs.

Verify:

```sh
kubectl -n graph port-forward deploy/graph-worker 9090:9090 &
curl -s localhost:9090/metrics | grep -c '^graph_'
kubectl -n <alerts.namespace> get vmrule graph-graph-alerts
```

## 13. Log and audit retention

- Application logs are JSON on stdout. Your cluster's log pipeline decides
  how long they are kept, so set its retention to match your policy.
- The audit trail is ClickHouse `audit_events`: append-only from the app,
  with a 7-year TTL, and not tamper-proof. Export it to your SIEM or to
  write-once storage ([Audit trail](security-hardening.md#audit-trail)).
- ClickHouse's own system logs expire after 1 to 3 days
  (`clickhouse-config.yaml`). Every other table expires on its own TTL.

Verify:

```sh
kubectl -n graph exec graph-clickhouse-0 -c clickhouse -- clickhouse-client -q \
  "SELECT name, extract(create_table_query, 'TTL .*') FROM system.tables WHERE database = 'graph' ORDER BY name"
```

## 14. Review the outbound destinations

With no configuration, the worker and the scanner contact OSV (package names
and versions), the threat-intel feeds, crt.sh, the registries of your images,
takeover-candidate hosts and GitHub (the nuclei-templates release). The
[README table](../README.md) lists them, and
[Network egress](configuration.md#network-egress) lists every destination
with its switch. Turn off what your policy forbids, one switch at a time or all of them with
`OFFLINE_MODE=true` (scoring then runs without KEV, EPSS and OSV). Set the
switch in the chart-wide `extraEnv` and in `scanner.extraEnv`: the scanner
takes only its own list. The chart's NetworkPolicy
covers ingress only, so add an egress policy of your own. Block
`169.254.169.254` unless workload identity uses it.

Verify that the worker logs which feeds are off:

```sh
kubectl -n graph logs deploy/graph-worker -c worker | grep 'outbound intel feeds disabled'
```
