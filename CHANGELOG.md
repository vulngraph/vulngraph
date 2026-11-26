# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0, a minor release may
contain breaking changes; they are called out in its entry.

## [Unreleased]

### Fixed

- Upgrade LadybugDB to v0.22.3, resolving multi-hop paths lost when a node table spans
  more than one storage group. Add the 131,112-node upstream reproducer to normal CI,
  stop issuing the obsolete size warning, and invalidate old graph snapshots so they
  rebuild from ClickHouse. Retain legacy status fields and metrics for existing clients.

- Update the pinned Go toolchain to 1.26.11 and patched OpenAPI, compression,
  WebSocket, HTML parsing and OpenTelemetry dependencies. Keep the existing
  deprecated OpenPGP exception explicit; moving it to a separate module is not a fix.
- Track AWS organization applicability and per-level SCP completeness, including management
  account and service-linked-role exemptions. Missing organization evidence cannot prove
  unrestricted authority or resolve privilege findings. Posture checks use the observed
  effective tier while preserving ordinary dormancy and configured-grant findings.
- Preserve all compatible permission-boundary and SCP action/resource alternatives;
  reordering equivalent cap statements no longer erases candidates.
- Match GCE and Azure exposure rules to interface/IP-configuration destinations, address
  families and protocol aliases. Azure subnet/NIC checks must admit the same packet.
  Incomplete rule/address/route evidence and evaluation limits retain possible exposure.
- Preserve live GCP grants under compound CEL conditions, retain role/ancestor read failures
  as unknown, and require complete per-principal observations before resolving CIEM findings.
  GCP allow-only role names and permissions no longer lower escalation severity as proven admin.
  Compliance sampling preserves the completeness and structured-grant facts needed to keep
  unknown observations separate from passing controls.
- Preserve raw IAM policy JSON and decode transport encoding only once, retaining literal
  `+` characters through collectors, permission/trust parsing and graph identifiers.
- Remove name-based escalation suppression; missing graph evidence cannot demote a
  finding through principal classification. Scoring version `v2` triggers recalculation
  of existing findings, including public-trust roles without a modeled workload path.
- Preserve Azure ARM scopes, conditions and per-grant exclusion sets, separate data-plane
  permissions, and retain incomplete role evidence. Azure allow-only inventory no longer
  lowers CIEM severity as proven admin; legacy or partial evidence cannot close findings.
- Preserve complete IAM `NotAction` and `NotResource` deny exception sets;
  do not infer unrestricted AWS admin authority from denied or approximated grants.
- Preserve unread permission boundaries and partial SCP collections as uncertain evidence;
  collect boundaries for scoped users too, and keep collector admin hints from overriding
  the evaluated AWS tier. Older inventory without completeness evidence needs a refresh.
- Apply role-trust denies to the assumption method they govern, correct MFA
  condition truth tables, and recognize bare negated organization restrictions
  without crediting unrelated conditions as universal protection.
- Resolve unconditional GCS public-access prevention through the inherited policy
  hierarchy. Unreadable or conditional policies remain unknown, and inherited
  enforcement no longer produces missing-guardrail or public-exposure findings.
  Collection now reads `orgpolicy.policies.get` on the applicable project and
  ancestors; see [GCP permissions](docs/iam/gcp-cspm-permissions.md).

## [0.1.0]

The first release.

### Added

- Single Go binary (`serve`, `worker` and `scanner` modes) with Postgres,
  ClickHouse and an embedded React UI; Docker Compose and Helm deployments.
- Asset collection for AWS, GCP, Azure, GitHub and
  Kubernetes, plus Okta and Google Workspace identity, with per-field drift
  history.
- A security graph in ClickHouse, projected into LadybugDB for multi-hop
  Cypher, with computed internet exposure and directed BFS risk propagation.
- CSPM checks mapped to CIS and AWS FSBP benchmarks
  ([`docs/cspm-coverage.md`](docs/cspm-coverage.md)), compliance framework
  rollups, and CIEM privilege-escalation detection for AWS, GCP and Azure.
- Vulnerability intel from OSV, CISA KEV and EPSS; VM package inventory from
  AWS SSM Inventory and GCP OS Config; SBOM-based supply-chain graph.
- Nuclei-based active scanning with a template editor, scan profiles and
  schedules, and a generic JSON import for findings from other scanners.
  Scans run one pinned nuclei-templates release, sha256-verified before use
  (`NUCLEI_TEMPLATES_VERSION`/`NUCLEI_TEMPLATES_SHA256` or
  `NUCLEI_TEMPLATES_DIR` to change it); interactsh out-of-band testing is
  off unless `NUCLEI_INTERACTSH_ENABLED=true`.
- Terraform IaC checks and IaC-to-graph correlation (k8s manifests,
  Terraform state, CI-workflow federation, identifiers harvested from repo
  text).
- Contextual 0–100 finding scores with "safe to fix" and "must fix" views.
- LLM-proposed action plans (Claude or any OpenAI-compatible model) routed to
  a human approval queue; no autonomous remediation.
- Agentless VM disk scanning for AWS and Azure, off by default and opt-in per
  connector (`DISK_SCAN_ENABLED`, then an admin enables each connector with a typed
  confirmation; never by API key or MCP): `existing_snapshots` reads snapshots you
  already have, `create_snapshots` also makes short-lived tagged ones with a separate
  dedicated role. Reads ext2/3/4 and XFS Linux boot volumes under MBR or GPT; a disk
  it cannot read is a gap, never a clean result. Asset page panel, Connectors
  controls, `GET /api/disk-scans`, `GET /api/assets/{id}/disk-scan`,
  `GET`/`PUT /api/connectors/{id}/disk-scan` and MCP `get_disk_scan_status`
  ([capabilities](docs/capabilities.md#vm-disk-scanning)).
- Scheduled Cypher detections, Slack and webhook alerting, an MCP endpoint
  with scoped API keys, Prometheus metrics and OpenTelemetry tracing.
- `graph keys rewrap` re-seals every stored connector credential,
  alert-channel secret and TOTP seed under the current `GRAPH_SECRET_KEY`;
  `GRAPH_RETIRED_SECRET_KEYS` (Helm `secret.retiredSecretKeys`) keeps previous
  keys readable during a rotation (deploy/README.md, "Rotating GRAPH_SECRET_KEY").
- TOTP seeds are stored under the same envelope encryption as connector
  credentials, bound to the user's row. `graph user`
  commands need `GRAPH_SECRET_KEY`.
- The container image ships the licence texts of every Go module, npm package
  and LadybugDB component it distributes, under `/usr/share/doc/graph/licenses`.
- Helm: `serviceAccount.azureWorkloadIdentity` labels only the serve and worker
  pods for Azure Workload Identity; ClickHouse `max_concurrent_queries` is
  derived from the replica counts and `config.chMaxConcurrent` (32 with the
  default scanner pod) unless `clickhouse.tuning.maxConcurrentQueries` is set; the
  `$HOME` emptyDir cap (`securityContext.homeSizeLimit`) defaults to 1Gi so
  the nuclei template download fits.
- Helm: nuclei runs in its own scanner pod by default (`scanner.enabled: true`),
  with no `GRAPH_SECRET_KEY`, LLM key, signing secret or cloud identity. The
  chart's Kubernetes RBAC binds only the worker's ServiceAccount, serve mounts
  no API token, and the node posture reader runs as its own ServiceAccount
  without one. `image.digest` pins every graph container by digest. The
  bundled Postgres and ClickHouse take a TLS Secret (`postgres.tlsSecret`,
  `clickhouse.tlsSecret`) with `postgres.sslMode` and `clickhouse.secure` for
  the DSNs. Alert routing labels come from `alerts.labels` and the VMRule's
  selector labels from `alerts.ruleLabels`, both empty by default.
- Docker Compose builds the image from the checkout by default;
  `docker-compose.release.yml` runs a published image and requires
  `GRAPH_VERSION`.
- The bundled datastores (Helm and Docker Compose) create non-admin users:
  the Postgres role `graph` owns the database but is not a superuser, and the
  ClickHouse user `graph` has no DDL and cannot rewrite `audit_events`;
  migrate applies the ClickHouse schema as `graph_migrate`. The scanner
  connects as `graph_scanner`, which reaches River's job tables, the scan
  tables and the assets and findings it reads and writes, and no user, API
  key or connector. The bundled ClickHouse has no passwordless `default`
  user. The admin, schema and scanner passwords
  (`secret.postgresSuperuserPassword`, `secret.clickhouseMigratePassword`,
  `secret.postgresScannerPassword`, `secret.clickhouseScannerPassword`) are
  new required values, and an external datastore with `scanner.enabled` needs
  `secret.scannerDatabaseUrl` and `secret.scannerClickhouseUrl`.
- Helm: the NetworkPolicy is on by default, one per component: the datastores
  accept only the graph pods that hold their credentials, the worker's graph
  RPC only serve and the scanner, and the scanner nothing.
  `networkPolicy.ingressNamespace` (empty by default) limits serve's port to
  the ingress controller and needs `networkPolicy.nodeCIDRs`;
  `config.oauth2Proxy` requires it.
- AWS templates: the Terraform-state read and the execution role's
  Block Public Access write are held to the role's own account
  (`s3:ResourceAccount`), and the execution role cannot act on security
  groups, instances or IAM users tagged `vulngraph-protected`.
- Drift events carry `findings_known`, false when the findings lookup failed
  (the UI shows "Findings unknown"), and the feed drops events whose asset
  ClickHouse marks as a dead ephemeral resource or an IaC declaration. An
  event whose asset context cannot be read is kept.
- `FORGET_ENFORCE_TYPES` accepts only `security_group` and `vpc`; any other
  name stops the worker at startup.
- `sg_rule_remove` revokes only `0.0.0.0/0` or `::/0` rules.
- The email approval-link routes answer 503 when `APPROVAL_TOKEN_SECRET` is
  not set.
- Admin actions are written to `audit_events`: connector create, mode change
  (before and after), delete and purge; user create, SSO provisioning, role
  change, disable, enable and delete, session revocation, TOTP enrolment and
  `graph user token`; API key create and revoke; alert-channel create, update
  and delete; approval-policy changes (docs/security-hardening.md, "Audit
  trail"). `graph user` commands need ClickHouse as well as Postgres.
- Sign-ins (password and SSO, refused ones with the reason and the email
  attempted), sign-outs, manual finding resolves, and saved-query and
  scan-profile create, update and delete are written to `audit_events`;
  refused password sign-ins are logged at warn.
- API keys get 403 (audited as `auth.api_key_refused`) on user and key
  management, connector mode change, purge and delete, approval-policy
  updates and queue verdicts. REST suppress, bulk suppress, suppression review
  and finding resolve on an API key apply the MCP `suppress_finding` rules
  (critical, must-fix, page/high-band and unscored findings refused; at most
  30 days).
- Google sign-in with `GOOGLE_ALLOWED_DOMAINS` also requires the account's
  hosted-domain (`hd`) claim to be an allowed domain.
- `OIDC_REQUIRED_GROUPS` (Helm `config.oidcRequiredGroups`) refuses any SSO
  sign-in that carries none of the listed groups.
- `REQUIRE_ADMIN_TOTP=true` (Helm `config.requireAdminTotp`) refuses password
  sign-in to an admin with no TOTP enrolled (docs/security-hardening.md,
  "Admin MFA").
- The AWS member role template (`graph-readonly-role.yaml`) leaves the
  Terraform-state read off by default (`GrantTerraformStateRead=false`),
  because state files hold secrets.
