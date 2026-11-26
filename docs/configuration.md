# Configuration reference

Vulngraph is configured entirely through environment variables. This page lists
every variable the `graph` binary reads, what it does, its default, and which
process reads it (the `cmd/benchmark-watch` maintainer tool is covered at the end). For a ready-to-edit local setup, copy [`.env.example`](../.env.example).

Where to set them: with `deploy/docker-compose`, add the variable to its
`app.env` (every entry reaches serve and worker; `.env` holds only the values
Compose itself needs, such as `GRAPH_VERSION`, and is never passed to
the app; the stack's secrets are generated on its first start). With the Helm chart, use the first-class value where `values.yaml`
has one (for example `config.smtpAllowPlaintext` for `SMTP_ALLOW_PLAINTEXT`),
and otherwise `extraEnv` / `extraEnvFrom` (serve, migrate and worker; the
scanner takes only its own lists) or `serve.extraEnv`, `worker.extraEnv`,
`scanner.extraEnv` for one component (see
[deploy/README.md](../deploy/README.md)). An `extraEnv` entry replaces a
variable the chart sets under the same name. Under `hardened: true` such an
entry, and any `extraEnvFrom` list, is refused
([production checklist](production-checklist.md#5-fill-in-the-overlay)).

Related pages: [LLM providers](llm-providers.md) (full detail on `LLM_*`),
[Security hardening](security-hardening.md) (the switches that weaken secure
defaults), [Network egress](#network-egress) (every outbound destination and
its switch).

## Conventions

**Process** column: `serve` (API and UI), `worker` (background jobs), `scanner`
(dedicated scan pod), `migrate`, `bootstrap`. "all" means serve, worker and
scanner. `migrate` and the `user` command also read `DATABASE_URL` and
`CLICKHOUSE_URL`: every `graph user` command writes an `audit_events` row to
ClickHouse and refuses to run without it. The `user` command also reads
`GRAPH_SECRET_KEY` (and `GRAPH_RETIRED_SECRET_KEYS`), which seal TOTP seeds.

- **Duration** values use Go syntax: `30m`, `2h`, `168h`. An unparseable value
  is treated as unset (the built-in default applies) unless noted.
- **Int** values must be positive integers; zero, negative or unparseable values
  fall back to the default.
- **Switch** variables are on/off: `1`, `true`, `yes` or `on` turns one on;
  `0`, `false`, `no`, `off` or unset leaves it off (case-insensitive, surrounding
  spaces ignored). Any other value stops the process at startup, so a typo is
  never read either way.
- **Flag** variables need the exact string `true`; any other value, including
  `TRUE` or `1`, leaves them off. The "Format" column says which a variable is.
- **Sensitive** = a secret or a value that weakens security. Do not commit it,
  log it, or put it in a ConfigMap.
- **Required** variables are marked in bold. Everything else is optional.

## Core and datastores

| Variable | Process | Default | Format | Sensitive | Description |
|---|---|---|---|---|---|
| **`GRAPH_SECRET_KEY`** | serve, worker | none (startup fails) | base64 of exactly 32 bytes | Yes | Master key, and the only key-encryption key. Encrypts connector credentials, notification-channel secrets and TOTP seeds at rest (AES-GCM envelopes), and derives the signing key for second-admin approval grants on destructive remediation. Generate with `head -c32 /dev/urandom \| base64`. Losing or changing it makes stored credentials unreadable; rotate it with `GRAPH_RETIRED_SECRET_KEYS` and `graph keys rewrap` (below), never by replacing it. |
| `GRAPH_RETIRED_SECRET_KEYS` | serve, worker, `graph keys rewrap` | empty | comma-separated base64 32-byte keys | Yes | Previous `GRAPH_SECRET_KEY` values, trusted for decryption only, during a rotation. A malformed entry, or one equal to `GRAPH_SECRET_KEY`, fails startup. Clear it once a rewrap run has finished without an error. |
| `DATABASE_URL` | all, migrate | `postgres://graph:graph@localhost:5432/graph?sslmode=disable` | Postgres DSN | Yes (contains password) | Postgres connection string. The scanner needs only River's job tables and the scan tables (the Helm chart gives it `graph_scanner`, which migrate grants those after every run; see [deploy/README.md](../deploy/README.md#datastore-users)). Optional: unset, it defaults to the local root `docker-compose.yml` DSN (`graph:graph` on localhost, `sslmode=disable`). A production deployment must set it; an unset value is not an error, so the process connects to that default. |
| `CLICKHOUSE_URL` | all, migrate | `clickhouse://graph:graph@localhost:9000/graph` | ClickHouse DSN (native protocol) | Yes (contains password) | ClickHouse connection string. migrate's user must be able to change the schema; serve and the worker need only the app grants, and the scanner less (the Helm chart gives migrate `graph_migrate`, the scanner pod `graph_scanner` and the rest `graph`; `deploy/docker-compose` has no scanner pod, and gives migrate `graph_migrate` and the rest `graph`; see [deploy/README.md](../deploy/README.md#datastore-users)). Optional: unset, it defaults to the local root `docker-compose.yml` DSN (`graph:graph` on localhost). A production deployment must set it; an unset value is not an error, so the process connects to that default. `go run ./cmd/coverage-gen` also reads it but has no default: unset, it writes the document without live data and says so in it. |
| `ADDR` | serve | `:8080` | `host:port` | No | Listen address of the HTTP server. |
| `PG_MAX_CONNS_SERVE` | serve | `10` | int | No | Postgres pool size for the serve pod. Its `/readyz` check holds one more connection outside the pool. |
| `PG_MAX_CONNS_WORKER` | worker | `30` | int | No | Postgres pool size for the worker pod. |
| `PG_MAX_CONNS_SCANNER` | scanner | `10` | int | No | Postgres pool size for the scanner pod. Keep the sum across pods comfortably under Postgres's `max_connections`. |
| `CH_MAX_CONCURRENT` | all | `8` | int | No | Per-pod cap on concurrent ClickHouse queries. The connection pool is sized to this plus 4. The ClickHouse server's `max_concurrent_queries` must stay above the sum across every pod (serve replicas + worker + scanner), or queries are refused with `TOO_MANY_SIMULTANEOUS_QUERIES` under load; the chart derives it from the replica counts unless `clickhouse.tuning.maxConcurrentQueries` is set. |

### Rotating `GRAPH_SECRET_KEY`

Re-sealing the stored credentials is a CLI subcommand, run in a pod or container
that has the database and key environment:

```sh
# Kubernetes
kubectl -n <namespace> exec deploy/graph-serve -c serve -- /graph keys rewrap
# Docker Compose (from deploy/docker-compose)
docker compose exec serve /graph keys rewrap
```

It re-seals every connector config, alert-channel secret and TOTP seed that is
not already sealed under the current `GRAPH_SECRET_KEY`, skips the rows that
are, and leaves a row it cannot open untouched (the error names it). Re-running it is safe. The
full procedure (set the new key, retire the old one, restart, rewrap, clear the
retired key) is in
[deploy/README.md](../deploy/README.md#rotating-graph_secret_key).

## Auth and sessions

Sign-in methods are additive. Google, Okta, IAP and oauth2-proxy are each
enabled by setting their variables; with none set, only locally created users
(`graph user create`) can sign in. All variables here are read by `serve`.

| Variable | Default | Format | Sensitive | Description |
|---|---|---|---|---|
| `GOOGLE_CLIENT_ID` | unset (Google sign-in off) | string | No | Enables Google OAuth sign-in when non-empty. |
| `GOOGLE_CLIENT_SECRET` | none | string | Yes | OAuth client secret. Required with `GOOGLE_CLIENT_ID`. |
| `GOOGLE_REDIRECT_URL` | none | URL | No | OAuth callback URL registered with Google. Required with `GOOGLE_CLIENT_ID`. |
| `GOOGLE_ALLOWED_DOMAINS` | none | comma-separated domains | No | Restricts sign-in to Google Workspace accounts of these domains: the email's domain **and** the account's hosted-domain (`hd`) claim must both be in the list, so a consumer Google account registered on a company address, which has no `hd`, is refused. List the Workspace's primary domain as well as any secondary email domains. A first sign-in is a viewer unless `ADMIN_EMAILS` or a group mapping says otherwise. Empty denies every Google sign-in unless `GOOGLE_ALLOW_ANY_DOMAIN=true`. |
| `GOOGLE_ALLOW_ANY_DOMAIN` | off | exact `true` | Yes | **Dangerous.** With no `GOOGLE_ALLOWED_DOMAINS`, accept any Google account, consumer accounts included (new users become viewers). |
| `OKTA_CLIENT_ID` | unset (Okta sign-in off) | string | No | Enables Okta OIDC sign-in when non-empty. |
| `OKTA_CLIENT_SECRET` | none | string | Yes | Required with `OKTA_CLIENT_ID`. |
| `OKTA_DOMAIN` | none | hostname | No | Your Okta org domain. Required with `OKTA_CLIENT_ID`. |
| `OKTA_REDIRECT_URL` | none | URL | No | OAuth callback URL. Required with `OKTA_CLIENT_ID`. |
| `OAUTH_REDIRECT_FROM_HOST` | off | exact `true` | Yes | **Local dev only.** Lets an unset `GOOGLE_REDIRECT_URL` / `OKTA_REDIRECT_URL` be built from the request's `Host` and `X-Forwarded-Proto` instead of failing startup. |
| `OKTA_ALLOWED_DOMAINS` | none | comma-separated email domains | No | Restricts sign-in to these domains; a first sign-in is a viewer unless `ADMIN_EMAILS` or a group mapping says otherwise. Empty denies every Okta sign-in unless `OKTA_ALLOW_ANY_DOMAIN=true`. |
| `OKTA_ALLOW_ANY_DOMAIN` | off | exact `true` | Yes | **Dangerous.** With no `OKTA_ALLOWED_DOMAINS`, accept any Okta account (new users become viewers). |
| `IAP_AUDIENCE` | unset (IAP off) | `/projects/{number}/global/backendServices/{id}` (GKE/LB) or `/projects/{number}/apps/{project_id}` (App Engine) | No | Enables GCP Identity-Aware Proxy: the `X-Goog-IAP-JWT-Assertion` JWT is validated against this audience and the user is logged in automatically. The assertion must carry `iss` `https://cloud.google.com/iap` and a `sub`; the account is bound to that subject on first IAP sign-in. |
| `IAP_ALLOWED_DOMAINS` | none | comma-separated email domains | No | Email domains whose IAP identities may sign in (first sign-in role as for Google). **Required with `IAP_AUDIENCE`:** empty denies every IAP sign-in (403) unless `IAP_ALLOW_ANY_DOMAIN=true`, and `serve` logs a startup error. |
| `IAP_ALLOW_ANY_DOMAIN` | off | exact `true` | Yes | **Dangerous.** With no `IAP_ALLOWED_DOMAINS`, accept any identity IAP lets through (new users become viewers). |
| `REQUIRE_ADMIN_TOTP` | off | `true` or `false` (case-insensitive); any other value stops serve | No | Refuses password sign-in to an admin with no TOTP enrolled (`graph user totp`), and ends a user's sessions when they are promoted to admin. SSO sign-ins are unaffected. Helm: `config.requireAdminTotp`. See [Admin MFA](security-hardening.md#admin-mfa). |
| `PASSWORD_LOGIN_BREAK_GLASS` | off | exact `true` | Yes | Keeps password login (`POST /api/auth/login`) available when `IAP_AUDIENCE` or `OAUTH2_PROXY=true` is set. Without it, password login answers 404 behind an authenticating proxy, so a local password cannot sidestep the proxy's identity checks. `serve` logs a warning when it is on. |
| `OAUTH2_PROXY` | off | exact `true` | Yes (trusts a proxy) | Sign in users an oauth2-proxy in front of the ingress authenticated. Requires `OAUTH2_PROXY_OIDC_ISSUER` (preferred) and/or `OAUTH2_PROXY_SHARED_SECRET`; `serve` refuses to start with neither. See [oauth2-proxy](security-hardening.md#oauth2-proxy). |
| `OAUTH2_PROXY_OIDC_ISSUER` | none | https issuer URL (http only for loopback), compared exactly | No | Verify the IdP-signed ID token oauth2-proxy forwards in `Authorization: Bearer` (`--set-authorization-header`) against this issuer's published keys. Email, `sub` and groups then come only from the token; the email and groups headers are ignored. |
| `OAUTH2_PROXY_OIDC_AUDIENCE` | none | string | No | Required with `OAUTH2_PROXY_OIDC_ISSUER`: the `aud` the ID token must carry (oauth2-proxy's client id). |
| `OAUTH2_PROXY_OIDC_ALLOW_UNVERIFIED_EMAIL` | off | exact `true` | Yes | Accept ID tokens that carry **no** `email_verified` claim (an explicit `false` is always refused). Risky: the first token sign-in binds an existing account by email, so use it only with an IdP that does not let users choose their address. |
| `OAUTH2_PROXY_SHARED_SECRET` | none | string, at least 32 characters | Yes | When set, every oauth2-proxy request must carry it in `X-Graph-Proxy-Secret` (constant-time compare). Defence in depth only: anyone who reads it and reaches `serve` can claim any identity, so never inject it from a publicly routed `/oauth2/auth`. Required unless `OAUTH2_PROXY_OIDC_ISSUER` is set. |
| `OAUTH2_PROXY_TRUST_GROUPS` | off | exact `true` | Yes | Shared-secret mode only: map `X-Auth-Request-Groups` to roles. Set only if that header is listed in nginx `auth-response-headers`; otherwise the client supplies it. |
| `OAUTH2_PROXY_ALLOWED_DOMAINS` | none | comma-separated email domains | No | Email domains accepted from the header (first sign-in role as for Google). With `OAUTH2_PROXY=true` and no list, the header path is denied unless the next flag is set. |
| `OAUTH2_PROXY_ALLOW_ANY_DOMAIN` | off | exact `true` | Yes | **Dangerous.** Accept any email in the header. See [Dev-only and dangerous](#dev-only-and-dangerous). |
| `ADMIN_EMAILS` | none | comma-separated emails | No | Emails provisioned as admin on their first SSO sign-in (Google, Okta, IAP, oauth2-proxy). Everyone else starts as viewer; existing users keep their role. With it and both `OIDC_*_GROUPS` empty, the first allowlisted sign-in on an install with no users becomes admin (bootstrap). |
| `OIDC_ADMIN_GROUPS` | none | comma-separated group names | No | IdP groups provisioned as admin on first sign-in: the Okta `groups` claim (the `groups` scope is requested when this, `OIDC_ANALYST_GROUPS` or `OIDC_REQUIRED_GROUPS` is set), the `groups` claim of a verified oauth2-proxy ID token, or `X-Auth-Request-Groups` with `OAUTH2_PROXY_TRUST_GROUPS=true`. Any group mapping turns off the first-user bootstrap. Google and IAP send no groups. |
| `OIDC_ANALYST_GROUPS` | none | comma-separated group names | No | IdP groups provisioned as analyst on first sign-in (admin groups win). |
| `OIDC_REQUIRED_GROUPS` | none (no group gate) | comma-separated group names, case-insensitive | No | Sign-in gate, not a role: an SSO sign-in (Okta, oauth2-proxy) that starts a session must carry one of these groups, from the same sources as `OIDC_ADMIN_GROUPS`, or it is refused with 403 and an `auth.login_failed` row; this applies to existing users too. Google and IAP send no groups, and shared-secret oauth2-proxy sends none without `OAUTH2_PROXY_TRUST_GROUPS=true`, so with this set they admit nobody. It is checked when a session starts, not on every request: someone removed from the group keeps a session they already hold until it expires (7 days) or `POST /api/users/{id}/revoke-sessions` ends it. Password login is not gated. It does not change roles or the first-user bootstrap. Helm: `config.oidcRequiredGroups`. |
| `COOKIE_INSECURE` | off | exact `true` | Yes | **Dangerous.** Drops `Secure` from cookies for plain-http local dev. See [Dev-only and dangerous](#dev-only-and-dangerous). |
| `BYPASS_AUTH` | off | exact `true` | Yes | **Dangerous.** Disables authentication entirely. See [Dev-only and dangerous](#dev-only-and-dangerous). |
| `BYPASS_AUTH_I_UNDERSTAND` | none | exact `yes` | Yes | Acknowledgement required alongside `BYPASS_AUTH=true`; `serve` refuses to start without it. |
| `BYPASS_AUTH_ALLOWED_HOSTS` | none | comma-separated hostnames | No | Under `BYPASS_AUTH`, extra `Host` header values accepted on top of `localhost`, `127.0.0.1`, `::1` and the `ADDR` host. Every other `Host` is rejected (a DNS-rebinding guard), so list the hostname the proxy forwards. Ignored without `BYPASS_AUTH`. |
| `API_KEY_MAX_LIFETIME_DAYS` | `90` | int (days) | No | Longest any API key lives. A key's effective expiry is the earlier of its own `expires_at` and `created_at` + this cap; this includes keys created with no expiry, so keys older than the cap stop authenticating. Creating a key with an expiry beyond the cap is refused (400). |
| `CLIENT_IP_HEADER` | unset (TCP peer address) | HTTP header name, e.g. `X-Forwarded-For` | No | Header the ingress or proxy in front of `serve` sets with the client address. Its last comma-separated entry is used (the one the nearest proxy appended; see [Client address](security-hardening.md#client-address) for multi-hop setups), and only when the TCP peer is in `TRUSTED_PROXY_CIDRS`. It keys the login per-IP limit and the executor's `approver_same_ip` audit flag. Set both behind any proxy, or every client shares the proxy's address. |
| `TRUSTED_PROXY_CIDRS` | none (header ignored) | comma-separated CIDRs or addresses | No | Addresses of the proxy that sets `CLIENT_IP_HEADER`. Empty means the header is never honoured (`serve` logs a `SECURITY:` error if the header is set); a malformed entry stops `serve`. |
| `LOGIN_RATE_LIMIT_PER_IP` | `20` | non-negative number (per minute; burst is the same number) | No | Password-login attempts per client address (see `CLIENT_IP_HEADER`); excess attempts get 429 with `Retry-After`. `0` disables. Unset or malformed uses the default. Limits are per `serve` replica. |
| `LOGIN_RATE_LIMIT_PER_ACCOUNT` | `5` | non-negative number (per minute; burst is the same number) | No | Password-login attempts per target email, whatever the source address. `0` disables. Anyone can use this to slow logins to a known account. |

## HTTP hardening

Read by `serve`.

| Variable | Default | Format | Sensitive | Description |
|---|---|---|---|---|
| `ALLOWED_ORIGINS` | none (same-origin only) | comma-separated origins, `scheme://host[:port]` | No | Extra origins trusted for state-changing (non-GET/HEAD/OPTIONS) `/api` requests; any other cross-origin one is rejected with 403. Same-origin requests, non-browser clients (they send no `Origin` or `Sec-Fetch-Site` header, e.g. API-key automation) and the signed webhook and email-link endpoints never need listing. Set it only when a browser UI on another origin calls the state-changing API, whether it uses the session cookie or an `Authorization` header. A malformed origin is a startup error. |
| `TLS_PROXY` | off | exact `true` | No | TLS terminates at a proxy in front of `serve`: send `Strict-Transport-Security` on the plain-HTTP hop too. Without it HSTS is only sent on requests that reached `serve` over TLS. Helm: `config.tlsProxy`. |
| `LLM_RATE_LIMIT_PER_USER` | `10` | non-negative number (per minute) | No | Budget per user for the LLM-backed routes (chat, NL graph query, graph query translation, scan-template generation, decision refine, and the MCP `graph_query` tool, from the same bucket). Excess calls get 429 with `Retry-After`. `0` disables. Unset or malformed uses the default. Per `serve` replica. |
| `CYPHER_RATE_LIMIT_PER_USER` | `30` | non-negative number (per minute) | No | Budget per user for the routes that run on the graph engine's two-connection caller-Cypher pool: `POST /api/graph/cypher`, `GET /api/graph/queries/health`, `GET /api/dspm/summary`, `GET /api/dspm/stores` and the MCP `run_cypher` tool, from one bucket. The pool also serves scheduled detections and the scanner's target resolution, so one user holding it makes those runs fail or finish incomplete. Excess calls get 429 with `Retry-After` (MCP: error `-32029`). `0` disables. Per `serve` replica. It caps how often a user starts a query, not how long each one runs: a few users sending slow queries (each is cut off at the engine timeout) can still hold both connections. |
| `ALERT_CONTEXT_RATE_LIMIT_PER_USER` | `30` | non-negative number (per minute) | No | Budget per user for alert-context lookups: `POST /api/context/alert` and the MCP `get_alert_context` tool, from one bucket. Each lookup can scan the assets table. Excess calls get 429 (MCP: error `-32029`). `0` disables. Per `serve` replica. |

## LLM provider

LLM features (reasoning on findings, chat) are optional.
Both `serve` and `worker` read these. Provider selection rules, model
defaults and examples for Anthropic, OpenAI, Ollama and other gateways are in
[llm-providers.md](llm-providers.md).

The OpenAI-compatible backend honours the standard `HTTPS_PROXY`, `HTTP_PROXY`
and `NO_PROXY` variables, so a model server behind an egress proxy works
without extra settings. Loopback hosts are never proxied; list any other
direct host (for example an in-cluster `ollama` Service or
`host.docker.internal`) in `NO_PROXY`. Slack delivery and OIDC ID-token
verification honour the same variables. Vulngraph's in-cluster calls, such as the
serve-to-worker graph RPC, ignore them and never go through the proxy.

| Variable | Process | Default | Format | Sensitive | Description |
|---|---|---|---|---|---|
| `LLM_PROVIDER` | serve, worker | inferred from which key or URL is set | `anthropic` \| `openai` (`openai-compatible` accepted) | No | Selects the backend. |
| `LLM_API_KEY` | serve, worker | none | string | Yes | API key for the selected provider. |
| `LLM_BASE_URL` | serve, worker | provider default | URL | No | Endpoint override. Required for non-OpenAI OpenAI-compatible servers (Ollama, vLLM, LM Studio). A base URL with no provider set implies `openai`. |
| `LLM_MODEL` | serve, worker | provider default | model name | No | Capable model for reasoning, chat and translation. |
| `LLM_FAST_MODEL` | serve, worker | provider default; on `openai`, `LLM_MODEL` | model name | No | Cheap model for high-volume triage. |
| `LLM_REASONING_EFFORT` | serve, worker | unset | `low` \| `medium` \| `high` | No | Passed as `reasoning_effort` on the `openai` backend only. |
| `ANTHROPIC_API_KEY` | serve, worker | none | string | Yes | Back-compat: alone, selects the Anthropic backend; also the fallback key when `LLM_API_KEY` is empty. |
| `OPENAI_API_KEY` | serve, worker | none | string | Yes | Back-compat: alone, selects the OpenAI backend; also the fallback key when `LLM_API_KEY` is empty. |
| `REASON_MODEL` | worker | provider default | model name | No | Model for the remediation reasoner. |
| `TEMPLATE_GEN_MODEL` | serve | provider default | model name | No | Model for AI-assisted scan-template generation. Ignored without an LLM client. |
| `ADJUDICATOR_ENABLED` | worker, scanner (schedule only) | off | switch | No | Turns on the LLM severity adjudicator. It spends LLM budget (capped at 40 findings per sweep, up to 4 LLM calls each, with change-driven caching), so it is off by default. |
| `ADJUDICATOR_MODEL` | worker | provider default | model name | No | Model used by the adjudicator, e.g. a cheaper tier. |
| `DRIFT_ANALYSIS_ENABLED` | worker, scanner (schedule only) | off | switch | No | Turns on the advisory LLM drift analysis: every 5 minutes it reads each connector's new inventory changes and records whether a scan looks worthwhile. It spends LLM budget, so it is off by default. It never starts a scan. |
| `DRIFT_ANALYSIS_MODEL` | worker | provider default | model name | No | Model used by the drift analysis. |
| `DISK_SCAN_ENABLED` | worker, scanner | off | switch | No | Makes the agentless VM disk-scan jobs exist: the worker plans a run every hour and sweeps leftover snapshots, and the scanner reads the disks. Each connector must still opt in (`PUT /api/connectors/{id}/disk-scan`, admin session); with this off a connector's mode changes nothing. Set it on **both** pods, or the plan is never read or the reads never planned. Needs `DISK_SCAN_ENVELOPE_KEY` or the pod refuses to start. serve ignores it. Helm: `config.diskScanEnabled`. See [disk scanning](capabilities.md#vm-disk-scanning). |
| `DISK_SCAN_ENVELOPE_KEY` | worker, scanner (with `DISK_SCAN_ENABLED`) | none | standard base64 of exactly 32 bytes | Yes | Seals each connector's disk-scan credentials into the volume job so the scanner pod never holds `GRAPH_SECRET_KEY`; it opens nothing else. The worker and the scanner must hold the same value. Helm derives one from `secret.secretKey` and stores it as `disk-scan-envelope-key`, or set `secret.diskScanEnvelopeKey`; elsewhere generate one, for example `openssl rand -base64 32`. Anyone holding it can open the credentials of an unexpired run ([threat 18](threat-model.md)). |
| `LLM_MONTHLY_BUDGET_USD` | serve, worker | `0` (unlimited) | non-negative dollar amount | No | Cap on **all** LLM spend per calendar month (UTC), summed from the `llm_usage` ledger. It gates background work (remediation reasoning, adjudication, CT triage): once reached, those calls are refused until the month rolls over, and they are also refused when the ledger cannot be read (`budget_unknown`). Interactive features are not cut off by it. A malformed value fails startup. See [LLM providers](llm-providers.md#usage-and-budgets). |
| `LLM_INTERACTIVE_MONTHLY_BUDGET_USD` | serve, worker | `0` (unlimited) | non-negative dollar amount | No | Cap on interactive LLM spend only (chat, NL graph query, decision refine, scan-template generation) per calendar month. Background spend never counts against it. With an unreadable ledger, interactive calls proceed (and are still bounded by `LLM_RATE_LIMIT_PER_USER`). A malformed value fails startup. |
| `LLM_USER_DAILY_BUDGET_USD` | serve | `0` (unlimited) | non-negative dollar amount | No | Cap on one user's interactive LLM spend (chat, NL graph query including MCP `graph_query`, refine) per UTC day. Interactive spend counts toward `LLM_MONTHLY_BUDGET_USD`, which halts background work, so this keeps one user from draining it. With an unreadable ledger the call proceeds. A malformed value fails startup. |
| `LLM_USER_MONTHLY_BUDGET_USD` | serve | `0` (unlimited) | non-negative dollar amount | No | Same, per calendar month. Every budget check reserves the call's worst-case cost until the call is recorded, but reservations are held per process: with N `serve` replicas (plus the worker), calls in flight on different processes do not see each other's reservations, so a cap can be overshot by up to one round of concurrent calls per process. The recorded spend itself is shared. |
| `CHAT_MAX_TOKENS_PER_TURN` | serve | `500000` | positive integer | No | Chargeable tokens one chat turn may use across its tool loop (each iteration resends the conversation). The turn ends with a note when reached. A malformed value fails startup. |
| `CHAT_MAX_TOOL_CALLS_PER_TURN` | serve | `24` | positive integer | No | Tool executions in one chat turn (on top of the 12-iteration ceiling). |
| `CHAT_TURN_TIMEOUT` | serve | `5m` | Go duration | No | Wall-clock budget for one chat turn; capped below the 10-minute hard stop so the turn can say why it ended. |
| `CHAT_MAX_HISTORY_MESSAGES` | serve | `40` | positive integer | No | Newest conversation turns sent to the model; older ones are dropped. |
| `CHAT_MAX_HISTORY_BYTES` | serve | `200000` | positive integer | No | Newest conversation text sent to the model; older turns are dropped, and a single message larger than this is a 400. |
| `CHAT_MAX_CONTEXT_BYTES` | serve | `8000` | positive integer | No | Size of the page context a chat request carries (what the user has open); larger is a 400. |
| `LLM_PRICES` | serve, worker | empty (every model at the fallback price) | JSON object: model id or prefix → `{"input","output","cache_read","cache_write"}` in USD per million tokens | No | Price table for the cost estimates the budgets compare against. A key matches exactly or as the longest prefix; `"*"` replaces the fallback. Unlisted models use a deliberately high fallback (input 15, output 75). A missing `cache_read` is charged at the input price and a missing `cache_write` at twice it. Set it from your provider's current price list; for a free local model use `{"*":{"input":0,"output":0}}`. Malformed JSON or a negative price fails startup. |

## Collectors and sync scheduling

| Variable | Process | Default | Format | Sensitive | Description |
|---|---|---|---|---|---|
| `SYNC_INTERVAL` | worker, scanner (schedule) | `2h` | duration | No | Cadence of the connector reconciliation sweep. Quiet connectors back off up to 6× this, never beyond 12h; values above 12h are effectively capped at 12h. |
| `CORRELATE_INTERVAL` | worker, scanner (schedule) | `30m` | duration | No | Cadence of the whole-graph correlation sweep. |
| `ENRICH_INTERVAL` | worker, scanner (schedule) | `15m` | duration | No | Cadence of the enrichment backstop sweep. Most enrichment happens at ingest and after correlate. |
| `ENRICH_MAX_AGE` | worker | `24h` | duration | No | Freshness backstop for the enrichment change-gate: a finding is re-enriched after this age even if unchanged. |
| `OWNER_TAG_KEYS` | worker, serve | unset | comma-separated tag keys | No | Extra resource tag keys that name an owner team, consulted before the defaults (`owner`, `Owner`, `team`, `Team`, `app.kubernetes.io/part-of`). Set the same value on both: the worker stamps finding owners with it and serve resolves the asset page's owner with it. See [ADR 089](adr/089-ownership-and-routing.md). |
| `GITHUB_MAX_PAGES` | worker | `50` | int | No | Pagination ceiling for the GitHub collector (about 5,000 repos at the default). Raise if inventory looks truncated. |
| `OKTA_MAX_PAGES` | worker | `50` | int | No | Pagination ceiling for the Okta collector (about 10,000 users). |
| `GOOGLE_MAX_PAGES` | worker | `20` | int | No | Pagination ceiling for the Google Workspace collector (about 10,000 users). |
| `GITHUB_MALFEED_TOKEN` | worker | none (unauthenticated, 60 requests/hour) | GitHub token | Yes | Optional token for the malicious-package feed. Only buys rate-limit headroom. |
| `INTEL_KEV_DISABLED` | worker, scanner (schedule) | off (feed on) | switch | No | Stops fetching the CISA Known Exploited Vulnerabilities catalog. Findings are no longer flagged `known_exploited` or escalated for it. |
| `INTEL_EPSS_DISABLED` | worker, scanner (schedule) | off (feed on) | switch | No | Stops fetching FIRST.org EPSS scores. CVE findings then get no EPSS points. |
| `INTEL_MALFEED_DISABLED` | worker, scanner (schedule) | off (feed on) | switch | No | Stops reading the OpenSSF malicious-packages feed from GitHub (the fast malicious-package detection path). |
| `INTEL_OSV_DISABLED` | worker, scanner (schedule) | off (feed on) | switch | No | Stops sending package names and versions to api.osv.dev. Turns off supply-chain CVE findings and the container-image sweep; VMs on OSV-matched distributions (Debian, Ubuntu, RHEL, Alma, Rocky, SUSE) are stamped `package_cve_gap=advisory_source_disabled`. |
| `INTEL_ALAS_DISABLED` | worker, scanner (schedule) | off (feed on) | switch | No | Stops reading Amazon Linux security advisories (ALAS) from the Amazon Linux 2 and 2023 repositories' `updateinfo.xml` on `cdn.amazonlinux.com`. Amazon Linux VM packages then get no CVE findings and their VMs are stamped `package_cve_gap=advisory_source_disabled`. |
| `INTEL_ELSA_DISABLED` | worker, scanner (schedule) | off (feed on) | switch | No | Stops reading Oracle Linux errata (ELSA) from the Oracle Linux 7 to 10 repositories' `updateinfo.xml` on `yum.oracle.com`. Oracle Linux VM packages then get no CVE findings and their VMs are stamped `package_cve_gap=advisory_source_disabled`. |
| `DOMAIN_MONITOR_DISABLED` | worker, scanner (schedule) | off (monitor on) | switch | No | Stops the domain-monitor job, which sends every monitored domain name to crt.sh. Domains and existing candidates stay visible; no new candidates are found. |
| `TAKEOVER_PROBE_DISABLED` | worker | off (probe on) | switch | No | Stops the subdomain-takeover HTTP probe, which sends GET requests to hostnames from your collected DNS records to fingerprint unclaimed services. Takeover candidates are then scored on DNS evidence only. |
| `COST_COLLECT_DISABLED` | serve | off (cost collection on) | switch | No | Stops the AWS Cost Explorer pull, which runs at serve startup and every 6 hours for each AWS connector. AWS bills each Cost Explorer request ($0.01). A connector collected in the last 5 hours (by any replica) is skipped, but replicas starting at the same moment can still both collect. Cost panels stay empty while this is set. Implied by `OFFLINE_MODE`. |
| `SCC_ORG_ID` | worker, scanner (schedule) | unset (feed off) | GCP organization ID | No | Enables the GCP Security Command Center threat-finding feed. |
| `SCC_QUOTA_PROJECT` | worker | ADC default project | GCP project ID | No | Project the SCC API call bills to; it must have the SCC API enabled. |
| `FORGET_MODE` | worker | `shadow` | `shadow` \| `enforce` | No | `shadow` only records what would be forgotten. `enforce` writes tombstones (still no deletion). An unrecognized value logs an error and runs `shadow`. |
| `FORGET_ENFORCE_TYPES` | worker | none | comma-separated subset of `security_group,vpc` | No | Limits `enforce` to these types. Empty means nothing is enforced even under `FORGET_MODE=enforce` (fail closed). Only `security_group` and `vpc` are accepted; any other name (a typo, or an audited type such as `ec2_instance`) fails worker startup, in either mode. A valid list has no effect in `shadow`. |
| `AWS_ENDPOINT_URL_S3` | serve | unset | URL | No | Standard AWS SDK override for S3-compatible endpoints. When non-empty, the live S3 `GetObject` call uses path-style addressing. Leave unset against real AWS. |

Cloud credentials for connectors are stored encrypted in Postgres through the
API or UI, not read from the environment. For local ingest from your own AWS
account, the AWS SDK's standard variables (`AWS_PROFILE`, `AWS_REGION`, and so
on) apply through the SDK. The application reads only a few of them itself:
`AWS_ENDPOINT_URL_S3` (above), any `AWS_ENDPOINT_URL*` override (which turns off
the regional-offering check), and `AWS_REGION` as the `graph bootstrap` default
region (see Bootstrap).

## Scanning

Nuclei external scanning and scan-profile APIs have been retired. Image and
package analysis remain available; VM disk scanning is opt-in.

| Variable | Process | Default | Format | Sensitive | Description |
|---|---|---|---|---|---|
| `SCAN_WORKER_DISABLED` | worker | off | switch | No | Delegates disk-volume reads to the isolated scanner. The Helm chart sets it when the disk-reader deployment is enabled. |
| `IMAGE_SCAN_DISABLED` | worker, scanner (schedule) | off (image scanning is on) | switch | No | Disables the container-image vulnerability sweep. It pulls images from registries by default, which is heavy locally. The sweep is also off whenever `INTEL_OSV_DISABLED` or `OFFLINE_MODE` is set, because every CVE match it makes is an OSV query. |
| `IMAGE_SCAN_ROOT` | worker | unset (registry-pull source) | directory path | No | Scan a local image root filesystem instead of pulling from registries. |
| `IMAGE_SCAN_MAX_STREAM_GIB` | worker | `4` | positive whole number of GiB | No | How much uncompressed layer data one image scan reads (newest layer first) before it stops. An image larger than this — typical of ML and CUDA images — is scanned only in part and carries a permanent `scan_incomplete` OS coverage finding, because its oldest layers (usually the OS base) are never reached; every rescan of the same digest stops at the same place. The stream is never held in memory, so raising the cap costs pull time and registry bandwidth, not memory; one pull is still bounded by a 5-minute timeout, past which the scan fails instead. A Go binary past the 512 MiB build-info probe budget, or a language manifest over 32 MiB, opens a separate `imagevuln-language-packages-incomplete` finding and does not affect the OS verdict. An invalid value stops the worker. |
| `IMAGE_REGISTRY_ALLOW_PRIVATE` | worker | unset (no private registry is reachable) | comma-separated CIDR prefixes or IPs, e.g. `10.20.0.0/16` | No | Private address ranges the image scanner may pull from. Every registry connection — including blob redirects and token-realm fetches — is checked at dial time and refused if it resolves to a private, loopback or reserved address, because image references come from connector data. List the subnet of an in-cluster or on-premises registry here. Link-local ranges (the cloud metadata endpoint) and catch-alls such as `0.0.0.0/0` are rejected, and an invalid value stops the worker; the metadata addresses outside link-local (`fd00:ec2::254`, `100.100.100.200`, `192.0.0.192`) stay blocked whatever the list allows. No HTTP proxy is used for registry pulls. |
| `IMAGE_REGISTRY_DOCKER_KEYCHAIN` | worker | off | exact `true` (case-insensitive) | No | Lets the image scanner present credentials from the pod's docker config (`$DOCKER_CONFIG/config.json`, `~/.docker/config.json`) to registries. Off by default so the scanner never sends ambient credentials to a registry that an image reference names; private ECR (via the AWS connector) and GCR/Artifact Registry (via application-default credentials) authenticate without it. |
| `BASE_IMAGE_CATALOGUE` | worker | unset (built-in catalogue) | path to a JSON file | No | Your preferred replacement base images, proposed ahead of the built-in vendor-neutral ones in base-image root-cause findings (ADR 088). The file is `{"replace_defaults": false, "entries": [{"name": "…", "image": "…", "runtime": "static\|glibc\|python\|node\|java\|ruby\|any", "note": "…"}]}`; `replace_defaults: true` proposes only your entries. A file that is missing or invalid stops the worker at startup. |

## Ladybug graph engine

Ladybug is the in-memory Cypher graph engine. The worker hosts the primary
instance and exposes it to `serve` and the scanner over an internal RPC.
`serve` can optionally run its own read-only replica. The graph tab falls back
to ClickHouse traversal when no engine is reachable.

| Variable | Process | Default | Format | Sensitive | Description |
|---|---|---|---|---|---|
| `LADYBUG_INTERNAL_PORT` | worker | unset (engine disabled) | port number | No | Enables Ladybug on the worker and sets the internal RPC port (e.g. `8090`). The engine is only opened when this is set; there is no effective default. If it is set and the engine fails to open, the worker stops at startup instead of running without a graph. Unset, the worker logs a startup warning naming what is off. |
| `LADYBUG_RPC_URL` | serve, scanner | unset | URL of the worker RPC | No | Where `serve` and the scanner reach the worker's Ladybug. With it unset and `SERVE_LADYBUG_ENABLED` off, `serve` has no Cypher and logs a startup warning saying so. |
| `LADYBUG_RPC_SECRET` | worker, serve, scanner | none | string | Yes | Shared secret on the internal RPC. The worker refuses to serve the RPC without it unless `LADYBUG_RPC_INSECURE=true`. Use the same value in all three. |
| `LADYBUG_RPC_INSECURE` | worker | off | exact `true` | Yes | **Dangerous.** Serves the RPC unauthenticated. See [Dev-only and dangerous](#dev-only-and-dangerous). |
| `LADYBUG_BUFFER_MB` | worker | `1280` | int (MiB) | No | Ladybug buffer pool size. Counted out of the container's memory budget. |
| `LADYBUG_POOL_SIZE` | worker | `8` | int | No | Concurrent Ladybug read connections. |
| `LADYBUG_QUERY_THREADS` | worker | `2` | int | No | Query parallelism per connection. |
| `LADYBUG_LOAD_THREADS` | worker | `min(NumCPU, 4)` | int | No | Parallelism of the bulk COPY load during a rebuild. |
| `LADYBUG_SNAPSHOT_PATH` | worker | `/data/ladybug/snapshot.gz` | file path | No | Topology snapshot written after each full rebuild and read at startup for warm starts. The path must be writable. |
| `LADYBUG_COPY_TMPDIR` | worker, serve (replica) | `/dev/shm` if it has at least 512 MiB free, else the OS temp dir | directory path | No | Staging directory for the transient bulk-load CSVs. |
| `SERVE_LADYBUG_ENABLED` | serve | off | switch | No | Runs a read-only Ladybug replica inside `serve`, refreshed from ClickHouse every 30 minutes. Needs roughly 512 MB extra memory. If it is on and the replica fails to open, `serve` stops at startup. |
| `SERVE_LADYBUG_BUFFER_MB` | serve | `512` | int (MiB) | No | Buffer pool size for the serve replica. |
| `SERVE_LADYBUG_SNAPSHOT_PATH` | serve | unset (no snapshots) | file path | No | Lets the serve replica warm-start from its own snapshot after a restart. |

## Observability

| Variable | Process | Default | Format | Sensitive | Description |
|---|---|---|---|---|---|
| `METRICS_PORT` | all | unset (no metrics listener) | port number | No | Serves Prometheus `/metrics` on this port. Pod-internal; do not expose it through the ingress. |
| `PPROF_PORT` | worker | unset | port number | Yes (heap and goroutine dumps) | Serves `net/http/pprof` on `127.0.0.1:<port>` only. Reach it with `kubectl port-forward`. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | all | unset (tracing off) | URL | No | Enables OTLP/HTTP trace export. The exporter also honors the other standard `OTEL_*` variables (headers, protocol, and so on). |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | all | unset | URL | No | Trace-specific endpoint; either this or the one above enables tracing. |

## Alerting, webhooks and SMTP

Slack and other alert channels are configured in the UI/API, not through the
environment. Besides event types, severities and a minimum score, a channel can
be scoped to owner teams and environments, and marked as the default channel for
unowned findings ([ADR 089](adr/089-ownership-and-routing.md)). These variables configure the legacy webhooks and just-in-time
email approvals. Approval emails are sent by the **worker** (which parks the
decision), and the links are verified by **serve**: set `SMTP_*` and
`APPROVAL_BASE_URL` on the worker, and the same `APPROVAL_TOKEN_SECRET` on both.

| Variable | Process | Default | Format | Sensitive | Description |
|---|---|---|---|---|---|
| `DECISION_WEBHOOK_URL` | worker | unset | URL | Yes (may embed a token) | Receives a POST on every non-observe remediation decision — a proposal awaiting a person (`action` is `parked_for_approval` or `escalated`), never an authorisation to act. Free-text fields (titles, summaries, rationale, CoVe concerns, owner/environment/deployed_from) are wrapped in `<<<UNTRUSTED>>>…<<<END UNTRUSTED>>>` markers and must be treated as data. `decision.blast_radius_known` is `false` when the blast-radius walk failed; `decision.blast_radius` is then an unmeasured `0`, not "touches nothing". |
| `DECISION_WEBHOOK_SECRET` | worker | unset (webhook not sent, startup `SECURITY:` error) | string | Yes | Signs each decision webhook: `X-Graph-Timestamp` (unix seconds) and `X-Graph-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<raw body>">`. Receivers should recompute it with a constant-time compare and reject stale timestamps (e.g. older than 5 minutes); Go receivers can call `webhooksig.Verify` (`pkg/webhooksig`). |
| `DECISION_WEBHOOK_ALLOW_UNSIGNED` | worker | off | exact `true` | No | Sends `DECISION_WEBHOOK_URL` posts unsigned when `DECISION_WEBHOOK_SECRET` is unset. Without it the worker skips the webhook rather than send something the receiver cannot authenticate. |
| `APPROVAL_WEBHOOK_URL` | serve | unset | URL | Yes (may embed a token) | Receives a POST when a governor approves a decision: one admin's queue verdict, or a confirmed email link for `observe`/`remediate`/`modify`. None of the executor's controls apply to it (no second admin, grant or intent row, for any action class); a receiver that changes anything is an executor outside Vulngraph. See [Approval webhook](security-hardening.md#approval-webhook). |
| `APPROVAL_WEBHOOK_SECRET` | serve | unset (startup error while `APPROVAL_WEBHOOK_URL` is set) | string | Yes | Signs each approval webhook with the same scheme as `DECISION_WEBHOOK_SECRET` (`X-Graph-Timestamp`, `X-Graph-Signature`), under its own key so one leaked key cannot forge the other receiver's posts. |
| `APPROVAL_WEBHOOK_ALLOW_UNSIGNED` | serve | off | exact `true` | No | **Dangerous.** Sends approval webhooks unsigned when `APPROVAL_WEBHOOK_SECRET` is unset (startup `SECURITY:` warning); without it that combination fails startup. A receiver may act on "a human approved this", so only for receivers that authenticate Vulngraph another way. See [Dev-only and dangerous](#dev-only-and-dangerous). |
| `SMTP_HOST` | worker | unset (email approvals off) | hostname | No | Emails an approval request with single-use approve/deny links whenever a decision is parked for approval. Needs `APPROVAL_TOKEN_SECRET`. |
| `SMTP_PORT` | worker | `587` | int | No | SMTP port. Port `465` uses implicit TLS; any other port requires STARTTLS, and a server that does not offer it is refused. |
| `SMTP_ALLOW_PLAINTEXT` | worker | off | exact `true` | Yes | **Dangerous.** Sends approval emails unencrypted when the SMTP server offers no STARTTLS. The approve/deny links are bearer credentials, so anyone on the path can use them first. See [Dev-only and dangerous](#dev-only-and-dangerous). |
| `SMTP_FROM` | worker | none | email address | No | Sender address. |
| `SMTP_TO` | worker | none | email address | No | Recipient of approval emails; recorded as the actor (`email-link:<address>`) when a link is used. A link can approve only `observe`, `remediate` and `modify` plans, and can deny only findings that are scored, readable and not urgent (page/high band or `must_fix`); everything else is decided in Vulngraph, behind a session. A link verdict does what the same queue verdict does (an approval fires `APPROVAL_WEBHOOK_URL`); it runs no fix. |
| `APPROVAL_BASE_URL` | worker | none | URL | No | Public base URL of Vulngraph, used to build links in approval emails. |
| `APPROVAL_TOKEN_SECRET` | worker, serve | none | string, at least 32 bytes | Yes | Signs (worker) and verifies (serve) the approval-link tokens; must be identical on both. Shorter values are a startup error. Without it the link routes answer 503 ("email approval links are not configured"). Each link is bound to the exact decision (finding + context fingerprint) and action class, and works once. A link is a bearer credential valid for 48 hours; see [Email approval links](security-hardening.md#email-approval-links). |

## Remediation and approvals

Destructive cloud actions (`ec2_stop`, `ec2_start`, `gcp_firewall_remove`,
`azure_nsg_rule_remove`, and the delete variant of `iam_key_disable`) require a
grant from a second admin, signed with a key derived from `GRAPH_SECRET_KEY`;
there is no switch to turn that off. The rule is in
[security-hardening.md](security-hardening.md#connectors-and-remediation).

| Variable | Process | Default | Format | Sensitive | Description |
|---|---|---|---|---|---|
| `EXECUTOR_APPROVER_MIN_ACCOUNT_AGE` | serve | `24h` | duration, non-negative (a malformed value is a startup error) | No | How long the approving admin must have held the admin role before it can mint a grant: counted from the later of the account's creation and its last promotion to admin (`users.admin_since`). Both times come from the user record, the key owner's for an API key. An admin from before `admin_since` existed counts from account creation. An account of unknown age never approves, even at `0`. Also applies to the second admin who confirms a decision panel approve-and-run. |
| `LIVE_CLOUD_TOOLS_ROLE` | serve | `admin` | `admin` \| `analyst` \| `viewer` (anything else is a startup error) | No | Minimum role for the live cloud read tools (`live_aws_describe`, `get_cloudtrail_events`, `list_connectors`) in MCP and chat. Every call writes an audit row first. |

Notification and approval delivery
use the variables in the previous section; the severity adjudicator is
`ADJUDICATOR_ENABLED` and `ADJUDICATOR_MODEL` under
[LLM provider](#llm-provider); `FORGET_MODE` is under
[Collectors](#collectors-and-sync-scheduling). See
[security hardening](security-hardening.md#connectors-and-remediation).

## Network egress

Every outbound destination Vulngraph can contact, what it sends, and how to turn
it off. The first table runs with no configuration at all; the second only
happens once you configure the integration. Set `OFFLINE_MODE=true` to turn
off everything in the first table that has a switch, plus one call in the
second: serve's AWS Cost Explorer pull over your AWS connectors
(`COST_COLLECT_DISABLED`). The takeover check's DNS lookups, which go to whatever
resolver the worker uses, have no switch. `OFFLINE_MODE` does not touch the other integrations
you configured (connector syncs, LLM, notifications, sign-in): to stop those,
remove the connector, channel or variable.

The worker logs one warning at startup listing the feeds that are off. Scoring
keeps working without them: a missing EPSS score adds no points and a missing
KEV catalog sets no `known_exploited` flag, so the affected findings score
lower than they otherwise would.

### On by default

| Destination | Process | What is sent | Purpose | Switch |
|---|---|---|---|---|
| `www.cisa.gov` | worker | Plain GET, no data | CISA KEV catalog: daily, and after OSV or image scans record CVE findings | `INTEL_KEV_DISABLED` |
| `epss.cyentia.com` | worker | Plain GET, no data | FIRST.org EPSS exploit-probability scores, daily and on every worker start | `INTEL_EPSS_DISABLED` |
| `api.github.com`, `raw.githubusercontent.com` | worker | GETs of the public `ossf/malicious-packages` repository, with `GITHUB_MALFEED_TOKEN` if set | Malicious-package feed, hourly | `INTEL_MALFEED_DISABLED` |
| `api.osv.dev` | worker | **Ecosystem, name and version of every package in your inventory** (repository dependencies, container-image OS packages, VM OS inventories) | CVE matching, daily | `INTEL_OSV_DISABLED` |
| `cdn.amazonlinux.com` | worker | Plain GETs of public repository metadata (`mirror.list`, `repomd.xml`, `updateinfo.xml.gz`), no data. Only once an Amazon Linux 2 or 2023 package is inventoried | Amazon Linux security advisories (ALAS), daily; a conditional GET when nothing changed | `INTEL_ALAS_DISABLED` |
| `yum.oracle.com` | worker | Plain GETs of public repository metadata (`repomd.xml`, `updateinfo.xml.gz`), no data. Only once an Oracle Linux package is inventoried | Oracle Linux errata (ELSA), daily; a conditional GET when nothing changed | `INTEL_ELSA_DISABLED` |
| `crt.sh` | worker | **Every domain name you added to domain monitoring** | Certificate-transparency look-alike (phishing) detection, every 6 hours. Sends nothing until a domain is added | `DOMAIN_MONITOR_DISABLED` |
| Registries of the container images running in your clusters (for example Docker Hub, `ghcr.io`, `registry.k8s.io`, your private registries) | worker | Image pulls by reference, with private-ECR tokens from your AWS connectors and GCP application-default credentials when available (pod docker credentials only with `IMAGE_REGISTRY_DOCKER_KEYCHAIN`); private addresses only within `IMAGE_REGISTRY_ALLOW_PRIVATE` | Container-image vulnerability sweep, daily | `IMAGE_SCAN_DISABLED` (also off with `INTEL_OSV_DISABLED`) |
| The worker's DNS resolver (the cluster or host resolver, and whatever it forwards to) | worker | DNS lookups of the CNAME/ALIAS targets of records flagged as subdomain-takeover candidates | Takeover check during enrichment: whether the target still resolves | **None.** It uses the system resolver; point the pod at a resolver you control to keep the names in-house |
| Hostnames from your collected DNS records (usually the third-party service a CNAME points at) | worker | HTTP GET to the hostname | Confirms or refutes subdomain-takeover candidates during enrichment | `TAKEOVER_PROBE_DISABLED` |

The web UI makes no third-party requests: its fonts are bundled and served locally.

### Only when configured

| Destination | Process | What is sent | Enabled by |
|---|---|---|---|
| AWS APIs (STS, Organizations, EC2, IAM, S3 and others) | worker, serve | Signed read-only API calls with the connector's credentials; write calls only for approved remediation | An AWS connector; remediation actions |
| AWS Cost Explorer (`ce:GetCostAndUsage`) | serve | Signed Cost Explorer queries with each AWS connector's credentials, at serve startup and every 6 hours; AWS bills each request | An AWS connector. Off with `COST_COLLECT_DISABLED` or `OFFLINE_MODE` |
| Google Cloud APIs (`*.googleapis.com`, including Security Command Center and GKE) | worker | Signed API calls with the connector's credentials | A GCP connector; `SCC_ORG_ID` |
| Azure APIs (`management.azure.com` and related) | worker | Signed API calls with the connector's credentials | An Azure connector |
| Microsoft Graph (`graph.microsoft.com`) and Key Vault data planes (`*.vault.azure.net`) | worker | Read-only GETs with the connector's credentials: Entra tenant settings, and key rotation policies (never secret values) — see [docs/iam/azure-permissions.md](iam/azure-permissions.md) | An Azure connector |
| Kubernetes API servers | worker | Read-only API calls with the connector's credentials | A Kubernetes connector |
| `api.github.com` or your GitHub Enterprise URL | worker | API calls with the connector's token | A GitHub connector |
| Your Okta org domain | worker, serve | API calls with the connector's token; OIDC sign-in | An Okta connector; `OKTA_CLIENT_ID` |
| `admin.googleapis.com`, `oauth2.googleapis.com` | worker | Directory API calls with the service-account key | A Google Workspace connector |
| `accounts.google.com`, `oauth2.googleapis.com`, `www.googleapis.com` | serve | OAuth code exchange and user-info lookup | `GOOGLE_CLIENT_ID` |
| `www.gstatic.com` | serve | Plain GET of the IAP public keys | `IAP_AUDIENCE` |
| LLM provider (`api.anthropic.com`, `api.openai.com`, or `LLM_BASE_URL`) | serve, worker | **Finding, asset and graph context** in prompts: remediation reasoning, chat, phishing triage, adjudication | `LLM_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` or `LLM_BASE_URL` |
| `slack.com` | worker, serve | Alert text: finding titles, severities, resource names | A Slack notification channel (serve sends only the "Test" message) |
| Webhook URLs | worker, serve | JSON alert, decision or approval payloads | A webhook channel; `DECISION_WEBHOOK_URL`; `APPROVAL_WEBHOOK_URL` |
| SMTP server | worker | Approval-request emails with single-use links | `SMTP_HOST` |
| OTLP collector | all | Trace spans | `OTEL_EXPORTER_OTLP_ENDPOINT` |

Calls to user-supplied endpoints (Okta domains, Google token URIs, webhooks) go through an SSRF-blocking HTTP client that refuses private and
metadata addresses.

## Tuning and scale

| Variable | Process | Default | Format | Sensitive | Description |
|---|---|---|---|---|---|
| `GOMEMLIMIT` | all | derived from the container memory limit | Go memory-limit syntax (e.g. `3GiB`) | No | The derived limit is the cgroup limit minus the Ladybug buffer minus the reserve. If `GOMEMLIMIT` is set, the tighter of the two applies, so a larger value cannot raise the derived limit; to do that, lower `MEM_RESERVE_MIB` or raise the container memory limit. If there is no cgroup limit, or the budget falls under 512 MiB and so is not applied, the runtime uses `GOMEMLIMIT` as-is. At chart defaults the serve pod (1Gi limit, 1024 MiB reserve) falls under the floor, so it runs on `GOMEMLIMIT` or the runtime default. |
| `MEM_RESERVE_MIB` | all | `1024` | int (MiB) | No | Memory held back from the Go heap budget for non-heap use (thread stacks, C++ allocator, mapped files). |
| `GOGC` | all | `60` (set by Vulngraph when unset) | int | No | Standard Go GC percent. If you set it, Vulngraph does not override it. |

Also see `PG_MAX_CONNS_*` and `CH_MAX_CONCURRENT` under
[Core](#core-and-datastores), `LADYBUG_*` under [Ladybug](#ladybug-graph-engine), and the
`*_MAX_PAGES` collector ceilings.

ClickHouse's own server-wide `max_execution_time` is not an environment variable:
the Helm chart sets it to `clickhouse.tuning.maxExecutionSeconds` (600) and
`deploy/docker-compose/clickhouse/users.xml` to 600. It is a backstop; each
query's Go context timeout is the real bound, and the longest of those is 10
minutes. A lower server value kills long bulk reads (the asset sync load, the
correlate view load) partway through a sweep.

## Bootstrap command

`graph bootstrap` is an optional one-shot that registers connectors by reading
credentials from Kubernetes Secrets in a source namespace (`GRAPH_MIGRATION_NAMESPACE`; AWS from the
Secret named below; Azure and GitHub App credentials from a Secret named
`graph-bootstrap-credentials`). Skip it if you add connectors through the UI or API.

| Variable | Default | Format | Sensitive | Description |
|---|---|---|---|---|
| **`GRAPH_ADMIN_TOKEN`** | none (required) | API key / token | Yes | Admin credential used to call the Vulngraph API. |
| `GRAPH_API_URL` | `http://localhost:8080` | URL | No | Vulngraph API to register connectors with. |
| `GRAPH_MIGRATION_NAMESPACE` | `graph-bootstrap` | Kubernetes namespace | No | Namespace holding the source credential Secrets. |
| `GRAPH_MIGRATION_AWS_SECRET_NAME` | `graph-aws-credentials` | Secret name | No | Secret containing the AWS credentials file. |
| `BOOTSTRAP_ONLY` | all providers | comma-separated subset of `aws,github,gcp,kubernetes` (azure is also recognized in code) | No | Restrict the run to some providers. |
| `AWS_ORG_MANAGEMENT_ROLE_ARN` | none | IAM role ARN | No | Registers one `aws_org` connector with this discovery role ([onboarding-aws-org.md](onboarding-aws-org.md)). Unset: no org connector. |
| `AWS_ORG_EXTERNAL_ID` | none (required with the above) | string | Yes | The ExternalId every Vulngraph role trusts. |
| `AWS_ORG_HUB_PROFILE` | none (ambient identity) | profile name | No | A credentials-file profile whose key the org connector stores once (`hub_auth=access_key`). Unset: graph's own identity is the hub. |
| `AWS_ORG_HUB_ROLE_ARN` | none | IAM role ARN | With `AWS_ORG_HUB_PROFILE` | The org connector's `hub_role_arn`: the hub role (`TrustType=principal`) that the hub profile's key, or graph's own identity, assumes first. |
| `AWS_ORG_CONNECTOR_NAME` | `aws-org` | string | No | Name of the org connector. |
| `AWS_REGION` | `us-east-1` | region | No | Home region of the org connector and its account connectors. |
| `AWS_READONLY_ROLE` | `GraphReadOnly` | IAM role name | No | Member role assumed in each account. |
| `GCP_PROJECT_IDS` | none | comma-separated project IDs | No | One GCP connector is created per project. |
| `K8S_CLUSTER_NAME` | `in-cluster` | string | No | Name for the Kubernetes connector. |

## Dev-only and dangerous

These weaken secure defaults. Each is off unless set to the exact value shown.
None belongs on an internet-reachable deployment unless the "safe only when"
condition holds. The authoritative description and the rationale for each is
in [security-hardening.md](security-hardening.md#dangerous-flags). This table
lists the same flags plus two that table does not: `OAUTH2_PROXY` (a trust mode,
covered in [oauth2-proxy](security-hardening.md#oauth2-proxy) rather than in the flag table) and
`PPROF_PORT`.

| Variable | Exact value | Process | Risk | Safe only when |
|---|---|---|---|---|
| `BYPASS_AUTH` + `BYPASS_AUTH_I_UNDERSTAND` | `true` + `yes` | serve | Every request runs as one synthetic admin, so audit rows name no person and cloud changes (executor runs) are refused. | A network-level auth gate fronts every path, or loopback-only local dev. |
| `LADYBUG_RPC_INSECURE` | `true` | worker | The internal graph RPC is unauthenticated; any pod that can reach it can query the whole graph. | Local dev only. |
| `SMTP_ALLOW_PLAINTEXT` | `true` | worker | Approval emails, and their single-use approve/deny links, can travel unencrypted to the SMTP server. | The SMTP relay is on the same host or a trusted private link. |
| `COOKIE_INSECURE` | `true` | serve | Session cookies lose the `Secure` attribute and travel over plain http. | Plain-http localhost development. |
| `OAUTH2_PROXY_ALLOW_ANY_DOMAIN` | `true` | serve | Any email the verified proxy sends is accepted and auto-provisioned (viewer unless `ADMIN_EMAILS`/groups say otherwise). | The proxy's own policy is the gate you want. |
| `OAUTH2_PROXY` | `true` | serve | Trusts the proxy: with only a shared secret, one credential stands in for every identity. | `OAUTH2_PROXY_OIDC_ISSUER` verifies the ID token, and a NetworkPolicy restricts ingress to the ingress controller. |
| `IAP_ALLOW_ANY_DOMAIN` | `true` | serve | Any identity IAP admits is auto-provisioned as a viewer. | The IAP access policy itself restricts who gets through. |
| `GOOGLE_ALLOW_ANY_DOMAIN` / `OKTA_ALLOW_ANY_DOMAIN` | `true` | serve | Any account from that IdP is auto-provisioned (viewer unless `ADMIN_EMAILS`/groups say otherwise). | The IdP itself restricts who can obtain a token for your client. |
| `OAUTH2_PROXY_TRUST_GROUPS` | `true` | serve | In shared-secret-only oauth2-proxy mode, `X-Auth-Request-Groups` maps to roles. | nginx overwrites any client-sent `X-Auth-Request-Groups`. |
| `OAUTH2_PROXY_OIDC_ALLOW_UNVERIFIED_EMAIL` | `true` | serve | ID tokens without `email_verified` are accepted, and the first sign-in binds an existing account by email. | The IdP never lets users choose or change their email. |
| `OAUTH_REDIRECT_FROM_HOST` | `true` | serve | An unset OAuth redirect URL is built from the request's `Host` / `X-Forwarded-Proto`, so a forged header can steer the OAuth callback. | Local dev only. |
| `DECISION_WEBHOOK_ALLOW_UNSIGNED` | `true` | worker | Decision webhook posts go out without an HMAC signature. | The receiver authenticates Vulngraph another way (mTLS, a private network path). |
| `APPROVAL_WEBHOOK_ALLOW_UNSIGNED` | `true` | serve | Approval webhook posts ("a human approved this") go out without an HMAC signature, so the receiver cannot tell them from forgeries. | The receiver authenticates Vulngraph another way (mTLS, a private network path). |
| `PASSWORD_LOGIN_BREAK_GLASS` | `true` | serve | Local passwords keep working behind IAP/oauth2-proxy, bypassing the proxy's MFA and offboarding. | Kept for emergency access, with strong passwords and TOTP. |
| `PPROF_PORT` | port | worker | Exposes profiling endpoints. | Reachable only through a port-forward. |

## How this list was produced

The inventory was built from the Go sources (excluding tests and
`third_party/`) and then each variable was traced to its call site to find the
process, default and format. To re-run the discovery after adding code:

```sh
grep -rnE '(getenv|Getenv|LookupEnv|[eE]nv[A-Za-z]*|parse[A-Za-z]*)\((getenv, *|os\.Getenv, *)?"[A-Z][A-Z0-9_]+"' \
  cmd internal pkg --include='*.go' | grep -v '_test.go' | grep -v third_party
```

That misses variables whose name is held in a constant or passed through a
helper (`COOKIE_INSECURE`, `SCAN_ALLOW_INTERNAL_TARGETS`, `BYPASS_AUTH_I_UNDERSTAND`).
Catch those with:

```sh
grep -rnE 'Getenv\(|LookupEnv\(|getenv\(' cmd internal pkg --include='*.go' \
  | grep -v '_test.go' | grep -vE '(getenv|Getenv|LookupEnv)\("[A-Z]'
```

Compare the union against the first column of the tables above.

### Maintainer tools

`cmd/benchmark-watch` (run by hand or in CI, never by the `graph` binary) reads
`GITHUB_TOKEN` (optional; raises the GitHub API rate limit above 60 requests an
hour) and `AWS_REGION`, falling back to `AWS_DEFAULT_REGION`, for the Security
Hub call it makes through the `aws` CLI when the CLI and AWS credentials are
available (region defaults to `us-east-1`; without the CLI or credentials it
falls back to the public reference page).
