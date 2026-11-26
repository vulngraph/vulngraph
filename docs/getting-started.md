# Getting started

This guide takes you from nothing to a working Vulngraph: first with the bundled demo data, then with your own
cloud accounts, and finally in production. Each step says what you should see.

| I want to | Go to |
|---|---|
| See it working in about 15 minutes, with no cloud account | [Run it locally](#1-run-it-locally) and [Explore the demo](#2-explore-the-demo) |
| Check one cloud account from the command line, with no database | [Quick scan](quick-scan.md) |
| Point it at my own accounts | [Connect your cloud](#3-connect-your-cloud) |
| Run it for real | [Production](#6-production) |

## 1. Run it locally

You need Docker with Compose v2.24 or newer (`docker compose version`) and about 6 GB of memory and 4 CPUs
available to Docker. Nothing else: the image builds from this checkout, so there is no Go or Node toolchain
to install.

```sh
git clone https://github.com/vulngraph/vulngraph
cd vulngraph/deploy/docker-compose
docker compose up -d
docker compose exec serve /graph user create --email you@example.com --role admin
```

The first build takes several minutes; later ones reuse the cache. `user create` prints a generated
password. Open **http://localhost:8080** and sign in with it.

The stack is Postgres (state), ClickHouse (assets, edges, findings, audit log), `serve` (API and UI) and
`worker` (sync, correlation, enrichment, scans). The compose stack generates its own secrets on first start
and keeps them in Docker volumes ([details](../deploy/docker-compose/README.md#secrets)). It is an
evaluation setup. Opted-in disk reads run in the worker there. Use the Helm chart for
anything real ([Production](#6-production)).

Two local-only notes:

- **Safari** refuses the session cookie over plain `http://localhost`, so sign-in loops back to the login
  page. Use Chrome or Firefox, or set `COOKIE_INSECURE=true` in `app.env` for local use only.
- **Small machines.** Set `IMAGE_SCAN_DISABLED=true`, `SCAN_WORKER_DISABLED=true` or a lower
  `LADYBUG_BUFFER_MB` in `app.env`. See [the Compose README](../deploy/docker-compose/README.md).

## 2. Explore the demo

The demo is a fictional AWS account, Acme, with a public web server, two services, a database, a bucket of
customer exports and a GitHub repository. It makes no cloud calls and needs no credentials.

1. Go to **Settings → Connectors → Add connector**, choose the provider **demo**, give it a name and create it.
2. Click **Sync now**.
3. Optionally add a monitored domain with look-alike domains for the Domain Monitor page:
   `docker compose exec serve /graph demo seed`

What you should see, and when:

| Time after the sync | What appears |
|---|---|
| Within a minute | Assets, the posture findings, the compliance rollup, the Drift page |
| About 5 minutes after the worker starts | The graph: attack paths, blast radius, the Graph page queries |
| About 12 to 16 minutes after the worker starts | Known-exploited and package vulnerability findings, which need internet access to OSV and the CISA KEV feed |

Then try the [examples](examples.md): ask the graph a question, open the "must fix" finding, trace a package
to its repository. The [query cookbook](queries.md) lists every ready-made query.

To see the checks without the stack at all: `docker compose exec serve /graph scan demo`.

## 3. Connect your cloud

Every collector is read-only. [Connecting your accounts](connecting.md) walks through each provider step by step. Create the connector under **Settings → Connectors → Add connector**, then
**Sync now**. The first sync takes a few minutes for a large account; the graph follows shortly after.

| Provider | What you provide | Grants and setup |
|---|---|---|
| AWS | `role_arn` (a role Vulngraph assumes) and `region` | [`iam/`](iam/README.md) lists the read-only policies |
| AWS Organization | A management role and an external ID | [`onboarding-aws-org.md`](onboarding-aws-org.md): one StackSet puts a read-only role in every account, including new ones |
| GCP | `project_id` | [`iam/gcp-cspm-permissions.md`](iam/gcp-cspm-permissions.md) |
| Azure | `subscription_id` | [`iam/azure-permissions.md`](iam/azure-permissions.md) |
| GitHub | A GitHub App: app id, installation id, private key | [`iam/identity-and-code-connectors.md`](iam/identity-and-code-connectors.md) |
| Kubernetes | Nothing; it uses in-cluster credentials | [Kubernetes connector RBAC](../deploy/README.md#kubernetes-connector-rbac) |
| Okta, Google Workspace | An API token, or a service account with domain-wide delegation | [`iam/identity-and-code-connectors.md`](iam/identity-and-code-connectors.md) |

A VM with no software inventory can also be read from a disk snapshot, once an admin opts that connector in
([disk scanning](capabilities.md#vm-disk-scanning); off by default).

For AWS you can also grant Vulngraph read access to Terraform state so that live resources are linked to
the repository that defines them ([`iam/README.md`](iam/README.md)). State files can hold secrets, so read
that page first.

If you would rather not run the stack yet, [`graph scan`](quick-scan.md) checks one AWS, GCP, Azure, Okta or
Google Workspace account from environment credentials and stores nothing.

## 4. Turn on the LLM (optional)

Inventory, checks, scanning and scoring work without an LLM. An LLM adds the plain-English query box,
the chat panel, remediation proposals and the triage of look-alike domains.

Put the provider in `deploy/docker-compose/app.env` (git-ignored) and run `docker compose up -d` again:

```sh
ANTHROPIC_API_KEY=...
# or any OpenAI-compatible endpoint, hosted or local:
# LLM_PROVIDER=openai
# LLM_API_KEY=...
# LLM_BASE_URL=http://host.docker.internal:11434/v1
# LLM_MODEL=...
```

[`llm-providers.md`](llm-providers.md) covers providers, budgets and what is sent. A configured provider
receives finding and graph context, so use a local endpoint if that data must stay in-house. The model only
proposes: a state-changing action runs only after a person approves it.

## 5. Keep the data fresh

Each connector fully re-syncs every 2 hours by default. Set `SYNC_INTERVAL` to change it: the scheduler
checks every 15 minutes, so about 15 minutes is the fastest cadence, and quiet connectors back off, up to
12 hours. After every sync the graph is re-correlated and rebuilt.

**GitHub, event-driven.** Set a `webhook_secret` on the GitHub connector, then add a GitHub webhook that posts
to `https://<your-host>/api/webhooks/github/<connector-id>` with the same secret. A verified event syncs that
connector immediately, and a burst of events coalesces into one sync.

**Any other event.** Anything that can make an HTTP call can trigger a sync:

```sh
curl -X POST https://<your-host>/api/connectors/<connector-id>/sync \
  -H "Authorization: Bearer $GRAPH_ADMIN_API_KEY"
```

The call returns 202 and queues one sync, however many events arrive. For example, an EventBridge rule on
security-group or bucket-policy changes can call it through an API destination. The key needs the `admin`
scope, so store it as a secret. Native AWS and GCP event sources are not built; without a trigger like this,
cloud connectors run on the schedule.

**Right now.** An agent can ask the cloud directly whether a finding is still true: **Verify live** on a
finding, or the `live_aws_describe` and `get_cloudtrail_events` MCP tools. Calls assume the connector's
read-only role through STS, are admin-gated, and are audited.

**Drift analysis.** `DRIFT_ANALYSIS_ENABLED=true` adds advisory LLM analysis of
inventory changes on the Drift page and over MCP. It cites affected assets and
never starts an external scan or changes cloud resources.

## 6. Production

The Compose stack is for evaluation. For production use the Helm chart:

1. Follow the [deploy quickstart](../deploy/README.md#quickstart): generate the secrets once and keep them.
2. Start from the hardened values overlay, [`deploy/helm-values/hardened.yaml`](../deploy/helm-values/hardened.yaml).
   It refuses to install until every setting only you can supply is set.
3. Work through the [production checklist](production-checklist.md).
4. Choose sign-in: local accounts, Google OAuth, Okta OIDC, GCP IAP, or an oauth2-proxy
   ([sign-in and ingress](../deploy/README.md#sign-in-ingress-and-extra-settings)).
5. Use cloud-native identity for the collectors instead of keys: [OIDC federation](../deploy/README.md#cloud-auth-oidc).
6. Verify the release image before you run it: [verifying a release image](../deploy/README.md#verifying-a-release-image).

The scanner runs in its own pod with no encryption key, LLM key or cloud identity, and the application
database users cannot change the schema or rewrite the audit log
([security hardening](security-hardening.md)). Every outbound connection is listed in
[configuration](configuration.md#network-egress); `OFFLINE_MODE=true` turns off the ones that can be.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Sign-in returns to the login page | Safari over plain http. Use another browser, or `COOKIE_INSECURE=true` locally. |
| The Graph page says "Graph engine not ready" | The graph is built by the first correlation sweep, about 5 minutes after the worker starts. Check `docker compose logs worker`. |
| No vulnerability findings after the sync | They come from OSV and CISA KEV, about 12 to 16 minutes after the worker starts, and need outbound internet. `OFFLINE_MODE` or `INTEL_OSV_DISABLED` turns them off. |
| "failed to create connector" for `demo` | The database was created before the demo type existed. Reset a throwaway stack with `docker compose down -v`, which deletes its data. |
| Port 8080 is in use | Stop what is using it, or change the published port in `docker-compose.yml`. |
| The build or the stack runs out of memory | Give Docker at least 6 GB and 4 CPUs, or use the switches in step 1. |
| A connector shows an error | Open it under **Settings → Connectors** for the message. A permission error names the missing grant. |

## Upgrading and removing

Compose rebuilds from the checkout on every `docker compose up -d`; migrations run as part of the stack. Pull the new
sources first, and read the [changelog](../CHANGELOG.md) for breaking changes. See
[Upgrading](../deploy/docker-compose/README.md#upgrading) and, for Helm, [upgrading the chart](../deploy/README.md#upgrading).

`docker compose down` stops the stack and keeps your data. `docker compose down -v` also deletes the
volumes, which removes every collected asset and finding.
