# Granting Vulngraph AWS Cost Explorer read access (`ce:GetCostAndUsage`)

Vulngraph's Cost surface collects daily per-service spend from **AWS Cost Explorer**
(`internal/collect/aws/costexplorer.go`, called every 6h and on startup by the
cost collect loop in `cmd/graph/serve.go`) and stores it in `cost_snapshots`.
Anomaly detection, and every dollar figure on the Cost page, is derived from
those rows.

This permission is **not** included in the read-only roles Vulngraph's setup
elsewhere in `docs/iam/` grants (`ViewOnlyAccess`/`SecurityAudit`-shaped roles
do not include Cost Explorer), so the Cost surface stays empty until it's
granted explicitly.

> Vulngraph never grants this itself: no code path grants IAM permissions to Vulngraph or
> anyone else. Its only IAM writes are human-approved key actions through the executor
> (disabling or deleting an AWS access key, disabling a GCP service-account key), run
> with the connector's separate execution role.
> Grant it through whatever IAM process your organization already uses.

## The grant

Cost Explorer is a **global, account-level** API — one region (`us-east-1`), no
resource ARNs, so the statement cannot be resource-scoped:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GraphCostExplorerRead",
      "Effect": "Allow",
      "Action": [
        "ce:GetCostAndUsage"
      ],
      "Resource": "*"
    }
  ]
}
```

Read-only and non-mutating. Add it to the role Vulngraph already assumes per account
(`GraphReadOnly`) via whatever mechanism provisions that role, as described in
[README.md](./README.md). No Vulngraph code, config, or connector
change is needed: the collect loop already runs, it just gets denied until the
grant lands.

Two account-level prerequisites beyond IAM, both one-time:

1. **Cost Explorer must be enabled** in each payer account (first enablement can
   take up to 24h to backfill data). A never-enabled account answers with
   `DataUnavailableException`.
2. In an AWS Organization, member accounts see their own spend only if the payer
   has **"Linked account access to Cost Explorer"** turned on; otherwise collect
   only ever succeeds for the management account.

## How to tell whether it worked

The collect loop never fails silently — every outcome is logged and counted:

- Metric `graph_cost_collect_total{outcome="permission_denied"}` (also
  `config_error`, `api_error`, `empty`, `store_error`, `connector_list_error`,
  `no_aws_connectors`, `ok`), and `graph_cost_last_success_timestamp_seconds`
  per connector (`internal/obs/metrics.go`).
- Log line `cost collect: AWS denied Cost Explorer; grant the permission to the
  connector role or cost panels stay empty`, carrying `connector_id`,
  `account_id` and `required_permission`.
- API `GET /api/cost/status` — per-connector outcome, stored row count, and the
  required permission string. The Cost page renders this verbatim, so a denial
  reads as a denial instead of "no cost anomalies".

After the grant lands, the next collect cycle (≤6h, or a pod restart) should show
`outcome="ok"` and a rising `graph_cost_snapshot_rows_written_total`.

## Why this matters beyond the panel

Until this is granted, **no dollar-weighted risk on the Cost page is possible**.
The page therefore states that its cost data is uncollected rather than implying
zero spend or zero waste. Its at-risk numbers come from findings joined to
cost-BEARING asset types (`internal/app/finding/risk.go`), which needs no AWS
billing permission — that half works regardless of this grant.

## Alerting on a denial

There is deliberately no standing `GraphCostExplorerDenied` rule in
`deploy/helm-chart/graph/alerts/rules.yaml` by default, because a permission
that was never granted would page forever with zero new information — exactly
the kind of noise that erodes trust in every other alert in that file (see
that file's own preamble on alert fatigue). `graph_cost_collect_total` keeps
recording throughout regardless (still visible on demand, and its two
siblings — `GraphCostCollectionDark` and `GraphCostCollectStoresNothing` —
still alert on it).

**If you want to page on this,** add a rule like the one below to the
`graph-cost-collection` group in `rules.yaml` — but only after granting the
permission is genuinely blocked on something outside your control (e.g.
waiting on a separate team), since the condition below is permanently true
until the grant actually lands:

```yaml
- alert: GraphCostExplorerDenied
  expr: |-
    sum by (namespace) (increase(graph_cost_collect_total{namespace="__NAMESPACE__", outcome="permission_denied"}[6h])) > 0
  for: 1h
  labels:
    severity: warning
  annotations:
    summary: "graph: AWS denied Cost Explorer — cost data cannot be collected"
    description: >-
      The connector role is missing ce:GetCostAndUsage (or the account has never
      enabled Cost Explorer). Every dollar figure on the Cost surface depends on
      it, and without this signal a denial renders as "no cost anomalies" —
      an empty panel that reads as good news. Grant it per
      docs/iam/cost-explorer-permission.md; no code change is needed.
```
