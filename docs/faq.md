# FAQ

**Does it need write access to my cloud?** No. Connectors start read-only and the executor rejects any
action on a read-only connector before it makes a cloud call. Write access needs an admin to switch a
connector to `read_write`, give its role the permissions, and then approve each action, with a second
admin for destructive ones.

**Do I need an LLM?** No. Inventory, checks, scanning and scoring work without one. An LLM adds the
plain-English query box, chat and fix proposals, and it only proposes
([providers and what is sent](llm-providers.md)).

**What leaves my network?** Only what [the egress list](configuration.md#network-egress) shows, each
with a switch. By default that is package names and versions to OSV and monitored domains to
certificate-transparency search. `OFFLINE_MODE=true` turns off the ones that can be.

**Why Postgres and ClickHouse?** Postgres holds transactional state: users, connectors, jobs and approvals.
ClickHouse holds assets, edges, findings and the audit log at scale, and the graph engine is rebuilt from it.

**What happens when it cannot read something?** It says so. A missing permission or an incomplete listing
is recorded as unknown and is never reported as clean or fixed.

**How fresh is the data?** Every connector fully re-syncs every 2 hours by default, as often as every 15
minutes if you set `SYNC_INTERVAL`, and the graph is re-correlated after every sync. GitHub changes sync
immediately through a signed webhook, and any other event, such as an EventBridge rule on a security-group
change, can trigger a sync with one API call. Native AWS and GCP event sources are not built, so cloud
connectors otherwise run on the schedule. Inventory changes can receive advisory drift analysis, and
**Verify live** checks a finding against the cloud right now. [Set it up](getting-started.md#5-keep-the-data-fresh).

**Can I try it without installing a database?** Yes: `graph scan` checks one account from environment
credentials and stores nothing ([quick scan](quick-scan.md)), and `graph scan demo` runs the bundled
demo account.

**What is it not?** Not an agent on your hosts, not a SIEM, not an auto-remediator and not a replacement
for your other controls. See [known limitations](known-limitations.md).
