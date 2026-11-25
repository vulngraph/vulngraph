# Demo: the Acme account

Vulngraph bundles a fictional company, Acme, so you can see the output without a cloud
account. Everything in it is invented. It is shaped like the real collectors' output, so the
same checks, correlation rules and privilege-escalation analysis run over it.

```sh
graph scan demo                  # table of findings
graph scan demo -format json     # full records
```

Acme is one AWS account with a public web server, a private batch worker, two container
services, a database, a bucket of customer exports and one GitHub repository.

## The story it tells

- **An exposed server with a way up.** `acme-web-1` has a public IP, SSH open to the internet
  and IMDSv1 enabled. It runs as `acme-web`, which may pass `acme-ec2-admin` to EC2 and start
  instances: whoever controls the web server can launch an instance as an administrator.
- **The same library, two very different risks.** `ai-gateway` (internet-facing, deployed
  from `acme-corp/ai-gateway`, declared in `acme-corp/infra`) and `support-bot` (private) both
  run LiteLLM 1.83.0. That release is in the range OSV lists for CVE-2026-40217, a remote code
  execution that CISA lists as exploited, and the gateway's role can read the LLM provider keys.
  Only the gateway is reachable from the internet.
- **A record left behind.** `status.acme.example` is a CNAME to an S3 website bucket that no
  longer exists, so anyone who creates a bucket of that name serves content under Acme's name.
  The takeover check flags it as a candidate on the record's pattern. The worker's HTTP probe
  confirms a takeover only by fetching the record's own hostname and matching an unclaimed-service
  response such as S3's "NoSuchBucket". `acme.example` is a reserved name that does not resolve
  on the public internet, so in the demo the probe is inconclusive and the candidate stays at a low
  score (18, monitor band). On a real domain whose bucket is gone, the same probe would raise it.
- **Data behind the web tier.** An unencrypted database that only the web security group can
  reach, and a bucket of customer exports with no default encryption, no versioning and no
  access logging.

`internal/collect/demo/demo_test.go` pins each of these, so the demo cannot drift away from
what the rules compute.

## In the UI

Add the **demo** connector under Settings → Connectors and click **Sync now**. After the first
correlation sweep (about five minutes after the worker starts), the Graph page answers questions
about Acme, for example the three queries in the README. `graph demo seed` adds the monitored
domain `acme.example` and three look-alike domains to the Domain Monitor page. Their AI verdicts
are fixed sample text, written for the demo, not model output.

The vulnerability findings come from OSV and the CISA KEV feed, so the worker needs internet and
runs those jobs about 16 minutes after it starts. The numbers (how many advisories, which are
known-exploited) change as the feeds change.

Delete the connector to remove the Acme assets again.
