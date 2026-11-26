# Security Policy

Vulngraph is security software that, like any software, can have security
bugs of its own. We treat reports about this repo the same way we'd want a
report about a finding it surfaced treated: fast, and without demanding a
public disclosure first.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report it privately through GitHub Security Advisories:
[open a private vulnerability report](https://github.com/vulngraph/vulngraph/security/advisories/new) for this
repository (Security tab → "Report a vulnerability"). This reaches the
maintainers privately and lets us work on a fix with you before disclosure.

Include:
- What you found and why it's a vulnerability (not just "this looks odd").
- Steps to reproduce, or a PoC if you have one.
- Impact as you understand it (what an attacker could actually do).
- Affected version/commit.

## Supported versions

Vulngraph is pre-1.0. Security fixes land on `main` and ship in the next
release; only the latest release is supported.

| Version | Supported |
| ------- | --------- |
| `main`  | Yes       |
| latest release (`CHANGELOG.md`) | Yes |
| older releases | No |

## What to expect

- Acknowledgement within 14 days, usually within a few days. This is a
  best-effort open-source project, not a staffed security team with an SLA, so
  the 14 days is a target, not a guarantee.
- We'll work with you on a fix and a coordinated disclosure timeline. Credit
  in the release notes if you want it; anonymous if you don't.

## Scope

In scope: the application (`cmd/`, `internal/`, `frontend/`), the Helm chart,
the Dockerfile/build pipeline, and the LadybugDB cgo binding
(`internal/graphdb/ladybug`) to the extent the vulnerability is in *our* integration
of it rather than an upstream dependency (report those upstream too).

Out of scope: issues that need the `admin` role and only let an admin do what
the role already allows by design (for example, creating a second admin
account; see "Limits of the two-person rule" in
[`docs/security-hardening.md`](docs/security-hardening.md#connectors-and-remediation)), and
findings in third-party dependencies with no Vulngraph-specific exploitation path
(report those to the upstream project).

In scope even with admin: any way for one admin account, or an API key or MCP
client holding admin, to run a state-changing action without the second,
different admin's grant where one is required, to run one with no person
approving it ([ADR 087](docs/adr/087-no-autonomous-remediation.md)), or to get
past the approver account-age floor, the API-key and MCP grant restrictions, or
the audit intent row.

## A note on what this platform touches

Vulngraph collects cloud/IAM/CI inventory and, when its executor is configured,
can mutate cloud resources under a scoped execution role
(`execute_role_arn`/`execute_service_account`/etc. — see
[`deploy/README.md`](deploy/README.md)). A vulnerability that lets an
unauthorized actor read connector credentials, forge an authenticated request,
or reach the executor without going through governance is high-severity by
construction — treat it as such when reporting, and we will too.
