# ADR 016 — Cloud auth is OIDC / workload-identity federation, not stored secrets

**Status:** accepted · amended 2026-07-18 (static-credential migration path and stored connector secrets)

## Context

Collectors authenticate to AWS, GCP, and GitHub to read inventory. The first cut let
connectors carry long-lived secrets: a GCP service-account JSON key and an AWS static
access-key/secret fallback, both stored AES-GCM-encrypted in Postgres. Encryption at rest
mitigates the blast radius but does not remove it — a stored key is still a standing
credential that can leak, must be rotated, and widens what an attacker gains by reading the
connector store. For a security platform that itself runs on Kubernetes, where workload
identity federation is available, that is the wrong default.

## Decision

**Cloud authentication is OIDC (workload identity federation) by default. A connector carries
a *reference* to an identity, never the credential itself.**

- **GCP** — Application Default Credentials. On GKE the pod runs as a Kubernetes
  ServiceAccount bound to a GCP service account (Workload Identity); in local dev it is the
  developer's `gcloud` ADC. The connector stores only `project_id`; cross-project reads rely
  on the workload SA holding read IAM on that project.
- **AWS** — the SDK default chain provides the base identity: on Kubernetes the projected
  web-identity token (`AWS_WEB_IDENTITY_TOKEN_FILE`), in local dev the developer's assumed
  role. That identity then assumes the connector's `role_arn` (cross-account, optional
  `external_id`). The connector stores only the role reference.
- **GitHub — unchanged.** GitHub Apps already mint short-lived installation tokens from the
  App private key; GitHub is not an OIDC *relying party* for inbound auth (its OIDC is for
  Actions authenticating outward). So the App private key remains a stored credential, and
  the connector cipher exists for it.

The original decision also excluded any static-key path, on the grounds that a static-key
fallback tends to become the path of least resistance and re-introduce stored secrets. See
the amendment below.

## Consequences

- **AWS and GCP connectors default to secretless** — the federated path needs only
  `{role_arn, region}` and `{project_id}` respectively.
- **The trust setup lives in the deployment's IAM, not the binary** (`deploy/aws`,
  `deploy/terraform`, deploy/README.md "Cloud auth: OIDC"). The AWS IAM OIDC provider + role
  trust policy, the GKE Workload-Identity binding, and the projected-token audience are
  provisioned alongside the deployment. The binary assumes that identity exists; it cannot
  self-provision it.
- **Local dev uses a role.** A developer runs against a role they can assume
  (SSO/`gcloud auth`), so the local path exercises the same code as a deployed instance.
- The GCP **cloud** collector (`internal/collect/gcp`) is ADC-only.

## Amendment (2026-07-18) — static-key migration path and other stored secrets

The absolute "secretless / no static keys" position no longer holds; OIDC federation remains
the **default and preferred** path, but:

- **AWS static keys are supported as a migration path.** `internal/collect/aws/auth.go`
  builds `credentials.NewStaticCredentialsProvider` when a connector carries
  `aws_access_key_id`/`aws_secret_access_key`, and `internal/app/connector/domain.go`
  accepts `aws_access_key_id` as an alternative to `role_arn`. This eases migration from
  existing static-key inventory tooling. Keys are stored AES-GCM-encrypted in the connector
  store.
- **Other connectors store secrets.** Identity connectors added later (outside the original
  AWS/GCP/GitHub scope) store `service_account_json` (Google Workspace SA, domain-wide
  delegation), `api_token` (Okta SSWS), and `client_secret` (Azure SP), so the GitHub App key
  is no longer the only secret at rest.

Read "secretless connectors" above as the default for federated cloud connectors, not a
property of the connector store as a whole.
