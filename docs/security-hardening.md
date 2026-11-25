# Security hardening

Every flag in the [table below](#dangerous-flags) weakens authentication,
transport or scan-target checks, and each is off by default. Several deployment
defaults are not hardened and are yours to change:

- The Helm chart's NetworkPolicy is on, but serve's API port accepts every
  source until you name the ingress controller's namespace
  (`networkPolicy.ingressNamespace`), and egress is open
  ([Network policy](#network-policy)).
- The chart's bundled Postgres and ClickHouse are plaintext on the pod network
  until you give them certificates, and Docker Compose connects in plaintext on
  its own network ([Network policy](#network-policy)).
- The app's datastore users (serve and the worker) are not admins but can
  write every row the app writes, users and API keys included; the scanner's
  own users cannot ([Datastore users](#datastore-users)).
- Admin TOTP is optional unless `REQUIRE_ADMIN_TOTP=true` ([Admin MFA](#admin-mfa)).
- Everything is sealed under one key ([Encryption key](#encryption-key)).
- The audit trail is not tamper-proof ([Audit trail](#audit-trail)).
- Several outbound connections to third parties are on: package names and
  versions to OSV, the threat-intel feeds, and the download of the pinned
  nuclei-templates release ([Network egress](configuration.md#network-egress)).
  nuclei's out-of-band (interactsh) callbacks are off unless
  `NUCLEI_INTERACTSH_ENABLED=true`.
- Offboarding a person at the IdP does not end their Vulngraph API keys, or
  their sessions in direct Google or Okta mode ([Offboarding](#offboarding)).
- An admin cannot list or revoke another user's API key, only disable or
  delete the user who owns it ([A leaked API key](#a-leaked-api-key)).

This page covers the switches and those choices. For a Helm install,
[`deploy/helm-values/hardened.yaml`](../deploy/helm-values/hardened.yaml) turns
on the chart's hardening values and sets `hardened: true`. The chart then
refuses to render while its NetworkPolicy leaves serve's port open to every
source, a datastore connection is plaintext, admin TOTP is off, or any flag in
the table below is set, as a chart value or an `extraEnv` entry. So that
nothing in a pod spec undoes those checks, it also refuses an `extraEnv` entry
that replaces a variable the chart sets, and any `extraEnvFrom` list. The
other defaults above (open egress,
the datastore users' grants, one sealing key, the audit trail, outbound OSV
and feed traffic, offboarding and API-key revocation) are outside what a chart
can check. The [production checklist](production-checklist.md) is the ordered
list of steps, each with a command to verify it.

## Dangerous flags

Each of these is off unless set to the exact value shown. None belongs on an
internet-reachable deployment unless the "safe only when" column holds.

| Variable | Effect | Safe only when |
|---|---|---|
| `BYPASS_AUTH=true` + `BYPASS_AUTH_I_UNDERSTAND=yes` | Every request runs as one synthetic admin (`admin@internal`, user id `00000000-0000-0000-0000-000000000000`). No session check. Everyone the gate lets through is that admin, so audit attribution collapses: every audit row names `admin@internal`, never the person. Cloud changes are refused (403) because no person is identified: executor runs over REST, Approve & run and stalled-run release. MCP `execute_action` is refused too: a call with an `approval_token` gets the same refusal, and one without fails asking for a second-admin grant, which cannot be minted under this flag. Second-admin grants cannot be minted either (the synthetic admin has no account age). Every other admin write (connectors and their mode, suppressions, policy, alert channels) still runs, unattributed. `serve` refuses to start when `BYPASS_AUTH=true` is set without `BYPASS_AUTH_I_UNDERSTAND=yes`, and logs a `SECURITY:` warning at startup. | A network-level auth gate (ZTNA, oauth2-proxy) fronts every path to the pod, or it is local dev on loopback. |
| `LADYBUG_RPC_INSECURE=true` | The worker serves its internal graph RPC without `LADYBUG_RPC_SECRET`, so any pod that can reach it can query the graph. Without this flag and without the secret, only the RPC listener refuses to start: the worker keeps running its jobs, logs `ladybug: internal RPC server exited`, and fails its readiness probe, since nothing serves `/internal/graph/ready`. | Local dev only. |
| `SCAN_ALLOW_INTERNAL_TARGETS=true` | The scanners may connect to private and loopback addresses (10/8, 172.16/12, 192.168/16, 127/8, fc00::/7, and similar). Link-local space and the cloud metadata endpoints (169.254.169.254, fd00:ec2::254, 100.100.100.200, metadata.google.internal) stay blocked. | You deliberately scan internal ranges and accept that a template-test user (admin) can reach in-cluster services. |
| `COOKIE_INSECURE=true` | Drops the `Secure` attribute from the session and OAuth state cookies. | Plain-http local dev (Safari rejects `Secure` cookies on `http://localhost`). Never behind a real hostname. |
| `OAUTH2_PROXY_ALLOW_ANY_DOMAIN=true` | With `OAUTH2_PROXY=true`, accept any email the verified proxy sends. Without this flag and without `OAUTH2_PROXY_ALLOWED_DOMAINS`, the header path is denied. | The proxy's own allowlist is the only gate you want. |
| `OAUTH2_PROXY_TRUST_GROUPS=true` | In shared-secret-only oauth2-proxy mode, map `X-Auth-Request-Groups` to roles (`OIDC_*_GROUPS`). | nginx lists `X-Auth-Request-Groups` in `auth-response-headers`, so a client-sent copy is overwritten. |
| `OAUTH2_PROXY_OIDC_ALLOW_UNVERIFIED_EMAIL=true` | Accept oauth2-proxy ID tokens with no `email_verified` claim. The first token sign-in binds an existing account by email. | The IdP never lets users choose or change their email address. |
| `PASSWORD_LOGIN_BREAK_GLASS=true` | Keeps password login enabled when IAP or oauth2-proxy fronts the app, so a local password bypasses the proxy's MFA and offboarding. Without it password login returns 404 in those modes. `serve` logs a `SECURITY:` warning. | It is an emergency path for a few admin accounts with strong passwords and TOTP. |
| `APPROVAL_WEBHOOK_ALLOW_UNSIGNED=true` | serve sends `APPROVAL_WEBHOOK_URL` posts ("a human approved this decision") without an HMAC signature when `APPROVAL_WEBHOOK_SECRET` is unset, and logs a `SECURITY:` warning. Without this flag that combination fails startup. A receiver that acts on approvals cannot tell an unsigned post from a forgery. | The receiver authenticates Vulngraph some other way (mTLS, a private network path). |
| `OAUTH_REDIRECT_FROM_HOST=true` | An unset `GOOGLE_REDIRECT_URL` / `OKTA_REDIRECT_URL` is built from the request's `Host` and `X-Forwarded-Proto` instead of failing startup, so whoever controls those headers chooses the OAuth callback host. `serve` logs a `SECURITY:` warning. | Local dev only. |
| `DECISION_WEBHOOK_ALLOW_UNSIGNED=true` | The worker sends `DECISION_WEBHOOK_URL` posts without an HMAC signature when `DECISION_WEBHOOK_SECRET` is unset. Without this flag it skips the webhook and logs a `SECURITY:` error. | The receiver authenticates Vulngraph some other way (mTLS, a private network path). |
| `SMTP_ALLOW_PLAINTEXT=true` | The worker sends approval emails without TLS when the SMTP server offers no STARTTLS. Without it the send is refused (port `465` uses implicit TLS, any other port requires STARTTLS). The worker logs a `SECURITY:` warning. | The SMTP relay is on the same host or reached over a trusted private link. |
| `GOOGLE_ALLOW_ANY_DOMAIN=true` / `OKTA_ALLOW_ANY_DOMAIN=true` / `IAP_ALLOW_ANY_DOMAIN=true` | With the provider configured and no `*_ALLOWED_DOMAINS`, accept any account from that IdP (first sign-in provisioned as viewer unless named in `ADMIN_EMAILS` or a mapped group, and never as the bootstrap admin). Without this flag and without an allowlist, every sign-in through that provider is refused and `serve` logs a `SECURITY:` error at startup. | The IdP itself restricts who can obtain a token for your client (e.g. an Okta org with assignment required). |

### SSO roles

A domain allowlist decides who may sign in, not who is an admin. A first-time
Google, Okta, IAP or oauth2-proxy sign-in is provisioned as **viewer** unless:

- its email is in `ADMIN_EMAILS` (admin);
- it carries a group in `OIDC_ADMIN_GROUPS` (admin) or `OIDC_ANALYST_GROUPS`
  (analyst). Groups come from the Okta `groups` claim (Vulngraph requests the
  `groups` scope when a group mapping is set), the `groups` claim of a
  verified oauth2-proxy ID token, or — only with `OAUTH2_PROXY_TRUST_GROUPS=true`
  — the `X-Auth-Request-Groups` header. Google and IAP send no groups;
- **bootstrap:** no role mapping is configured (`ADMIN_EMAILS`,
  `OIDC_ADMIN_GROUPS` and `OIDC_ANALYST_GROUPS` all empty), the users table is
  empty, and the sign-in matched a named domain allowlist. Then the very first
  sign-in becomes admin, so a fresh install is administrable. The check and the
  insert run under one Postgres advisory lock, so two simultaneous first
  sign-ins cannot both win. An `*_ALLOW_ANY_DOMAIN` sign-in never qualifies: it
  could be a stranger racing you to be first. Once you configure a mapping you
  have said who administers, so a non-member never bootstraps. Set
  `ADMIN_EMAILS` on any install that is reachable before you sign in.

Existing users keep their role on every sign-in; promote or demote them in
Settings → Users.

**Who may sign in at all.** The domain allowlist is the gate, plus:

- **Google: the hosted domain.** With `GOOGLE_ALLOWED_DOMAINS` set, the
  account's `hd` claim (the Google Workspace that manages it) must be in the
  list as well as its email's domain. A consumer Google account registered on
  a company address has no `hd` and is refused, as is one an offboarded person
  kept on their old address. List every Workspace domain your users' emails
  and `hd` claims may carry.
- **`OIDC_REQUIRED_GROUPS`** (Helm `config.oidcRequiredGroups`): when set,
  every SSO sign-in that starts a session, new or existing user, must carry
  one of these groups (from the same sources as `OIDC_ADMIN_GROUPS`), or it is
  refused with 403. Google and IAP send no groups, and shared-secret
  oauth2-proxy sends none without `OAUTH2_PROXY_TRUST_GROUPS=true`, so with it
  set they admit nobody. It is checked when a session starts: someone removed
  from the group keeps a session they already hold until it expires (7 days)
  or `POST /api/users/{id}/revoke-sessions` ends it. Password login is not
  gated, and it changes no role. You can also restrict who may obtain a token
  at the IdP (Okta "assignment required", a Workspace OU behind IAP).

### Offboarding

Removing someone at the IdP does not reach Vulngraph. There is no SCIM or
deprovisioning sync, so:

- A role from `ADMIN_EMAILS` or IdP groups is applied only at the first sign-in.
  Removing a person from `OIDC_ADMIN_GROUPS` never demotes them.
- A session lasts 7 days from sign-in, with no idle timeout. In direct Google or
  Okta mode it survives the IdP account being disabled. Behind IAP or
  oauth2-proxy, the proxy stops their requests once its own session ends.
- An API key lives until its own expiry, at most `API_KEY_MAX_LIFETIME_DAYS`
  (default 90) after it was created. It is not tied to the IdP account.

What ends access is disabling the user in Vulngraph: Settings → Users, or
`PATCH /api/users/{id}` with `{"disabled": true}` from an admin's signed-in
session (an API key is refused, and an admin cannot disable themselves or the
last active admin). That deletes their sessions in the same transaction
(`auth.user_disable` records how many). Their API keys are not deleted: they
stay in the database and every request with one is refused while the user is
disabled, because key lookup skips disabled owners. Re-enabling the user
(`{"disabled": false}`) brings back every key that has not expired.
`DELETE /api/users/{id}` removes the user with their sessions and API keys;
prefer disabling, because audit rows refer to users by id. Add the disable step
to your offboarding runbook (or script it from IdP events), and lower
`API_KEY_MAX_LIFETIME_DAYS` to shorten the window a forgotten key stays usable.

### A leaked API key

API keys are managed by their owner only. `GET /api/keys` lists the caller's
own keys and `DELETE /api/keys/{id}` revokes only a key the caller owns (an
`apikey.revoke` row); neither has an admin variant, so an admin can neither
see nor revoke another user's key through the API or UI. Settings → API Keys
is the same per-user view. To respond to a leaked key:

1. If the owner is available, they revoke it from a signed-in session
   (Settings → API Keys, or `DELETE /api/keys/{id}`). A key cannot revoke a
   key.
2. If not, an operator with the database and `GRAPH_SECRET_KEY` can act as
   the owner: `graph user token --email <owner>` (enabled owners only) mints
   a session, sent as `Authorization: Bearer <token>`, that can list the
   owner's keys with `GET /api/keys` and revoke just the leaked one with
   `DELETE /api/keys/{id}`. The revoke is an `apikey.revoke` row with the
   owner as actor, next to the `auth.token_issue` row for the token. Then a
   different admin, from their own signed-in session, ends the token with
   `POST /api/users/{id}/revoke-sessions`, which ends all the owner's
   sessions; nobody can call it on themselves, and the token cannot end
   itself (see [`graph user token`](#graph-user-token)).
3. Otherwise an admin disables the owner (above). That stops the leaked key and
   all the owner's other keys and sessions at once, but does not remove the
   key. Re-enabling revives it with the rest, and it works from that moment
   until the owner revokes it, so re-enable only when the owner can revoke it
   straight away. Deleting the user instead removes every key they hold.
4. Review what the key did: audit rows carry `api_key_id` for requests that
   authenticated with an API key ([Audit trail](#audit-trail)).

### oauth2-proxy

With `OAUTH2_PROXY=true`, Vulngraph signs in users that an oauth2-proxy in front of
the ingress (nginx `auth-url`) authenticated. `X-Auth-Request-Email` by itself
is just text that anything reaching the pod can set; before these checks,
naming an existing admin's address was enough to get an admin session. `serve`
refuses to start with `OAUTH2_PROXY=true` and neither check below configured,
and a request that fails them gets 401 and a `SECURITY:` log line.

**Network isolation is the control.** Nothing but the ingress controller
should be able to reach `serve`. The Helm chart refuses to render
`config.oauth2Proxy` without `networkPolicy.ingressNamespace`, which limits
serve's port to the ingress controller and the node CIDRs. Without Helm
(compose, a published port), keep `ADDR` off every network except the proxy's.

**Preferred: verify the ID token** (`OAUTH2_PROXY_OIDC_ISSUER`,
`OAUTH2_PROXY_OIDC_AUDIENCE`; Helm `config.oauth2ProxyOidcIssuer` /
`oauth2ProxyOidcAudience`). Run oauth2-proxy with `--set-authorization-header`
(it adds `Authorization: Bearer <id_token>` to the `/oauth2/auth` response) and
list `Authorization` in `nginx.ingress.kubernetes.io/auth-response-headers`.
Vulngraph verifies the token's signature against the issuer's published keys
(discovery → `jwks_uri`, fetched over https; plain http is accepted only for a
loopback issuer), the issuer (compared exactly as configured, trailing slash
included), the audience (oauth2-proxy's client id), `azp` when present or when
there are several audiences, and expiry, with 30 seconds of clock-skew leeway.
Email, `sub` and `groups` then come **only** from the token;
`X-Auth-Request-Email` and `X-Auth-Request-Groups` are ignored, and the account
is bound to (issuer, `sub`) like a Google or Okta sign-in. A caller can at most
present its own token, so this holds even if something reaches the pod around
the proxy.

- **`email_verified` must be `true`.** The first token sign-in of an account
  that is not yet bound (every account created before this mode, e.g. through
  the shared-secret path) matches it by the token's email, so an IdP that lets
  users choose an unverified address (Azure AD's "nOAuth") would hand over that
  account, admins included. For an IdP that never sends the claim,
  `OAUTH2_PROXY_OIDC_ALLOW_UNVERIFIED_EMAIL=true` accepts a token **without**
  it (an explicit `false` is always refused); use it only if the IdP does not
  let users set their email. Every such first binding of an existing account is
  logged as `SECURITY: existing account bound to an SSO identity by email`,
  with the account's id, email and role: review those lines after enabling the
  mode.
- **Use a dedicated oauth2-proxy instance and OAuth client id for Vulngraph.** The
  audience check only proves the token was issued to that client id. If other
  applications share it, an ID token one of them received (and may log or
  forward) is accepted by Vulngraph too.
- **Sessions.** The token is needed only to start a Vulngraph session. On later
  requests that carry both a session cookie and a token, Vulngraph keeps the
  session when the token is the session's bound identity, keeps it when the
  token fails to verify (for instance it expired before oauth2-proxy refreshed
  it), and ends it and signs in from the token when the token is a different
  person's (someone else signed in to the proxy in the same browser). A session
  that no longer authenticates falls back to the token. Set oauth2-proxy's
  `--cookie-refresh` below the ID token lifetime so a new sign-in never
  receives an expired token.
- **CSRF.** Because the proxy adds the token to every request it forwards,
  including one a cross-site page forged in a signed-in browser, Vulngraph never
  treats a JWT-shaped `Authorization` header as proof the request came from a
  script: cross-origin and `application/json` checks still apply to it. Run
  oauth2-proxy with `--cookie-samesite=strict` as well, so the browser does not
  attach the proxy's own cookie to a cross-site request in the first place.

**Shared secret: defence in depth** (`OAUTH2_PROXY_SHARED_SECRET`, at least 32
characters, compared in constant time; Helm `secret.oauth2ProxySharedSecret`).
When set, every proxy request must carry it in `X-Graph-Proxy-Secret`. It is
one bearer credential for every identity: anyone who reads it and can reach
`serve` can sign in as anyone, so on its own it is only as strong as the
network isolation. In particular, do **not** inject it with oauth2-proxy
`injectResponseHeaders` on a publicly routed oauth2-proxy: `/oauth2/auth`
returns the injected headers to any signed-in user who calls it. If you use the
secret:

- point `auth-url` at the in-cluster oauth2-proxy Service
  (`http://oauth2-proxy.<ns>.svc.cluster.local/oauth2/auth`) and route only
  `/oauth2/start`, `/oauth2/callback` and `/oauth2/sign_in` publicly, never
  `/oauth2/auth`; or
- have the ingress add it to the upstream request
  (`proxy_set_header X-Graph-Proxy-Secret ...`) instead of the auth response.

In shared-secret-only mode, `X-Auth-Request-Groups` is ignored unless
`OAUTH2_PROXY_TRUST_GROUPS=true`. ingress-nginx overwrites only the headers
listed in `auth-response-headers`, so an unlisted groups header is whatever the
client sent; with `OIDC_ADMIN_GROUPS` set that would let any proxied user grant
itself admin. Set the flag only when `X-Auth-Request-Groups` is in that list.

### IAP

The IAP assertion is checked for signature (Google's IAP key set), audience
(`IAP_AUDIENCE`), expiry, and issuer `https://cloud.google.com/iap`. The account
is bound to the assertion's (issuer, `sub`) on its first IAP sign-in, as Google
and Okta sign-ins bind theirs: a later assertion with the same email and a
different subject (a recycled address, another Google identity) is refused with
403. An account bound to a Google or Okta identity cannot sign in through IAP.

### Client address

`CLIENT_IP_HEADER` (e.g. `X-Forwarded-For`) is honoured only when the TCP peer
is in `TRUSTED_PROXY_CIDRS`; with no trusted ranges the header is ignored and
the peer address is used. Otherwise a caller that reached `serve` without going
through the proxy could choose the address that keys its own login rate limit
and the executor's `approver_same_ip` flag. Set `TRUSTED_PROXY_CIDRS` to your
ingress controller's addresses (pod or node range).

Vulngraph uses the header's **rightmost** entry, the one the nearest proxy
appended, and strips only that one hop. Behind more than one proxy (CDN → load
balancer → ingress) the rightmost entry is the hop in front of the ingress,
not the client. Have the outermost proxy you trust set the client address and
the inner ones pass it on unchanged (for ingress-nginx: `use-forwarded-headers`
with `proxy-real-ip-cidr` set to the outer proxy's range and
`compute-full-forwarded-for` off, so the header it forwards is the resolved
client address).

### API keys

A key is `gph_` followed by 64 hex characters (32 random bytes) and is shown
once, at creation. The `api_keys` row holds the hex SHA-256 of the full key
(`key_hash`), its first 16 characters (`lookup_id`, the indexed column a
presented key is found by) and its first 8 (`prefix`, the UI label). The
plaintext is never stored. A presented key is looked up by `lookup_id`, its
SHA-256 is compared with `key_hash` in constant time
(`subtle.ConstantTimeCompare`), and it is refused past its expiry (capped at
`API_KEY_MAX_LIFETIME_DAYS`) or while its owner is disabled. The digest is unkeyed and unsalted, the same as session
tokens: 256 random bits cannot be brute-forced from a digest, so a password
hash such as bcrypt would cost every request CPU and add nothing.
`last_used_at` is rewritten only when it is a minute or more old, so it is
accurate to a minute.

An API key acts as its owner with the key's scope (capped at the owner's
current role). The `inventory` scope is narrower than `read`: only an admin can
create one, it is refused on every route but the two package-inventory routes and
the one MCP tool, and it stops working if its owner is no longer an admin
([bring your own agent](iam/byoa-inventory.md)). An admin key may be held by an agent, so these routes take a
signed-in session and answer 403 to a key, whatever its scope, before the
request body is read; each refusal is an `auth.api_key_refused` row naming the
key and the route:

- `POST /api/keys` and `DELETE /api/keys/{id}`. Otherwise a leaked read-only
  key could mint fresh keys that survive its revocation, or revoke its owner's
  admin keys.
- `POST /api/users`, `PATCH`/`DELETE /api/users/{id}` and
  `POST /api/users/{id}/revoke-sessions`, so a leaked admin key cannot create
  or promote an account that keeps access after the key is revoked.
- `PUT /api/connectors/{id}/mode`, `POST /api/connectors/{id}/purge` and
  `DELETE /api/connectors/{id}`: a key cannot make a connector `read_write`,
  or destroy a connector's assets, findings and edges.
- `PUT /api/connectors/{id}/disk-scan`: a key cannot opt a connector into reading, or creating
  snapshots of, VM disks.
- `PUT /api/policy`: a key cannot loosen the approval policy.
- `POST /api/queue/resolve` (below).

Suppressions and manual resolves on a key get the rules MCP
`suppress_finding` applies (one shared check): `POST /api/findings/{id}/suppress`,
`POST /api/suppressions/bulk`, `POST /api/findings/{id}/suppress/review` and
`POST /api/findings/{id}/resolve` refuse, with 403, a finding that is critical,
must-fix, in the page or high band, or not yet scored; a finding that does not
exist is a 404 and one that cannot be read fails the request, so nothing is
written unchecked. A key's suppression or renewal may expire at most 30 days
out (400 beyond). A bulk request is refused whole if any finding fails.
Refusals are audited (`suppress.refused`, `finding.resolve_refused`). From a
session the same routes keep their normal limits (any finding, up to 365
days).

Other admin writes stay open to an admin key, audited where the
[audit trail](#what-is-recorded) says so: connector create, sync and
connection test; alert channels (including repointing a webhook channel);
saved queries; scans, scan profiles and templates; intel domains and phishing
triage; unsuppressing; decision refinement. Give agents read-scoped keys
unless they need one of these.

Queue verdicts (`POST /api/queue/resolve`) take a session too: an API key
gets 403 before the request body is read, so a key an agent holds cannot
approve or deny. A verdict comes from a signed-in admin or from a confirmed
email link, and the links cannot approve isolate or destroy or deny an urgent
finding. Vulngraph runs nothing on a verdict (its executor never reads one;
a fix still goes through the executor's grant rules below), but a verdict is
not inert. A denial records a negative memory outcome, which lowers
confidence for that action class on that asset type,
and a pattern verdict for its check, action class and resource type. Once
every action class for a check and resource type is denied, later non-urgent
findings of that pattern are suppressed for up to 90 days (urgent ones still
go to a person, with the denial noted). An approval records an approved pattern
verdict, which the reasoner sees as a note on later findings of that pattern,
and fires the approval notifiers: the signed approval webhook (see
[Approval webhook](#approval-webhook)) and an approval alert to the alert
channels that route approvals.

### Email approval links

With `SMTP_HOST` set on the worker, each decision parked for approval is
emailed to `SMTP_TO` with an approve link and a deny link. Each link is a
bearer credential: whoever holds the URL can use it without signing in, and
the verdict is recorded with the actor `email-link:<SMTP_TO>`, not the person
who clicked.

- **48 hours.** A link expires 48 hours after the email is built.
- **Single use.** The approve and deny links of one email share a nonce,
  spent in Postgres on the first confirmed use, so once either link is used
  both are refused on every replica.
- **Bound to the decision set.** The token signs the exact finding ids, the
  context fingerprint each was decided under, the action class and the
  verdict. A link whose decisions are no longer pending, or whose context
  changed, is refused; it cannot act on any other finding.
- **Limited.** An approve link is only sent for the `observe`, `remediate` and
  `modify` classes, never `isolate` or `destroy`. A deny link is refused for a
  finding that is `must_fix`, in the page or high band, not yet scored, or
  cannot be read.
- **What a confirmed link does.** Exactly what the same verdict from the queue
  does, with the actor `email-link:<SMTP_TO>`: it records the verdict on the
  signed decisions (they leave the queue) and a `governor_verdict` row per
  finding. An approval also records an approved pattern verdict (a note the
  reasoner sees on later findings of the pattern) and fires the approval
  webhook and approval alerts; a denial records the negative memory outcome
  and pattern verdict described under API keys. Vulngraph runs no fix on it:
  the executor never reads a verdict, and a fix runs only through the
  executor, from a signed-in session or on an API key holding a grant a
  different admin minted from one. A receiver of the approval webhook that
  acts on approvals is not bound by that (see
  [Approval webhook](#approval-webhook)).
- **GET never acts.** Opening a link (GET or HEAD, any number of times) only
  renders a confirmation page whose button POSTs the same URL. Only that POST
  records the verdict and spends the link, so a mail gateway or link scanner
  that fetches the URL records nothing.

Caveats. A mail-security product that opens links in a headless browser and
submits the forms it finds would confirm the verdict as if the recipient had.
An approval fires the approval webhook; a denial can suppress later non-urgent
findings of the same pattern for up to 90 days (see API keys). Forwarding the
email forwards the credential. Send approval mail to a mailbox whose gateway
does not submit forms, or exempt `APPROVAL_BASE_URL` from link detonation.
URL rewriting alone is harmless: the token travels in the path and still needs
the POST.

To turn the links off, leave `SMTP_HOST` unset on the worker (no approval
email is sent) and `APPROVAL_TOKEN_SECRET` unset on serve (the link routes
answer 503, so links already sent stop working). Changing
`APPROVAL_TOKEN_SECRET` invalidates every link already sent.

### Approval webhook

`APPROVAL_WEBHOOK_URL` receives a signed POST (`event_type`
`decision_approved`) for every approved queue cluster, of any action class,
`isolate` and `destroy` included. The payload carries `action_class`,
`approved_by` (an admin's email, or `email-link:<SMTP_TO>` for a link
approval of `observe`, `remediate` or `modify`), the finding ids and the risk
context. It is one approval: none of the executor's controls apply to it. No
second admin is asked for any class, there is no grant, grant expiry,
approver account-age floor or `approver_same_ip` flag, and no intent row is
written before anything acts. If the receiver only opens a ticket, that is
fine. If it changes infrastructure, it is an executor outside Vulngraph and
outside [ADR 087](adr/087-no-autonomous-remediation.md)'s guarantees, and it
must apply its own rules: at least, require a second person for
`isolate` and `destroy`, and treat an `email-link:` approver as a mailbox,
not a person. To keep every mutation inside Vulngraph's rules, leave
`APPROVAL_WEBHOOK_URL` unset, or point it at a ticketing system only, and
run fixes through the executor.

### `graph user token`

`graph user token --email <user>` prints a session token for that user with
no password or TOTP step. It is a full session, valid for 7 days, not an API
key: Vulngraph cannot tell it from the user signing in, so it counts as a
person for the executor's rules. It runs non-destructive actions with no
grant, mints two-person grants, and manages users and keys, all of which an
API key is refused. Minting one needs the database and `GRAPH_SECRET_KEY`, the
same trust as `graph user create`. Use it for bootstrap, hand it only to
tooling you would let act as that person, and give agents and standing CI
jobs an API key instead. To end it, a different admin calls
`POST /api/users/{id}/revoke-sessions` from their own signed-in session
(nobody can call it on themselves).
Every token minted is an `auth.token_issue` row in `audit_events` (actor
`cli`), so the command needs ClickHouse as well as Postgres.

### Admin MFA

Vulngraph's only local second factor is TOTP, enrolled with
`graph user totp --email <user>`. Running it again replaces the seed: that is
the TOTP reset (each run is an `auth.totp_enroll` row, `replaced: true` for a
reset). TOTP is checked only on password sign-in (`POST /api/auth/login`).
Google, Okta, IAP and oauth2-proxy sign-ins never ask for it, and Vulngraph
does not read the IdP's `amr`/`acr` claims, so for them MFA is whatever the
IdP enforces. There is no password-reset path: an admin who forgot a password
is given a new account or signs in through SSO.

By default TOTP is optional. `REQUIRE_ADMIN_TOTP=true` on serve (`true` or
`false`, case-insensitive; any other value stops serve at startup; Helm:
`config.requireAdminTotp: true`, Docker Compose: `app.env`) makes it mandatory for
admins on the password path:

- an admin with no TOTP enrolled is refused password sign-in with the same 401
  as a wrong password, and serve logs a `SECURITY:` warning with the user id.
  Enroll with `graph user totp` first;
- promoting a user to admin ends that user's sessions (recorded as
  `sessions_revoked` on the `auth.user_role_change` row), so the new admin
  signs in again under the rule.

Executor approvals, grants and Approve & run need an admin session, so with
the switch on, every admin session opened by password carried a TOTP code. The
switch does not reach:

- sessions opened before it was turned on: end them with
  `POST /api/users/{id}/revoke-sessions`, or they last their 7 days;
- `graph user token`, which mints a session with no password or TOTP step
  (it needs the database and `GRAPH_SECRET_KEY`);
- SSO sessions, whose second factor is the IdP's;
- API keys, which carry no second factor. They cannot mint grants, resolve
  the queue, manage users and keys, change a connector's mode, purge or
  delete a connector, or change the approval policy (see API keys).

To enforce MFA for every admin, enforce it where people sign in:

- **oauth2-proxy or IAP in front.** Require MFA in the IdP behind the proxy
  (for example an Okta authentication policy on the oauth2-proxy app that
  demands a possession factor, or Google Workspace 2-Step Verification
  enforcement for the users IAP admits). Password login then answers 404
  unless `PASSWORD_LOGIN_BREAK_GLASS=true`. If you keep break-glass, also set
  `REQUIRE_ADMIN_TOTP=true` so admins need TOTP. It does not cover analysts or
  viewers: any of them with a password you know signs in with no second
  factor.
- **Google or Okta sign-in without a proxy.** Require MFA for the Vulngraph
  app in the IdP. Password login stays available next to SSO, so either set
  `REQUIRE_ADMIN_TOTP=true` or create no admin with a password you know:
  accounts SSO provisions have a random password nobody holds.
- **Password only.** Set `REQUIRE_ADMIN_TOTP=true`.

Local admin TOTP stays optional when you enforce MFA at the IdP and keep
password login closed.

### Scan target policy

By default (no `SCAN_ALLOW_INTERNAL_TARGETS`):

- **Template "test against URL"** (`POST /api/scans/templates/test`, admin
  only) returns 400 if the target resolves to an internal address. The nuclei
  engine also refuses internal addresses when it dials, so a template that
  hard-codes `169.254.169.254`, or a DNS name that changes after the check,
  is still blocked. Local file access from templates is always disabled.
- **Scheduled and profile scans** target owned inventory (asset domains and
  public IPs). Each target is resolved before the scan and dropped (with a
  warning) if it points at an internal or metadata address, and the same
  dial-time policy applies during the scan, so an owned DNS record that
  points inward is not probed.

With `SCAN_ALLOW_INTERNAL_TARGETS=true`, scheduled scans against internal
assets and template tests against internal URLs both work. Link-local space
and the cloud metadata endpoints stay blocked even then. Set it on the
process that runs the scan: the worker for scheduled scans, `serve` for
template tests.

## Put a TLS-terminating proxy in front

`serve` speaks plain HTTP on `ADDR` (default `:8080`). Run it behind a reverse
proxy or ingress that terminates TLS, and do not publish `ADDR` directly.

- Cookies are `Secure` by default. They are never downgraded based on
  `X-Forwarded-Proto`, which a client can set when nothing overwrites it.
- `GOOGLE_REDIRECT_URL` / `OKTA_REDIRECT_URL` are required with their client
  id: `serve` refuses to start without them. Only `OAUTH_REDIRECT_FROM_HOST=true`
  (local dev, logs a `SECURITY:` warning) builds an unset one from the
  request's `Host` and `X-Forwarded-Proto`, which a client controls. The Helm
  chart never sets it: `sso.google.redirectUrl` / `sso.okta.redirectUrl` are
  required with their `clientId` and must be absolute http(s) URLs with a
  host; the chart fails to render otherwise.
- The dev `docker-compose.yml` publishes Postgres and ClickHouse on
  `127.0.0.1` only. Its `graph`/`graph` credentials are for local use; never
  reuse them.

## Connectors and remediation

- Connectors start `read_only`. The executor rejects every action on a
  `read_only` connector before it makes any cloud API call. Upgrade a
  connector to `read_write` only when it needs to remediate, and give its
  IAM role only the write permissions those actions need.
- Remediation requires approval. Every action needs an admin's explicit
  request. Destructive executor actions also need an approval grant from a
  second admin (two-person control), whether they come from the UI,
  `POST /api/executor/*` or the MCP `execute_action` tool. An action is
  destructive when it destroys state that nothing in the request or its audit
  row can restore, or when it undoes a containment. That is `ec2_stop` (the
  instance's memory, instance-store data and auto-assigned public IP are lost),
  `iam_key_disable` with `delete_key=true`, `gcp_firewall_remove` and
  `azure_nsg_rule_remove` (the key or rule is deleted and its definition is not
  in the request), and `ec2_start` (it can bring back a host that was stopped
  to contain it). The test is not whether an action can cause an outage.
  `sg_rule_remove` can cut a public load balancer's world ingress,
  `iam_key_disable` and `gcp_sa_key_disable` can break a job that uses the key,
  and `s3_block_public` can break a public website. Each of these is undone
  exactly from its request and audit row: the revoked rule is re-added from
  its five parameters (its free-text description is not kept), the key is set
  active again, and `s3_block_public` reads the bucket's earlier bucket-level
  block first and records it in the audit row, so the undo re-applies it (or
  deletes the block when there was none). If it cannot read the earlier block
  it changes nothing. These are the routine remediations, so one admin can
  run them. To bound that, keep the execution principal's IAM to the
  actions and resources you want remediated, and keep connectors `read_only`
  unless they need to remediate.
  Every execution is audited: an intent row is written before the cloud call
  (if it cannot be written the call is refused) and a result row after it.
  Rows carry the acting user's id (`actor_user_id`), not only a display name.
- Limits of the two-person rule. It compares user ids, so it stops one
  account approving its own change, but not one person holding two admin
  accounts. Mitigations: the approving account must have been an admin for at
  least `EXECUTOR_APPROVER_MIN_ACCOUNT_AGE` (default `24h`), counted from the
  later of its creation and the moment its role last became admin
  (`users.admin_since`), so neither a freshly created second account nor an old
  account that was just promoted can approve at once. An admin who existed
  before `admin_since` was recorded (migration `00006`) has no promotion time
  and counts from creation, so an upgrade locks no one out; the next promotion
  or re-creation records one. One person who creates or promotes a second
  admin account and waits out the floor still defeats the rule; and when approver and
  executor reach Vulngraph from the same peer address the execution's audit rows
  carry `approver_same_ip: true`. The address is the TCP peer unless
  `CLIENT_IP_HEADER` and `TRUSTED_PROXY_CIDRS` are set (see Client address);
  behind a proxy without them every request shares the proxy's address and
  the flag means nothing. Which admin created or promoted an account is
  recorded (`auth.user_create`, `auth.user_role_change`), but the rule does not
  check "created by the executor". Review those rows, and keep the admin role
  to a few people.
- MCP executions always need a grant. An LLM client with an admin API key
  reads attacker-influenceable data (finding titles, resource names, live
  cloud responses — all returned fenced as untrusted), so `execute_action`
  refuses every real execution, destructive or not, without an
  `approval_token` minted by a different admin (`POST /api/executor/approvals`
  with `"agent": true`). `dry_run` needs no grant. A grant runs one
  execution: it expires after 10 minutes, and its first use is recorded in
  Postgres, so presenting it again is refused on every replica.
- REST executions on an API key get the same rule. An admin key may be held
  by an agent, so `/api/executor/*` and decision approve-and-run refuse every
  real execution on a key without a grant minted by a different admin from a
  signed-in session, and an API key can never mint a grant
  (`POST /api/executor/approvals` and `/api/decisions/{id}/execution/request`
  answer 403 to a key for any action, connector or decision state; a body
  that does not parse, or an approvals body with no `connector_id` or
  `action`, is a 400 first, and mints nothing either). A
  decision fix that needs no second admin is refused outright on a key (403):
  run it from a session. A key may only confirm another admin's live request.
  Each of these refusals is audited as `executor.refused`, with the key
  owner as the actor.
- MCP write tools (`suppress_finding`, `execute_action`) check for the admin
  role on the session. `suppress_finding` caps the expiry at 30 days, records
  the actor as `mcp:<user>`, and refuses critical, must-fix, page/high-band and
  not-yet-scored findings, whatever the MCP client authenticated with. The
  same check applies to REST suppress, bulk suppress, suppression review and
  finding resolve on an API key, and the 30-day cap to the suppressions (see
  API keys), so those findings are suppressed or resolved only from a
  signed-in session. `run_cypher` and `graph_query` are read-only:
  `graphquery.IsReadOnly` rejects CREATE/MERGE/SET/DELETE/REMOVE/LOAD/... in
  the MCP tool, in the explore service (for LLM-generated Cypher) and in
  graphstore (for both the RPC and in-process paths). Raw Cypher has no
  ClickHouse fallback; the ClickHouse BFS fallback only runs parameterised
  SELECTs. Caller Cypher runs on a two-connection pool that scheduled
  detections also use, so `POST /api/graph/cypher`, the query-health and DSPM
  routes and `run_cypher` share a per-user budget
  (`CYPHER_RATE_LIMIT_PER_USER`, default 30 a minute; 429 with `Retry-After`).
  There is no queue or per-user concurrency cap, so several users sending slow
  queries can still hold both connections for the engine timeout.

## Datastore users

No graph pod connects as a datastore admin, in the Helm chart and in
`deploy/docker-compose` alike. The bundled datastores come with these users
([the table](../deploy/README.md#datastore-users)):

- Postgres: `graph`, which migrate, serve and the worker connect as. It owns
  the `graph` database (migrate creates the schema and River's job tables as
  it, and River's reindexing needs the owner) but is not a superuser and holds
  none of the `pg_*_server_*` roles, so it cannot run commands on the database
  host (`COPY ... TO PROGRAM`), read server files, or create roles or
  databases. The superuser `postgres` exists for the image's bootstrap, and
  only the Postgres container gets its password.
- ClickHouse: `graph` for serve and the worker, with `SELECT` and `INSERT` on
  the `graph` database, `ALTER DELETE` on `assets` and `graph_edges`
  (connector purge) and `OPTIMIZE` on five tables; no DDL, no `DROP` or
  `TRUNCATE`, and nothing that rewrites `audit_events`. migrate runs as
  `graph_migrate`, with every right on the `graph` database and none outside
  it, and only the migrate container gets its password. The image's
  passwordless `default` admin is removed, so no user has access management.
- The scanner: `graph_scanner` on both. On Postgres it owns nothing, and
  migrate grants it River's job tables and the scan tables after every run
  (`internal/migrate/scanner.go`). Migrate fails while the role holds
  `CREATE` on a schema or the database, a membership in any role,
  `SUPERUSER`, `CREATEROLE` or `REPLICATION`, or a privilege on graph's tables
  through `PUBLIC` or a role. On ClickHouse it reads `assets`, `findings` and
  `finding_enrichment` and inserts `findings`. Neither touches users,
  sessions, API keys, connectors or `audit_events`.

What is left: on Postgres the app role owns its tables, so it can change any
row and, being the owner, the schema too; on ClickHouse it can insert any row.
Users and API keys are rows, so serve's and the worker's credentials are still
Vulngraph admin ([Credential isolation](#credential-isolation)). The scanner's
users can read the asset inventory and findings, insert, change or delete
River jobs of any kind, and write scan runs and findings. No job changes your
cloud: a state-changing action runs only after a person approves it. The
worker does run what is enqueued with no person involved, though, so those
users can make it reason over a finding they wrote, send that decision to the
alert channels and the decision webhook, and run other jobs (see [Credential
isolation](#credential-isolation)).

External datastores (`postgres.enabled=false` / `clickhouse.enabled=false`)
get whatever users you create; [External
datastores](../deploy/README.md#external-datastores) gives the statements for
the same split.

The root `docker-compose.yml`, the datastores for local development and the
integration tests, keeps one admin user per datastore (`graph`/`graph` on
loopback): the tests delete audit rows and other fixtures as it.

## Encryption key

Vulngraph has one key-encryption key: `GRAPH_SECRET_KEY`, a 32-byte AES key in
the environment of serve and the worker. It seals every connector credential,
alert-channel secret (Slack bot token, webhook URL) and TOTP seed. Each row is
sealed under its own random data key, which the KEK wraps, and both are bound
to the row's id. That means a leaked data key opens one row, and a ciphertext
copied onto another row does not open. It does not protect against a
compromise of the KEK: whoever holds `GRAPH_SECRET_KEY` and the database (a
pod, its environment, a backup with the env file) opens every row. There is
no KMS or HSM integration, so unwrapping is not an IAM-authorized or
separately audited call.

The same key is also the root of other secrets, through one-way, domain-
separated derivations: the second-admin grant signing key (HKDF) and the Helm
chart's Ladybug RPC secret (`sha256("ladybug-rpc|" + key)`, unless you set
`secret.ladybugRpcSecret`). A leaked derived secret does not reveal the
key, but rotating the key changes them all.

Rotation: set the new key as `GRAPH_SECRET_KEY` and the old one in
`GRAPH_RETIRED_SECRET_KEYS` (trusted for reads only), restart serve and the
worker, run `graph keys rewrap` to re-seal every row under the new key, then
clear `GRAPH_RETIRED_SECRET_KEYS` and restart again. The steps are in
[deploy/README.md](../deploy/README.md#rotating-graph_secret_key). Rotation
re-seals the stored data; it does not revoke anything already read with the
old key, so after a suspected compromise rotate the credentials themselves as
well (see the last mitigation below).

## Credential isolation

"Vulngraph never remediates on its own" (ADR 087) is a guarantee of the
application, not an IAM boundary. The approval rules, the two-person grant, the
approver age floor and the `executor.execute_intent` audit row are all enforced
by code running in serve. Code execution in a Vulngraph pod is assumed here to
come from a bug in nuclei, in a collector parsing a cloud API response, or in a
Go dependency. Such code holds whatever its pod holds:

| | serve | worker | scanner (`scanner.enabled`, the chart default) |
|---|---|---|---|
| The app's datastore users (`graph` on Postgres and ClickHouse: not admins, but every row the app writes; see [Datastore users](#datastore-users)) | yes (its migrate init container alone gets the ClickHouse schema user) | yes | no: `graph_scanner`, River's job tables and the scan tables, reads of assets and findings, inserts of findings |
| `GRAPH_SECRET_KEY`: opens every connector credential, alert-channel secret and TOTP seed, derives the second-admin grant key, and with the database mints sessions (`graph user token`) | yes | yes | no |
| LLM key, approval and decision-webhook signing secrets | yes | yes | no |
| Cloud identity (the ServiceAccount the hub role or workload identity is bound to) | yes | yes | no: its own ServiceAccount (`scanner.serviceAccountName`, default `graph-scanner`), no API token mounted, no identity annotations |
| Kubernetes API token, and with it the chart's RBAC (collector, policy-engine and node-posture log reads) | no: `automountServiceAccountToken: false` | yes: the RBAC binds only its ServiceAccount | no |
| Chart-wide `extraEnv` / `extraEnvFrom` | yes | yes | no: only `scanner.extraEnv` / `scanner.extraEnvFrom`, so keep secrets out of those two |
| Runs nuclei against hosts you scan | template tests only | every scan, unless `scanner.enabled` | every scan |

So, without the mitigations below:

- Code running in serve or the worker can call `sts:AssumeRole` on the
  execution role in every account directly. The role trusts the hub role plus
  the connector's ExternalId, and the ExternalId is in the connector config,
  which `GRAPH_SECRET_KEY` opens. That skips every approval rule and leaves no
  intent row.
- The same code can forge second-admin grants and sessions, because both are
  derived from `GRAPH_SECRET_KEY`.
- With `scanner.enabled: false` nuclei runs in the worker, the pod that holds
  everything above. The chart turns the scanner pod on by default; Docker
  Compose has no scanner pod, so there scans run nuclei in the worker and
  template tests run it in serve.
- serve and the worker connect as the same app users (see Datastore users).
  They are not datastore admins, but the database credentials alone are still
  full Vulngraph admin: passwords are bcrypt hashes and API keys SHA-256
  digests, neither with a server-side pepper, so such a pod can insert or
  promote an admin user or API key (backdating `created_at` past the approver
  age floor) and then act through serve, Approve & run included. It can also
  rewrite findings and enqueue River jobs; it cannot rewrite or delete
  `audit_events` rows. No cloud mutation runs as a River job, so an enqueued
  job cannot act on your cloud by itself. The scanner's `graph_scanner` users
  reach none of the user, key or connector tables. Code running there can
  still read the whole asset inventory and every finding, insert findings,
  read scan profiles, write scan runs and their per-target findings, and
  insert, change or delete River jobs of any kind, other jobs' arguments
  included (a `decide` job carries the finding it decides on, and can be
  rewritten before the worker runs it). None of that changes your cloud: only
  a person's approval runs a state-changing action. Every other job runs on
  the worker with no person involved. A finding the scanner inserts is
  enriched, which can page the alert channels, and over the pipeline
  threshold its enrich job enqueues a `decide`. A `decide` job, forged,
  rewritten or enqueued that way, has the worker reason over the finding with
  the LLM key, spending its budget, write a decision audit row, and hand the
  decision, with text the scanner chose, to the alert channels, the decision
  webhook and, for one parked for approval with `SMTP_HOST` set, the approval
  email.
  Other jobs run on the worker the same way: `verify_ci_role` (an IAM
  `GetRole` with a connector's credentials), `reenrich_all` (a re-enrichment
  pass over open findings) and `adjudicate` (LLM calls), among them. With
  an external datastore whose scanner URLs are the app's (the chart's
  opt-out), the scanner holds the app users after all.
- On GCP the executor impersonates `execute_service_account` from the pod's
  ambient identity, and on Azure the execution client secret is in the
  connector config. Neither can be limited to serve the way the AWS path can.

Mitigations, in order of value:

1. **Keep the scanner pod on** (`scanner.enabled: true`, the chart default).
   Scans then run nuclei in a pod with no master key, no LLM key, no signing
   secrets and no chart-assigned cloud identity. Template tests do not: an
   admin's `POST /api/scans/templates/test` (an admin API key is enough) runs
   nuclei inside serve against the URL it names, and writes no audit row. The
   scanner pod connects as `graph_scanner`, not the app's database users (see
   the list above). Do not bind
   a cloud identity to `graph-scanner`, and block the node's metadata endpoint
   for it: on EKS a pod without its own identity can
   otherwise fall back to the node role through IMDS. Docker Compose has no
   scanner pod: scans run nuclei in the worker and template tests in serve.
2. **Pin the hub's Pod Identity trust** (EKS Pod Identity, the default
   `TrustType`). `graph-hub-role.yaml` accepts sessions only from
   `PodNamespace` and `PodServiceAccount` (default `graph`/`graph`), and from
   `EKSClusterArn` when you set it, so an association made for any other
   ServiceAccount, the scanner's included, cannot obtain the hub. IRSA pins the
   subject the same way through `ServiceAccount`. This is graph's own
   identity: in the clusters graph scans, Pod Identity associations are not
   collected ([Known limitations](known-limitations.md)).
3. **Hold the execution path to serve** (EKS Pod Identity only). Set the
   chart's `serviceAccount.serveName` (for example `graph-serve`), add a pod
   identity association for it to the hub role, and deploy
   `graph-hub-role.yaml` and every `graph-execution-role.yaml` with
   `ExecutorServiceAccount=graph-serve`. The hub then lets only sessions tagged
   with that ServiceAccount assume the execution role, and the execution role's
   own trust requires the same tag, so the worker keeps read access and loses
   the write path (the scanner has no cloud identity at all). Setting
   `serveName` without `ExecutorServiceAccount` makes the hub trust refuse
   serve, which then has no cloud identity (connector Test and Approve & run
   fail). serve itself still holds the write path: this narrows
   who can bypass the approval rules, it does not remove the bypass. IRSA,
   `aws.enabled` web identity and `TrustType=principal` cannot do this; there
   serve and the worker share one identity.
4. **Deploy execution roles only where you need Approve & run**, and keep the
   other connectors `read_only`. An account without `GraphExecute` has no write
   path to bypass.
5. **Alert on the bypass.** In CloudTrail, every `AssumeRole` of the execution
   role (`GraphExecute`) should line up with an `executor.execute_intent` row
   in `audit_events` written just before it. Alert on any that does not, and on
   any `AssumeRole` of the hub role from a session whose
   `kubernetes-service-account` tag is not one of graph's.
6. **Keep the datastore users and the NetworkPolicy the chart sets up**
   ([Datastore users](#datastore-users), [Network policy](#network-policy)),
   give external datastores the same split (scanner users included), and
   block the cloud metadata endpoint for the scanner pod. The app users still
   let a compromised serve or worker pod write any row, users and API keys
   included; they rule out `COPY ... TO PROGRAM`, ClickHouse DDL and rewriting
   `audit_events`.
7. **After a suspected pod compromise**, rotate `GRAPH_SECRET_KEY`
   (`graph keys rewrap`, deploy/README.md), every connector credential it
   sealed, the connector ExternalIds, and the database passwords.

## Audit trail

`audit_events` (ClickHouse, plain `MergeTree`, `TTL ts + INTERVAL 7 YEAR`) is
append-only from the application's side: every Vulngraph write path inserts
rows and none updates or deletes them. Rows leave the table only through that
7-year TTL. serve and the worker connect as the ClickHouse user `graph`,
which can insert and read `audit_events` but not alter, delete, drop or
truncate it, and the scanner as `graph_scanner`, which cannot touch it at all
([Datastore users](#datastore-users)), so a compromised app pod can add rows
but not remove them. It is still not tamper-proof: migrate's `graph_migrate`
(also what `clickhouse-client` inside the ClickHouse pod logs in as) and
whoever runs that pod can rewrite the trail, and so can an external ClickHouse user you grant
more than the bundled grants. The integration tests' datastore (the root
`docker-compose.yml`) deletes audit rows as its admin user.

### What is recorded

Each row has `actor` (the signed-in user's email), `action`, `target_type`,
`target_id` and JSON `details`. `details` carries `actor_user_id` (the stable
user id), `api_key_id` when the request authenticated with an API key, and
`client_ip` when one was resolved (see Client address). A row with no
principal is written with the actor `unknown`; the `graph user` commands write
the actor `cli`. No row carries a password, password hash, TOTP seed, session
token, API key (or its prefix), connector credential value, Slack bot token or
webhook URL.

Admin actions. Each row is written after the change has committed. If
ClickHouse refuses the write, the change stands and serve (or the `graph user`
command) logs `AUDIT WRITE FAILED` at error level: alert on that line. The
`graph user` commands refuse to run when ClickHouse cannot be reached.

| Action | Target | Written when | Details |
|---|---|---|---|
| `connector.create` | `connector` | `POST /api/connectors` (the children an `aws_org` connector's discovery creates are not rows) | `type`, `name`, `event_source`, `mode`, `config_keys` (key names only) |
| `connector.mode_change` | `connector` | every `PUT /api/connectors/{id}/mode` that finds the connector, including a set to the mode it already had | `before`, `after` (`read_only` / `read_write`), read under the row lock of the update |
| `connector.disk_scan_change` | `connector` | every `PUT /api/connectors/{id}/disk-scan` that changes the mode | `before`, `after` (`off` / `existing_snapshots` / `create_snapshots`), `role` (the disk-scan principal's identifier), `actor`, `at` |
| `connector.delete` | `connector` | `DELETE /api/connectors/{id}` | `type`, `name`, `mode`, `children_disabled` (an `aws_org` connector's children) |
| `connector.purge` | `connector` | `POST /api/connectors/{id}/purge` finished | `type`, `name`, `accounts`, `assets_deleted`, `findings_resolved`, `edges_deleted` |
| `connector.purge_failed` | `connector` | a purge stopped part way | the same, counting what it had already removed, plus `error` |
| `auth.user_create` | `user` | `POST /api/users` or `graph user create` | `email`, `role` |
| `auth.user_provision` | `user` | a first SSO sign-in creates the account (actor: the new user) | `email`, `role`, `via` (`oidc` with `issuer`, or `oauth2_proxy`) |
| `auth.user_role_change` | `user` | a `PATCH /api/users/{id}` that sets `role` | `email`, `before`, `after`; `sessions_revoked` for a promotion under `REQUIRE_ADMIN_TOTP` |
| `auth.user_disable` / `auth.user_enable` | `user` | a `PATCH /api/users/{id}` that sets `disabled` | `email`, `was_disabled`; `sessions_revoked` on disable |
| `auth.user_delete` | `user` | `DELETE /api/users/{id}` (the user's sessions and API keys go with it) | `email`, `role` |
| `auth.sessions_revoke` | `user` | `POST /api/users/{id}/revoke-sessions` | `email`, `sessions_revoked` |
| `auth.totp_enroll` | `user` | `graph user totp` | `email`, `replaced` (true: an enrolled seed was reset) |
| `auth.token_issue` | `user` | `graph user token` | `email`, `role`, `expires_at` |
| `auth.login` | `user` | a session starts: a password sign-in, or a Google, Okta, IAP or oauth2-proxy sign-in (actor: the user) | `email`, `method` (`password`, `oidc` with `issuer`, or `oauth2_proxy`); `totp` (enrolled) for a password sign-in |
| `auth.login_failed` | `user` (`target_id` the account the sign-in matched, or empty; an SSO refusal names one only for `disabled` and `identity_mismatch`, since its domain, hosted-domain, group and verified-email gates refuse before any account is looked up) | a refused password sign-in, whatever the failed factor; a Google or Okta callback, IAP or oauth2-proxy sign-in refused after the identity provider vouched for the identity (actor `unknown`) | `method` (`password`, `google`, `okta`, `iap`, `oauth2_proxy`), `reason` (`unknown_email`, `wrong_password`, `disabled`, `admin_totp_required`, `wrong_or_missing_totp`, `totp_replayed`, `email_unverified`, `domain_not_allowed`, `hosted_domain_not_allowed`, `required_group_missing`, `identity_mismatch`), `email` as typed or asserted (left out, with `email_malformed: true`, when it is not an email address) |
| `auth.logout` | `user` | `POST /api/auth/logout` with a session cookie, or an oauth2-proxy session replaced because the proxy now vouches for someone else | `reason` (`sign_out`, `proxy_identity_changed`) |
| `auth.api_key_refused` | `api_key` | a session-only route refused an API key (see API keys) | `route` |
| `apikey.create` | `api_key` | `POST /api/keys` | `owner_user_id`, `name`, `scope`, `expires_at` |
| `apikey.revoke` | `api_key` | `DELETE /api/keys/{id}` | `owner_user_id` |
| `notify.channel_create` | `alert_channel` | `POST /api/alerts/channels` | `type`, `name`, `enabled`, `slack_channel` or `webhook_host` |
| `notify.channel_update` | `alert_channel` | `PUT /api/alerts/channels/{id}` | `type`, `name`, `enabled`, `slack_channel` (Slack), `webhook_host` only when the request replaces the webhook URL, and `secret_replaced` (a new bot token or webhook URL was stored) |
| `notify.channel_delete` | `alert_channel` | `DELETE /api/alerts/channels/{id}` | `type`, `name`, `enabled`, `slack_channel` (Slack); no `webhook_host`, since the stored webhook URL stays sealed (the channel's `notify.channel_create` row names it) |
| `policy.update` | `approval_policy` | `PUT /api/policy` | `before`, `after` (`suggest_threshold`, `action_rules`), read under the row lock of the update |
| `finding.resolve` | `finding` | `POST /api/findings/{id}/resolve` | `reason` (the person's text), `severity`, `score_band`, `must_fix_class` |
| `finding.resolve_refused` | `finding` | the same route refused an API key for that finding (see API keys) | `refusal` |
| `savedquery.create` / `savedquery.delete` | `saved_query` | `POST /api/saved-queries` / `DELETE /api/saved-queries/{id}` | `name`, `cypher`, `schedule`, `enabled`, `alert_on_change`, `alert_severity`, `alert_channel_ids` (for a delete, the definition it removed) |
| `savedquery.update` | `saved_query` | `PUT /api/saved-queries/{id}` | `before`, `after` (the same fields; `before` is read just before the update) |
| `scan.profile_create` / `scan.profile_delete` | `scan_profile` | `POST /api/scan-profiles` / `DELETE /api/scan-profiles/{id}` | `name`, `target_query`, `scanner_type`, `template_strategy`, `template_tags`, `schedule`, `enabled`, `drift_enabled` (for a delete, the definition it removed) |
| `scan.profile_update` | `scan_profile` | `PUT /api/scan-profiles/{id}` | `before`, `after` (the same fields; `before` is read just before the update) |
| `scan.start` | `scan` (empty `target_id`: the worker creates the run) | `POST /api/scans` enqueued a full scan of the internet-facing assets | `scope` (`internet_facing`) |
| `scan.profile_start` | `scan_profile` | `POST /api/scan-profiles/{id}/trigger` created and enqueued a run | `run_id`, `name`, `scanner_type`, `template_strategy`, `target_query` |

Other than the sign-in and API-key refusals above and `suppress.refused`
below, a request refused before it changes anything (a validation error, a
missing row, a self-action, the last admin) writes no admin-action row.

Remediation and review, written by their own domains:

| Action | Written when |
|---|---|
| `executor.execute_intent` | before every cloud call; if it cannot be written the call is refused |
| `executor.execute` / `executor.execute_failed` / `executor.execute_outcome_unknown` | after the call: success, failure, or cut off after its intent row |
| `executor.dry_run` | a dry run |
| `executor.approve` | a second admin mints a grant |
| `executor.refused` | a grant or decision run refused for who asked, before Execute |
| `executor.run_marked_failed` | an admin releases a stalled decision run |
| `suppress.suppress` / `suppress.unsuppress` / `suppress.review` / `suppress.carry` | a finding is suppressed, unsuppressed, reviewed, or its suppression carried to a superseding finding |
| `suppress.refused` | an API key asked to suppress or renew a finding only a person may (details: `reason`, `operation`) |
| `governor_verdict` | a queue verdict, signed in or by email link |
| `governor_execution` | a decision's fix ran through approve-and-run |
| `decision` | the agent's remediation decision for a finding |
| `chat.live_read` / `mcp.live_read` | a live cloud read from chat or an MCP client |

Not recorded in `audit_events`: a sign-in request refused before any identity
provider vouched for an identity (a bad OAuth state, a failed code exchange,
an invalid IAP assertion, an oauth2-proxy request whose ID token or shared
secret did not verify) and a password sign-in answered 429 by the rate limit,
which serve logs at warn; a session that expires, or ends because its user
was disabled, deleted or had their sessions revoked (those admin actions have
their own rows); connector sync and connection tests;
saved-query runs; scheduled profile runs (no person starts them), scan cancels,
scan imports, template tests and LLM template generation; intel domains and
phishing triage; alert-channel tests; reads, raw Cypher and MCP queries, per
call. The serve log has some of these; it is not a durable record.

A refused IAP or oauth2-proxy sign-in (domain not allowed, a required group
missing) is refused again, and written again, on every request the proxy
forwards for that person without a session, until they stop.

### Tamper-evidence

If you need tamper-evidence:

- keep the bundled split, or on an external ClickHouse give serve, the worker
  and the scanner a user with only `INSERT` and `SELECT` on `audit_events` and
  keep DDL and `ALTER ... DELETE` to the user `migrate` runs as
  ([the grants](../deploy/README.md#external-datastores)); and/or
- export audit rows off the box (for example a scheduled
  `SELECT ... FROM audit_events WHERE ts > ...` into your SIEM or write-once
  storage).

## Network policy

- The Helm chart's NetworkPolicy is on by default (`networkPolicy.enabled`;
  [deploy/README.md](../deploy/README.md#network-policy) has the table).
  Postgres and ClickHouse accept their client ports only from serve (with its
  migrate init container), the worker and the scanner, the pods that hold
  their credentials; the worker's graph RPC accepts serve and the scanner; the
  scanner accepts nothing. serve's API port accepts every source until you set
  `networkPolicy.ingressNamespace` (the ingress controller's namespace) and
  `networkPolicy.nodeCIDRs` (kubelet probes; the render fails without them):
  probes come from the node address, which no namespace matches, so the
  default cannot limit serve without breaking its probes. A load balancer that
  targets pod IPs directly (the AWS Load Balancer Controller in IP target
  mode, GKE container-native load balancing) connects from its own addresses,
  so its subnets or health-check ranges go in `nodeCIDRs` too.
  `nodeCIDRs` without `ingressNamespace` fails the render, since it would
  restrict nothing. `config.oauth2Proxy` requires `ingressNamespace`. serve's probe shares its API port, so anything
  on the node network can still reach serve: prefer ID-token verification for
  oauth2-proxy. The objects need a CNI that enforces NetworkPolicy (Calico or
  Cilium do; not every CNI does); on any other they do nothing.
- The policy restricts ingress only. Collectors need egress to cloud APIs.
  If your cluster can restrict egress, block the cloud metadata endpoint
  (`169.254.169.254`) for the graph pods unless they use it for workload
  identity.
- Keep Postgres, ClickHouse and the worker RPC off public networks.
- The chart's bundled Postgres and ClickHouse are plaintext on the pod network
  until you give them certificates (`postgres.tlsSecret` with `sslMode`,
  `clickhouse.tlsSecret` with `secure`; see
  [deploy/README.md](../deploy/README.md#datastores--in-cluster-default)).
  Docker Compose connects in plaintext (`sslmode=disable`) on its own network.
- Vulngraph also calls out on its own: threat-intel feeds (CISA KEV, EPSS, OSV,
  the OpenSSF malicious-packages feed, Amazon and Oracle Linux advisories),
  crt.sh for domain monitoring, the registries of your running container
  images, the subdomain-takeover probe, and the download of the pinned,
  checksum-verified nuclei-templates release. nuclei's interactsh servers are
  contacted only with `NUCLEI_INTERACTSH_ENABLED=true`.
  [Network egress](configuration.md#network-egress) lists every destination,
  what it sends and its switch. `OFFLINE_MODE=true` turns off all of them except the
  takeover check's DNS lookups, which go to the worker's resolver. The
  nuclei SDK's built-in version check to `api.pdtm.sh` is refused inside the
  process in every mode, so it never reaches the network. For defence in depth
  add an egress policy as well; the chart's NetworkPolicy restricts ingress
  only.
