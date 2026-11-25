-- +goose Up
-- The Vulngraph Postgres schema. River's job tables are not here: River
-- migrates them itself (internal/migrate).

-- ---------------------------------------------------------------------------
-- Identity: users, sessions, API keys
-- ---------------------------------------------------------------------------

-- Emails are stored lowercase (CHECK) and unique on lower(email); the app
-- lowercases before every write and lookup. A disabled user cannot log in, and
-- their sessions and API keys stop authenticating, while the row that audit
-- history refers to stays. The first OIDC sign-in binds the account to the
-- IdP's stable (issuer, subject) pair; later sign-ins must present the same
-- pair. totp_last_step is the 30-second step of the last accepted TOTP code: a
-- login must present a code from a strictly later step.
CREATE TABLE users (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email          text        NOT NULL,
    password_hash  text        NOT NULL,
    role           text        NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    totp_secret    text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    disabled_at    timestamptz,
    oidc_issuer    text,
    oidc_subject   text,
    totp_last_step bigint,
    CONSTRAINT users_email_lowercase CHECK (email = lower(email)),
    CONSTRAINT users_oidc_identity_pair CHECK ((oidc_issuer IS NULL) = (oidc_subject IS NULL))
);

CREATE UNIQUE INDEX users_email_lower_key ON users (lower(email));
CREATE UNIQUE INDEX users_oidc_identity_key ON users (oidc_issuer, oidc_subject) WHERE oidc_subject IS NOT NULL;

CREATE TABLE sessions (
    token_hash text        PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

-- Programmatic credentials (gph_ prefix). key_hash is the hex SHA-256 of the
-- full key. lookup_id is the first 16 characters of the key (48 bits of
-- randomness) and is what a key is found by; prefix is the shorter UI display
-- value.
CREATE TABLE api_keys (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         text        NOT NULL,
    key_hash     text        NOT NULL UNIQUE,
    prefix       text        NOT NULL,
    scopes       text        NOT NULL DEFAULT 'read',
    last_used_at timestamptz,
    expires_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    lookup_id    text        NOT NULL
);

CREATE INDEX api_keys_user_id_idx ON api_keys (user_id);
CREATE UNIQUE INDEX api_keys_lookup_id_idx ON api_keys (lookup_id);

-- ---------------------------------------------------------------------------
-- Connectors and sync state
-- ---------------------------------------------------------------------------

-- aws_org is one connector per AWS Organization (ADR 091): it manages one
-- child aws connector per member account. A child stores only references; the
-- hub credential and ExternalId are resolved from the org connector at read
-- time.
--
-- sync_fingerprint hashes the sorted (id:content_hash) pairs of everything the
-- connector returned last sweep; an unchanged fingerprint skips the asset write
-- and enrichment enqueue. last_synced_at is stamped on every attempt,
-- last_success_at only on success (staleness is measured against it).
-- sync_streak counts consecutive clean syncs and drives the adaptive backoff
-- (internal/jobs/enqueue.go); partial_streak counts consecutive Partial syncs
-- so Connector.PartiallyStale can flag a collector that never completes.
CREATE TABLE connectors (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    type             text        NOT NULL CHECK (type IN ('aws', 'aws_org', 'gcp', 'github', 'kubernetes', 'azure', 'okta', 'google_workspace', 'demo')),
    name             text        NOT NULL,
    config_enc       bytea       NOT NULL,              -- AES-256-GCM ciphertext of the JSON config
    enabled          boolean     NOT NULL DEFAULT true,
    event_source     text        NOT NULL DEFAULT '',   -- '' = schedule-only
    sync_status      text        NOT NULL DEFAULT 'pending',
    sync_error       text        NOT NULL DEFAULT '',
    last_synced_at   timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    sync_fingerprint text        NOT NULL DEFAULT '',
    mode             text        NOT NULL DEFAULT 'read_only' CHECK (mode IN ('read_only', 'read_write')),
    last_success_at  timestamptz,
    sync_streak      integer     NOT NULL DEFAULT 0,
    partial_streak   integer     NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX connectors_type_name_idx ON connectors (type, name);

-- Per-asset content hash from the connector's last sweep, so the sync diff is
-- an indexed read rather than a ClickHouse scan. asset_type and region let the
-- deletion decision match a stored row against exactly the enumeration scope
-- that proved it complete; '' is "not attributable to any completed scope" and
-- is never a deletion candidate. curr_* / prev_* and change_count back the
-- drift view.
CREATE TABLE connector_asset_hashes (
    connector_id    uuid        NOT NULL REFERENCES connectors (id) ON DELETE CASCADE,
    asset_id        text        NOT NULL,
    hash            text        NOT NULL,
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    last_changed_at timestamptz NOT NULL DEFAULT now(),
    curr_public_ip  text        NOT NULL DEFAULT '',
    curr_name       text        NOT NULL DEFAULT '',
    prev_public_ip  text        NOT NULL DEFAULT '',
    prev_name       text        NOT NULL DEFAULT '',
    change_count    integer     NOT NULL DEFAULT 0,
    asset_type      text        NOT NULL DEFAULT '',
    region          text        NOT NULL DEFAULT '',
    PRIMARY KEY (connector_id, asset_id)
);

CREATE INDEX idx_asset_hashes_first_seen ON connector_asset_hashes (first_seen_at DESC);
CREATE INDEX idx_asset_hashes_last_changed ON connector_asset_hashes (last_changed_at DESC);
CREATE INDEX connector_asset_hashes_asset_id_idx ON connector_asset_hashes (asset_id);

-- Capabilities a collector has proven at least once (for example, being the
-- AWS Identity Center admin account). Monotonic: a row is only ever inserted,
-- so a later denial is judged as a regression rather than re-opening the gap
-- on a transient failure.
CREATE TABLE connector_proven_capabilities (
    connector_id    uuid        NOT NULL REFERENCES connectors (id) ON DELETE CASCADE,
    capability      text        NOT NULL,
    first_proven_at timestamptz NOT NULL,
    PRIMARY KEY (connector_id, capability)
);

-- One row per account an org connector's discovery has ever listed. An account
-- that leaves the organization is kept with status 'removed'.
CREATE TABLE aws_org_accounts (
    org_connector_id   uuid        NOT NULL REFERENCES connectors (id) ON DELETE CASCADE,
    account_id         text        NOT NULL,
    name               text        NOT NULL DEFAULT '',
    email              text        NOT NULL DEFAULT '',
    -- The Organizations account State as last listed (ACTIVE, SUSPENDED, ...).
    aws_state          text        NOT NULL DEFAULT '',
    -- Root-to-parent OU ids, '/'-joined; '' when no OU filter needed the walk.
    ou_path            text        NOT NULL DEFAULT '',
    status             text        NOT NULL CHECK (status IN
        ('active', 'pending', 'suspended', 'closed', 'excluded', 'removed', 'conflict', 'unknown', 'error')),
    status_detail      text        NOT NULL DEFAULT '',
    -- SET NULL, not CASCADE: deleting a child connector by hand must not erase
    -- the record that the account exists.
    child_connector_id uuid        REFERENCES connectors (id) ON DELETE SET NULL,
    first_seen_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at       timestamptz NOT NULL DEFAULT now(),
    status_changed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_connector_id, account_id)
);

CREATE INDEX aws_org_accounts_child_idx ON aws_org_accounts (child_connector_id);

-- Assets a complete sweep proved deleted. Asset rows in ClickHouse are never
-- deleted, so this is how derived-finding jobs tell "deleted" from "stopped
-- being collected". A reader compares deleted_at with the asset's last_seen, so
-- a resource that came back is not read as deleted.
CREATE TABLE asset_deletions (
    asset_id     text        PRIMARY KEY,
    connector_id text        NOT NULL,
    deleted_at   timestamptz NOT NULL
);

CREATE INDEX asset_deletions_deleted_at_idx ON asset_deletions (deleted_at);

-- Per-scope completeness watermarks and the forget shadow decision.
CREATE TABLE forget_scope_state (
    connector_id          text        NOT NULL,
    scope                 text        NOT NULL,
    asset_type            text        NOT NULL,
    -- prev_complete_at is what makes consecutive-sweep confirmation possible:
    -- one complete listing is a claim about one API call.
    last_complete_at      timestamptz NOT NULL,
    prev_complete_at      timestamptz,
    -- What the scope enumerated when it last proved complete, and the
    -- high-water of that number. A truncated listing returns fewer items while
    -- churn keeps the count roughly flat, so a shrink against the high-water is
    -- the signal. high_water_at lets the watermark decay for an account that
    -- genuinely shrinks.
    enumerated            integer     NOT NULL,
    enumerated_high_water integer     NOT NULL,
    high_water_at         timestamptz NOT NULL,
    -- stored:      asset rows attributable to this scope
    -- absent:      stored rows this enumeration did not re-observe
    -- confirmed:   absent across the whole confirmation window
    -- forgettable: confirmed AND every refusal passed (0 whenever refusal <> '')
    stored                integer     NOT NULL,
    absent                integer     NOT NULL,
    confirmed             integer     NOT NULL,
    forgettable           integer     NOT NULL,
    refusal               text        NOT NULL,
    evaluated_at          timestamptz NOT NULL,
    PRIMARY KEY (connector_id, scope, asset_type)
);

-- "Believed gone at T", never "deleted". Written only under FORGET_MODE=enforce
-- and only for candidates that survived every refusal.
CREATE TABLE forget_tombstones (
    asset_id         text        PRIMARY KEY,
    connector_id     text        NOT NULL,
    scope            text        NOT NULL,
    asset_type       text        NOT NULL,
    last_seen        timestamptz NOT NULL,
    believed_gone_at timestamptz NOT NULL
);

CREATE INDEX forget_tombstones_scope_idx ON forget_tombstones (connector_id, scope);

CREATE TABLE cost_snapshots (
    id           uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
    connector_id text          NOT NULL,
    account_id   text          NOT NULL,
    service      text          NOT NULL,
    cost_usd     numeric(12,4) NOT NULL,
    period_date  date          NOT NULL,
    collected_at timestamptz   NOT NULL DEFAULT now(),
    UNIQUE (connector_id, service, period_date)
);

CREATE INDEX cost_snapshots_connector_period ON cost_snapshots (connector_id, period_date DESC);

-- ---------------------------------------------------------------------------
-- Vulnerability feeds and scan cursors
-- ---------------------------------------------------------------------------

-- (ecosystem, name, version) tuples already checked against OSV, so the OSV
-- worker queries only new or stale entries.
CREATE TABLE osv_scanned_packages (
    ecosystem  text        NOT NULL,
    name       text        NOT NULL,
    version    text        NOT NULL,
    scanned_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (ecosystem, name, version)
);

-- MalFeedWorker's last-seen commit SHA in ossf/malicious-packages, the base
-- for GitHub's compare API. Single row by construction.
CREATE TABLE osv_malfeed_watermark (
    id         smallint    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    last_sha   text        NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Per-image cursor for the image-vuln sweep. attempted_at records attempts, not
-- just clean scans, so a digest that fails every time cannot hold the per-run
-- budget forever; scanned_at is NULL until a scan succeeds.
CREATE TABLE image_scan_state (
    digest       text        PRIMARY KEY,
    scanned_at   timestamptz,
    attempted_at timestamptz,
    failures     integer     NOT NULL DEFAULT 0,
    last_error   text        NOT NULL DEFAULT ''
);

-- The KEV catalog as last seen, and the `kev.added` event stream (ADR 085,
-- ADR 086). A CVE not yet in kev_catalog gets exactly one kev_added_events row:
-- the primary key is the idempotency key. The first refresh on an empty
-- catalog seeds it and emits events only for entries CISA added recently.
CREATE TABLE kev_catalog (
    cve_id        text        PRIMARY KEY,
    -- CISA's dateAdded (a calendar date, stored at midnight UTC). NULL when the
    -- feed's value did not parse: unknown, never a made-up date.
    date_added    timestamptz,
    name          text        NOT NULL DEFAULT '',
    first_seen_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE kev_added_events (
    cve_id        text        PRIMARY KEY,
    date_added    timestamptz,
    name          text        NOT NULL DEFAULT '',
    -- Open findings matching the CVE when the addition was detected.
    open_findings integer     NOT NULL,
    detected_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX kev_added_events_detected_at_idx ON kev_added_events (detected_at DESC);

-- ---------------------------------------------------------------------------
-- Active scanning
-- ---------------------------------------------------------------------------

-- Reusable scan profiles: what to scan, how, and when.
CREATE TABLE scan_profiles (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name              text        NOT NULL,
    description       text        NOT NULL DEFAULT '',
    target_query      text        NOT NULL DEFAULT '',        -- Cypher query for target selection; empty = all exposed
    scanner_type      text        NOT NULL DEFAULT 'nuclei',  -- nuclei | openvas | qualys | burp | custom
    template_strategy text        NOT NULL DEFAULT 'all',     -- all | tags | ai_contextual
    template_tags     text[]      NOT NULL DEFAULT '{}',
    schedule          text        NOT NULL DEFAULT '',        -- cron expression; empty = manual only
    enabled           boolean     NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    drift_enabled     boolean     NOT NULL DEFAULT false      -- scan automatically when an asset changes
);

CREATE INDEX idx_scan_profiles_enabled ON scan_profiles (enabled);

CREATE TABLE scan_runs (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    status         text        NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed', 'cancelled')),
    target_count   int         NOT NULL DEFAULT 0,
    finding_count  int         NOT NULL DEFAULT 0,
    error          text        NOT NULL DEFAULT '',
    started_at     timestamptz NOT NULL DEFAULT now(),
    finished_at    timestamptz,
    template_tags  text[]      NOT NULL DEFAULT '{}',  -- template tags nuclei used
    template_count int         NOT NULL DEFAULT 0,     -- templates that fired
    target_urls    text[]      NOT NULL DEFAULT '{}',  -- the URLs/IPs actually scanned
    scanner_name   text        NOT NULL DEFAULT 'nuclei',
    profile_id     uuid        REFERENCES scan_profiles (id) ON DELETE SET NULL
);

CREATE INDEX scan_runs_started_at_idx ON scan_runs (started_at DESC);
CREATE INDEX idx_scan_runs_profile_id ON scan_runs (profile_id);

-- Links scan-run findings to graph findings and tracks their lifecycle across
-- runs: one live record per (asset_id, check_id).
CREATE TABLE scan_findings (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id   uuid        NOT NULL REFERENCES scan_runs (id) ON DELETE CASCADE,
    finding_id    text        NOT NULL,  -- graph finding ID
    asset_id      text        NOT NULL,
    check_id      text        NOT NULL,
    title         text        NOT NULL,
    severity      text        NOT NULL,
    status        text        NOT NULL DEFAULT 'new',  -- new | confirmed | resolved | regressed
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    resolved_at   timestamptz,
    UNIQUE (asset_id, check_id)
);

CREATE INDEX idx_scan_findings_asset_check ON scan_findings (asset_id, check_id);
CREATE INDEX idx_scan_findings_scan_run_id ON scan_findings (scan_run_id);

COMMENT ON COLUMN scan_findings.asset_id IS
    'Scanned target host (scan.Target.Host), not a graph asset ID: a scan target carries no asset ID.';

-- ---------------------------------------------------------------------------
-- Enrichment and reasoning caches
-- ---------------------------------------------------------------------------

-- The change-driven gate for enrichment: a finding whose inputs are unchanged
-- and which was enriched within the freshness backstop is not re-enriched.
-- input_fp is the full (LogicVersion + context) fingerprint, context_fp the
-- version-independent part, so a miss caused only by a LogicVersion bump can
-- skip the decide step when score_band did not move. graph_* hold the raw
-- graph context the fingerprint was built from, so a failed graph read carries
-- the last measured value forward; '' is never measured, and graph_exposed is
-- '' | 'true' | 'false'.
CREATE TABLE enrich_cache (
    finding_id    text        PRIMARY KEY,
    input_fp      text        NOT NULL,
    enriched_at   timestamptz NOT NULL DEFAULT now(),
    context_fp    text        NOT NULL DEFAULT '',
    score_band    text        NOT NULL DEFAULT '',
    graph_exposed text        NOT NULL DEFAULT '',
    graph_privesc text        NOT NULL DEFAULT '',
    graph_reach   text        NOT NULL DEFAULT ''
);

-- The urgency a finding last alerted at. Alerts fire on a transition, never on
-- a re-enrich of the same state. Kept apart from enrich_cache so the
-- change-gate's writes can never erase the record that an alert went out.
CREATE TABLE finding_alert_state (
    finding_id     text        PRIMARY KEY,
    score_band     text        NOT NULL,
    must_fix_class text        NOT NULL,
    alerted_at     timestamptz NOT NULL DEFAULT now()
);

-- The enrichment LogicVersion (internal/app/enrichcache) that a full corpus
-- re-enrichment last completed for. On boot the worker compares the deployed
-- version against this row and enqueues one bulk pass on a mismatch. A single
-- global watermark (enforced by the CHECK), seeded with '' so the first boot
-- runs a pass; rows are updated, never inserted.
CREATE TABLE enrich_logic_version (
    id         boolean     PRIMARY KEY DEFAULT true CHECK (id),
    version    text        NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO enrich_logic_version (id, version) VALUES (true, '');

-- The change-driven gate for the LLM reasoner and the full decision snapshot
-- per finding (plan, confidence, blast radius, CoVe concerns), so the
-- finding-detail UI renders the whole trace from one read. Plan fields are
-- primitive columns to keep the dependency one-way. blast_radius_known says
-- whether the blast-radius walk measured anything: a blast_radius of 0 with
-- blast_radius_known = false is unknown, not isolated. repeat_count counts
-- byte-identical repeats that skipped the audit write.
CREATE TABLE reasoning_cache (
    finding_id         text             PRIMARY KEY,
    fingerprint        text             NOT NULL,
    plan_action_class  text             NOT NULL,
    plan_summary       text             NOT NULL DEFAULT '',
    plan_rationale     text             NOT NULL DEFAULT '',
    outcome            text             NOT NULL DEFAULT '',
    decided_at         timestamptz      NOT NULL DEFAULT now(),
    confidence_band    text             NOT NULL DEFAULT '',
    confidence_score   double precision NOT NULL DEFAULT 0,
    effective_n        double precision NOT NULL DEFAULT 0,
    sample_count       integer          NOT NULL DEFAULT 0,
    blast_radius       integer          NOT NULL DEFAULT 0,
    cove_concerns      text[]           NOT NULL DEFAULT '{}',
    safety_band        text             NOT NULL DEFAULT '',  -- advisory safe | caution | risky
    repeat_count       bigint           NOT NULL DEFAULT 0,
    last_repeated_at   timestamptz,
    escalation_reason  text             NOT NULL DEFAULT '',
    blast_radius_known boolean          NOT NULL DEFAULT false
);

CREATE INDEX reasoning_cache_decided_at_idx ON reasoning_cache (decided_at DESC);

-- ---------------------------------------------------------------------------
-- Governance: suppressions, verdicts, executions, learning
-- ---------------------------------------------------------------------------

-- A suppressed finding keeps being detected and stored but never enters the
-- decision pipeline. finding_id is the deterministic ClickHouse finding id.
-- Every suppression expires; the row is kept after expiry so the finding can
-- say its exception lapsed. expiry_notified_at is when the notice for the
-- current expires_at went out, cleared whenever expires_at moves.
CREATE TABLE finding_suppressions (
    finding_id         text        PRIMARY KEY,
    reason             text        NOT NULL,
    suppressed_by      text        NOT NULL,  -- user id/email from the session
    suppressed_at      timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    last_reviewed_at   timestamptz,           -- NULL = never reviewed since suppressed
    reviewed_by        text        NOT NULL DEFAULT '',
    expiry_notified_at timestamptz
);

CREATE INDEX finding_suppressions_expires_at_idx ON finding_suppressions (expires_at);

-- A person's standing verdict on a parked or escalated decision, one per
-- finding. fingerprint is the finding's context fingerprint when the verdict
-- was recorded: a finding whose context later changes re-surfaces for review.
CREATE TABLE decision_verdicts (
    finding_id  text        PRIMARY KEY,
    cluster_key text        NOT NULL DEFAULT '',
    verdict     text        NOT NULL,  -- approved | risk_accepted | denied
    actor       text        NOT NULL,
    note        text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    fingerprint text        NOT NULL DEFAULT ''
);

CREATE INDEX decision_verdicts_created_at_idx ON decision_verdicts (created_at DESC);

-- A verdict that applies to every finding of one check and action class
-- (optionally narrowed to a resource type), so the same question is not
-- asked again per finding.
CREATE TABLE pattern_verdicts (
    check_id      text        NOT NULL,
    action_class  text        NOT NULL,
    resource_type text        NOT NULL DEFAULT '',
    verdict       text        NOT NULL,  -- approved | risk_accepted | denied
    decided_by    text        NOT NULL,
    decided_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (check_id, action_class, resource_type)
);

-- "Approve & run" execution state, one row per decision (ADR 087). The
-- executor's ClickHouse audit_events rows are the full history.
--
--   awaiting_second_admin — the first admin approved a destructive fix and
--                           minted the grant; a second admin's click runs it.
--                           grant_token is that grant and is never sent to a
--                           client.
--   running               — claimed by one click; the cloud call is in flight.
--   succeeded / failed    — the executor's actual result.
--
-- connector_id is not a foreign key on purpose: deleting a connector must not
-- erase the record that a fix ran through it.
CREATE TABLE decision_executions (
    decision_id      text        PRIMARY KEY,
    finding_id       text        NOT NULL,
    connector_id     text        NOT NULL,
    action           text        NOT NULL,
    params           jsonb       NOT NULL,
    plan             text        NOT NULL,
    status           text        NOT NULL,
    requested_by     text        NOT NULL,
    requested_by_id  text        NOT NULL,
    grant_token      text        NOT NULL DEFAULT '',
    grant_expires_at timestamptz,
    executed_by      text        NOT NULL DEFAULT '',
    executed_by_id   text        NOT NULL DEFAULT '',
    detail           text        NOT NULL DEFAULT '',
    error            text        NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);

-- Makes each two-person approval grant single-use across serve replicas: the
-- first execution inserts the grant's hash, every later one finds the row.
-- Rows are needed only until the grant expires.
CREATE TABLE executor_grant_redemptions (
    grant_hash     text        PRIMARY KEY,
    redeemed_by_id text        NOT NULL,
    redeemed_at    timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL
);

CREATE INDEX executor_grant_redemptions_expires_at_idx ON executor_grant_redemptions (expires_at);

-- Single-use email approval links: the first use of a request's nonce inserts
-- it, and the primary key makes every later use a no-op. expires_at mirrors the
-- token's own expiry so spent rows can be purged.
CREATE TABLE approval_link_nonces (
    nonce      text        PRIMARY KEY,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX approval_link_nonces_expires_at_idx ON approval_link_nonces (expires_at);

-- The decaying-memory ledger: every action's context and result, used to
-- compute confidence by an exponentially decayed weighted success rate.
-- dedupe_key names the decision an outcome is evidence of (finding + context
-- fingerprint), so a retried decision cannot add a second sample; NULL appends
-- unconditionally.
CREATE TABLE action_outcomes (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    action_class text        NOT NULL,
    asset_type   text        NOT NULL DEFAULT '',
    environment  text        NOT NULL DEFAULT '',
    success      boolean     NOT NULL,
    decided_by   text        NOT NULL DEFAULT '',  -- "governor" (a denial) | "executor" (a fix that ran)
    occurred_at  timestamptz NOT NULL DEFAULT now(),
    dedupe_key   text
);

CREATE INDEX action_outcomes_lookup_idx ON action_outcomes (action_class, asset_type, occurred_at DESC);
CREATE INDEX action_outcomes_by_asset_idx ON action_outcomes (asset_type, occurred_at DESC);
CREATE UNIQUE INDEX action_outcomes_dedupe_key_idx ON action_outcomes (dedupe_key) WHERE dedupe_key IS NOT NULL;

-- The remediation policy, a single row (id = 'default'). Action modes are
-- "jit" (proposed, waits for a human) and "disabled" (guidance only); nothing
-- runs on its own (ADR 087).
CREATE TABLE automation_policy (
    id                text        PRIMARY KEY DEFAULT 'default',
    suggest_threshold int         NOT NULL DEFAULT 60,
    action_rules      jsonb       NOT NULL DEFAULT '{}',
    updated_at        timestamptz NOT NULL DEFAULT now(),
    updated_by        text        NOT NULL DEFAULT 'system'
);

INSERT INTO automation_policy (id) VALUES ('default');

-- ---------------------------------------------------------------------------
-- Alerting, detections, intel
-- ---------------------------------------------------------------------------

-- Outbound alert destinations with per-event routing rules. Empty arrays mean
-- "match everything" (no scope); route_unowned makes the channel a default
-- destination for findings nobody owns (ADR 089).
CREATE TABLE alert_channels (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    type              text        NOT NULL,                -- 'slack'
    name              text        NOT NULL,                -- human label
    channel           text        NOT NULL DEFAULT '',     -- Slack channel ("#alerts" or channel ID)
    config_encrypted  bytea       NOT NULL,                -- encrypted JSON {"bot_token": "..."}
    enabled           boolean     NOT NULL DEFAULT true,
    event_types       text[]      NOT NULL DEFAULT '{}',   -- e.g. {phishing,finding,drift,decision}
    severities        text[]      NOT NULL DEFAULT '{}',   -- e.g. {critical,high}
    min_score         integer     NOT NULL DEFAULT 0,
    last_delivered_at timestamptz,
    last_status       text        NOT NULL DEFAULT '',     -- '' | 'ok' | 'error'
    last_error        text        NOT NULL DEFAULT '',
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    owner_teams       text[]      NOT NULL DEFAULT '{}',
    environments      text[]      NOT NULL DEFAULT '{}',
    route_unowned     boolean     NOT NULL DEFAULT false
);

CREATE INDEX idx_alert_channels_enabled ON alert_channels (enabled);

-- Saved Cypher queries (detection-as-code): run on a cron schedule and alert
-- through alert_channels when the result set changes.
CREATE TABLE saved_queries (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name              text        NOT NULL,
    description       text        NOT NULL DEFAULT '',
    cypher            text        NOT NULL,
    created_by        text        NOT NULL DEFAULT '',     -- user email/id
    schedule          text        NOT NULL DEFAULT '',     -- cron expr; '' = manual only
    alert_channel_ids uuid[]      NOT NULL DEFAULT '{}',
    alert_on_change   boolean     NOT NULL DEFAULT false,  -- alert when result hash changes
    enabled           boolean     NOT NULL DEFAULT true,
    last_run_at       timestamptz,
    last_result_count integer     NOT NULL DEFAULT 0,
    last_result_hash  text        NOT NULL DEFAULT '',
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    alert_severity    text        NOT NULL DEFAULT 'high'  -- severity of the change alert
);

CREATE INDEX idx_saved_queries_scheduled ON saved_queries (enabled) WHERE schedule != '';

-- Every execution of a saved query, for the timeline and change detection.
CREATE TABLE saved_query_runs (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    saved_query_id uuid        NOT NULL REFERENCES saved_queries (id) ON DELETE CASCADE,
    ran_at         timestamptz NOT NULL DEFAULT now(),
    node_count     integer     NOT NULL DEFAULT 0,
    edge_count     integer     NOT NULL DEFAULT 0,
    result_hash    text        NOT NULL DEFAULT '',
    trigger        text        NOT NULL DEFAULT 'manual',  -- manual | schedule
    error          text        NOT NULL DEFAULT ''
);

CREATE INDEX idx_saved_query_runs_query ON saved_query_runs (saved_query_id, ran_at DESC);

CREATE TABLE intel_monitored_domains (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    domain     text        NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- LLM spend
-- ---------------------------------------------------------------------------

-- One row per model call from any feature (ADR 085); the budget checks sum
-- cost_micro_usd over it. usage_reported = false means the provider sent no
-- usage and the token columns hold the worst-case charge, never a zero read as
-- a measurement. user_id is the user whose request made the call, '' for
-- unattended work.
CREATE TABLE llm_usage (
    id                 bigserial   PRIMARY KEY,
    ts                 timestamptz NOT NULL DEFAULT now(),
    purpose            text        NOT NULL,  -- chat | reason | adjudicate | nl_query | …
    interactive        boolean     NOT NULL,  -- a person is waiting on the call
    provider           text        NOT NULL,
    model              text        NOT NULL,
    input_tokens       bigint      NOT NULL,
    output_tokens      bigint      NOT NULL,
    cache_read_tokens  bigint      NOT NULL,
    cache_write_tokens bigint      NOT NULL,
    usage_reported     boolean     NOT NULL,
    failed             boolean     NOT NULL,
    -- Estimated from the configured price table at write time, in millionths
    -- of a dollar so sums stay exact.
    cost_micro_usd     bigint      NOT NULL,
    user_id            text        NOT NULL DEFAULT ''
);

CREATE INDEX llm_usage_ts_idx ON llm_usage (ts);
CREATE INDEX llm_usage_user_ts_idx ON llm_usage (user_id, ts) WHERE user_id <> '';

-- +goose Down
DROP TABLE llm_usage;
DROP TABLE intel_monitored_domains;
DROP TABLE saved_query_runs;
DROP TABLE saved_queries;
DROP TABLE alert_channels;
DROP TABLE automation_policy;
DROP TABLE action_outcomes;
DROP TABLE approval_link_nonces;
DROP TABLE executor_grant_redemptions;
DROP TABLE decision_executions;
DROP TABLE pattern_verdicts;
DROP TABLE decision_verdicts;
DROP TABLE finding_suppressions;
DROP TABLE reasoning_cache;
DROP TABLE enrich_logic_version;
DROP TABLE finding_alert_state;
DROP TABLE enrich_cache;
DROP TABLE scan_findings;
DROP TABLE scan_runs;
DROP TABLE scan_profiles;
DROP TABLE kev_added_events;
DROP TABLE kev_catalog;
DROP TABLE image_scan_state;
DROP TABLE osv_malfeed_watermark;
DROP TABLE osv_scanned_packages;
DROP TABLE cost_snapshots;
DROP TABLE forget_tombstones;
DROP TABLE forget_scope_state;
DROP TABLE asset_deletions;
DROP TABLE aws_org_accounts;
DROP TABLE connector_proven_capabilities;
DROP TABLE connector_asset_hashes;
DROP TABLE connectors;
DROP TABLE api_keys;
DROP TABLE sessions;
DROP TABLE users;
