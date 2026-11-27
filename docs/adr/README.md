# Architecture Decision Records

Each ADR records one decision and why. **Read the relevant ADR before changing anything it
covers** (CLAUDE.md). The overview that ties them together is
[`../architecture.md`](../architecture.md); when a doc and the code disagree, the code wins.

## Start here

New to the codebase? These explain most of how the system is shaped:

1. [001](001-single-binary.md) — one Go binary, single-tenant, self-hosted
2. [003](003-postgres-clickhouse.md) — Postgres for transactional state, ClickHouse as the source of truth
3. [010](010-enforced-layering.md) — the domain layering, and which parts the linter enforces
4. [025](025-graph-topology-and-reachability.md) — graph topology and computed internet reachability
5. [048](048-graphschema-registry.md) — `internal/graphschema`, the single source of truth for edges
6. [049](049-graph-edge-staleness.md) — edges are re-stamped, never deleted; every reader filters on freshness
7. [074](074-ladybug-rebuild-gate-is-a-content-digest.md) and [077](077-rebuild-fidelity-gate.md) — when the in-memory graph is rebuilt, and when a rebuild is refused
8. [080](080-unmeasured-is-not-zero.md) — unmeasured evidence is unknown, never zero
9. [084](084-provider-neutral-llm-seam.md) — the provider-neutral LLM seam
10. [087](087-no-autonomous-remediation.md) — no autonomous remediation: Vulngraph proposes, a person approves
11. [095](095-upstream-ladybugdb.md) — LadybugDB is linked unmodified from a pinned upstream release

## Index

Status key: **accepted** · **amended** (accepted, then extended in place; see the ADR's status
line and tail) · **superseded in part by NNN** (the named part no longer holds; the ADR's header
says which) · **partially implemented** · **not implemented** · **proposed** · **retired** (number
unused). Each ADR's own status line carries the dates and detail.

| # | Title | Status |
|---|---|---|
| [001](001-single-binary.md) | Single Go binary, single-tenant, self-hosted | amended |
| [002](002-river-not-temporal.md) | River job queue replaces Temporal | superseded in part by 087 |
| [003](003-postgres-clickhouse.md) | Postgres + ClickHouse; graph lives in ClickHouse | superseded in part by 025, 026 |
| [004](004-anthropic-direct.md) | Anthropic Go SDK called directly | amended by 084 |
| [005](005-decaying-memory-not-a-neural-model.md) | Decaying outcome memory replaces a per-tenant neural model | superseded in part by 087 |
| [006](006-embedded-opa.md) | OPA embedded as a Go library | superseded (the gate is the Go function `policy.Decide`; OPA is no longer a dependency) |
| [007](007-clouds-and-cis-scope.md) | AWS + GCP + GitHub only; focused CIS check set | amended |
| [008](008-no-monitoring-stack.md) | No monitoring/error-tracking stack | superseded in part by 037 |
| [009](009-embedded-nuclei-sdk.md) | Nuclei embedded via its official Go SDK | accepted |
| [010](010-enforced-layering.md) | Layering: import bans lint-enforced, the rest in review | accepted |
| [011](011-mcp-first-a2a-deferred.md) | MCP server in the binary; A2A deferred | superseded in part by 015 |
| [012](012-supply-chain-first-class.md) | Supply chain is a first-class domain | accepted |
| [013](013-hybrid-sync.md) | Hybrid sync: reconciliation + event freshness | amended |
| [014](014-enrichment-stage.md) | Enrichment: findings scored in context | superseded in part by 075 |
| [015](015-mcp-write-tools.md) | MCP write tools: session-role-gated | accepted |
| [016](016-oidc-cloud-auth.md) | Cloud auth is OIDC / workload-identity federation | amended |
| [017](017-openapi-spec.md) | OpenAPI spec as the API contract | amended |
| [018](018-findings-pagination.md) | Keyset pagination for findings | amended |
| [019](019-compliance-reporting-and-evidence.md) | Compliance reporting with frozen evidence | not implemented |
| [020](020-context-aware-active-scanning.md) | Context-aware active scanning | partially implemented |
| [021](021-change-driven-context-aware-reasoning.md) | Change-driven, context-aware reasoning | accepted |
| [022](022-incremental-diff-sync.md) | Incremental, diff-based sync | amended |
| [023](023-asset-provenance.md) | Asset provenance | accepted |
| [024](024-change-driven-enrichment.md) | Change-driven enrichment | amended |
| [025](025-graph-topology-and-reachability.md) | Graph topology and computed reachability | accepted |
| [026](026-ciem-and-ladybug-graph-schema.md) | CIEM privilege escalation in Ladybug | amended |
| [027](027-detection-as-code.md) | Detection-as-code (scheduled Cypher) | accepted |
| [028](028-drift-change-history.md) | Per-field drift change history | amended |
| [029](029-multi-framework-compliance.md) | Multi-framework compliance mapping | accepted |
| [030](030-agentic-first-decision-pipeline.md) | Decision → govern → execute pipeline (autonomous path withdrawn by 087) | superseded in part by 087 |
| [031](031-unified-identity-graph.md) | Unified identity graph (human identities) | accepted |
| [032](032-dspm-data-classification.md) | DSPM: heuristic data classification | amended |
| [033](033-outbound-alerting.md) | Outbound alerting (notify) | amended |
| [034](034-agentless-scanning-scope.md) | Agentless workload scanning: scope | amended |
| 035 | Number retired. | retired |
| [036](036-read-only-cypher-trust-model.md) | Read-only Cypher trust model + single validator | accepted |
| [037](037-observability.md) | Vendor-neutral observability (metrics + tracing) | amended |
| [038](038-reasoning-eval-harness.md) | Reasoning evaluation harness (golden-set gate; manual, coarse, single-sample) | amended |
| [039](039-attack-path-narratives.md) | Deterministic attack-path narratives | accepted |
| [040](040-operator-auth-and-sso.md) | Operator authn/authz + SSO (Okta) | partially implemented |
| [041](041-ladybug-serve-worker-rpc.md) | Ladybug serve/worker split + internal RPC seam | amended |
| [042](042-prompt-injection-posture.md) | Prompt-injection posture | amended by 095 |
| [043](043-safe-to-fix-signal.md) | "Safe to fix" signal computed at enrich time | superseded in part by 075 |
| [044](044-must-fix-prioritization.md) | Evidence-backed "must fix" prioritization (reachability + controls + age) | superseded in part by 075 |
| [045](045-live-verification-read-only.md) | Live finding verification is read-only | accepted |
| [046](046-graph-scalar-results.md) | Graph queries carry scalar and tabular results | accepted |
| [047](047-dspm-graph-data-layer.md) | DSPM is a data layer of the attack graph | amended |
| [048](048-graphschema-registry.md) | `internal/graphschema`: single source of truth for the edge pipeline | amended |
| [049](049-graph-edge-staleness.md) | Graph edge staleness: re-stamp + 48h freshness filter, no deletes | amended |
| [050](050-signal-fidelity-tiers.md) | Signal fidelity: confirmed vs possible exposure, IAM inbound assumability | amended |
| [051](051-verification-fabric.md) | Verification fabric: confidence by corroboration across sensors | partially implemented |
| [052](052-ciem-unified-core.md) | One CIEM core: collapse the two privesc engines | amended |
| [053](053-continuous-severity-adjudication.md) | Continuous severity adjudication | partially implemented |
| [054](054-finding-lifecycle.md) | Finding lifecycle: sync-time auto-resolution | amended |
| [055](055-dangling-finding-sweep.md) | Dangling-finding resolve sweep | accepted |
| [056](056-k8s-reachability-edges.md) | Kubernetes internet reachability: exposure-chain edges | accepted |
| [057](057-image-vulnerability-scanning.md) | Container-image vulnerability scanning | amended |
| [058](058-k8s-workload-assets.md) | Kubernetes workload assets: StatefulSet, DaemonSet, Job | accepted |
| [059](059-band-floor-family.md) | The band-floor family: deterministic score floors and the hygiene ceiling | accepted |
| [060](060-reachability-gate-widening.md) | Reachability gate widening for network resources | accepted |
| [061](061-iac-graph-correlation.md) | IaC → graph correlation by deterministic join keys | amended |
| [062](062-cloud-ladybug-sync-fidelity.md) | Cloud → Ladybug sync fidelity: three silent-drop gaps closed | accepted |
| [063](063-ci-workflow-federation.md) | CI-workflow → cloud-identity federation | accepted |
| 064 | Number retired. | retired |
| [065](065-terraform-state-ownership.md) | Terraform-state ownership (address-confirmed, high confidence) | amended |
| [066](066-scp-permission-boundary-caps.md) | SCP + permission-boundary caps for CIEM effective permissions | amended |
| [067](067-scoring-integrity-pipeline.md) | Scoring-integrity pipeline: fix reach-poisoning at the source | amended |
| [068](068-policy-scope-and-liveness-semantics.md) | Policy scope/deny semantics, and liveness vs row-presence | amended |
| [069](069-enrichment-version-full-pass.md) | Version-triggered full re-enrichment | accepted |
| [070](070-identifier-harvest-ownership.md) | Map IAM-as-code by harvesting identifiers, not by per-tool parsers | accepted |
| [071](071-worker-memory-budget.md) | The worker memory budget: GOMEMLIMIT bounds Go, the cgroup kills the process | amended |
| [072](072-cluster-identity-is-discovered-not-configured.md) | A cluster's identity is discovered, not configured | accepted |
| [073](073-connector-force-resync.md) | Force a connector to resync from scratch | proposed |
| [074](074-ladybug-rebuild-gate-is-a-content-digest.md) | The Ladybug rebuild gate is a content digest, not a version counter | amended |
| [075](075-enrichment-write-ownership.md) | Enrichment write ownership: one writer per column | partially implemented |
| [076](076-negative-factors-clamp-order.md) | Negative score factors are spent against a clamped positive subtotal | accepted |
| [077](077-rebuild-fidelity-gate.md) | A rebuild publishes only a graph it can vouch for | amended |
| [078](078-inventory-reads-are-gated.md) | Inventory reads are gated: live resources, counted by id | accepted |
| [079](079-identity-census-is-computed-server-side.md) | The identity census is computed server-side | accepted |
| [080](080-unmeasured-is-not-zero.md) | Unmeasured is not zero: gate evidence carries its known-ness | superseded in part by 087 |
| [081](081-deletion-authority-shadow-mode.md) | Deletion authority: shadow mode by default, enforcement per named type | amended |
| [082](082-pattern-verdicts-suppress-reasking.md) | A pattern verdict stops re-asking but is never standing consent | superseded in part by 087 |
| [083](083-sync-deletion-scope-unification.md) | Sync's deletion path gets ADR 081's scope discipline | partially implemented |
| [084](084-provider-neutral-llm-seam.md) | Provider-neutral LLM seam (`internal/llm`) | accepted |
| [085](085-agent-runtime.md) | Agent runtime: declarative, budgeted, audited agents | proposed (runtime not implemented); superseded in part by 087 |
| [086](086-first-party-agents.md) | First-party agents and the closed loop | proposed (design only) |
| [087](087-no-autonomous-remediation.md) | No autonomous remediation: Vulngraph proposes, a person says yes | amended |
| [088](088-container-base-image-root-cause.md) | Container base images: identify, grade, group, recommend | amended |
| [089](089-ownership-and-routing.md) | Ownership and routing: one owner per asset, routed by channel scope | amended |
| [090](090-cspm-benchmark-matrix.md) | CSPM coverage is measured control by control against public benchmarks | accepted |
| [091](091-aws-org-onboarding.md) | AWS Organization onboarding: one StackSet, one org connector | accepted |
| [092](092-benchmark-freshness.md) | Benchmark matrices are checked against their upstream lists | accepted |
| [093](093-requirement-level-compliance-frameworks.md) | Compliance frameworks are rolled up per requirement | accepted |
| [094](094-node-posture-reader.md) | Kubernetes control-plane and node posture without new privileges | accepted |
| [095](095-upstream-ladybugdb.md) | Run upstream LadybugDB, unmodified | accepted |
| [096](096-opt-in-vm-disk-scanning.md) | Opt-in VM disk scanning, and the one cloud write it needs | accepted |

| [097](097-retire-external-scanning.md) | Retire active external scanning; preserve opt-in disk inventory | accepted |

| [098](098-precise-storage-versions.md) | Precise storage versions and verified resumable upgrades | accepted |
