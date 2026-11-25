// TanStack Query hooks + mutations over the typed api client. queryOptions-style
// factories keep keys and fetchers colocated.
import { queryOptions, useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { clearChatStorage } from "./chatStorage";
import {
  api,
  APIError,
  type APIKey,
  type Asset,
  type Belief,
  type RemediationPolicy,
  type UpdatePolicyPayload,
  type AssetDiskScan,
  type AssetPage,
  type AssetSummary,
  type BlastRadius,
  type ScanRunFindings,
  type ComplianceCoverage,
  type ComplianceFramework,
  type ComplianceFrameworkList,
  type Connector,
  type ConnectorDiskScan,
  type DiskScanMode,
  type OrgAccount,
  type OrgTestReport,
  type CreateAPIKeyPayload,
  type CreateAPIKeyResponse,
  type CreateConnectorPayload,
  type CreateUserPayload,
  type DecisionPage,
  type DriftAnalysis,
  type DriftAnalysisList,
  type FindingContext,
  type FindingCluster,
  type QueueItem,
  type FindingPage,
  type FindingSummary,
  type GraphStats,
  type GraphStatus,
  type IdentityCensus,
  type LLMUsageSummary,
  type ScanProfile,
  type ScanRun,
  type TemplateValidation,
  type Suppression,
  type User,
  type UserList,
} from "./api";

export const meQuery = queryOptions({
  queryKey: ["me"],
  queryFn: () => api.get<User>("/api/auth/me"),
  retry: false,
  // The session's identity/role doesn't change mid-visit — without a staleTime
  // every route mount refired /api/auth/me (observed: one per navigation).
  staleTime: 5 * 60_000,
});

export function useMe() {
  return useQuery(meQuery);
}

// useIsAdmin reports whether the current session is an admin — the single gate
// the UI uses to show write actions. Reads from the cached `me` query.
export function useIsAdmin() {
  return useMe().data?.role === "admin";
}

export function useAuthProviders() {
  return useQuery({
    queryKey: ["auth-providers"],
    queryFn: () => api.get<Array<{ id: string; name: string }>>("/api/auth/providers"),
    retry: false,
    staleTime: Infinity,
  });
}

export function useLogin() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (creds: { email: string; password: string; totp_code?: string }) =>
      api.post<User>("/api/auth/login", creds),
    // A 401 here is "credentials rejected", not session expiry.
    meta: { skipAuthRedirect: true },
    onSuccess: () => {
      // Drop anything cached under the previous session (possibly another
      // user's data) before the shell re-mounts its pages.
      qc.removeQueries({ predicate: (q) => q.queryKey[0] !== "me" && q.queryKey[0] !== "auth-providers" });
      return qc.invalidateQueries({ queryKey: ["me"] });
    },
  });
}

// useSessionExpired is true when the login screen is showing because a
// request came back 401 mid-session (set by lib/queryClient.ts).
export function useSessionExpired() {
  const q = useQuery({ queryKey: ["session-expired"], queryFn: () => false, enabled: false, staleTime: Infinity });
  return q.data === true;
}

export function useLogout() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.post<void>("/api/auth/logout"),
    // Chat history goes even if the server call fails: the person asked to
    // leave this browser, and the transcript can quote live cloud data.
    onSettled: () => clearChatStorage(),
    onSuccess: () => qc.clear(),
  });
}

// ── Findings ────────────────────────────────────────────────────────────────

export interface FindingFilter {
  source?: string;
  severity?: string;
  resource_id?: string;
  check_id?: string;
  min_score?: number;
  sort?: "score" | "detected";
  safe?: boolean; // only structurally safe-to-fix findings (the "start here" worklist)
  must_fix?: boolean; // only evidence-backed must-fix findings (the "must fix now" worklist)
  owner?: string; // owner team, or "unowned" (server-side; ADR 089)
  environment?: string; // prod | staging | dev | unknown (server-side)
  limit?: number; // page size; the API caps it. Used for cheap probes, not just paging.
}

// useFindings pages through findings with keyset pagination: each page
// carries a next_cursor, fed back as ?cursor= for the following page.
export function useFindings(filter: FindingFilter = {}) {
  return useInfiniteQuery({
    queryKey: ["findings", filter],
    initialPageParam: "",
    retry: false,
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams();
      if (filter.source) params.set("source", filter.source);
      if (filter.severity) params.set("severity", filter.severity);
      if (filter.resource_id) params.set("resource_id", filter.resource_id);
      if (filter.check_id) params.set("check_id", filter.check_id);
      if (filter.min_score) params.set("min_score", String(filter.min_score));
      if (filter.sort === "detected") params.set("sort", "detected");
      if (filter.safe) params.set("safe", "true");
      if (filter.must_fix) params.set("must_fix", "true");
      if (filter.owner) params.set("owner", filter.owner);
      if (filter.environment) params.set("environment", filter.environment);
      if (filter.limit) params.set("limit", String(filter.limit));
      if (pageParam) params.set("cursor", pageParam);
      const qs = params.toString();
      return api.get<FindingPage>(`/api/findings${qs ? `?${qs}` : ""}`);
    },
    getNextPageParam: (last) => last.next_cursor || undefined,
  });
}

// useFindingClusters fetches findings grouped by check (worst-score first) — the
// triage view that collapses thousands of instances into the few dozen real issues.
export function useFindingClusters(source?: string) {
  return useQuery({
    queryKey: ["finding-clusters", source ?? ""],
    // total_checks/truncated: the server caps items at 500 — the UI must
    // disclose truncation, never present items.length as the population.
    queryFn: () =>
      api.get<{ items: FindingCluster[]; total_checks: number; truncated: boolean }>(
        `/api/findings/clusters${source ? `?source=${encodeURIComponent(source)}` : ""}`,
      ),
  });
}

// useFindingSummary fetches aggregate counts (total + by severity/band) over ALL
// current findings — the true totals the overview leads on, not a single page.
export function useFindingSummary() {
  return useQuery({
    queryKey: ["finding-summary"],
    queryFn: () => api.get<FindingSummary>("/api/findings/summary"),
  });
}

export function useFinding(id: string) {
  return useQuery({
    queryKey: ["finding", id],
    queryFn: () => api.get<FindingContext>(`/api/findings/${encodeURIComponent(id)}`),
    enabled: !!id,
  });
}

// useBelief fetches the belief engine's grounded true-severity belief for a
// finding. Not every finding has one yet (only enriched findings form a
// belief), so a 404 resolves to null rather than surfacing as an error — the panel
// simply renders nothing.
export function useBelief(id: string) {
  return useQuery({
    queryKey: ["belief", id],
    queryFn: async (): Promise<Belief | null> => {
      try {
        return await api.get<Belief>(`/api/beliefs/${encodeURIComponent(id)}`);
      } catch (e) {
        if (e instanceof APIError && e.status === 404) return null;
        throw e;
      }
    },
    enabled: !!id,
    retry: false,
    staleTime: 60 * 1000,
  });
}

export function useSuppressions() {
  return useQuery({ queryKey: ["suppressions"], queryFn: () => api.get<Suppression[]>("/api/suppressions") });
}

// Suppressing/unsuppressing/resolving flips is_suppressed (or removes the
// finding) everywhere it is shown: the lists, the single-finding detail (the
// panel's Suppress/Unsuppress toggle reads it), the totals and the clustered
// view, plus the suppressions list.
function invalidateFindings(qc: ReturnType<typeof useQueryClient>) {
  return Promise.all(
    ["findings", "finding", "finding-summary", "finding-clusters", "suppressions"].map((k) =>
      qc.invalidateQueries({ queryKey: [k] }),
    ),
  );
}

// Every suppression expires: expiresAt (RFC 3339) is required by the API.
export function useSuppressFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, reason, expiresAt }: { id: string; reason: string; expiresAt: string }) =>
      api.post<Suppression>(`/api/findings/${encodeURIComponent(id)}/suppress`, { reason, expires_at: expiresAt }),
    onSuccess: () => invalidateFindings(qc),
  });
}

// Renew a suppression: records the review and moves the expiry. Also
// re-instates an expired one.
export function useReviewSuppression() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, expiresAt }: { id: string; expiresAt: string }) =>
      api.post<Suppression>(`/api/findings/${encodeURIComponent(id)}/suppress/review`, { expires_at: expiresAt }),
    onSuccess: () => invalidateFindings(qc),
  });
}

export function useUnsuppressFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.del<void>(`/api/findings/${encodeURIComponent(id)}/suppress`),
    onSuccess: () => invalidateFindings(qc),
  });
}

// Manual resolve — the human-driven counterpart to sync-time auto-resolve,
// for closing the loop after a "Verify live" check refutes a
// finding the emitting check hasn't re-synced away yet.
export function useResolveFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.post<{ id: string; resolved_at: string }>(`/api/findings/${encodeURIComponent(id)}/resolve`, { reason }),
    onSuccess: () => invalidateFindings(qc),
  });
}

// Bulk suppress/unsuppress — the team-triage path. One call for a whole
// selection instead of N round-trips.
export function useBulkSuppress() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ ids, reason, expiresAt }: { ids: string[]; reason: string; expiresAt: string }) =>
      api.post<{ applied: number }>("/api/suppressions/bulk", { finding_ids: ids, reason, expires_at: expiresAt }),
    onSuccess: () => invalidateFindings(qc),
  });
}

export function useBulkUnsuppress() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (ids: string[]) =>
      api.post<{ applied: number }>("/api/suppressions/bulk-remove", { finding_ids: ids }),
    onSuccess: () => invalidateFindings(qc),
  });
}

// ── Assets ──────────────────────────────────────────────────────────────────

export interface AssetFilter {
  provider?: string;
  type?: string;
  region?: string;
  q?: string;
  sort?: "risk";
  exposed?: boolean;   // only internet-facing assets
  minScore?: number;   // only assets with risk_score >= minScore
}

// useAssets pages through the inventory with keyset pagination, filtered by
// provider/type/region/search — so the list is navigable, not a 50k-row dump.
export function useAssets(filter: AssetFilter = {}) {
  return useInfiniteQuery({
    queryKey: ["assets", filter],
    initialPageParam: "",
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams();
      if (filter.provider) params.set("provider", filter.provider);
      if (filter.type) params.set("type", filter.type);
      if (filter.region) params.set("region", filter.region);
      if (filter.q) params.set("q", filter.q);
      if (filter.sort) params.set("sort", filter.sort);
      if (filter.exposed) params.set("exposed", "true");
      if (filter.minScore) params.set("min_score", String(filter.minScore));
      if (pageParam) params.set("cursor", pageParam);
      const qs = params.toString();
      return api.get<AssetPage>(`/api/assets${qs ? `?${qs}` : ""}`);
    },
    getNextPageParam: (last) => last.next_cursor || undefined,
  });
}

// useAssetSummary fetches inventory counts by provider/type — drives the filters.
export function useAssetSummary() {
  return useQuery({
    queryKey: ["asset-summary"],
    queryFn: () => api.get<AssetSummary>("/api/assets/summary"),
  });
}

// useIdentityCensus fetches the backend's identity census: distinct people
// (deduplicated across accounts), workload identities across every cloud, and
// the IAM role split by purpose.
//
// The headlines must not be derived in the browser from
// useAssetSummary().by_type: rows are not people (multiple IAM rows can belong
// to one deduplicated person, and some rows are root principals, not people at
// all) and one provider's service accounts are not every cloud's workload
// identities. Those judgements need principal metadata and the graph's
// executes_as edges, so they live server-side.
export function useIdentityCensus() {
  return useQuery({
    queryKey: ["identity-census"],
    queryFn: () => api.get<IdentityCensus>("/api/identity/summary"),
  });
}

// useLLMUsage fetches this month's LLM spend against the monthly budgets
// (admin-only on the server, so it is only enabled for admins).
export function useLLMUsage(enabled: boolean) {
  return useQuery({
    queryKey: ["llm-usage"],
    queryFn: () => api.get<LLMUsageSummary>("/api/llm/usage"),
    enabled,
  });
}

export function useAsset(id: string) {
  return useQuery({
    queryKey: ["asset", id],
    queryFn: () => api.get<Asset>(`/api/assets/${encodeURIComponent(id)}`),
    enabled: !!id,
  });
}

// useBlastRadius fetches the reachability graph for an asset. direction picks
// "out" (what this asset can reach — default), "in" (what can reach it), or "both".
export function useBlastRadius(id: string, direction: "out" | "in" | "both" = "out") {
  return useQuery({
    queryKey: ["blast-radius", id, direction],
    queryFn: () => api.get<BlastRadius>(`/api/assets/${encodeURIComponent(id)}/blast-radius?direction=${direction}`),
    enabled: !!id,
  });
}

// ── Drift ──────────────────────────────────────────────────────────────────

export interface DriftEvent {
  // Real kinds — internal/app/asset/drift.go:20-23. "field_changed" is never
  // emitted; that member was stray.
  kind: "new_asset" | "new_exposure" | "removed_exposure" | "changed";
  asset_id: string;    // full ARN (AWS) or resource name (GCP) — use as identifier
  asset_name: string;
  asset_type: string;
  provider: string;
  account_id: string;  // AWS account ID or GCP project ID
  region?: string;
  public_ip?: string;
  private_ip?: string;
  domain?: string;     // DNS name if known
  endpoint?: string;   // URL or hostname
  detected_at: string;
  // Enriched fields
  findings_count: number;   // 0 if none (only when findings_known)
  max_score: number;        // 0 if none (only when findings_known)
  findings_known: boolean;  // false: the findings lookup failed — counts are unknown, not zero
  why?: string;             // human-readable explanation from backend
  old_value?: string;       // what it was before
  new_value?: string;       // what it is now
  field?: string;           // what field changed
}

export function useDriftEvents(since = "24h") {
  return useQuery({
    queryKey: ["drift-events", since],
    queryFn: () => api.get<{ events: DriftEvent[] }>(`/api/drift/events?since=${since}`),
    staleTime: 2 * 60 * 1000, // 2 min — drift data changes at sync cadence
  });
}

export type { DriftAnalysis, DriftAnalysisList };

// Advisory LLM reading of drift batches. enabled:false means no analysis runs;
// it is not a verdict on any change.
export function useDriftAnalyses(since = "24h") {
  return useQuery({
    queryKey: ["drift-analyses", since],
    queryFn: () => api.get<DriftAnalysisList>(`/api/drift/analyses?since=${since}`),
    staleTime: 2 * 60 * 1000,
  });
}

// ── Domain monitoring (Intel) ───────────────────────────────────────────────

export interface MonitoredDomain {
  id: string;
  domain: string;
  created_at: string;
}

export interface PhishingCandidate {
  id: string;
  domain: string;
  monitored_domain: string;
  source: string;
  similarity_score: number;
  issuer: string;
  not_before: string;
  not_after: string;
  status: "pending" | "dismissed" | "confirmed" | "auto_dismissed";
  ai_confidence: number;
  ai_reasoning: string;
  triage_source: "llm" | "heuristic" | ""; // what produced the ai_* verdict
  cleared_by: "triage" | "rescore" | ""; // why it is auto_dismissed
  detected_at: string;
  confirmed_by?: string;
  confirmed_at?: string;
}

export function useMonitoredDomains() {
  return useQuery({
    queryKey: ["intel-domains"],
    queryFn: () => api.get<{ domains: MonitoredDomain[] }>("/api/intel/domains"),
  });
}

export function useAddMonitoredDomain() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (domain: string) => api.post<MonitoredDomain>("/api/intel/domains", { domain }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["intel-domains"] }),
  });
}

export function useRemoveMonitoredDomain() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (domain: string) => api.del<void>(`/api/intel/domains/${encodeURIComponent(domain)}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["intel-domains"] }),
  });
}

export function usePhishingCandidates(status = "pending") {
  return useQuery({
    queryKey: ["phishing-candidates", status],
    queryFn: () =>
      api.get<{ candidates: PhishingCandidate[]; total: number }>(
        `/api/intel/phishing?status=${encodeURIComponent(status)}`,
      ),
    staleTime: 2 * 60 * 1000,
  });
}

export function useConfirmPhishing() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.post<void>(`/api/intel/phishing/${encodeURIComponent(id)}/confirm`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["phishing-candidates"] }),
  });
}

export function useDismissPhishing() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.post<void>(`/api/intel/phishing/${encodeURIComponent(id)}/dismiss`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["phishing-candidates"] }),
  });
}

// ── Alert channels (Slack) ──────────────────────────────────────────────────

export interface AlertChannel {
  id: string;
  type: string;
  name: string;
  channel: string;
  enabled: boolean;
  event_types: string[];
  severities: string[];
  min_score: number;
  owner_teams: string[]; // empty = no owner scope
  environments: string[]; // empty = no environment scope
  route_unowned: boolean; // default channel for unowned findings
  last_delivered_at?: string;
  last_status?: string;
  last_error?: string;
  has_token: boolean;
  unwired_event_types?: string[]; // routed event types nothing emits yet
}

export interface AlertChannelList {
  channels: AlertChannel[];
  unwired_event_types: string[]; // routable event types nothing emits yet
}

export interface AlertChannelInput {
  type: string;
  name: string;
  channel: string;
  bot_token?: string; // slack; omitted on update = keep existing
  webhook_url?: string; // webhook; omitted on update = keep existing
  enabled: boolean;
  event_types: string[];
  severities: string[];
  min_score: number;
  owner_teams: string[];
  environments: string[];
  route_unowned: boolean;
}

export function useAlertChannels() {
  return useQuery({
    queryKey: ["alert-channels"],
    queryFn: () => api.get<AlertChannelList>("/api/alerts/channels"),
  });
}

export function useCreateAlertChannel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: AlertChannelInput) => api.post<AlertChannel>("/api/alerts/channels", input),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["alert-channels"] }),
  });
}

export function useUpdateAlertChannel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, input }: { id: string; input: AlertChannelInput }) =>
      api.put<AlertChannel>(`/api/alerts/channels/${encodeURIComponent(id)}`, input),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["alert-channels"] }),
  });
}

export function useDeleteAlertChannel() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.del<void>(`/api/alerts/channels/${encodeURIComponent(id)}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["alert-channels"] }),
  });
}

export function useTestAlertChannel() {
  return useMutation({
    mutationFn: (id: string) => api.post<{ ok: boolean }>(`/api/alerts/channels/${encodeURIComponent(id)}/test`),
  });
}

// ── Saved queries (Cypher detection-as-code) ────────────────────────────────

export interface SavedQuery {
  id: string;
  name: string;
  description: string;
  cypher: string;
  created_by?: string;
  schedule: string; // cron expr; "" = manual
  schedule_error?: string; // set when a stored schedule can never fire
  alert_channel_ids: string[];
  alert_on_change: boolean;
  enabled: boolean;
  // last_run_at / last_result_count are the change-detection baseline: they
  // move only on a good scheduled run, never on a manual or failed one.
  last_run_at?: string;
  last_result_count: number;
  // The newest run of any outcome; absent when the query never ran.
  last_attempt_at?: string;
  last_attempt_status?: "ok" | "truncated" | "incomplete" | "failed";
  last_attempt_error?: string;
  last_attempt_trigger?: "manual" | "schedule";
}

export interface SavedQueryInput {
  name: string;
  description: string;
  cypher: string;
  schedule: string;
  alert_channel_ids: string[];
  alert_on_change: boolean;
  enabled: boolean;
}

export function useSavedQueries() {
  return useQuery({
    queryKey: ["saved-queries"],
    queryFn: () => api.get<{ queries: SavedQuery[] }>("/api/saved-queries"),
  });
}

export function useCreateSavedQuery() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: SavedQueryInput) => api.post<SavedQuery>("/api/saved-queries", input),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["saved-queries"] }),
  });
}

export function useDeleteSavedQuery() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.del<void>(`/api/saved-queries/${encodeURIComponent(id)}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["saved-queries"] }),
  });
}

export function useRunSavedQuery() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api.post<{ node_count: number; edge_count: number; error: string }>(
        `/api/saved-queries/${encodeURIComponent(id)}/run`,
      ),
    // A failed run is recorded too, so the list refetches either way.
    onSettled: () => qc.invalidateQueries({ queryKey: ["saved-queries"] }),
  });
}

// ── Asset change history (drift timeline) ───────────────────────────────────

export interface AssetChange {
  field: string;
  old_value: string;
  new_value: string;
  changed_at: string;
}

export function useAssetChanges(id: string) {
  return useQuery({
    queryKey: ["asset-changes", id],
    queryFn: () => api.get<{ changes: AssetChange[] }>(`/api/assets/${encodeURIComponent(id)}/changes`),
    enabled: !!id,
  });
}

// ── Scans ─────────────────────────────────────────────────────────────────

export function useScans() {
  return useQuery({ queryKey: ["scans"], queryFn: () => api.get<ScanRun[]>("/api/scans") });
}

export function useScan(id: string) {
  return useQuery({
    queryKey: ["scan", id],
    queryFn: () => api.get<ScanRun>(`/api/scans/${encodeURIComponent(id)}`),
    enabled: !!id,
  });
}

export function useTriggerScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.post<void>("/api/scans"),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });
}

export function useCancelScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.del<void>(`/api/scans/${encodeURIComponent(id)}`),
    onSuccess: (_data, id) =>
      Promise.all([
        qc.invalidateQueries({ queryKey: ["scans"] }),
        qc.invalidateQueries({ queryKey: ["scan", id] }),
      ]),
  });
}

export function useScanFindings(id: string) {
  return useQuery({
    queryKey: ["scan-findings", id],
    queryFn: () => api.get<ScanRunFindings>(`/api/scans/${encodeURIComponent(id)}/findings`),
    enabled: !!id,
  });
}

export function useValidateTemplate() {
  return useMutation({
    mutationFn: (yaml: string) =>
      api.post<TemplateValidation>("/api/scans/templates/validate", { yaml }),
  });
}

export function useTestTemplate() {
  return useMutation({
    mutationFn: ({ yaml, target }: { yaml: string; target: string }) =>
      api.post<{ results: { template_id: string; name: string; severity: string; matched_url: string }[]; count: number; target: string }>(
        "/api/scans/templates/test", { yaml, target }
      ),
  });
}

export function useGenerateTemplate() {
  return useMutation({
    mutationFn: (description: string) =>
      api.post<{ yaml: string; validation: TemplateValidation; attempts: number }>(
        "/api/scans/templates/generate", { description }
      ),
  });
}

// ── Scan Profiles ────────────────────────────────────────────────────────────

export function useScanProfiles() {
  return useQuery({
    queryKey: ["scan-profiles"],
    queryFn: () => api.get<ScanProfile[]>("/api/scan-profiles"),
  });
}

// Fields sent to the backend CreateProfile / UpdateProfile handlers.
type ScanProfileWritePayload = Pick<
  ScanProfile,
  "name" | "description" | "template_tags" | "enabled" | "scanner_type" | "template_strategy" | "target_query" | "schedule" | "drift_enabled"
>;

export function useCreateScanProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: ScanProfileWritePayload) =>
      api.post<ScanProfile>("/api/scan-profiles", payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scan-profiles"] }),
  });
}

export function useUpdateScanProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...payload }: { id: string } & ScanProfileWritePayload) =>
      api.put<ScanProfile>(`/api/scan-profiles/${encodeURIComponent(id)}`, payload),
    onSuccess: (_data, { id }) => {
      qc.invalidateQueries({ queryKey: ["scan-profiles"] });
      qc.invalidateQueries({ queryKey: ["scan-profile", id] });
    },
  });
}

export function useDeleteScanProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.del<void>(`/api/scan-profiles/${encodeURIComponent(id)}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scan-profiles"] }),
  });
}

export function useTriggerProfileScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api.post<{ run_id: string }>(`/api/scan-profiles/${encodeURIComponent(id)}/trigger`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });
}

// Workflow preset catalog — target (WHO) and trigger (WHEN) presets for WorkflowBuilder.
export type TargetPreset = {
  id: string;
  label: string;
  description: string;
  query: string;
};

export type TriggerPreset = {
  id: string;
  label: string;
  description: string;
  schedule: string;
  drift_enabled: boolean;
};

export function useWorkflowPresets() {
  return useQuery({
    queryKey: ["workflow-presets"],
    queryFn: () => api.get<{ targets: TargetPreset[]; triggers: TriggerPreset[] }>("/api/workflows/presets"),
    staleTime: Infinity, // static catalog, never re-fetch
  });
}

// ── Connectors ──────────────────────────────────────────────────────────────

export function useConnectors() {
  return useQuery({ queryKey: ["connectors"], queryFn: () => api.get<Connector[]>("/api/connectors") });
}

export function useCreateConnector() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateConnectorPayload) => api.post<Connector>("/api/connectors", payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["connectors"] }),
  });
}

export function useDeleteConnector() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.del<void>(`/api/connectors/${encodeURIComponent(id)}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["connectors"] }),
  });
}

export function useSyncConnector() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.post<void>(`/api/connectors/${encodeURIComponent(id)}/sync`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["connectors"] }),
  });
}

export function useSetConnectorMode() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, mode }: { id: string; mode: "read_only" | "read_write" }) =>
      api.put<void>(`/api/connectors/${encodeURIComponent(id)}/mode`, { mode }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["connectors"] }),
  });
}

// useConnectorDiskScan reads one connector's disk scan opt-in and status (admin).
export function useConnectorDiskScan(id: string, enabled: boolean) {
  return useQuery({
    queryKey: ["connectors", id, "disk-scan"],
    queryFn: () => api.get<ConnectorDiskScan>(`/api/connectors/${encodeURIComponent(id)}/disk-scan`),
    enabled,
  });
}

// useSetConnectorDiskScan is the admin's standing approval for disk scanning.
// The server refuses anything but a signed-in admin and checks the typed
// confirmation sentence itself.
export function useSetConnectorDiskScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, mode, confirmation }: { id: string; mode: DiskScanMode; confirmation?: string }) =>
      api.put<void>(`/api/connectors/${encodeURIComponent(id)}/disk-scan`, { mode, confirmation }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["connectors"] }),
  });
}

// useAssetDiskScan reads what disk scanning knows about one VM. not_enabled and
// none mean the disk was not read: unknown, never clean.
export function useAssetDiskScan(id: string, enabled: boolean) {
  return useQuery({
    queryKey: ["asset", id, "disk-scan"],
    queryFn: () => api.get<AssetDiskScan>(`/api/assets/${encodeURIComponent(id)}/disk-scan`),
    enabled: enabled && !!id,
  });
}

// useOrgAccounts lists an aws_org connector's discovered accounts and the
// health of each account's child connector.
export function useOrgAccounts(id: string, enabled: boolean) {
  return useQuery({
    queryKey: ["connectors", id, "org-accounts"],
    queryFn: () => api.get<OrgAccount[]>(`/api/connectors/${encodeURIComponent(id)}/org-accounts`),
    enabled,
  });
}

// useTestConnector runs the aws_org connection test (live AWS calls).
export function useTestConnector() {
  return useMutation({
    mutationFn: (id: string) => api.post<OrgTestReport>(`/api/connectors/${encodeURIComponent(id)}/test`),
  });
}

// ── Governor queue / decisions / compliance ──────────────────────────────────

// useQueue fetches the decisions awaiting a human governor (parked/escalated),
// clustered worst-first — the "Your Queue" surface. actionClass filters
// server-side, ahead of the backend's pending-scan cap — mirrors
// useDecisionsInfinite's filter: it is part of queryKey, so switching it
// mounts a fresh query instead of re-filtering whatever page happened to
// already be loaded under the old key.
export function useQueue(actionClass?: string) {
  return useQuery({
    queryKey: ["queue", actionClass],
    queryFn: () => {
      const params = new URLSearchParams();
      if (actionClass) params.set("action_class", actionClass);
      const qs = params.toString();
      return api.get<{ items: QueueItem[] }>(`/api/queue${qs ? `?${qs}` : ""}`);
    },
  });
}

export interface ResolveInput {
  finding_ids: string[];
  cluster_key?: string;
  action_class?: string;
  verdict: "approved" | "risk_accepted" | "denied";
  note?: string;
}

// useResolveDecision records the governor's verdict on a queued cluster, then
// refreshes the queue + decision history.
export function useResolveDecision() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: resolveDecision,
    onSuccess: () => invalidateQueue(qc),
  });
}

export function resolveDecision(input: ResolveInput) {
  return api.post<void>("/api/queue/resolve", input);
}

export function invalidateQueue(qc: ReturnType<typeof useQueryClient>) {
  return Promise.all([
    qc.invalidateQueries({ queryKey: ["queue"] }),
    qc.invalidateQueries({ queryKey: ["decisions"] }),
  ]);
}

// useDecisions fetches the first page of the decision trail — for the Home peek
// (count + latest). The Decisions route uses useDecisionsInfinite for paging.
export function useDecisions() {
  return useQuery({ queryKey: ["decisions"], queryFn: () => api.get<DecisionPage>("/api/decisions") });
}

// DecisionsSummary mirrors GET /api/decisions/summary — whole-trail aggregates
// computed server-side. The Decisions banner and Home footer must use this,
// never a fold over loaded pages of the paginated list.
export type DecisionsSummary = {
  total: number;
  // Read-only observe decisions: nothing to approve, nothing executed.
  observed: number;
  escalated: number;
  parked_for_approval: number;
  quick_wins: number;
  unique_resources: number;
  action_classes: Record<string, number>;
  confidence_bands: Record<string, number>;
  // Decisions the agent stopped re-asking because a human already ruled on the
  // pattern. NOT escalations — the opposite.
  suppressed_by_verdict: number;
  // Tally of Decision.EscalationReason over the trail. Keys observed today:
  // policy_blocked (the gate escalated a destroy/isolate action regardless of
  // confidence), verification_concern (CoVe forced it), insufficient_confidence,
  // and pattern_denied (which rides on suppressed_by_verdict decisions, not
  // escalations — the UI must not fold it in with the others).
  // Treat as an open set — an unrecognized key must still render, never be
  // silently dropped.
  escalation_reasons: Record<string, number>;
  hotspots: {
    target_id: string;
    target_title?: string;
    target_resource?: string;
    count: number;
    latest: string;
  }[];
};

export function useDecisionsSummary() {
  return useQuery({
    queryKey: ["decisions", "summary"],
    queryFn: () => api.get<DecisionsSummary>("/api/decisions/summary"),
  });
}

// DecisionFilter narrows GET /api/decisions server-side. outcome accepts the
// raw outcome values plus the two UI-derived groupings the backend also
// understands: needs_action (escalated OR parked_for_approval) and
// safe_to_fix (DecisionsSummary's quick_wins predicate). actionClass ANDs
// with outcome.
export interface DecisionFilter {
  outcome?: string;
  actionClass?: string;
}

// useDecisionsInfinite keyset-pages the full (uncapped) decision trail,
// filtered server-side. The filter is part of queryKey, so switching it mounts
// a fresh paginated query (React Query's normal behavior) instead of
// re-filtering whatever pages happened to already be loaded under the old key:
// a page loaded under one filter (or none) must never be presented as if it
// were a complete answer to a different one.
export function useDecisionsInfinite(filter: DecisionFilter = {}) {
  return useInfiniteQuery({
    queryKey: ["decisions", "infinite", filter],
    initialPageParam: "",
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams();
      if (filter.outcome) params.set("outcome", filter.outcome);
      if (filter.actionClass) params.set("action_class", filter.actionClass);
      if (pageParam) params.set("cursor", pageParam);
      const qs = params.toString();
      return api.get<DecisionPage>(`/api/decisions${qs ? `?${qs}` : ""}`);
    },
    getNextPageParam: (last) => last.next_cursor || undefined,
    staleTime: 0,          // always re-fetch on mount — decisions change in real time
    refetchOnMount: true,
  });
}

export function useCompliance() {
  return useQuery({ queryKey: ["compliance"], queryFn: () => api.get<ComplianceCoverage>("/api/compliance") });
}

// Requirement-level compliance frameworks (ADR 093).
export function useComplianceFrameworks() {
  return useQuery({
    queryKey: ["compliance", "frameworks"],
    queryFn: () => api.get<ComplianceFrameworkList>("/api/compliance/frameworks"),
  });
}

export function useComplianceFramework(id: string | undefined) {
  return useQuery({
    queryKey: ["compliance", "frameworks", id],
    queryFn: () => api.get<ComplianceFramework>(`/api/compliance/frameworks/${encodeURIComponent(id ?? "")}`),
    enabled: !!id,
  });
}

// complianceExportURL is the auditor CSV download. A plain link carries the
// session cookie, so the browser saves the attachment itself.
export function complianceExportURL(id: string): string {
  return `/api/compliance/frameworks/${encodeURIComponent(id)}/export`;
}

export function useUsers() {
  return useQuery({ queryKey: ["users"], queryFn: () => api.get<UserList>("/api/users") });
}

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateUserPayload) => api.post<User>("/api/users", payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }),
  });
}

// ── API Keys ─────────────────────────────────────────────────────────────────

export function useAPIKeys() {
  return useQuery({ queryKey: ["api-keys"], queryFn: () => api.get<APIKey[]>("/api/keys") });
}

export function useCreateAPIKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateAPIKeyPayload) => api.post<CreateAPIKeyResponse>("/api/keys", payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["api-keys"] }),
  });
}

export function useDeleteAPIKey() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.del<void>(`/api/keys/${encodeURIComponent(id)}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["api-keys"] }),
  });
}

// ── Remediation policy ────────────────────────────────────────────────────────

export function useRemediationPolicy() {
  return useQuery({
    queryKey: ["remediation-policy"],
    queryFn: () => api.get<RemediationPolicy>("/api/policy"),
  });
}

export function useUpdatePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: UpdatePolicyPayload) => api.put<void>("/api/policy", payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["remediation-policy"] }),
  });
}

// ── Graph ──────────────────────────────────────────────────────────────────────

// useEscalationPaths counts the high-risk roles (risk score >= 70) a resource's
// role can assume. Risk score ranks findings and reachability, not the
// permissions a role holds. Uses RETURN target (not count()) so the Ladybug
// Cypher engine returns typed nodes that execCypher can process; the chain
// count is the number of distinct target nodes returned.
export function useEscalationPaths(resourceId: string | undefined) {
  return useQuery({
    queryKey: ["escalation-paths", resourceId ?? ""],
    enabled: !!resourceId,
    queryFn: async () => {
      // Escape the resource_id for safe inline substitution. resource_id values
      // are internal asset IDs (ARNs, URIs) — they may contain colons and slashes
      // but never double-quotes; replace any stray double-quote to be safe.
      const safeId = (resourceId ?? "").replace(/"/g, "");
      const cypher =
        `MATCH (n:Asset {id: "${safeId}"})-[:ExecutesAs|HasRole]->(r:IamRole)-[:CanAssume]->(target:IamRole) WHERE target.score >= 70 RETURN DISTINCT target LIMIT 100`;
      const res = await api.post<{ nodes: unknown[]; edges: unknown[]; truncated: boolean }>(
        "/api/graph/cypher",
        { query: cypher, max_nodes: 100, max_edges: 0 },
      );
      return { chains: res.nodes.length, truncated: res.truncated };
    },
    staleTime: 5 * 60 * 1000,
    retry: false,
  });
}

export function useGraphStatus() {
  return useQuery({
    queryKey: ["graph-status"],
    queryFn: () => api.get<GraphStatus>("/api/graph/status"),
    staleTime: 30 * 1000,
    retry: false,
  });
}

export function useGraphStats() {
  return useQuery({
    queryKey: ["graph-stats"],
    queryFn: () => api.get<GraphStats>("/api/graph/stats"),
    staleTime: 60 * 1000,
    retry: false,
  });
}

