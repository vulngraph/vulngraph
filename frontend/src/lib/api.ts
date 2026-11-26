// Typed client for the Vulngraph REST API. Session auth rides on the HttpOnly
// cookie, so every request sends credentials and never touches localStorage.
//
// Domain types are generated from the OpenAPI spec: run `bun run gen:api`
// to refresh `api.gen.ts` after a spec change. This barrel is the only place the
// app imports them from — never import from `api.gen` directly.

import type { components } from "./api.gen";

// APIError carries the HTTP status plus the server's problem `detail`.
// `message` is what the UI renders: 403 and 429 are rewritten into clear
// permission / rate-limit copy (the raw detail is still on `.detail`).
export class APIError extends Error {
  public detail: string;
  constructor(
    public status: number,
    message: string,
    opts: { detail?: string } = {},
  ) {
    super(message);
    this.detail = opts.detail ?? message;
  }
}

// FORBIDDEN_MESSAGE is the UI copy for any 403: the action needs a role the
// session doesn't have. Clear and actionable, instead of a bare "Forbidden".
export const FORBIDDEN_MESSAGE =
  "You don't have permission to do this — it needs a higher role. Ask an admin if you need access.";

// RATE_LIMITED_MESSAGE is the UI copy for a 429 whose body carries no detail.
export const RATE_LIMITED_MESSAGE = "Rate limited — try again shortly.";

// statusMessage is the user-facing text for a failed response: fixed copy for
// 403, the server's problem detail otherwise. A 429 keeps the server's detail
// when it sent one (a provider rate-limiting a connector says which), and falls
// back to fixed copy when it didn't.
function statusMessage(status: number, detail: string, fromServer: boolean): string {
  if (status === 403) return FORBIDDEN_MESSAGE;
  if (status === 429 && !fromServer) return RATE_LIMITED_MESSAGE;
  return detail;
}

export function isUnauthorized(e: unknown): boolean {
  return e instanceof APIError && e.status === 401;
}

export function isForbidden(e: unknown): boolean {
  return e instanceof APIError && e.status === 403;
}

// errorMessage turns anything thrown into UI copy. Never "[object Object]".
export function errorMessage(e: unknown, fallback = "Something went wrong — try again"): string {
  if (e instanceof Error && e.message) return e.message;
  if (typeof e === "string" && e) return e;
  return fallback;
}

// ── Session-expiry signal ───────────────────────────────────────────────────
// Code paths outside TanStack Query (raw streaming fetches) report a 401 here;
// AppShell subscribes and sends the user back to the login screen. Queries and
// mutations are covered by the QueryCache/MutationCache handlers in
// lib/queryClient.ts.
type UnauthorizedListener = () => void;
const unauthorizedListeners = new Set<UnauthorizedListener>();

export function onUnauthorized(fn: UnauthorizedListener): () => void {
  unauthorizedListeners.add(fn);
  return () => unauthorizedListeners.delete(fn);
}

export function notifyUnauthorized() {
  for (const fn of unauthorizedListeners) fn();
}

// rawFetchError builds the user-facing Error for a failed streamPost, reporting
// a 401 as session expiry and a 403 as a permission problem — the same
// treatment request() gives everything else.
async function rawFetchError(res: Response): Promise<Error> {
  if (res.status === 401) notifyUnauthorized();
  let serverDetail: string | undefined;
  try {
    const body = await res.json();
    serverDetail = body.detail ?? body.error;
  } catch {
    /* non-JSON */
  }
  const detail = serverDetail ?? `HTTP ${res.status}`;
  return new APIError(res.status, statusMessage(res.status, detail, serverDetail != null), { detail });
}

interface RequestOptions {
  signal?: AbortSignal;
}

// streamPost POSTs a JSON body and returns the in-flight response body, for
// the SSE endpoints (chat, decision refine): request() awaits a single
// res.json() and cannot hand back a reader. A failed request throws the same
// APIError treatment request() gives.
export async function streamPost(
  path: string,
  body: unknown,
  options?: RequestOptions,
): Promise<ReadableStream<Uint8Array>> {
  const res = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: options?.signal,
  });
  if (!res.ok || !res.body) {
    throw await rawFetchError(res);
  }
  return res.body;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  options?: RequestOptions,
): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    signal: options?.signal,
  });
  if (!res.ok) {
    let serverDetail: string | undefined;
    try {
      const doc = await res.json();
      serverDetail = doc?.detail;
    } catch {
      /* non-JSON error body */
    }
    const detail = serverDetail ?? res.statusText;
    throw new APIError(res.status, statusMessage(res.status, detail, serverDetail != null), { detail });
  }
  if (res.status === 204) return undefined as T;
  try {
    return await res.json() as T;
  } catch {
    // Server returned a 200 with a non-JSON body (e.g. an HTML error page).
    throw new APIError(500, "Server returned an unexpected response — try again");
  }
}

export const api = {
  get: <T>(path: string, options?: RequestOptions) => request<T>("GET", path, undefined, options),
  post: <T>(path: string, body?: unknown, options?: RequestOptions) => request<T>("POST", path, body, options),
  put: <T>(path: string, body?: unknown, options?: RequestOptions) => request<T>("PUT", path, body, options),
  patch: <T>(path: string, body?: unknown, options?: RequestOptions) => request<T>("PATCH", path, body, options),
  del: <T>(path: string, options?: RequestOptions) => request<T>("DELETE", path, undefined, options),
};

// ── Domain types (generated from openapi/ — do not hand-edit; see api.gen.ts) ──

type Schemas = components["schemas"];

export type User = Schemas["User"];
export type UserList = Schemas["UserList"];
export type Finding = Schemas["Finding"];
export type FindingContext = Schemas["FindingContext"];
export type Belief = Schemas["Belief"];
export type FindingPage = Schemas["FindingPage"];
export type FindingSummary = Schemas["FindingSummary"];
export type FindingCluster = Schemas["FindingCluster"];
export type RoutingEnvironment = Schemas["RoutingEnvironment"];
export type EventType = Schemas["EventType"];
export type QueueItem = Schemas["QueueItem"];
export type DecisionPage = Schemas["DecisionPage"];
export type DriftAnalysis = Schemas["DriftAnalysis"];
export type DriftAnalysisList = Schemas["DriftAnalysisList"];
export type Asset = Schemas["Asset"];
export type AssetPage = Schemas["AssetPage"];
export type AssetSummary = Schemas["AssetSummary"];
// The identity census. Deliberately NOT derivable from AssetSummary.by_type —
// a person is not an asset row, and "workload identity" is not one asset type.
export type IdentityCensus = Schemas["IdentityCensus"];
export type LLMUsageSummary = Schemas["LLMUsageSummary"];
export type BlastRadius = Schemas["BlastRadius"];
export type Suppression = Schemas["Suppression"];
export type Connector = Schemas["Connector"];
export type ConnectorType = Schemas["ConnectorType"];
export type AssetDiskScan = Schemas["AssetDiskScan"];
export type ConnectorDiskScan = Schemas["ConnectorDiskScan"];
export type DiskScanMode = Schemas["DiskScanMode"];
// aws_org connectors (ADR 091): discovered accounts and the connection test.
export type OrgAccount = Schemas["OrgAccount"];
export type OrgTestReport = Schemas["OrgTestReport"];
export type Decision = Schemas["Decision"];
// Approve-and-run from the decision panel (/api/decisions/{id}/execution*).
export type DecisionExecutionPlan = Schemas["DecisionExecutionPlan"];
export type DecisionDryRun = Schemas["DecisionDryRun"];
export type DecisionRun = Schemas["DecisionRun"];
export type DecisionRunResult = Schemas["DecisionRunResult"];
export type DecisionAuditRow = Schemas["DecisionAuditRow"];
export type ComplianceCoverage = Schemas["ComplianceCoverage"];
// Requirement-level frameworks (ADR 093): NIST 800-53, PCI DSS, SOC 2, ISO 27001, HIPAA.
export type ComplianceFrameworkList = Schemas["ComplianceFrameworkList"];
export type ComplianceFramework = Schemas["ComplianceFramework"];
export type ComplianceRequirement = Schemas["ComplianceRequirement"];
export type GraphResult = Schemas["GraphResult"];
export type NLResult = Schemas["NLResult"];
export type GraphStatus = Schemas["GraphStatus"];
export type GraphStats = Schemas["GraphStats"];
export type GraphQuerySpec = Schemas["GraphQuerySpec"];
export type GraphNode = Schemas["GraphNode"];
export type GraphEdge = Schemas["GraphEdge"];
// DSPM tile counts come from GET /api/dspm/summary — computed server-side, never
// assembled from Cypher in the browser (see internal/app/explore/dspm.go).
export type DSPMSummary = Schemas["DSPMSummary"];
export type DSPMClassCount = Schemas["DSPMClassCount"];

// Request payloads keep their UI-facing names; the spec calls them *Request.
export type CreateConnectorPayload = Schemas["CreateConnectorRequest"];
export type CreateUserPayload = Schemas["CreateUserRequest"];

export type CostAnomaly = Schemas["CostAnomaly"];
export type CostSnapshot = Schemas["CostSnapshot"];
export interface CostAnomalyPage {
  items: CostAnomaly[];
}
export type CostAtRiskItem = Schemas["CostAtRiskResource"];
export type CostAtRiskResponse = Schemas["CostAtRisk"];
export type CostStatusResponse = Schemas["CostStatus"];

export type ActionMode = Schemas["ActionMode"];
export type RemediationPolicy = Schemas["Policy"];
export type UpdatePolicyPayload = Schemas["UpdatePolicyRequest"];

// APIKey types — mirror internal/app/apikey/handler.go. `scopes` is a single
// access level (read | write | admin are mutually exclusive), not a list.
export interface APIKey {
  id: string;
  name: string;
  prefix: string;
  scopes: string;
  last_used_at: string | null;
  expires_at?: string | null;
  created_at: string;
}

export interface CreateAPIKeyPayload {
  name: string;
  scopes: string;
  expires_at?: string | null;
}

// The create response is the API key fields plus the one-time plaintext `key`
// (handler.go flattens apiKeyResponse and adds `key`).
export interface CreateAPIKeyResponse extends APIKey {
  key: string;
}

// connectorConfigKeys mirrors connector/domain.go:requiredKeys — the per-provider
// config inputs the create form renders. Keep in sync with the backend. Cloud
// auth is OIDC-only: AWS/GCP take a role/project reference, no secret;
// only GitHub still supplies a credential. `kubernetes` is a valid connector type
// (it's in the spec enum) but is in-cluster with no form config — the create form
// does not offer it (see connectorTypes in routes/Connectors.tsx).
export const connectorConfigKeys: Record<ConnectorType, string[]> = {
  aws: ["role_arn", "region"],
  aws_org: ["management_role_arn", "external_id"],
  gcp: ["project_id"],
  github: ["app_id", "installation_id", "private_key_pem"],
  kubernetes: [],
  azure: ["subscription_id"],
  okta: ["domain", "api_token"],
  google_workspace: ["service_account_json", "admin_email"],
  demo: [],
};

// connectorOptionalConfigKeys are config inputs the form offers but does not
// require. webhook_secret opts a GitHub connector into event-driven sync:
// set it here and point a GitHub webhook at /api/webhooks/github/{id}.
export const connectorOptionalConfigKeys: Partial<Record<ConnectorType, string[]>> = {
  github: ["webhook_secret"],
  // hub_auth defaults to Vulngraph's own ambient identity; access_key (with the two
  // key fields) is the fallback. hub_role_arn is the hub role to assume first when
  // it trusts a principal (TrustType=principal), required with access_key.
  // Filters are comma-separated ids.
  aws_org: [
    "member_role_name",
    "region",
    "regions",
    "include_ous",
    "exclude_ous",
    "include_accounts",
    "exclude_accounts",
    "execute_role_name",
    "hub_auth",
    "hub_role_arn",
    "aws_access_key_id",
    "aws_secret_access_key",
  ],
};
