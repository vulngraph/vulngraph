// Approve-and-run for one decision: GET /api/decisions/{id}/execution and the
// dry-run / request / run POSTs. Every route is admin-only; the server runs
// every check (connector, typed confirmation, the two-person rule) — the UI
// only walks a person through them.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type DecisionDryRun, type DecisionExecutionPlan, type DecisionRun, type DecisionRunResult } from "./api";
import { invalidateQueue } from "./queries";

export type RunBody = { inputs?: Record<string, string>; confirm?: string };

const base = (id: string) => `/api/decisions/${encodeURIComponent(id)}/execution`;
const planKey = (id: string) => ["decision-execution", id];

// While a request waits on a second admin, poll so the first admin sees it run
// and a second admin sees it arrive without reloading.
const AWAITING_POLL_MS = 5000;

export function useDecisionExecution(decisionId: string, enabled: boolean) {
  return useQuery({
    queryKey: planKey(decisionId),
    queryFn: () => api.get<DecisionExecutionPlan>(base(decisionId)),
    enabled,
    refetchInterval: (q) => (q.state.data?.run?.status === "awaiting_second_admin" ? AWAITING_POLL_MS : false),
  });
}

export function useDecisionDryRun(decisionId: string) {
  return useMutation({
    mutationFn: (body: RunBody) => api.post<DecisionDryRun>(`${base(decisionId)}/dry-run`, body),
  });
}

// Both writes refetch the plan either way: on a refusal the run state may
// still have moved (a failed run is recorded as failed).
function useExecutionWrite<T>(decisionId: string, path: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: RunBody) => api.post<T>(`${base(decisionId)}/${path}`, body),
    onSettled: () =>
      Promise.all([qc.invalidateQueries({ queryKey: planKey(decisionId) }), invalidateQueue(qc)]),
  });
}

export function useRequestDecisionRun(decisionId: string) {
  return useExecutionWrite<DecisionRun>(decisionId, "request");
}

export function useRunDecision(decisionId: string) {
  return useExecutionWrite<DecisionRunResult>(decisionId, "run");
}

// liveRequest reports whether a run is a second-admin request that can still
// be confirmed.
export function liveRequest(run: DecisionRun | undefined, now = Date.now()): boolean {
  return (
    run?.status === "awaiting_second_admin" &&
    !!run.grant_expires_at &&
    new Date(run.grant_expires_at).getTime() > now
  );
}
