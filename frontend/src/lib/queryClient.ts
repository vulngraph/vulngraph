// QueryClient factory shared by main.tsx and the test harness, so tests run
// with the same global error handling as the app.
//
// Global 401 handling: AppShell gates on the ["me"] query (staleTime 5 min) and
// stays mounted across navigation, so an expired or revoked session would
// otherwise leave the shell up with every panel failing. Any 401 from a query
// or mutation (or a raw fetch via notifyUnauthorized) marks the session expired
// and resets ["me"]; its refetch then fails and AppShell renders the login
// screen in place. The URL is untouched, so signing back in lands on the page
// the user was on. Chat history is cleared at the same moment (lib/chatStorage).
import { MutationCache, QueryCache, QueryClient, type QueryClientConfig } from "@tanstack/react-query";
import { isUnauthorized } from "./api";
import { clearChatStorage } from "./chatStorage";

export const ME_KEY = ["me"] as const;
export const SESSION_EXPIRED_KEY = ["session-expired"] as const;

// Mutations whose 401 is an answer, not session expiry (bad credentials on the
// login form) opt out with `meta: { skipAuthRedirect: true }`.
declare module "@tanstack/react-query" {
  interface Register {
    mutationMeta: { skipAuthRedirect?: boolean };
    queryMeta: { skipAuthRedirect?: boolean };
  }
}

export function handleUnauthorized(qc: QueryClient) {
  // Already signed out (the me query itself is failing) — nothing to do, and
  // resetting again would loop.
  const me = qc.getQueryState(ME_KEY);
  if (me?.status === "error" && me.fetchStatus === "idle") return;
  clearChatStorage();
  qc.setQueryData(SESSION_EXPIRED_KEY, true);
  void qc.resetQueries({ queryKey: ME_KEY, exact: true });
}

function isMeKey(key: readonly unknown[]) {
  return key.length === 1 && key[0] === ME_KEY[0];
}

export function createQueryClient(config: QueryClientConfig = {}): QueryClient {
  const qc: QueryClient = new QueryClient({
    ...config,
    queryCache: new QueryCache({
      onError: (error, query) => {
        if (!isUnauthorized(error) || isMeKey(query.queryKey) || query.meta?.skipAuthRedirect) return;
        handleUnauthorized(qc);
      },
    }),
    mutationCache: new MutationCache({
      onError: (error, _vars, _ctx, mutation) => {
        if (!isUnauthorized(error) || mutation.meta?.skipAuthRedirect) return;
        handleUnauthorized(qc);
      },
    }),
  });
  return qc;
}
