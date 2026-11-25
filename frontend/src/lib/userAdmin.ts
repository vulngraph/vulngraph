// User-management actions (admin): PATCH/DELETE /api/users/{id} and
// POST /api/users/{id}/revoke-sessions. Real failure semantics: acting on your
// own row is 403, demoting/disabling/deleting the last active admin is 409, an
// unknown id is 404 — each with a problem `detail` worth showing.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, APIError, errorMessage, type UserList } from "./api";

export type AdminUser = UserList["items"][number];
export type Role = AdminUser["role"];
export const ROLES: Role[] = ["admin", "analyst", "viewer"];

export type UserPatch = { disabled?: boolean; role?: Role };

const usersPath = (id: string) => `/api/users/${encodeURIComponent(id)}`;

// userActionError prefers the server's problem detail over api.ts's generic 403
// copy: here a 403 means "not your own account", not "you lack a role".
export function userActionError(e: unknown): string {
  return e instanceof APIError ? e.detail : errorMessage(e);
}

function useUserMutation<V>(fn: (v: V) => Promise<unknown>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    // Refetch either way: on failure the row may have changed underneath us.
    onSettled: () => qc.invalidateQueries({ queryKey: ["users"] }),
  });
}

export function useUpdateUser() {
  return useUserMutation(({ id, patch }: { id: string; patch: UserPatch }) =>
    api.patch<AdminUser>(usersPath(id), patch),
  );
}

export function useRevokeUserSessions() {
  return useUserMutation((id: string) => api.post<void>(`${usersPath(id)}/revoke-sessions`));
}

export function useDeleteUser() {
  return useUserMutation((id: string) => api.del<void>(usersPath(id)));
}
