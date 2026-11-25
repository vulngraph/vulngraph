import { useRef, useState } from "react";
import { errorMessage, type CreateUserPayload } from "../lib/api";
import { useCreateUser, useIsAdmin, useMe, useUsers } from "../lib/queries";
import {
  ROLES,
  useDeleteUser,
  useRevokeUserSessions,
  useUpdateUser,
  userActionError,
  type AdminUser,
  type Role,
} from "../lib/userAdmin";
import { Card, Empty, ErrorNote, Loading } from "../components/ui";
import { ConfirmButton, FormField, FormActions, SuccessNote } from "../components/form";
import { roleTone, timeAgo } from "../lib/format";

// Password policy is length-only (internal/app/auth/service.go: minPasswordLength).
const MIN_PASSWORD_LENGTH = 12;

// Rendered as the Users section inside Settings.
export function UsersSection() {
  const { isLoading: meLoading } = useMe();
  const isAdmin = useIsAdmin();
  const listRef = useRef<HTMLDivElement>(null);

  // Gate on "am I still loading who I am", not just isAdmin, so a hard reload
  // doesn't flash "Admin access required" for an actual admin while /api/me
  // is still in flight.
  if (meLoading) {
    return <Loading />;
  }
  if (!isAdmin) {
    return <Empty message="Admin access required for user management." />;
  }
  return (
    <div className="space-y-4">
      <UserList listRef={listRef} />
      <CreateUserForm listRef={listRef} />
    </div>
  );
}

function UserList({ listRef }: { listRef: React.RefObject<HTMLDivElement | null> }) {
  const { data, isLoading, isError, error } = useUsers();
  const me = useMe().data;
  const users: AdminUser[] = data?.items ?? [];

  return (
    <div ref={listRef}>
      <h2 className="mb-2 font-display text-sm text-text">
        Users <span className="font-mono text-[11px] text-text-3">{users.length}</span>
      </h2>
      {isLoading && <Loading />}
      {isError && <ErrorNote message={errorMessage(error)} />}
      {!isLoading && !isError && users.length === 0 && <Empty message="No users." />}
      {users.length > 0 && (
        <ul className="glass overflow-hidden rounded-xl">
          {users.map((u) => (
            <UserRow key={u.id} user={u} isSelf={u.id === me?.id || u.email === me?.email} />
          ))}
        </ul>
      )}
    </div>
  );
}

// UserRow: one user plus the admin actions. Your own row has none — the server
// refuses them (403), so the UI doesn't offer them.
function UserRow({ user: u, isSelf }: { user: AdminUser; isSelf: boolean }) {
  const update = useUpdateUser();
  const revoke = useRevokeUserSessions();
  const remove = useDeleteUser();
  const [revoked, setRevoked] = useState(false);
  const busy = update.isPending || revoke.isPending || remove.isPending;
  const failure = [update, revoke, remove].find((m) => m.isError);

  return (
    <li aria-label={u.email} className="border-b border-border-subtle/40 px-3 py-2 last:border-0">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-xs text-text" title={u.email}>
            {u.email}
            {isSelf && <span className="ml-1.5 text-[11px] text-text-3">(you)</span>}
            {u.disabled && (
              <span className="ml-1.5 rounded border border-red/30 bg-red/10 px-1 py-0.5 text-[11px] uppercase text-red">
                disabled
              </span>
            )}
          </div>
          <div className="text-[11px] text-text-3">
            joined {timeAgo(u.created_at, "compact")} · {u.totp_enabled ? "2FA on" : "2FA off"}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {!isSelf ? (
            <select
              aria-label={`Role for ${u.email}`}
              value={u.role}
              disabled={busy}
              onChange={(e) => update.mutate({ id: u.id, patch: { role: e.target.value as Role } })}
              className={`rounded border px-1.5 py-0.5 text-[11px] uppercase disabled:opacity-50 ${roleTone(u.role)}`}
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          ) : (
            <span className={`rounded border px-1.5 py-0.5 text-[11px] uppercase ${roleTone(u.role)}`}>{u.role}</span>
          )}
          {!isSelf && (
            <button
              type="button"
              disabled={busy}
              onClick={() => update.mutate({ id: u.id, patch: { disabled: !u.disabled } })}
              className="rounded border border-border-subtle px-2 py-1 text-[11px] text-text-2 transition-colors hover:text-text disabled:opacity-50"
            >
              {u.disabled ? "Enable" : "Disable"}
            </button>
          )}
          {!isSelf && (
            <ConfirmButton
              label="Revoke sessions"
              verb="revoke"
              isPending={busy}
              onConfirm={() => revoke.mutate(u.id, { onSuccess: () => setRevoked(true) })}
            />
          )}
          {!isSelf && <ConfirmButton label="Delete" isPending={busy} onConfirm={() => remove.mutate(u.id)} />}
        </div>
      </div>
      {failure && (
        <p role="alert" className="mt-1 text-[11px] text-red">
          {userActionError(failure.error)}
        </p>
      )}
      {revoked && !failure && (
        <p className="mt-1 text-[11px] text-emerald">Sessions revoked — they'll need to sign in again.</p>
      )}
    </li>
  );
}

function CreateUserForm({ listRef }: { listRef: React.RefObject<HTMLDivElement | null> }) {
  const create = useCreateUser();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<CreateUserPayload["role"]>("viewer");

  function submit(e: React.FormEvent) {
    e.preventDefault();
    create.mutate(
      { email, password, role },
      {
        onSuccess: () => {
          setEmail("");
          setPassword("");
          setRole("viewer");
          const prefersReducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
          listRef.current?.scrollIntoView({ behavior: prefersReducedMotion ? "auto" : "smooth" });
        },
      },
    );
  }

  return (
    <Card className="max-w-md">
      <h2 className="mb-3 font-display text-sm text-text">Create user</h2>
      <form onSubmit={submit} className="space-y-3">
        <FormField label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        <FormField
          label="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
          help={`At least ${MIN_PASSWORD_LENGTH} characters.`}
          required
        />
        <FormField
          as="select"
          label="Role"
          value={role}
          onChange={(e) => setRole(e.target.value as CreateUserPayload["role"])}
        >
          {ROLES.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </FormField>
        {create.isError && <ErrorNote message={errorMessage(create.error)} />}
        {create.isSuccess && <SuccessNote message="User created. They can sign in immediately." />}
        <FormActions submitLabel="Create user" isPending={create.isPending} type="submit" />
      </form>
    </Card>
  );
}
