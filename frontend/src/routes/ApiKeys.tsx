import { useEffect, useRef, useState } from "react";
import { useAPIKeys, useCreateAPIKey, useDeleteAPIKey, useMe } from "../lib/queries";
import { Card, Empty, ErrorNote, Loading } from "../components/ui";
import { FormField, FormActions, ConfirmButton, SuccessNote } from "../components/form";
import { timeAgo as timeAgoBase } from "../lib/format";

const timeAgo = (iso?: string) => timeAgoBase(iso, "compact");

const API_SCOPES = ["read", "write", "admin", "inventory"] as const;
type APIScope = (typeof API_SCOPES)[number];

// Mirrors auth.Role.Privilege() (internal/app/auth/domain.go) and
// auth.APIKeyScopeToRole (internal/app/auth/handler.go): a scope maps to the
// role it grants, and the backend clamps Create to scopes at or below the
// caller's own role privilege. Kept in lockstep with those so the options
// shown here never include a scope the backend would reject. "inventory" maps to
// viewer but only an admin may create one (apikey/handler.go), so it ranks
// with admin here.
const ROLE_PRIVILEGE: Record<string, number> = { admin: 3, analyst: 2, viewer: 1 };
const SCOPE_PRIVILEGE: Record<APIScope, number> = { admin: 3, inventory: 3, write: 2, read: 1 };

function allowedScopes(role: string | undefined): APIScope[] {
  const privilege = ROLE_PRIVILEGE[role ?? ""] ?? 0;
  return API_SCOPES.filter((s) => SCOPE_PRIVILEGE[s] <= privilege);
}

// Copy-to-clipboard confirmation state, keyed by action so unrelated buttons
// never clear each other's "copied"/"failed" flash.
type CopyState = "copied" | "failed";
const REVEAL_COPY_ACTION = "reveal";

// Rendered as the API Keys section inside Settings. Mirrors Users.tsx: reads
// isAdmin itself rather than taking it as a prop (Settings.tsx renders every
// section with <Active /> and passes no props).
export function APIKeysSection() {
  const { data: me, isLoading: meLoading } = useMe();
  const { data, isLoading } = useAPIKeys();
  const deleteKey = useDeleteAPIKey();
  const createKey = useCreateAPIKey();

  const scopes = allowedScopes(me?.role);
  const [name, setName] = useState("");
  const [scope, setScope] = useState<APIScope>("read");
  const [revealed, setRevealed] = useState<string | null>(null);
  const [created, setCreated] = useState(false);
  const [copyStates, setCopyStates] = useState<Record<string, CopyState>>({});

  // Per-action copy-confirmation timeouts, so copying one thing can never
  // clear a different action's flash, and nothing fires after unmount.
  const copyTimeouts = useRef<Record<string, ReturnType<typeof setTimeout>>>({});
  useEffect(() => {
    return () => {
      Object.values(copyTimeouts.current).forEach(clearTimeout);
    };
  }, []);

  const keys = data ?? [];

  function flashCopyState(action: string, state: CopyState) {
    setCopyStates((prev) => ({ ...prev, [action]: state }));
    if (copyTimeouts.current[action]) clearTimeout(copyTimeouts.current[action]);
    copyTimeouts.current[action] = setTimeout(() => {
      setCopyStates((prev) => {
        const { [action]: _dropped, ...rest } = prev;
        return rest;
      });
    }, 2000);
  }

  function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    createKey.mutate(
      { name, scopes: scope },
      {
        onSuccess: (res) => {
          setRevealed(res.key);
          setCreated(true);
          setName("");
          setScope("read");
        },
      },
    );
  }

  function copyRevealed() {
    if (!revealed) return;
    // navigator.clipboard is undefined on plain HTTP (e.g. when the app is
    // reached over kubectl port-forward, i.e. http not https) — guard instead
    // of letting the click handler throw at the one moment the key is visible.
    const promise = navigator.clipboard?.writeText(revealed);
    if (!promise) {
      flashCopyState(REVEAL_COPY_ACTION, "failed");
      return;
    }
    promise.then(
      () => flashCopyState(REVEAL_COPY_ACTION, "copied"),
      () => flashCopyState(REVEAL_COPY_ACTION, "failed"),
    );
  }

  // Dismissing the reveal is the terminal action for the "just created" flow —
  // nothing about it should linger for the rest of the session.
  function dismissReveal() {
    setRevealed(null);
    setCreated(false);
  }

  return (
    <div className="space-y-4">
      {/* Revealed key — shown once after creation */}
      {revealed && (
        <div className="glass rounded-xl border border-amber/30 p-4">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-[11px] font-medium text-amber">Copy this key now. It will not be shown again.</span>
          </div>
          <div className="flex items-start gap-2">
            <textarea
              readOnly
              rows={2}
              value={revealed}
              onFocus={(e) => e.currentTarget.select()}
              className="min-w-0 flex-1 resize-none break-all rounded border border-border-subtle bg-bg px-2 py-1.5 font-mono text-[11px] text-text focus:border-teal/50 focus:outline-none"
            />
            <button
              onClick={copyRevealed}
              className="flex-shrink-0 rounded border border-border-subtle bg-surface px-2 py-1 text-[11px] text-text-2 hover:border-teal/50 hover:text-teal"
            >
              {copyStates[REVEAL_COPY_ACTION] === "copied" ? "copied" : "copy"}
            </button>
          </div>
          {copyStates[REVEAL_COPY_ACTION] === "failed" && (
            <p className="mt-1.5 text-[11px] text-red">copy failed — select and copy manually</p>
          )}
          <button
            onClick={dismissReveal}
            className="mt-2 text-[11px] text-text-3 hover:text-text"
          >
            dismiss
          </button>
        </div>
      )}
      {created && !revealed && <SuccessNote message="API key created." />}

      {/* Existing keys list */}
      {(isLoading || meLoading) && <Loading />}
      {!isLoading && keys.length === 0 && !revealed && (
        <Empty message="No API keys. Create one below." />
      )}
      {deleteKey.isError && <ErrorNote message={(deleteKey.error as Error).message} />}
      {keys.length > 0 && (
        <div className="glass overflow-hidden rounded-xl">
          {keys.map((k) => {
            const expired = !!k.expires_at && new Date(k.expires_at).getTime() < Date.now();
            return (
              <div
                key={k.id}
                className="flex items-start justify-between gap-3 border-b border-border-subtle/40 px-4 py-3 last:border-0"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-medium text-text">{k.name}</span>
                    <span className="font-mono text-[11px] text-text-3">{k.prefix}…</span>
                  </div>
                  <div className="mt-1 flex flex-wrap items-center gap-1.5">
                    <span className="rounded border border-border-subtle bg-surface px-1.5 py-0.5 font-mono text-[11px] uppercase text-text-3">
                      {k.scopes}
                    </span>
                    {expired && (
                      <span className="rounded border border-red/30 bg-red/10 px-1.5 py-0.5 text-[11px] uppercase text-red">
                        expired
                      </span>
                    )}
                  </div>
                  <div className="mt-1 text-[11px] text-text-3">
                    created {timeAgo(k.created_at)}
                    {k.last_used_at ? ` · last used ${timeAgo(k.last_used_at)}` : " · never used"}
                    {k.expires_at && ` · expires ${new Date(k.expires_at).toLocaleDateString()}`}
                  </div>
                </div>
                {/* GET /api/keys already scopes the list to the caller's own
                    keys (apikey/handler.go List), and DELETE is scoped the
                    same way (svc.Delete matches id+userID) — every row here
                    is already "mine", so any authenticated user can revoke
                    their own key, not just admins. */}
                <ConfirmButton
                  className="flex-shrink-0"
                  label="delete"
                  verb="delete"
                  onConfirm={() => deleteKey.mutate(k.id)}
                  isPending={deleteKey.isPending && deleteKey.variables === k.id}
                />
              </div>
            );
          })}
        </div>
      )}

      {/* Create form — shown to every authenticated user; the backend clamps
          Create to scopes at or below the caller's own role (apikey/handler.go),
          so the scope options here are limited the same way rather than gating
          the form itself on isAdmin. */}
      {!meLoading && (
        <Card className="max-w-md">
          <h2 className="mb-3 font-display text-sm text-text">Create API key</h2>
          <form onSubmit={handleCreate} className="space-y-3">
            <FormField
              label="Name"
              type="text"
              placeholder="e.g. CI pipeline"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
            <FormField
              as="select"
              label="Scope"
              value={scope}
              onChange={(e) => setScope(e.target.value as APIScope)}
            >
              {scopes.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </FormField>
            {scope === "inventory" && (
              <p className="text-xs text-text-3">
                For a bring-your-own scanning agent: it may only submit package inventory
                (PUT /api/package-inventory) and reads nothing else.
              </p>
            )}
            {createKey.isError && <ErrorNote message={(createKey.error as Error).message} />}
            <FormActions submitLabel="Create key" isPending={createKey.isPending} type="submit" />
          </form>
        </Card>
      )}
    </div>
  );
}
