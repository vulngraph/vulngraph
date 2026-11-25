import { useState } from "react";
import {
  connectorConfigKeys,
  connectorOptionalConfigKeys,
  type Connector,
  type ConnectorType,
} from "../lib/api";
import {
  useConnectors,
  useCreateConnector,
  useDeleteConnector,
  useIsAdmin,
  useSetConnectorMode,
  useSyncConnector,
} from "../lib/queries";
import { Button, Card, Empty, ErrorNote, Loading, StatusDot } from "../components/ui";
import { ConfirmButton, FormField, FormActions, SuccessNote } from "../components/form";
import { timeAgo } from "../lib/format";
import { ConnectorDiskScan } from "../components/ConnectorDiskScan";
import { AwsOrgPanel, AwsOrgSetupGuide, generateExternalId } from "./AwsOrg";

// Rendered as the Connectors section inside Settings.
export function ConnectorsSection() {
  const { data, isLoading, isError, error } = useConnectors();
  const isAdmin = useIsAdmin();
  const [status, setStatus] = useState("");
  const [search, setSearch] = useState("");

  const all = data ?? [];
  const counts = { ok: 0, pending: 0, error: 0 } as Record<string, number>;
  for (const c of all) counts[c.sync_status] = (counts[c.sync_status] ?? 0) + 1;

  const q = search.trim().toLowerCase();
  const shown = all.filter(
    (c) =>
      (!status || c.sync_status === status) &&
      (!q || c.name.toLowerCase().includes(q) || c.type.toLowerCase().includes(q)),
  );

  return (
    <div>
      {isAdmin && <CreateConnectorForm />}

      {all.length > 0 && (
        <div className="mb-4 flex flex-wrap items-center gap-3">
          <div className="flex flex-wrap gap-1">
            <StatusBtn label={`all (${all.length})`} active={!status} onClick={() => setStatus("")} />
            {/* Keep the active filter's chip mounted even if its count drops to
                zero mid-session (e.g. the last errored connector recovers) —
                otherwise the filter goes silently unexplainable. */}
            {(status === "ok" || (counts.ok ?? 0) > 0) && (
              <StatusBtn label={`ok (${counts.ok ?? 0})`} active={status === "ok"} onClick={() => setStatus(status === "ok" ? "" : "ok")} />
            )}
            {(status === "pending" || (counts.pending ?? 0) > 0) && (
              <StatusBtn label={`pending (${counts.pending ?? 0})`} active={status === "pending"} onClick={() => setStatus(status === "pending" ? "" : "pending")} />
            )}
            {(status === "error" || (counts.error ?? 0) > 0) && (
              <StatusBtn label={`errored (${counts.error ?? 0})`} active={status === "error"} onClick={() => setStatus(status === "error" ? "" : "error")} />
            )}
          </div>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="search connectors…"
            className="flex-1 rounded border border-border-subtle bg-bg px-3 py-1.5 text-xs text-text outline-none focus:border-teal"
          />
        </div>
      )}

      {isLoading && <Loading />}
      {isError && <ErrorNote message={(error as Error).message} />}
      {data && data.length === 0 && <Empty message="No connectors configured." />}
      {!isLoading && all.length > 0 && shown.length === 0 && (
        <Empty
          message={
            status
              ? `No connectors currently match "${status}". Click the ${status} chip above (or "all") to clear the filter.`
              : "No connectors match."
          }
        />
      )}
      {shown.length > 0 && (
        // Cap height so the Settings sidebar nav stays reachable beside a long grid.
        <div className="max-h-[600px] overflow-y-auto rounded-lg pr-1 [scrollbar-width:thin]">
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            {shown.map((c) => (
              <ConnectorCard key={c.id} connector={c} isAdmin={isAdmin} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function StatusBtn({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button onClick={onClick} className={`rounded px-2 py-1 text-[11px] ${active ? "bg-surface-3 text-text" : "text-text-3 hover:text-text-2"}`}>
      {label}
    </button>
  );
}

// fieldControlKind maps a connector config key to the input control it needs:
// PEM/JSON blobs get a multi-line monospace textarea (matching AlertChannels'
// treatment of its token field for the single-line case), tokens/secrets get
// a masked single-line input, everything else is plain text.
function fieldControlKind(key: string): "textarea" | "password" | "text" {
  if (key.endsWith("_pem") || key.endsWith("_json")) return "textarea";
  if (key.endsWith("_token") || key.endsWith("_secret") || key.includes("secret_access")) return "password";
  return "text";
}

function ConnectorCard({ connector: c, isAdmin }: { connector: Connector; isAdmin: boolean }) {
  const sync = useSyncConnector();
  const del = useDeleteConnector();
  const setMode = useSetConnectorMode();

  const isReadWrite = c.mode === "read_write";

  return (
    <div
      className={`rounded-lg border p-4 ${
        !c.enabled
          ? "border-border-subtle bg-surface-2 opacity-60"
          : isReadWrite
            ? "border-teal/30 bg-teal/5"
            : "border-border-subtle bg-surface-2"
      }`}
    >
      <div className="flex items-center justify-between">
        <span className="text-sm text-text">{c.name}</span>
        <div className="flex items-center gap-1.5">
          {!c.enabled && (
            <span className="rounded border border-border-subtle px-1.5 py-0.5 text-[11px] uppercase text-text-3">
              disabled
            </span>
          )}
          {/* Mode badge — teal for read_write, muted for read_only */}
          <span className={`rounded border px-1.5 py-0.5 text-[11px] uppercase ${
            isReadWrite
              ? "border-teal/30 bg-teal/10 text-teal"
              : "border-border-subtle text-text-3"
          }`}>
            {isReadWrite ? "read/write" : "read only"}
          </span>
          <span className="rounded border border-border-subtle px-1.5 py-0.5 text-[11px] uppercase text-text-3">
            {c.type}
          </span>
        </div>
      </div>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-y-1">
        <div className="flex flex-wrap items-center gap-2">
          <StatusDot
            tone={c.sync_status === "ok" ? "ok" : c.sync_status === "error" ? "error" : "warning"}
            label={c.sync_status}
          />
          {c.stale && <StatusDot tone="error" label="stale" />}
          {c.partially_stale && <StatusDot tone="warning" label="partially stale" />}
        </div>
        <div
          className="text-right text-[11px] text-text-3"
          title={c.last_success_at ? new Date(c.last_success_at).toLocaleString() : undefined}
        >
          {/* last_success_at (not last_synced_at) is the last time sync actually
              completed without error — the attempt time is secondary/less
              prominent, and only shown when it differs from the success time. */}
          <div>{c.last_success_at ? `synced ${timeAgo(c.last_success_at)}` : "never synced"}</div>
          {c.last_synced_at && c.last_synced_at !== c.last_success_at && (
            <div title={new Date(c.last_synced_at).toLocaleString()}>
              last attempt {timeAgo(c.last_synced_at)}
            </div>
          )}
        </div>
      </div>
      {c.sync_status === "pending" && !c.last_synced_at && (
        <p className="mt-1.5 text-[11px] text-amber">
          Waiting for first sync — click &quot;Sync now&quot; or wait for the next scheduled sweep.
        </p>
      )}
      {c.sync_error && (
        <div className="mt-2 rounded border border-red/20 bg-red/5 px-2.5 py-1.5 text-[11px]">
          <span className="font-medium text-red">Sync failed: </span>
          <span className="line-clamp-3 break-words text-text-2">{c.sync_error}</span>
          <p className="mt-1 text-text-3">Check your credentials and try syncing again.</p>
        </div>
      )}
      {c.type === "aws_org" && <AwsOrgPanel connector={c} isAdmin={isAdmin} />}
      <ConnectorDiskScan connector={c} isAdmin={isAdmin} />
      {isAdmin && (
        <div className="mt-3 space-y-1.5">
          <div className="flex flex-wrap gap-1.5">
            <Button onClick={() => sync.mutate(c.id)} disabled={sync.isPending}>
              {sync.isPending ? "Syncing…" : "Sync now"}
            </Button>
            {/* Mode toggle — read_only ↔ read_write */}
            <Button
              onClick={() => setMode.mutate({ id: c.id, mode: isReadWrite ? "read_only" : "read_write" })}
              disabled={setMode.isPending}
              title={isReadWrite ? "Downgrade to read-only (disables executor actions)" : "Upgrade to read/write (enables executor actions — ensure IAM has write permissions first)"}
            >
              {setMode.isPending ? "Updating…" : isReadWrite ? "Set read-only" : "Enable read/write"}
            </Button>
            <ConfirmButton label="Delete" verb="delete" onConfirm={() => del.mutate(c.id)} isPending={del.isPending} />
          </div>
          {sync.isSuccess && !sync.isPending && <SuccessNote message="Sync queued." />}
          {sync.isError && <ErrorNote message={(sync.error as Error).message} />}
          {setMode.isError && <ErrorNote message={(setMode.error as Error).message} />}
          {del.isError && <ErrorNote message={(del.error as Error).message} />}
        </div>
      )}
    </div>
  );
}

const connectorTypes: ConnectorType[] = ["aws", "aws_org", "gcp", "azure", "github", "okta", "google_workspace", "demo"];

// initialConfig pre-fills what the form can choose for the operator: an
// aws_org connector gets a fresh random ExternalId to paste into the StackSet.
function initialConfig(type: ConnectorType): Record<string, string> {
  return type === "aws_org" ? { external_id: generateExternalId() } : {};
}

function CreateConnectorForm() {
  const create = useCreateConnector();
  const [open, setOpen] = useState(false);
  const [type, setType] = useState<ConnectorType>("aws");
  const [name, setName] = useState("");
  const [config, setConfig] = useState<Record<string, string>>({});

  const keys = connectorConfigKeys[type];
  const optionalKeys = connectorOptionalConfigKeys[type] ?? [];

  function reset() {
    setName("");
    setConfig({});
    setType("aws");
    setOpen(false);
  }

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const required = Object.fromEntries(keys.map((k) => [k, config[k] ?? ""]));
    // Optional keys are sent only when filled, so an empty webhook_secret isn't
    // stored as a blank value.
    const optional = Object.fromEntries(
      optionalKeys.filter((k) => config[k]).map((k) => [k, config[k]]),
    );
    create.mutate({ type, name, config: { ...required, ...optional } }, { onSuccess: reset });
  }

  if (!open) {
    return (
      <div className="mb-4">
        <Button variant="primary" onClick={() => setOpen(true)}>
          Add connector
        </Button>
      </div>
    );
  }

  function fieldControl(k: string, required: boolean) {
    const kind = fieldControlKind(k);
    const label = required ? k : `${k} (optional)`;
    if (kind === "textarea") {
      return (
        <FormField
          key={k}
          label={label}
          as="textarea"
          value={config[k] ?? ""}
          onChange={(e) => setConfig((prev) => ({ ...prev, [k]: e.target.value }))}
          required={required}
        />
      );
    }
    return (
      <FormField
        key={k}
        label={label}
        type={kind === "password" ? "password" : "text"}
        value={config[k] ?? ""}
        onChange={(e) => setConfig((prev) => ({ ...prev, [k]: e.target.value }))}
        required={required}
      />
    );
  }

  return (
    <Card className="mb-4">
      <form onSubmit={submit} className="space-y-3">
        <FormField
          as="select"
          label="Provider"
          value={type}
          onChange={(e) => {
            const next = e.target.value as ConnectorType;
            setType(next);
            setConfig(initialConfig(next));
          }}
        >
          {connectorTypes.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </FormField>
        <FormField label="Name" value={name} onChange={(e) => setName(e.target.value)} required />
        {type === "aws_org" && (
          <AwsOrgSetupGuide
            externalId={config.external_id ?? ""}
            onRegenerate={() => setConfig((prev) => ({ ...prev, external_id: generateExternalId() }))}
          />
        )}
        {keys.map((k) => fieldControl(k, true))}
        {optionalKeys.map((k) => fieldControl(k, false))}
        {create.isError && <ErrorNote message={(create.error as Error).message} />}
        <FormActions submitLabel="Create" onCancel={reset} isPending={create.isPending} type="submit" />
      </form>
    </Card>
  );
}
