import { useState } from "react";
import type { Connector, DiskScanMode } from "../lib/api";
import { useConnectorDiskScan, useSetConnectorDiskScan } from "../lib/queries";
import { Button, ErrorNote } from "./ui";
import { FormField, SuccessNote } from "./form";
import { timeAgo } from "../lib/format";

const SUPPORTED = ["aws", "azure", "gcp"];

export function supportsDiskScan(type: string): boolean {
  return SUPPORTED.includes(type);
}

const MODE_LABEL: Record<DiskScanMode, string> = {
  off: "Off",
  existing_snapshots: "Existing snapshots (read only)",
  create_snapshots: "Create short-lived snapshots",
};

const MODE_BADGE: Record<DiskScanMode, string> = {
  off: "off",
  existing_snapshots: "existing snapshots",
  create_snapshots: "creating snapshots",
};

const MODE_HELP: Record<DiskScanMode, string> = {
  off: "Nothing is read. VM disks stay unknown, which is not a clean result.",
  existing_snapshots: "Reads snapshots you already have, with a read-only snapshot permission. Nothing is written to your account.",
  create_snapshots: "Also creates and deletes tagged snapshots with a separate, dedicated role. Needs that role set on the connector.",
};

// ConnectorDiskScan is the disk scan section of a connector card: the current
// mode for everyone, and for an admin the controls that change it. Turning it
// on is the standing approval, so it needs the typed confirmation sentence.
export function ConnectorDiskScan({ connector: c, isAdmin }: { connector: Connector; isAdmin: boolean }) {
  const [open, setOpen] = useState(false);
  if (!supportsDiskScan(c.type)) return null;
  const mode = (c.disk_scan_mode ?? "off") as DiskScanMode;

  return (
    <section aria-label="Disk scan" className="mt-3 rounded border border-border-subtle bg-surface px-2.5 py-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-[11px] uppercase text-text-3">
          Disk scan <span className="ml-1 rounded border border-border-subtle px-1.5 py-0.5 normal-case text-text-2">{MODE_BADGE[mode] ?? mode}</span>
        </span>
        {isAdmin && (
          <Button onClick={() => setOpen((v) => !v)} aria-expanded={open}>
            {open ? "Hide disk scan" : "Configure disk scan"}
          </Button>
        )}
      </div>
      {c.type === "gcp" && (
        <p className="mt-1 text-[11px] text-text-3">GCP: existing snapshots only, creation not available yet.</p>
      )}
      {isAdmin && open && <DiskScanSettings connector={c} />}
    </section>
  );
}

function DiskScanSettings({ connector: c }: { connector: Connector }) {
  const { data, isLoading, isError, error } = useConnectorDiskScan(c.id, true);
  const set = useSetConnectorDiskScan();
  const [picked, setPicked] = useState<DiskScanMode | null>(null);
  const [typed, setTyped] = useState("");

  if (isLoading) return <p className="mt-2 text-[11px] text-text-3">Loading…</p>;
  if (isError || !data) return <div className="mt-2"><ErrorNote message={(error as Error | null)?.message ?? "Could not load disk scan settings."} /></div>;

  const selected = picked ?? data.mode;
  const needsConfirmation = selected !== "off";
  const changed = selected !== data.mode;
  const confirmed = !needsConfirmation || typed === data.confirmation;
  const run = data.last_run;

  return (
    <div className="mt-2 space-y-2 text-xs">
      {data.role && (
        <p className="text-text-3">
          Disk scan principal: <span className="font-mono text-[11px] text-text-2">{data.role}</span>
        </p>
      )}
      {data.enabled_by && data.enabled_at && (
        <p className="text-text-3">Enabled by {data.enabled_by} {timeAgo(data.enabled_at)}.</p>
      )}
      {run && (
        <p className="text-text-3">
          Last run {timeAgo(run.started_at)}: {run.status.replace(/_/g, " ")}, {run.counts.scanned} of {run.counts.volumes} volumes read, {run.counts.gaps} with a gap.
        </p>
      )}
      <div className="rounded border border-amber/30 bg-amber/5 px-2.5 py-1.5 text-[11px] text-text-2">{data.warning}</div>
      <FormField
        as="select"
        label="Mode"
        value={selected}
        onChange={(e) => { setPicked(e.target.value as DiskScanMode); setTyped(""); set.reset(); }}
        help={MODE_HELP[selected]}
      >
        {data.modes.map((m) => (
          <option key={m} value={m}>{MODE_LABEL[m] ?? m}</option>
        ))}
      </FormField>
      {needsConfirmation && changed && (
        <FormField
          label="Type this sentence to confirm"
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          placeholder={data.confirmation}
          help={data.confirmation}
          autoComplete="off"
        />
      )}
      <Button
        variant="primary"
        disabled={!changed || !confirmed || set.isPending}
        onClick={() => set.mutate({ id: c.id, mode: selected, confirmation: needsConfirmation ? typed : undefined }, { onSuccess: () => { setPicked(null); setTyped(""); } })}
      >
        {set.isPending ? "Saving…" : "Save disk scan mode"}
      </Button>
      {set.isSuccess && <SuccessNote message="Disk scan mode saved." />}
      {set.isError && <ErrorNote message={(set.error as Error).message} />}
    </div>
  );
}
