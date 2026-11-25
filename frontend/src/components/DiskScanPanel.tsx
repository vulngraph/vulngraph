import { useAssetDiskScan } from "../lib/queries";
import { Card } from "./ui";
import { timeAgo } from "../lib/format";

// VM asset types disk scanning can read.
const VM_TYPES = ["ec2_instance", "azure_vm", "gce_instance"];

export function isDiskScanVM(type?: string): boolean {
  return !!type && VM_TYPES.includes(type);
}

const GAP_TEXT: Record<string, string> = {
  not_enabled: "Disk scanning is not enabled for this VM's connector, so its disk was not read.",
  no_snapshot_available: "No snapshot of this volume exists to read. Create one, or let Vulngraph create short-lived snapshots.",
  snapshot_pending: "A snapshot was requested but was not ready yet. The next run tries again.",
  encrypted_no_key: "The volume is encrypted and the scanner's role cannot use its key.",
  unsupported_fs: "The filesystem is not one Vulngraph can read (only ext4 and XFS on Linux).",
  unsupported_partition: "The disk layout is not supported (for example LVM, RAID or a Windows disk).",
  read_error: "The disk could not be read completely.",
  over_cap: "The volume is larger than the scan limits allow.",
  permission_denied: "The cloud role does not have permission to read or create snapshots of this volume.",
  stale: "The last successful read is too old to trust.",
};

export function gapText(gap?: string): string {
  if (!gap) return "";
  return GAP_TEXT[gap] ?? `The disk was not read (reason: ${gap}).`;
}

const SOURCE_LABEL: Record<string, string> = {
  reused: "existing snapshot",
  created: "snapshot created by Vulngraph",
  image_baseline: "machine image baseline",
};

const STATE_BADGE: Record<string, { label: string; cls: string }> = {
  scanned: { label: "Scanned", cls: "bg-emerald/10 text-emerald" },
  not_enabled: { label: "Not enabled", cls: "bg-surface-3 text-text-3" },
  none: { label: "Not scanned", cls: "bg-surface-3 text-text-3" },
};

// DiskScanPanel shows whether this VM's disk was read. A disk that was not read
// is shown as unknown: this panel never says or implies "no vulnerabilities".
export function DiskScanPanel({ assetId }: { assetId: string }) {
  const { data, isLoading, isError } = useAssetDiskScan(assetId, true);
  if (isLoading || isError || !data) return null;

  const badge = STATE_BADGE[data.state] ?? STATE_BADGE.none;
  const stateGap = data.gap ?? "";
  return (
    <Card className="mt-3">
      <section aria-label="Disk scan">
        <div className="mb-2 flex items-center gap-2">
          <span className="text-[11px] uppercase text-text-3">Disk scan</span>
          <span className={`rounded px-1.5 py-0.5 text-[11px] font-medium ${badge.cls}`}>{badge.label}</span>
        </div>
        {data.state === "not_enabled" && (
          <p className="text-xs text-text-2">
            {gapText(stateGap || "not_enabled")} The packages on this VM are unknown from its disk; that is not a clean result.
          </p>
        )}
        {data.state === "none" && (
          <p className="text-xs text-text-2">
            {stateGap ? gapText(stateGap) : "No disk scan has produced a package list for this VM."} The packages on this VM are unknown from its disk; that is not a clean result.
          </p>
        )}
        {data.volumes.length > 0 && (
          <ul className="mt-2 space-y-1.5 text-xs">
            {data.volumes.map((v) => (
              <li key={v.volume_ref} className="rounded border border-border-subtle bg-surface px-2.5 py-1.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-[11px] text-text-2">{v.volume_ref}</span>
                  <span className="text-[11px] text-text-3" title={new Date(v.observed_at).toLocaleString()}>
                    observed {timeAgo(v.observed_at)}
                  </span>
                </div>
                {v.inventory_known ? (
                  <p className="mt-0.5 text-text-2">
                    {v.package_count} packages read
                    {v.snapshot_source ? ` from an ${SOURCE_LABEL[v.snapshot_source] ?? v.snapshot_source}` : ""}.
                    {v.encrypted ? " The volume is encrypted." : ""}
                  </p>
                ) : (
                  <p className="mt-0.5 text-amber">
                    Not read. {gapText(v.gap) || "The disk was not read."}
                  </p>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
    </Card>
  );
}
