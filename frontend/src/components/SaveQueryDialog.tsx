import { useEffect, useRef, useState } from "react";
import { Star, Clock, Bell } from "lucide-react";
import { useCreateSavedQuery, useAlertChannels, type SavedQueryInput } from "../lib/queries";
import { SCHEDULES } from "./SavedDetections";

export type SavedQuery = { name: string; cypher: string };

// The one Save action on the Cypher workbench. A single dialog, one name field,
// and a "Monitor on a schedule" toggle:
//   OFF — saves locally in this browser, in the {name, cypher} localStorage
//         shape the query-library grid reads.
//   ON  — reveals schedule + alert-channel fields and persists server-side as a
//         scheduled detection (POST /api/saved-queries). Managing those lives in
//         the Detections panel; this dialog only creates.
//
// Open state is owned by the caller (CypherEditor) so ⌘S can open it.
export function SaveQueryDialog({
  query,
  saved,
  onPersist,
  open,
  onOpenChange,
  onSavedDetection,
}: {
  query: string;
  saved: SavedQuery[];
  onPersist: (next: SavedQuery[]) => void;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSavedDetection?: () => void;
}) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [monitor, setMonitor] = useState(false);
  const [schedule, setSchedule] = useState("0 2 * * *");
  const [alertOnChange, setAlertOnChange] = useState(false);
  const [channelIDs, setChannelIDs] = useState<string[]>([]);
  const nameRef = useRef<HTMLInputElement>(null);

  const create = useCreateSavedQuery();
  const { data: channelsData } = useAlertChannels();
  const channels = channelsData?.channels ?? [];

  // Reset the form each time the dialog opens, and take focus for typing.
  useEffect(() => {
    if (!open) return;
    setName("");
    setDescription("");
    setMonitor(false);
    setSchedule("0 2 * * *");
    setAlertOnChange(false);
    setChannelIDs([]);
    create.reset();
    const t = setTimeout(() => nameRef.current?.focus(), 30);
    return () => clearTimeout(t);
  }, [open]);

  function close() {
    onOpenChange(false);
  }

  function confirm() {
    const n = name.trim();
    const q = query.trim();
    if (!n || !q) return;

    if (!monitor) {
      // Local save — the same {name, cypher} shape the query-library grid reads.
      onPersist([...saved.filter((s) => s.name !== n), { name: n, cypher: q }]);
      close();
      return;
    }

    const input: SavedQueryInput = {
      name: n,
      description: description.trim(),
      cypher: q,
      schedule,
      alert_channel_ids: channelIDs,
      alert_on_change: alertOnChange,
      enabled: true,
    };
    create.mutate(input, {
      onSuccess: () => {
        close();
        onSavedDetection?.();
      },
    });
  }

  function toggleChannel(id: string) {
    setChannelIDs((prev) => (prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id]));
  }

  return (
    <div className="relative">
      <button
        onClick={() => onOpenChange(!open)}
        disabled={!query.trim()}
        title="Save this query — locally, or as a scheduled detection (⌘S)"
        className={`flex items-center gap-1 rounded border px-2.5 py-1.5 text-[12px] transition-colors disabled:opacity-30 ${
          open
            ? "border-teal/40 bg-teal/10 text-teal"
            : "border-border-subtle text-text-2 hover:border-teal/30 hover:text-text"
        }`}
      >
        <Star className="h-3 w-3" /> Save
      </button>

      {open && (
        <div
          onKeyDown={(e) => {
            if (e.key === "Escape") close();
            if (e.key === "Enter" && (e.target as HTMLElement).tagName === "INPUT") confirm();
          }}
          className="absolute left-0 top-full z-30 mt-1 w-80 space-y-3 rounded-lg border border-border-subtle bg-surface p-3 shadow-lg"
        >
          <div className="flex items-center justify-between">
            <span className="text-[11px] uppercase tracking-wide text-text-3">Save query</span>
            <button onClick={close} className="text-[11px] text-text-3 hover:text-text-2" aria-label="Close">✕</button>
          </div>

          <input
            ref={nameRef}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Name this query…"
            className="w-full rounded border border-border-subtle bg-bg px-2 py-1.5 text-[12px] text-text placeholder-text-3 outline-none focus:border-teal"
          />

          {/* The one switch between the two save systems */}
          <label className="flex items-start gap-2 text-[12px] text-text-2">
            <input
              type="checkbox"
              checked={monitor}
              onChange={(e) => setMonitor(e.target.checked)}
              className="mt-0.5"
            />
            <span>
              Monitor on a schedule
              <span className="block text-[11px] text-text-3">
                {monitor
                  ? "Saved on the server as a detection — runs on a schedule, can alert."
                  : "Off: saved locally in this browser only."}
              </span>
            </span>
          </label>

          {monitor && (
            <>
              <input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Description (optional)"
                className="w-full rounded border border-border-subtle bg-bg px-2 py-1.5 text-[11px] text-text placeholder-text-3 outline-none focus:border-teal"
              />

              <div>
                <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-text-3">Schedule</div>
                <div className="flex flex-wrap gap-1.5">
                  {SCHEDULES.filter((s) => s.cron !== "").map((s) => (
                    <button
                      key={s.cron}
                      onClick={() => setSchedule(s.cron)}
                      className={`rounded border px-2 py-1 text-[11px] font-medium transition-colors ${
                        schedule === s.cron
                          ? "border-teal/40 bg-teal/10 text-teal"
                          : "border-border-subtle text-text-3 hover:bg-surface-2"
                      }`}
                    >
                      <Clock className="mr-1 inline h-3 w-3" />
                      {s.label}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="flex items-center gap-2 text-[12px] text-text-2">
                  <input
                    type="checkbox"
                    checked={alertOnChange}
                    onChange={(e) => setAlertOnChange(e.target.checked)}
                  />
                  <Bell className="h-3 w-3" /> Alert when results change
                </label>
                {alertOnChange && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {channels.length === 0 && (
                      <span className="text-[11px] text-text-3">
                        No alert channels — add one in Settings → Alerts.
                      </span>
                    )}
                    {channels.map((c) => (
                      <button
                        key={c.id}
                        onClick={() => toggleChannel(c.id)}
                        className={`rounded border px-2 py-1 text-[11px] transition-colors ${
                          channelIDs.includes(c.id)
                            ? "border-teal/40 bg-teal/10 text-teal"
                            : "border-border-subtle text-text-3 hover:bg-surface-2"
                        }`}
                      >
                        {c.name}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}

          {create.isError && (
            <p className="text-[11px] text-red">{(create.error as Error).message}</p>
          )}

          <div className="flex items-center gap-2">
            <button
              onClick={confirm}
              disabled={!name.trim() || !query.trim() || create.isPending}
              className="rounded border border-teal/30 bg-teal/10 px-2 py-1 text-[11px] text-teal hover:bg-teal/20 disabled:opacity-30"
            >
              {create.isPending ? "Saving…" : monitor ? "Save detection" : "Save"}
            </button>
            <button onClick={close} className="text-[11px] text-text-3 hover:text-text-2">Cancel</button>
          </div>
        </div>
      )}
    </div>
  );
}
