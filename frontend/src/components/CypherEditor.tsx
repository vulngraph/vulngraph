import { useEffect, useState } from "react";
import type { RefObject } from "react";
import { History, Bell, Copy, Check } from "lucide-react";
import { Button } from "./ui";
import { copyText } from "../lib/clipboard";
import { SaveQueryDialog, type SavedQuery } from "./SaveQueryDialog";

export type HistoryEntry = { query: string; timestamp: number; nodeCount: number };

// The Cypher workbench: textarea + run/save/history/detections toolbar. Owns
// only its own toolbar-popover state (history dropdown, copy feedback) —
// query text, saved queries, and history entries are all controlled by Explore
// so the query library chips and NL "Ask" flow can drive the same editor.
export function CypherEditor({
  workbenchRef,
  taRef,
  query,
  onQueryChange,
  onSubmit,
  isPending,
  saved,
  onPersistSaved,
  history,
  onSelectHistory,
  showDetections,
  onToggleDetections,
  onShowDetections,
  onClear,
}: {
  workbenchRef: RefObject<HTMLDivElement | null>;
  taRef: RefObject<HTMLTextAreaElement | null>;
  query: string;
  onQueryChange: (v: string) => void;
  onSubmit: () => void;
  isPending: boolean;
  saved: SavedQuery[];
  onPersistSaved: (next: SavedQuery[]) => void;
  history: HistoryEntry[];
  onSelectHistory: (query: string) => void;
  showDetections: boolean;
  onToggleDetections: () => void;
  // Called after a scheduled detection is saved, so the management panel opens
  // and the analyst sees what they just created.
  onShowDetections?: () => void;
  onClear: () => void;
}) {
  const [showHistory, setShowHistory] = useState(false);
  const [copied, setCopied] = useState(false);
  const [saveOpen, setSaveOpen] = useState(false);

  // ⌘S / Ctrl+S opens the Save dialog instead of the browser's page save.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && (e.key === "s" || e.key === "S")) {
        e.preventDefault();
        if (query.trim()) setSaveOpen(true);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [query]);

  return (
    <>
      {/* Cypher editor */}
      <div ref={workbenchRef} />
      <textarea
        ref={taRef}
        value={query}
        onChange={(e) => onQueryChange(e.target.value)}
        onKeyDown={(e) => { if ((e.metaKey || e.ctrlKey) && e.key === "Enter") onSubmit(); }}
        spellCheck={false}
        rows={5}
        className="w-full resize-y rounded-lg border border-border-subtle bg-bg px-3 py-2.5 font-mono text-[12px] leading-relaxed text-text outline-none focus:border-teal"
        placeholder="MATCH (n:Asset)-[r:ExposedToInternet]->(m) RETURN n, r, m LIMIT 50"
      />

      <div className="mt-2 flex flex-wrap items-center gap-2">
        <Button variant="primary" onClick={onSubmit} disabled={isPending || !query.trim()}>
          {isPending ? "Running…" : "Run query"}
        </Button>
        <SaveQueryDialog
          query={query}
          saved={saved}
          onPersist={onPersistSaved}
          open={saveOpen}
          onOpenChange={setSaveOpen}
          onSavedDetection={onShowDetections}
        />
        {/* History dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowHistory((v) => !v)}
            disabled={history.length === 0}
            className="flex items-center gap-1 rounded border border-border-subtle px-2.5 py-1.5 text-[12px] text-text-2 hover:border-teal/30 hover:text-text disabled:opacity-30 transition-colors"
          >
            <History className="h-3 w-3" /> History{history.length > 0 ? ` (${history.length})` : ""}
          </button>
          {showHistory && history.length > 0 && (
            <div className="absolute left-0 top-full z-20 mt-1 w-80 rounded-lg border border-border-subtle bg-surface shadow-lg">
              <div className="flex items-center justify-between border-b border-border-subtle px-3 py-2">
                <span className="text-[11px] uppercase tracking-wide text-text-3">Recent queries</span>
                <button onClick={() => setShowHistory(false)} className="text-[11px] text-text-3 hover:text-text-2">✕</button>
              </div>
              <div className="max-h-64 overflow-y-auto py-1">
                {history.map((h, i) => (
                  <button
                    key={i}
                    onClick={() => { onSelectHistory(h.query); setShowHistory(false); }}
                    className="group w-full px-3 py-2 text-left hover:bg-surface-2 transition-colors"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate font-mono text-[11px] text-text-2 group-hover:text-text">{h.query.split("\n")[0]}</span>
                      <span className="shrink-0 text-[11px] text-text-3">{h.nodeCount}n</span>
                    </div>
                    <div className="mt-0.5 text-[11px] text-text-3">
                      {new Date(h.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                      {" · "}{h.nodeCount} node{h.nodeCount !== 1 ? "s" : ""}
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
        {/* Detections — backend-persisted, schedulable, alerting saved queries */}
        <button
          onClick={onToggleDetections}
          title="Server-side scheduled detections — list, run, delete"
          className={`flex items-center gap-1 rounded border px-2.5 py-1.5 text-[12px] transition-colors ${
            showDetections
              ? "border-teal/40 bg-teal/10 text-teal"
              : "border-border-subtle text-text-2 hover:border-teal/30 hover:text-text"
          }`}
        >
          <Bell className="h-3 w-3" /> Detections
        </button>
        {query.trim() && (
          <button
            onClick={() => {
              void copyText(query).then((ok) => {
                if (!ok) return;
                setCopied(true);
                setTimeout(() => setCopied(false), 1500);
              });
            }}
            className="flex items-center gap-1 rounded border border-border-subtle px-2.5 py-1.5 text-[12px] text-text-2 hover:border-teal/30 hover:text-text transition-colors">
            {copied ? <><Check className="h-3 w-3" /> Copied</> : <><Copy className="h-3 w-3" /> Copy</>}
          </button>
        )}
        {query.trim() && (
          <button onClick={onClear}
            className="text-[12px] text-text-3 hover:text-text-2">clear</button>
        )}
        <span className="ml-auto text-[12px] text-text-3">⌘ Enter to run · ⌘S to save · read-only · Ladybug · max 500 nodes</span>
      </div>
    </>
  );
}
