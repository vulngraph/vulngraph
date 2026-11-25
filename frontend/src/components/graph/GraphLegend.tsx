import { useState } from "react";

// GraphLegend is the canvas caption key (bottom-left, like Neo4j Browser): what
// the edge colours, node risk colours, and signal glows mean. Collapsed to a
// small chip by default so it never crowds the graph.
const EDGES = [
  { color: "#f87171", label: "exposed" },
  { color: "#2dd4bf", label: "privilege / deploy" },
  { color: "#fbbf24", label: "protects" },
  { color: "#3f3f46", label: "other" },
];
const RISK = [
  { color: "#f87171", label: "critical" },
  { color: "#fb923c", label: "high" },
  { color: "#fbbf24", label: "medium" },
  { color: "#2dd4bf", label: "low" },
];
const SIGNALS = [
  { color: "bg-red", label: "toxic / exploitable" },
  { color: "bg-amber", label: "known exploited vuln (KEV)" },
  { color: "bg-orange", label: "internet-exposed" },
];

export function GraphLegend() {
  const [open, setOpen] = useState(false);

  if (!open) {
    return (
      <button onClick={() => setOpen(true)}
        className="absolute bottom-2 left-2 z-10 rounded border border-border-subtle bg-bg/90 px-2 py-1 text-[11px] text-text-3 backdrop-blur-sm hover:text-text-2">
        ▤ Legend
      </button>
    );
  }
  return (
    <div className="absolute bottom-2 left-2 z-10 w-44 rounded-lg border border-border-subtle bg-bg/95 p-2.5 text-[11px] shadow-lg backdrop-blur-sm">
      <div className="mb-1.5 flex items-center justify-between">
        <span className="font-semibold text-text-2">Legend</span>
        <button onClick={() => setOpen(false)} className="text-text-3 hover:text-text-2">✕</button>
      </div>
      <Section title="Relationships">
        {EDGES.map((e) => (
          <div key={e.label} className="flex items-center gap-1.5 text-text-3">
            <span className="h-0.5 w-4 rounded" style={{ background: e.color }} />
            {e.label}
          </div>
        ))}
      </Section>
      <Section title="Risk">
        {RISK.map((r) => (
          <div key={r.label} className="flex items-center gap-1.5 text-text-3">
            <span className="h-2 w-2 rounded-full" style={{ background: r.color }} />
            {r.label}
          </div>
        ))}
      </Section>
      <Section title="Signals (glow)">
        {SIGNALS.map((s) => (
          <div key={s.label} className="flex items-center gap-1.5 text-text-3">
            <span className={`h-2 w-2 rounded-full ${s.color}`} />
            {s.label}
          </div>
        ))}
      </Section>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mb-1.5 last:mb-0">
      <div className="mb-0.5 text-[11px] uppercase tracking-wide text-text-3">{title}</div>
      <div className="space-y-0.5">{children}</div>
    </div>
  );
}
