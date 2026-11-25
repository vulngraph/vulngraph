import { Handle, Position, useStore } from "@xyflow/react";
import { typeMetaFor } from "../../lib/assetMeta";

export type AssetNodeData = {
  label: string;
  typeLabel?: string;
  rawType?: string;
  isCenter?: boolean;
  exposed?: boolean;
  hasKev?: boolean;
  exploitable?: boolean;
  toxicCombo?: boolean;
  accent: string; // left accent bar colour (risk/type)
  glow: string | null;
  width: number;
  // kept for dot-zoom sizing
  bg: string;
  border: string;
};

// Below this zoom a node collapses to a dot. Kept low (0.35) so node cards stay
// readable across the normal fit range — a higher threshold (e.g. 0.55) puts a
// fit-to-view graph just under it, rendering every node as a bare dot.
const DOT_ZOOM = 0.35;

function signalDots(d: AssetNodeData) {
  const dots: string[] = [];
  if (d.toxicCombo) dots.push("bg-red");
  if (d.exploitable) dots.push("bg-red/70");
  if (d.hasKev) dots.push("bg-amber");
  if (d.exposed) dots.push("bg-orange");
  return dots;
}

export function AssetNode({ data, selected }: { data: AssetNodeData; selected?: boolean }) {
  const far = useStore((s) => s.transform[2] < DOT_ZOOM);
  const meta = typeMetaFor(data.rawType ?? "");
  const Icon = meta.icon;
  const dots = signalDots(data);

  if (far) {
    const size = Math.round(8 + ((data.width - 140) / 60) * 10);
    return (
      <>
        <Handle type="target" position={Position.Left} className="!opacity-0" />
        <div
          title={data.label}
          style={{
            width: size, height: size, borderRadius: "50%",
            background: data.accent,
            boxShadow: selected ? `0 0 0 2px #2dd4bf` : (data.glow ?? "none"),
            opacity: 0.9,
          }}
        />
        <Handle type="source" position={Position.Right} className="!opacity-0" />
      </>
    );
  }

  return (
    <>
      <Handle type="target" position={Position.Left} className="!opacity-0" />
      <div
        style={{
          width: data.width,
          background: "#0e0e11",
          border: selected
            ? "1px solid rgba(45,212,191,0.6)"
            : "1px solid rgba(255,255,255,0.07)",
          borderLeft: `3px solid ${data.accent}`,
          borderRadius: 6,
          padding: "4px 7px 4px 6px",
          minHeight: 28,
          boxShadow: selected
            ? "0 0 0 2px rgba(45,212,191,0.2), 0 4px 12px rgba(0,0,0,0.6)"
            : data.glow
            ? data.glow + ", 0 2px 8px rgba(0,0,0,0.5)"
            : "0 2px 8px rgba(0,0,0,0.5)",
          cursor: "pointer",
          display: "flex",
          alignItems: "center",
          gap: 5,
        }}
      >
        <Icon
          style={{ width: 10, height: 10, flexShrink: 0, opacity: 0.65 }}
          className={meta.color}
          aria-hidden
        />
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{
            fontSize: data.isCenter ? 11 : 10,
            fontWeight: data.isCenter ? 600 : 400,
            color: "#e8e8ea",
            lineHeight: 1.3,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            letterSpacing: "0.01em",
          }}>{data.label}</div>
          {data.typeLabel && (
            <div style={{
              fontSize: 10,
              color: "rgba(255,255,255,0.32)",
              lineHeight: 1.2,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
              letterSpacing: "0.04em",
              textTransform: "uppercase",
              marginTop: 1,
            }}>{data.typeLabel}</div>
          )}
        </div>
        {dots.length > 0 && (
          <div style={{ display: "flex", flexShrink: 0, gap: 2, alignItems: "center" }}>
            {dots.map((c, i) => (
              <span key={i} className={`inline-block h-1 w-1 rounded-full ${c}`} />
            ))}
          </div>
        )}
      </div>
      <Handle type="source" position={Position.Right} className="!opacity-0" />
    </>
  );
}
