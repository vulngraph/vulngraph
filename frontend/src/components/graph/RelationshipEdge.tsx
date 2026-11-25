import { EdgeLabelRenderer, useStore, type EdgeProps } from "@xyflow/react";

// RelationshipEdge renders a Neo4j-style edge: a gentle fixed-curvature bezier
// (not React Flow's wild routing curves), a directional arrowhead, and an
// on-select label. The curve is a simple symmetric bow — consistent regardless
// of handle position — so edges look clean and intentional, not like routing
// artifacts.
export function RelationshipEdge({
  id,
  sourceX, sourceY,
  targetX, targetY,
  style,
  label,
  selected,
  markerEnd,
}: EdgeProps) {
  const zoom = useStore((s) => s.transform[2]);

  // Straight-line midpoint + small perpendicular offset for a gentle fixed bow.
  // At close zoom we increase the bow slightly so parallel edges separate.
  const dx = targetX - sourceX;
  const dy = targetY - sourceY;
  const len = Math.sqrt(dx * dx + dy * dy) || 1;
  // Perpendicular unit vector
  const px = -dy / len;
  const py = dx / len;
  const bow = Math.min(len * 0.08, 20); // max 20px bow — subtle, not dramatic
  const mx = (sourceX + targetX) / 2 + px * bow;
  const my = (sourceY + targetY) / 2 + py * bow;

  // Build a simple quadratic bezier path for the fixed-bow curve.
  const path = `M ${sourceX} ${sourceY} Q ${mx} ${my} ${targetX} ${targetY}`;

  const strokeColor = (style?.stroke as string) ?? "#3f3f46";
  const strokeWidth = selected ? 2 : ((style?.strokeWidth as number) ?? 1);
  const opacity = (style?.opacity as number) ?? 1;
  const midX = (sourceX + targetX) / 2 + px * bow * 0.5;
  const midY = (sourceY + targetY) / 2 + py * bow * 0.5;

  const showLabel = selected && label && zoom > 0.5;

  return (
    <>
      {/* Wider invisible hit area so edges are easy to click */}
      <path
        id={`${id}-hit`}
        d={path}
        fill="none"
        strokeWidth={16}
        stroke="transparent"
        strokeOpacity={0}
      />
      <path
        id={id}
        d={path}
        fill="none"
        stroke={strokeColor}
        strokeWidth={strokeWidth}
        opacity={opacity}
        markerEnd={markerEnd}
        style={{ transition: "opacity 0.15s, stroke-width 0.1s" }}
      />
      {showLabel && (
        <EdgeLabelRenderer>
          <div
            style={{
              position: "absolute",
              transform: `translate(-50%, -50%) translate(${midX}px, ${midY}px)`,
              background: "rgba(10,10,13,0.88)",
              border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: 4,
              padding: "1px 5px",
              fontSize: 10,
              color: strokeColor,
              letterSpacing: "0.05em",
              textTransform: "uppercase",
              fontWeight: 500,
              pointerEvents: "none",
              whiteSpace: "nowrap",
              backdropFilter: "blur(4px)",
            }}
          >
            {label as string}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}
