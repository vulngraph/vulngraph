/**
 * Vulngraph Icon Registry - shared helper used by every icons/* category file.
 *
 * All semantic security icons follow the Vulngraph brand palette below.
 * Icons use a 32×32 design grid with explicit brand colors:
 *   teal  #2dd4bf - nodes, edges, positive states
 *   red   #ef4444 - threats, compromised states
 *   orange #fb923c - alerts, signals, warnings
 *   green  #4ade80 - approved/safe leaf outcomes
 */

import type { LucideProps } from "lucide-react"

// ── Brand SVG helper ──────────────────────────────────────────────────────────
// 32×32 viewBox, explicit brand colors, no currentColor inheritance.
// Width/height come from the `size` prop (default 24) or className overrides.

export function bp(props: LucideProps): React.SVGProps<SVGSVGElement> {
  return {
    xmlns: "http://www.w3.org/2000/svg",
    viewBox: "0 0 32 32",
    fill: "none",
    width: props.size ?? 24,
    height: props.size ?? 24,
    className: props.className,
    style: props.style,
    "aria-hidden": true,
  }
}

export type IC = React.ForwardRefExoticComponent<LucideProps & React.RefAttributes<SVGSVGElement>>
