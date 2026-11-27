// Overview-zoom helpers. A large result is fitted at a low zoom, where nodes
// collapse to dots and 1px edges shrink to nothing; these keep both visible on
// screen.

// Below this zoom a node collapses to a dot.
export const DOT_ZOOM = 0.35;

const MIN_DOT_PX = 6;
const MAX_DOT = 30;
const MIN_EDGE_PX = 0.8;
const MAX_EDGE = 8;

// dotDiameter is the dot's size in canvas units: the card-width based size,
// raised so it never renders under MIN_DOT_PX on screen.
export function dotDiameter(cardWidth: number, zoom: number): number {
  const base = Math.round(8 + ((cardWidth - 140) / 60) * 10);
  return Math.max(base, Math.min(MIN_DOT_PX / zoom, MAX_DOT));
}

// edgeWidth is the stroke width in canvas units: unchanged at normal zoom,
// raised at overview zoom so it never renders under MIN_EDGE_PX on screen.
export function edgeWidth(base: number, zoom: number): number {
  if (zoom >= DOT_ZOOM) return base;
  return Math.max(base, Math.min(MIN_EDGE_PX / zoom, MAX_EDGE));
}
