interface VLogomarkProps {
  size?: number
  className?: string
  /** "default" = vivid teal (dark bg). "chat" = slightly lighter (chat avatars). */
  variant?: "default" | "chat"
}

/**
 * Vulngraph brand logomark - Mesh Fragment.
 * Bottom-left anchor node, diagonal cross-edge, fading ghost grid.
 * Works at 14px favicon through large hero sizes.
 */
export function VLogomark({ size = 36, className, variant = "default" }: VLogomarkProps) {
  const primary = variant === "chat" ? "#5eead4" : "#2dd4bf"
  const edge = variant === "chat" ? "#5eead4" : "#14b8a6"

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 36 36"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-label="GRAPH"
    >
      {/* Ghost grid edges */}
      <line x1="6" y1="28" x2="18" y2="28" stroke={edge} strokeWidth="1.5" strokeOpacity="0.4"/>
      <line x1="18" y1="28" x2="30" y2="28" stroke={edge} strokeWidth="1.5" strokeOpacity="0.2"/>
      <line x1="6" y1="16" x2="18" y2="16" stroke={edge} strokeWidth="1.5" strokeOpacity="0.4"/>
      <line x1="18" y1="16" x2="30" y2="16" stroke={edge} strokeWidth="1.5" strokeOpacity="0.2"/>
      <line x1="6" y1="16" x2="6" y2="28" stroke={edge} strokeWidth="1.5" strokeOpacity="0.5"/>
      <line x1="18" y1="8" x2="18" y2="28" stroke={edge} strokeWidth="1.5" strokeOpacity="0.35"/>
      <line x1="30" y1="16" x2="30" y2="28" stroke={edge} strokeWidth="1.5" strokeOpacity="0.15"/>

      {/* Primary diagonal - the "direction" edge from anchor */}
      <line x1="6" y1="28" x2="18" y2="16" stroke={edge} strokeWidth="1.5" strokeOpacity="0.65"/>

      {/* Nodes - fading outward from bottom-left anchor */}
      <circle cx="6" cy="28" r="4" fill={primary}/>
      <circle cx="18" cy="28" r="2.5" fill={edge} opacity="0.7"/>
      <circle cx="30" cy="28" r="2" fill={edge} opacity="0.35"/>
      <circle cx="6" cy="16" r="2.5" fill={edge} opacity="0.7"/>
      <circle cx="18" cy="16" r="2.5" fill={edge} opacity="0.5"/>
      <circle cx="30" cy="16" r="2" fill={edge} opacity="0.25"/>
      <circle cx="18" cy="8" r="2" fill={edge} opacity="0.25"/>
    </svg>
  )
}
