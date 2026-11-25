/**
 * Threat/alert/security-state icons. See icons/shared.tsx for the design system.
 */

import type { LucideProps } from "lucide-react"
import { forwardRef } from "react"
import { bp, type IC } from "./shared"

export const Shield: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="6" cy="8" r="3" fill="#2dd4bf" />
    <circle cx="18" cy="16" r="3" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    <circle cx="26" cy="26" r="3.5" fill="#ef4444" />
    <line x1="9" y1="9.5" x2="15.5" y2="14.5" stroke="#2dd4bf" strokeWidth="1.5" strokeDasharray="2 2" />
    <line x1="20.5" y1="18" x2="24" y2="23.5" stroke="#ef4444" strokeWidth="1.5" strokeDasharray="2 2" />
  </svg>
))
Shield.displayName = "Shield"

/** Blast Radius - expanding impact rings from a compromised core. Replaces ShieldAlert. */

export const ShieldAlert: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="16" r="3" fill="#ef4444" />
    <circle cx="16" cy="16" r="8" stroke="#ef4444" strokeWidth="1" opacity="0.4" />
    <circle cx="16" cy="16" r="13" stroke="#ef4444" strokeWidth="0.75" opacity="0.2" />
    <line x1="19" y1="13" x2="22" y2="10" stroke="#ef4444" strokeWidth="1.5" opacity="0.6" />
    <line x1="22" y1="10" x2="20" y2="10" stroke="#ef4444" strokeWidth="1.5" opacity="0.6" />
    <line x1="22" y1="10" x2="22" y2="12" stroke="#ef4444" strokeWidth="1.5" opacity="0.6" />
    <line x1="13" y1="13" x2="10" y2="10" stroke="#ef4444" strokeWidth="1.5" opacity="0.6" />
    <line x1="10" y1="10" x2="12" y2="10" stroke="#ef4444" strokeWidth="1.5" opacity="0.6" />
    <line x1="10" y1="10" x2="10" y2="12" stroke="#ef4444" strokeWidth="1.5" opacity="0.6" />
  </svg>
))
ShieldAlert.displayName = "ShieldAlert"

/** Threat Vector - red arrow targeting a teal node. Replaces ShieldX. */

export const ShieldX: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="22" cy="22" r="5" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    <line x1="5" y1="5" x2="18.5" y2="18.5" stroke="#ef4444" strokeWidth="2" />
    <polygon points="18.5,18.5 14,17 17,14" fill="#ef4444" />
  </svg>
))
ShieldX.displayName = "ShieldX"

/** Security Boundary - dashed perimeter ring + solid core. Replaces ShieldCheck. */

export const ShieldCheck: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="16" r="12" stroke="#2dd4bf" strokeWidth="1.5" strokeDasharray="3 2" />
    <circle cx="16" cy="16" r="4" fill="#2dd4bf" />
  </svg>
))
ShieldCheck.displayName = "ShieldCheck"

// ── 02 - Intelligence & Reasoning ─────────────────────────────────────────────

/** Neural Prior - weighted edge with attention parallels. Replaces Brain, Sparkles. */

export const AlertTriangle: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="16" r="4" fill="#fb923c" />
    <circle cx="16" cy="16" r="9" stroke="#fb923c" strokeWidth="1.5" opacity="0.5" />
    <circle cx="16" cy="16" r="13" stroke="#fb923c" strokeWidth="1" opacity="0.2" />
    <line x1="3" y1="3" x2="10" y2="10" stroke="#fb923c" strokeWidth="1" opacity="0.4" strokeDasharray="2 2" />
  </svg>
))
AlertTriangle.displayName = "AlertTriangle"

/** Alert Pulse - same as AlertTriangle. Replaces Bell. */

export const AlertCircle: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="16" r="12" stroke="#fb923c" strokeWidth="2" fill="none"/>
    <line x1="16" y1="10" x2="16" y2="18" stroke="#fb923c" strokeWidth="2" strokeLinecap="round"/>
    <circle cx="16" cy="23" r="1.5" fill="#fb923c"/>
  </svg>
))
AlertCircle.displayName = "AlertCircle"

/** Error circle - circle with X indicating failure. Red. Replaces XCircle. */

export const AlertOctagon: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <polygon points="11,4 21,4 28,11 28,21 21,28 11,28 4,21 4,11" stroke="#ef4444" strokeWidth="2" fill="none" strokeLinejoin="round"/>
    <line x1="16" y1="11" x2="16" y2="18" stroke="#ef4444" strokeWidth="2.5" strokeLinecap="round"/>
    <circle cx="16" cy="22" r="1.5" fill="#ef4444"/>
  </svg>
))
AlertOctagon.displayName = "AlertOctagon"

/** AI Security - robot agent head with threat-sensing grid. Replaces Bot. */

export const Ban: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="5" cy="16" r="3" fill="#2dd4bf" />
    <line x1="8" y1="16" x2="14" y2="16" stroke="#2dd4bf" strokeWidth="1.5" strokeDasharray="3 2" />
    <circle cx="16" cy="16" r="5" stroke="#ef4444" strokeWidth="1.5" fill="none" />
    <line x1="13" y1="13" x2="19" y2="19" stroke="#ef4444" strokeWidth="1.5" />
    <line x1="19" y1="13" x2="13" y2="19" stroke="#ef4444" strokeWidth="1.5" />
    <circle cx="27" cy="16" r="3" stroke="#2dd4bf" strokeWidth="1.5" fill="none" opacity="0.3" />
  </svg>
))
Ban.displayName = "Ban"

/** Identity Cluster - lead node → two member nodes + peer edge. Replaces Users, UserGroup. */

export const Bell: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="16" r="4" fill="#fb923c" />
    <circle cx="16" cy="16" r="9" stroke="#fb923c" strokeWidth="1.5" opacity="0.5" />
    <circle cx="16" cy="16" r="13" stroke="#fb923c" strokeWidth="1" opacity="0.2" />
    <line x1="3" y1="3" x2="10" y2="10" stroke="#fb923c" strokeWidth="1" opacity="0.4" strokeDasharray="2 2" />
  </svg>
))
Bell.displayName = "Bell"

/** Scanner / Observe - observer + scan rays + target. Replaces Eye, EyeOff. */

export const BellOff: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <path d="M20 12 C20 9 18.2 6.5 16 6 L16 5 C16 4.4 15.3 4 14.5 4 C13.7 4 13 4.4 13 5 L13 6 C10.8 6.5 9 9 9 12 L9 20 L7 22 L22 22 L20 20 Z" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinejoin="round" opacity="0.5"/>
    <line x1="13" y1="22" x2="17" y2="26" stroke="#2dd4bf" strokeWidth="2" strokeLinecap="round"/>
    <line x1="6" y1="6" x2="26" y2="26" stroke="#ef4444" strokeWidth="2" strokeLinecap="round"/>
  </svg>
))
BellOff.displayName = "BellOff"

/** Emergency Controls - octagon caution frame with critical-state center. Replaces AlertOctagon. */

export const CheckCircle2: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="16" r="11" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    <circle cx="16" cy="16" r="4" fill="#2dd4bf" opacity="0.2" />
    <polyline points="11,16 14.5,19.5 21,12.5" stroke="#2dd4bf" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
))
CheckCircle2.displayName = "CheckCircle2"

/** Alias → CheckCircle2 (Verified Node). Replaces CheckCircle. */

export const CheckCircle = CheckCircle2

// ── 04 - Alert & Signal ───────────────────────────────────────────────────────

/** Signal Propagation - alert arc from orange source to target. Replaces Zap, AlertTriangle. */

export const XCircle: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="16" r="12" stroke="#ef4444" strokeWidth="2" fill="none"/>
    <line x1="11" y1="11" x2="21" y2="21" stroke="#ef4444" strokeWidth="2" strokeLinecap="round"/>
    <line x1="21" y1="11" x2="11" y2="21" stroke="#ef4444" strokeWidth="2" strokeLinecap="round"/>
  </svg>
))
XCircle.displayName = "XCircle"

// ── Admin panel icons ─────────────────────────────────────────────────────────

/** Organization - building facade with windows. Replaces Building2. */

export const Zap: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="8" cy="24" r="3" fill="#fb923c" />
    <path d="M12 20 Q16 12 20 8" stroke="#fb923c" strokeWidth="1.5" strokeLinecap="round" fill="none" />
    <path d="M10 22 Q14 10 22 4" stroke="#fb923c" strokeWidth="1" opacity="0.5" strokeLinecap="round" fill="none" />
    <circle cx="22" cy="6" r="3" stroke="#fb923c" strokeWidth="1.5" fill="none" />
  </svg>
))
Zap.displayName = "Zap"

/** Alert Pulse - pulsing rings from hot node. Replaces AlertTriangle, Bell, BellRing. */

export const Power: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="17" r="12" stroke="#ef4444" strokeWidth="1" opacity="0.25" fill="none"/>
    <path d="M8 10 A10 10 0 1 0 24 10" stroke="#ef4444" strokeWidth="2.5" fill="none" strokeLinecap="round"/>
    <line x1="16" y1="3" x2="16" y2="15" stroke="#ef4444" strokeWidth="2.5" strokeLinecap="round"/>
  </svg>
))
Power.displayName = "Power"

/** Silenced Alerts - speaker with red X. Replaces VolumeX. */

export const VolumeX: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <path d="M4 13 L9 13 L15 8 L15 24 L9 19 L4 19 Z" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinejoin="round"/>
    <line x1="20" y1="12" x2="28" y2="20" stroke="#ef4444" strokeWidth="2.5" strokeLinecap="round"/>
    <line x1="28" y1="12" x2="20" y2="20" stroke="#ef4444" strokeWidth="2.5" strokeLinecap="round"/>
  </svg>
))
VolumeX.displayName = "VolumeX"

/**  Boxes - stacked packages for supply chain. Replaces lucide Boxes. */
