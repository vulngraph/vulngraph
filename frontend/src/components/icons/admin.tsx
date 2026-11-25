/**
 * Admin panel and settings-navigation icons. See icons/shared.tsx for the design system.
 */

import type { LucideProps } from "lucide-react"
import { forwardRef } from "react"
import { bp, type IC } from "./shared"

/** Organization - building facade with windows. Replaces Building2. */
export const Building2: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <rect x="5" y="8" width="22" height="20" rx="1.5" stroke="#2dd4bf" strokeWidth="2" fill="none"/>
    <line x1="5" y1="16" x2="27" y2="16" stroke="#2dd4bf" strokeWidth="1" opacity="0.4"/>
    <rect x="10" y="10" width="3.5" height="4" rx="0.5" fill="#2dd4bf" fillOpacity="0.35"/>
    <rect x="18.5" y="10" width="3.5" height="4" rx="0.5" fill="#2dd4bf" fillOpacity="0.35"/>
    <rect x="10" y="18" width="3.5" height="4" rx="0.5" fill="#2dd4bf" fillOpacity="0.35"/>
    <rect x="18.5" y="18" width="3.5" height="4" rx="0.5" fill="#2dd4bf" fillOpacity="0.35"/>
    <rect x="13" y="24" width="6" height="4" fill="#2dd4bf" fillOpacity="0.2"/>
  </svg>
))
Building2.displayName = "Building2"

/** Support - life ring with diagonal cross straps. Replaces LifeBuoy. */
export const LifeBuoy: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="16" r="12" stroke="#2dd4bf" strokeWidth="2" fill="none"/>
    <circle cx="16" cy="16" r="6" stroke="#2dd4bf" strokeWidth="2" fill="none"/>
    <line x1="7.5" y1="7.5" x2="11.8" y2="11.8" stroke="#2dd4bf" strokeWidth="2"/>
    <line x1="24.5" y1="7.5" x2="20.2" y2="11.8" stroke="#2dd4bf" strokeWidth="2"/>
    <line x1="7.5" y1="24.5" x2="11.8" y2="20.2" stroke="#2dd4bf" strokeWidth="2"/>
    <line x1="24.5" y1="24.5" x2="20.2" y2="20.2" stroke="#2dd4bf" strokeWidth="2"/>
  </svg>
))
LifeBuoy.displayName = "LifeBuoy"

/** Synth Lab - conical flask with reaction bubbles. Replaces FlaskConical. */
export const FlaskConical: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <path d="M11 5 L11 16 L5 26 L27 26 L21 16 L21 5 Z" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinejoin="round"/>
    <line x1="11" y1="5" x2="21" y2="5" stroke="#2dd4bf" strokeWidth="2" strokeLinecap="round"/>
    <line x1="9" y1="20" x2="23" y2="20" stroke="#2dd4bf" strokeWidth="1" opacity="0.35"/>
    <circle cx="13" cy="22.5" r="1.5" fill="#2dd4bf" fillOpacity="0.45"/>
    <circle cx="17.5" cy="23.5" r="1" fill="#2dd4bf" fillOpacity="0.55"/>
    <circle cx="21" cy="22" r="1" fill="#2dd4bf" fillOpacity="0.4"/>
  </svg>
))
FlaskConical.displayName = "FlaskConical"

/** Automation Rules - three horizontal slider tracks with control knobs. Replaces SlidersHorizontal. */
export const SlidersHorizontal: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <line x1="5" y1="10" x2="27" y2="10" stroke="#2dd4bf" strokeWidth="2" strokeLinecap="round"/>
    <line x1="5" y1="16" x2="27" y2="16" stroke="#2dd4bf" strokeWidth="2" strokeLinecap="round"/>
    <line x1="5" y1="22" x2="27" y2="22" stroke="#2dd4bf" strokeWidth="2" strokeLinecap="round"/>
    <circle cx="11" cy="10" r="3" fill="#09090b" stroke="#2dd4bf" strokeWidth="2"/>
    <circle cx="20" cy="16" r="3" fill="#09090b" stroke="#2dd4bf" strokeWidth="2"/>
    <circle cx="14" cy="22" r="3" fill="#09090b" stroke="#2dd4bf" strokeWidth="2"/>
  </svg>
))
SlidersHorizontal.displayName = "SlidersHorizontal"

/** Organization / SSO - stacked windows suggesting tenant directory. Replaces Building. */
export const Building: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <rect x="6" y="6" width="20" height="22" rx="1" stroke="#2dd4bf" strokeWidth="2" fill="none"/>
    <rect x="10" y="11" width="3" height="3" fill="#2dd4bf"/>
    <rect x="15" y="11" width="3" height="3" fill="#2dd4bf" opacity="0.6"/>
    <rect x="20" y="11" width="3" height="3" fill="#2dd4bf" opacity="0.6"/>
    <rect x="10" y="17" width="3" height="3" fill="#2dd4bf" opacity="0.6"/>
    <rect x="15" y="17" width="3" height="3" fill="#2dd4bf"/>
    <rect x="20" y="17" width="3" height="3" fill="#2dd4bf" opacity="0.6"/>
    <rect x="13" y="23" width="6" height="5" fill="#2dd4bf" opacity="0.4"/>
  </svg>
))
Building.displayName = "Building"

/** Audit Log - clipboard with timestamped rows. Replaces ClipboardList. */
export const ClipboardList: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <rect x="7" y="6" width="18" height="22" rx="2" stroke="#2dd4bf" strokeWidth="2" fill="none"/>
    <rect x="11" y="3" width="10" height="5" rx="1" stroke="#2dd4bf" strokeWidth="2" fill="none"/>
    <circle cx="12" cy="13" r="1" fill="#2dd4bf"/>
    <line x1="15" y1="13" x2="21" y2="13" stroke="#2dd4bf" strokeWidth="1.5" strokeLinecap="round"/>
    <circle cx="12" cy="18" r="1" fill="#2dd4bf"/>
    <line x1="15" y1="18" x2="21" y2="18" stroke="#2dd4bf" strokeWidth="1.5" strokeLinecap="round"/>
    <circle cx="12" cy="23" r="1" fill="#2dd4bf"/>
    <line x1="15" y1="23" x2="21" y2="23" stroke="#2dd4bf" strokeWidth="1.5" strokeLinecap="round"/>
  </svg>
))
ClipboardList.displayName = "ClipboardList"

/** Billing - card with magstripe. Replaces CreditCard. */
export const CreditCard: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <rect x="3" y="7" width="26" height="18" rx="2" stroke="#2dd4bf" strokeWidth="2" fill="none"/>
    <rect x="3" y="11" width="26" height="3" fill="#2dd4bf"/>
    <rect x="7" y="18" width="6" height="3" rx="0.5" fill="#2dd4bf" opacity="0.4"/>
    <rect x="19" y="18" width="6" height="3" rx="0.5" fill="#2dd4bf" opacity="0.6"/>
  </svg>
))
CreditCard.displayName = "CreditCard"

/** Trust & Autonomy - arc gauge with needle. Replaces Gauge. */
export const Gauge: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <path d="M6 22 A12 12 0 1 1 26 22" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinecap="round"/>
    <line x1="16" y1="22" x2="22" y2="12" stroke="#fb923c" strokeWidth="2.5" strokeLinecap="round"/>
    <circle cx="16" cy="22" r="2" fill="#2dd4bf"/>
    <circle cx="6" cy="22" r="1.2" fill="#2dd4bf" opacity="0.5"/>
    <circle cx="26" cy="22" r="1.2" fill="#2dd4bf" opacity="0.5"/>
  </svg>
))
Gauge.displayName = "Gauge"

/** Integrations - plug with two prongs. Replaces Plug. */
export const Plug: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <line x1="12" y1="2" x2="12" y2="7" stroke="#2dd4bf" strokeWidth="2" strokeLinecap="round"/>
    <line x1="20" y1="2" x2="20" y2="7" stroke="#2dd4bf" strokeWidth="2" strokeLinecap="round"/>
    <rect x="8" y="7" width="16" height="10" rx="1" stroke="#2dd4bf" strokeWidth="2" fill="none"/>
    <line x1="16" y1="17" x2="16" y2="22" stroke="#2dd4bf" strokeWidth="2"/>
    <path d="M10 22 L22 22 Q22 30 16 30 Q10 30 10 22 Z" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinejoin="round"/>
  </svg>
))
Plug.displayName = "Plug"
