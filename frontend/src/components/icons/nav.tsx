/**
 * App navigation and utility icons. See icons/shared.tsx for the design system.
 */

import type { LucideProps } from "lucide-react"
import { forwardRef } from "react"
import { bp, type IC } from "./shared"

/** Knowledge Node - teal node connected to document outline. Replaces FileText for Docs nav. */
export const FileText: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="5" cy="16" r="3.5" fill="#2dd4bf" opacity="0.7" />
    <line x1="8.5" y1="16" x2="12" y2="16" stroke="#2dd4bf" strokeWidth="1.5" />
    <rect x="12" y="7" width="15" height="18" rx="2" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    <line x1="15" y1="12" x2="24" y2="12" stroke="#2dd4bf" strokeWidth="1" opacity="0.5" />
    <line x1="15" y1="16" x2="24" y2="16" stroke="#2dd4bf" strokeWidth="1" opacity="0.7" />
    <line x1="15" y1="20" x2="21" y2="20" stroke="#2dd4bf" strokeWidth="1" opacity="0.4" />
  </svg>
))
FileText.displayName = "FileText"

/** API Surface - central node with code bracket endpoints. Replaces Code for Developers nav. */
export const Code: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="16" r="3.5" fill="#2dd4bf" />
    <line x1="12.5" y1="16" x2="7" y2="16" stroke="#2dd4bf" strokeWidth="1.5" strokeDasharray="2 2" opacity="0.5" />
    <line x1="19.5" y1="16" x2="25" y2="16" stroke="#2dd4bf" strokeWidth="1.5" strokeDasharray="2 2" opacity="0.5" />
    <path d="M9 10 L4 16 L9 22" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M23 10 L28 16 L23 22" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
))
Code.displayName = "Code"

// ── Nav-scale icons ───────────────────────────────────────────────────────────
// These are designed to be clearly distinct from Lucide at 14-16px nav sizes.
// Use these instead of FileText/Code in navigation bars.

/** DocsIcon - knowledge graph triangle (3 connected nodes). Clearly distinct at nav scale. */
export const DocsIcon: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="6" r="5" fill="#2dd4bf" />
    <circle cx="6" cy="24" r="5" fill="#2dd4bf" opacity="0.75" />
    <circle cx="26" cy="24" r="5" fill="#2dd4bf" opacity="0.75" />
    <line x1="12.5" y1="10" x2="8.5" y2="20" stroke="#2dd4bf" strokeWidth="1.5" opacity="0.6" />
    <line x1="19.5" y1="10" x2="23.5" y2="20" stroke="#2dd4bf" strokeWidth="1.5" opacity="0.6" />
    <line x1="11" y1="24" x2="21" y2="24" stroke="#2dd4bf" strokeWidth="1.5" opacity="0.6" />
  </svg>
))
DocsIcon.displayName = "DocsIcon"

/** DevelopersIcon - hexagonal API node (service mesh motif). Clearly distinct at nav scale. */
export const DevelopersIcon: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <path d="M16 4 L26 10 L26 22 L16 28 L6 22 L6 10 Z" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinejoin="round" />
    <circle cx="16" cy="16" r="4.5" fill="#2dd4bf" />
  </svg>
))
DevelopersIcon.displayName = "DevelopersIcon"

// ── App navigation icons ──────────────────────────────────────────────────────

/** Dashboard layout - asymmetric panel grid. Replaces LayoutDashboard. */
export const LayoutDashboard: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <rect x="4" y="4" width="11" height="10" rx="1.5" stroke="#2dd4bf" strokeWidth="2" fill="#2dd4bf" fillOpacity="0.15"/>
    <rect x="17" y="4" width="11" height="24" rx="1.5" stroke="#2dd4bf" strokeWidth="2" fill="#2dd4bf" fillOpacity="0.1"/>
    <rect x="4" y="16" width="11" height="12" rx="1.5" stroke="#2dd4bf" strokeWidth="2" fill="#2dd4bf" fillOpacity="0.15"/>
  </svg>
))
LayoutDashboard.displayName = "LayoutDashboard"

/** Config node - center core with 4 adjustable endpoints. Replaces Settings. */
export const Settings: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="16" r="4" fill="#2dd4bf"/>
    <circle cx="16" cy="6" r="2.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none"/>
    <circle cx="16" cy="26" r="2.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none"/>
    <circle cx="6" cy="16" r="2.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none"/>
    <circle cx="26" cy="16" r="2.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none"/>
    <line x1="16" y1="10" x2="16" y2="12" stroke="#2dd4bf" strokeWidth="1.5"/>
    <line x1="16" y1="20" x2="16" y2="22" stroke="#2dd4bf" strokeWidth="1.5"/>
    <line x1="10" y1="16" x2="12" y2="16" stroke="#2dd4bf" strokeWidth="1.5"/>
    <line x1="20" y1="16" x2="22" y2="16" stroke="#2dd4bf" strokeWidth="1.5"/>
  </svg>
))
Settings.displayName = "Settings"

/** Exit - door frame with outgoing arrow. Replaces LogOut. */
export const LogOut: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <path d="M12 6 L6 6 L6 26 L12 26" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
    <line x1="16" y1="16" x2="28" y2="16" stroke="#2dd4bf" strokeWidth="2" strokeLinecap="round"/>
    <polyline points="22,10 28,16 22,22" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
))
LogOut.displayName = "LogOut"

/** Observe - targeting scope with crosshairs. Replaces Telescope. */
export const Telescope: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="16" r="11" stroke="#2dd4bf" strokeWidth="2" fill="none"/>
    <circle cx="16" cy="16" r="4" stroke="#2dd4bf" strokeWidth="1.5" fill="#2dd4bf" fillOpacity="0.2"/>
    <line x1="5" y1="16" x2="12" y2="16" stroke="#2dd4bf" strokeWidth="1.5"/>
    <line x1="20" y1="16" x2="27" y2="16" stroke="#2dd4bf" strokeWidth="1.5"/>
    <line x1="16" y1="5" x2="16" y2="12" stroke="#2dd4bf" strokeWidth="1.5"/>
    <line x1="16" y1="20" x2="16" y2="27" stroke="#2dd4bf" strokeWidth="1.5"/>
  </svg>
))
Telescope.displayName = "Telescope"

/** Search - magnifying glass with inner focus ring. */
export const Search: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="13.5" cy="13.5" r="9" stroke="#2dd4bf" strokeWidth="2" fill="none"/>
    <circle cx="13.5" cy="13.5" r="4" fill="#2dd4bf" fillOpacity="0.2"/>
    <line x1="20.5" y1="20.5" x2="28" y2="28" stroke="#2dd4bf" strokeWidth="2.5" strokeLinecap="round"/>
  </svg>
))
Search.displayName = "Search"

/** Feedback - chat bubble with three signal dots. Replaces MessageSquare. */
export const MessageSquare: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <path d="M5 5 L27 5 L27 21 L14 21 L8 27 L8 21 L5 21 Z" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinejoin="round"/>
    <circle cx="11" cy="13" r="1.5" fill="#2dd4bf"/>
    <circle cx="16" cy="13" r="1.5" fill="#2dd4bf"/>
    <circle cx="21" cy="13" r="1.5" fill="#2dd4bf"/>
  </svg>
))
MessageSquare.displayName = "MessageSquare"

/** Dark mode - crescent moon. Replaces Moon. */
export const Moon: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <path d="M20 8 A10 10 0 1 0 8 20 A8 8 0 0 1 20 8 Z" fill="#2dd4bf" fillOpacity="0.25" stroke="#2dd4bf" strokeWidth="2" strokeLinejoin="round"/>
  </svg>
))
Moon.displayName = "Moon"

/** Light mode - center circle with 8 radiating rays. Replaces Sun. */
export const Sun: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="16" r="5.5" fill="#fb923c" fillOpacity="0.3" stroke="#fb923c" strokeWidth="2"/>
    <line x1="16" y1="3" x2="16" y2="7" stroke="#fb923c" strokeWidth="2" strokeLinecap="round"/>
    <line x1="16" y1="25" x2="16" y2="29" stroke="#fb923c" strokeWidth="2" strokeLinecap="round"/>
    <line x1="3" y1="16" x2="7" y2="16" stroke="#fb923c" strokeWidth="2" strokeLinecap="round"/>
    <line x1="25" y1="16" x2="29" y2="16" stroke="#fb923c" strokeWidth="2" strokeLinecap="round"/>
    <line x1="7" y1="7" x2="9.8" y2="9.8" stroke="#fb923c" strokeWidth="2" strokeLinecap="round"/>
    <line x1="22.2" y1="22.2" x2="25" y2="25" stroke="#fb923c" strokeWidth="2" strokeLinecap="round"/>
    <line x1="7" y1="25" x2="9.8" y2="22.2" stroke="#fb923c" strokeWidth="2" strokeLinecap="round"/>
    <line x1="22.2" y1="9.8" x2="25" y2="7" stroke="#fb923c" strokeWidth="2" strokeLinecap="round"/>
  </svg>
))
Sun.displayName = "Sun"

/** FAQ / Help - circle with question mark. Replaces HelpCircle. */
export const HelpCircle: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="16" r="12" stroke="#2dd4bf" strokeWidth="2" fill="none"/>
    <path d="M12 13 C12 10.8 13.8 9 16 9 C18.2 9 20 10.8 20 13 C20 15 18.5 16.5 16.5 17.5 C16.2 17.7 16 18 16 18.5 L16 20" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinecap="round"/>
    <circle cx="16" cy="23" r="1.5" fill="#2dd4bf"/>
  </svg>
))
HelpCircle.displayName = "HelpCircle"

/** Keyboard Shortcuts - keyboard chassis with key grid. Replaces Keyboard. */
export const Keyboard: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <rect x="3" y="8" width="26" height="16" rx="2" stroke="#2dd4bf" strokeWidth="2" fill="none"/>
    <rect x="7" y="13" width="3" height="3" rx="0.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none"/>
    <rect x="12" y="13" width="3" height="3" rx="0.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none"/>
    <rect x="17" y="13" width="3" height="3" rx="0.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none"/>
    <rect x="22" y="13" width="3" height="3" rx="0.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none"/>
    <rect x="9" y="18" width="14" height="3" rx="0.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none"/>
    <rect x="7" y="18" width="1" height="3" rx="0.5" fill="#2dd4bf" opacity="0.4"/>
    <rect x="24" y="18" width="1" height="3" rx="0.5" fill="#2dd4bf" opacity="0.4"/>
  </svg>
))
Keyboard.displayName = "Keyboard"

/** MCP Server - terminal prompt with blinking cursor. Replaces Terminal. */
export const Terminal: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <rect x="3" y="5" width="26" height="22" rx="2" stroke="#2dd4bf" strokeWidth="2" fill="none"/>
    <polyline points="8,12 14,17 8,22" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
    <line x1="16" y1="22" x2="24" y2="22" stroke="#2dd4bf" strokeWidth="2" strokeLinecap="round"/>
  </svg>
))
Terminal.displayName = "Terminal"

/** AI Security - robot agent head with threat-sensing grid. Replaces Bot. */
export const Bot: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <rect x="6" y="10" width="20" height="16" rx="3" stroke="#2dd4bf" strokeWidth="2" fill="none"/>
    <circle cx="11" cy="18" r="2.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none"/>
    <circle cx="21" cy="18" r="2.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none"/>
    <line x1="16" y1="4" x2="16" y2="10" stroke="#2dd4bf" strokeWidth="2" strokeLinecap="round"/>
    <circle cx="16" cy="4" r="1.5" fill="#2dd4bf"/>
    <line x1="6" y1="23" x2="4" y2="26" stroke="#2dd4bf" strokeWidth="2" strokeLinecap="round"/>
    <line x1="26" y1="23" x2="28" y2="26" stroke="#2dd4bf" strokeWidth="2" strokeLinecap="round"/>
    <line x1="11" y1="22" x2="21" y2="22" stroke="#2dd4bf" strokeWidth="1.5" strokeLinecap="round" opacity="0.5"/>
  </svg>
))
Bot.displayName = "Bot"

/** Wrench - precision tool with targeting. */
export const Wrench: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg
    ref={ref}
    xmlns="http://www.w3.org/2000/svg"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth={1.5}
    strokeLinecap="round"
    strokeLinejoin="round"
    width={props.size ?? 24}
    height={props.size ?? 24}
    className={props.className}
    style={props.style}
  >
    <path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94L6.7 20.2a2 2 0 01-2.83 0 2 2 0 010-2.83l6.73-6.73A6 6 0 016.3 2.5l3.77 3.77z" />
    <circle cx="16" cy="8" r="1" fill="currentColor" strokeWidth="0" opacity="0.5" />
  </svg>
))
Wrench.displayName = "Wrench"
