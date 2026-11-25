/**
 * Intelligence, reasoning and graph-topology icons. See icons/shared.tsx for the design system.
 */

import type { LucideProps } from "lucide-react"
import { forwardRef } from "react"
import { bp, type IC } from "./shared"

/** Neural Prior - weighted edge with attention parallels. Replaces Brain, Sparkles. */
export const Brain: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="6" cy="16" r="3" fill="#2dd4bf" />
    <circle cx="26" cy="16" r="5" fill="#2dd4bf" opacity="0.6" />
    <line x1="9" y1="16" x2="21" y2="16" stroke="#2dd4bf" strokeWidth="3" opacity="0.4" />
    <line x1="9" y1="12" x2="21" y2="12" stroke="#2dd4bf" strokeWidth="1" opacity="0.2" />
    <line x1="9" y1="20" x2="21" y2="20" stroke="#2dd4bf" strokeWidth="0.75" opacity="0.15" />
  </svg>
))
Brain.displayName = "Brain"

/** Neural Prior - same as Brain. Replaces Sparkles. */
export const Sparkles: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="6" cy="16" r="3" fill="#2dd4bf" />
    <circle cx="26" cy="16" r="5" fill="#2dd4bf" opacity="0.6" />
    <line x1="9" y1="16" x2="21" y2="16" stroke="#2dd4bf" strokeWidth="3" opacity="0.4" />
    <line x1="9" y1="12" x2="21" y2="12" stroke="#2dd4bf" strokeWidth="1" opacity="0.2" />
    <line x1="9" y1="20" x2="21" y2="20" stroke="#2dd4bf" strokeWidth="0.75" opacity="0.15" />
  </svg>
))
Sparkles.displayName = "Sparkles"

/** Reasoning Stack - layered graph (L0–L6) with cross-connections. Replaces Layers. */
export const Layers: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <line x1="4" y1="6" x2="28" y2="6" stroke="#2dd4bf" strokeWidth="1" opacity="0.3" />
    <circle cx="10" cy="6" r="2" fill="#2dd4bf" opacity="0.4" />
    <line x1="4" y1="11" x2="28" y2="11" stroke="#2dd4bf" strokeWidth="1" opacity="0.4" />
    <circle cx="18" cy="11" r="2" fill="#2dd4bf" opacity="0.5" />
    <line x1="4" y1="16" x2="28" y2="16" stroke="#2dd4bf" strokeWidth="1.5" opacity="0.6" />
    <circle cx="8" cy="16" r="2.5" fill="#2dd4bf" opacity="0.7" />
    <circle cx="24" cy="16" r="2" fill="#2dd4bf" opacity="0.5" />
    <line x1="4" y1="21" x2="28" y2="21" stroke="#2dd4bf" strokeWidth="1" opacity="0.5" />
    <circle cx="14" cy="21" r="2" fill="#2dd4bf" opacity="0.6" />
    <line x1="4" y1="26" x2="28" y2="26" stroke="#2dd4bf" strokeWidth="1" opacity="0.4" />
    <circle cx="22" cy="26" r="2" fill="#2dd4bf" opacity="0.4" />
    <line x1="10" y1="8" x2="14" y2="19" stroke="#2dd4bf" strokeWidth="0.75" strokeDasharray="2 2" opacity="0.3" />
    <line x1="18" y1="13" x2="14" y2="19" stroke="#2dd4bf" strokeWidth="0.75" strokeDasharray="2 2" opacity="0.3" />
  </svg>
))
Layers.displayName = "Layers"

/** Confidence Score - ascending bars with terminal node. Replaces BarChart3. */
export const BarChart3: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <rect x="3" y="22" width="4" height="6" rx="1" fill="#2dd4bf" opacity="0.3" />
    <rect x="10" y="17" width="4" height="11" rx="1" fill="#2dd4bf" opacity="0.5" />
    <rect x="17" y="11" width="4" height="17" rx="1" fill="#2dd4bf" opacity="0.7" />
    <rect x="24" y="5" width="4" height="23" rx="1" fill="#2dd4bf" />
    <circle cx="28" cy="4" r="3" fill="#2dd4bf" />
  </svg>
))
BarChart3.displayName = "BarChart3"

/** Decision Tree - branching graph with colored leaf outcomes. Replaces GitBranch. */
export const GitBranch: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="5" r="3" fill="#2dd4bf" />
    <line x1="14" y1="7.5" x2="9" y2="14" stroke="#2dd4bf" strokeWidth="1.5" />
    <line x1="18" y1="7.5" x2="23" y2="14" stroke="#2dd4bf" strokeWidth="1.5" />
    <circle cx="9" cy="17" r="3" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    <circle cx="23" cy="17" r="3" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    <line x1="7.5" y1="19.5" x2="5" y2="25" stroke="#2dd4bf" strokeWidth="1" opacity="0.6" />
    <line x1="10.5" y1="19.5" x2="13" y2="25" stroke="#2dd4bf" strokeWidth="1" opacity="0.6" />
    <circle cx="5" cy="27" r="2.5" fill="#4ade80" />
    <circle cx="13" cy="27" r="2.5" fill="#fb923c" />
    <line x1="23" y1="20" x2="23" y2="25" stroke="#2dd4bf" strokeWidth="1" opacity="0.4" />
    <circle cx="23" cy="27" r="2" fill="#2dd4bf" opacity="0.3" />
  </svg>
))
GitBranch.displayName = "GitBranch"

/** Directed Edge - source node + edge + arrowhead. Replaces ArrowRight. */
export const ArrowRight: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="4" cy="16" r="3" fill="#2dd4bf" opacity="0.5" />
    <line x1="7" y1="16" x2="23" y2="16" stroke="#2dd4bf" strokeWidth="1.5" />
    <polygon points="28,16 22,12.5 22,19.5" fill="#2dd4bf" />
  </svg>
))
ArrowRight.displayName = "ArrowRight"

/** Network Topology - 5-node partial mesh. Replaces Network, Globe, GitGraph. */
export const Network: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="6" r="3" fill="#2dd4bf" />
    <circle cx="5" cy="18" r="2.5" fill="#2dd4bf" opacity="0.7" />
    <circle cx="27" cy="18" r="2.5" fill="#2dd4bf" opacity="0.7" />
    <circle cx="10" cy="28" r="2" fill="#2dd4bf" opacity="0.5" />
    <circle cx="22" cy="28" r="2" fill="#2dd4bf" opacity="0.5" />
    <line x1="13.5" y1="8.5" x2="7" y2="16" stroke="#2dd4bf" strokeWidth="1.5" opacity="0.6" />
    <line x1="18.5" y1="8.5" x2="25" y2="16" stroke="#2dd4bf" strokeWidth="1.5" opacity="0.6" />
    <line x1="7" y1="20" x2="9" y2="26.5" stroke="#2dd4bf" strokeWidth="1" opacity="0.4" />
    <line x1="25" y1="20" x2="23" y2="26.5" stroke="#2dd4bf" strokeWidth="1" opacity="0.4" />
    <line x1="12" y1="28" x2="20" y2="28" stroke="#2dd4bf" strokeWidth="1" opacity="0.4" />
    <line x1="7.5" y1="17" x2="25" y2="17" stroke="#2dd4bf" strokeWidth="0.75" strokeDasharray="2 2" opacity="0.3" />
  </svg>
))
Network.displayName = "Network"

/** Network Topology - large-scale mesh. Replaces Globe. */
export const Globe: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="6" r="3" fill="#2dd4bf" />
    <circle cx="5" cy="18" r="2.5" fill="#2dd4bf" opacity="0.7" />
    <circle cx="27" cy="18" r="2.5" fill="#2dd4bf" opacity="0.7" />
    <circle cx="10" cy="28" r="2" fill="#2dd4bf" opacity="0.5" />
    <circle cx="22" cy="28" r="2" fill="#2dd4bf" opacity="0.5" />
    <line x1="13.5" y1="8.5" x2="7" y2="16" stroke="#2dd4bf" strokeWidth="1.5" opacity="0.6" />
    <line x1="18.5" y1="8.5" x2="25" y2="16" stroke="#2dd4bf" strokeWidth="1.5" opacity="0.6" />
    <line x1="7" y1="20" x2="9" y2="26.5" stroke="#2dd4bf" strokeWidth="1" opacity="0.4" />
    <line x1="25" y1="20" x2="23" y2="26.5" stroke="#2dd4bf" strokeWidth="1" opacity="0.4" />
    <line x1="12" y1="28" x2="20" y2="28" stroke="#2dd4bf" strokeWidth="1" opacity="0.4" />
  </svg>
))
Globe.displayName = "Globe"

/** Activity - ECG waveform with decision node. */
export const Activity: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <polyline points="4,16 8,16 10,10 14,22 16,6 18,20 20,16 24,16 28,16" stroke="#2dd4bf" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    <circle cx="16" cy="6" r="2.5" fill="#2dd4bf" opacity="0.7" />
    <circle cx="8" cy="16" r="1.5" fill="#2dd4bf" opacity="0.4" />
    <circle cx="24" cy="16" r="1.5" fill="#2dd4bf" opacity="0.4" />
  </svg>
))
Activity.displayName = "Activity"
