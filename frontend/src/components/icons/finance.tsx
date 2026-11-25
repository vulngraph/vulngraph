/**
 * Cost, time and labeling icons. See icons/shared.tsx for the design system.
 */

import type { LucideProps } from "lucide-react"
import { forwardRef } from "react"
import { bp, type IC } from "./shared"

/** Cost node - vertical rule with S-curve. Replaces DollarSign. */
export const DollarSign: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <line x1="16" y1="3" x2="16" y2="29" stroke="#2dd4bf" strokeWidth="2" strokeLinecap="round"/>
    <path d="M22 9 C22 9 20 7 16 7 C11 7 8.5 9.5 8.5 12.5 C8.5 15.5 12 17 16 18 C20 19 23.5 20.5 23.5 24 C23.5 27 21 27 16 27 C11 27 9 25 9 25" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinecap="round"/>
  </svg>
))
DollarSign.displayName = "DollarSign"

/** Upward trend - ascending polyline with arrowhead. Green positive. Replaces TrendingUp. */
export const TrendingUp: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <polyline points="4,23 11,15 17,19 28,8" stroke="#4ade80" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
    <polyline points="20,8 28,8 28,16" stroke="#4ade80" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
))
TrendingUp.displayName = "TrendingUp"

/** Downward trend - descending polyline with arrowhead. Red negative. Replaces TrendingDown. */
export const TrendingDown: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <polyline points="4,9 11,17 17,13 28,24" stroke="#ef4444" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
    <polyline points="20,24 28,24 28,16" stroke="#ef4444" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
))
TrendingDown.displayName = "TrendingDown"

/** Time - circle clockface with hour and minute hands. Replaces Clock. */
export const Clock: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="16" r="12" stroke="#2dd4bf" strokeWidth="2" fill="none"/>
    <line x1="16" y1="8" x2="16" y2="16" stroke="#2dd4bf" strokeWidth="2" strokeLinecap="round"/>
    <line x1="16" y1="16" x2="22" y2="16" stroke="#2dd4bf" strokeWidth="2" strokeLinecap="round"/>
    <circle cx="16" cy="16" r="1.5" fill="#2dd4bf"/>
  </svg>
))
Clock.displayName = "Clock"

/** Sync - circular arrow indicating data refresh. Replaces RefreshCw. */
export const RefreshCw: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <path d="M26 12 A11 11 0 1 0 24.5 22.5" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinecap="round"/>
    <polyline points="26,5 26,12 19,12" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
))
RefreshCw.displayName = "RefreshCw"

/** Label - price-tag silhouette with identifier dot. Replaces Tag. */
export const Tag: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <path d="M5 5 L19 5 L28 16 L19 27 L5 27 Z" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinejoin="round"/>
    <circle cx="11" cy="16" r="2.5" fill="#2dd4bf"/>
  </svg>
))
Tag.displayName = "Tag"
