/**
 * Identity/access/credential icons. See icons/shared.tsx for the design system.
 */

import type { LucideProps } from "lucide-react"
import { forwardRef } from "react"
import { bp, type IC } from "./shared"

export const Users: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="7" r="4" fill="#2dd4bf" />
    <circle cx="7" cy="23" r="3" fill="#2dd4bf" opacity="0.6" />
    <circle cx="25" cy="23" r="3" fill="#2dd4bf" opacity="0.6" />
    <line x1="13.2" y1="10.2" x2="9.2" y2="20.2" stroke="#2dd4bf" strokeWidth="1.5" opacity="0.5" />
    <line x1="18.8" y1="10.2" x2="22.8" y2="20.2" stroke="#2dd4bf" strokeWidth="1.5" opacity="0.5" />
    <line x1="10" y1="23" x2="22" y2="23" stroke="#2dd4bf" strokeWidth="1" strokeDasharray="2 2" opacity="0.35" />
  </svg>
))
Users.displayName = "Users"

/** Identity Node - single identity: small marker above a filled node. Replaces User. */

export const User: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="9" r="4" fill="#2dd4bf" />
    <circle cx="16" cy="22" r="7" stroke="#2dd4bf" strokeWidth="1.5" fill="none" opacity="0.5" />
    <line x1="16" y1="13" x2="16" y2="15" stroke="#2dd4bf" strokeWidth="1.5" opacity="0.4" />
  </svg>
))
User.displayName = "User"

/** Directed Edge - source node + edge + arrowhead. Replaces ArrowRight. */

export const UserCheck: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="13" cy="9" r="5" stroke="#2dd4bf" strokeWidth="2" fill="none"/>
    <path d="M4 28 C4 21 8.5 17 13 17 C15 17 16.5 17.5 18 18.5" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinecap="round"/>
    <polyline points="19,23 22,26 28,20" stroke="#4ade80" strokeWidth="2.5" fill="none" strokeLinecap="round" strokeLinejoin="round"/>
  </svg>
))
UserCheck.displayName = "UserCheck"

/** Support - life ring with diagonal cross straps. Replaces LifeBuoy. */

export const UserCog: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="14" cy="10" r="5" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    <path d="M5 27 C5 20, 10 17, 14 17 C18 17, 23 20, 23 27" stroke="#2dd4bf" strokeWidth="1.5" fill="none" strokeLinecap="round" />
    <circle cx="26" cy="26" r="3.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    <circle cx="26" cy="26" r="1.5" fill="#2dd4bf" opacity="0.6" />
    <line x1="26" y1="21" x2="26" y2="22.5" stroke="#2dd4bf" strokeWidth="1" />
    <line x1="26" y1="29.5" x2="26" y2="31" stroke="#2dd4bf" strokeWidth="1" />
    <line x1="21" y1="26" x2="22.5" y2="26" stroke="#2dd4bf" strokeWidth="1" />
    <line x1="29.5" y1="26" x2="31" y2="26" stroke="#2dd4bf" strokeWidth="1" />
    <circle cx="14" cy="10" r="1.5" fill="#2dd4bf" />
  </svg>
))
UserCog.displayName = "UserCog"

/** Container - layered container image with whale base. Replaces lucide Container. */

export const KeyRound: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <polygon points="16,4 24,14 16,24 8,14" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    <circle cx="4" cy="26" r="2.5" fill="#2dd4bf" opacity="0.5" />
    <circle cx="16" cy="29" r="2.5" fill="#2dd4bf" opacity="0.7" />
    <circle cx="28" cy="26" r="2.5" fill="#2dd4bf" opacity="0.5" />
    <line x1="10" y1="21" x2="5" y2="24" stroke="#2dd4bf" strokeWidth="1" opacity="0.5" />
    <line x1="16" y1="24" x2="16" y2="27" stroke="#2dd4bf" strokeWidth="1" opacity="0.7" />
    <line x1="22" y1="21" x2="27" y2="24" stroke="#2dd4bf" strokeWidth="1" opacity="0.5" />
  </svg>
))
KeyRound.displayName = "KeyRound"

/** Access Denied - blocked path with X gate. Replaces Ban, ShieldX (contextual). */

export const Key = KeyRound

/** Verified Node - circle + checkmark. Replaces CheckCircle2, CheckCircle. */

export const Fingerprint: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <path d="M16 6 C10.5 6 6 10.5 6 16" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinecap="round"/>
    <path d="M16 6 C21.5 6 26 10.5 26 16" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinecap="round"/>
    <path d="M10 18 C10 14.7 12.7 12 16 12 C19.3 12 22 14.7 22 18 C22 21 20 24 18 26" stroke="#2dd4bf" strokeWidth="2" fill="none" strokeLinecap="round"/>
    <path d="M13 26 C11.5 23.5 11 21 11 18 C11 15.2 13.2 13 16 13" stroke="#2dd4bf" strokeWidth="1.5" fill="none" strokeLinecap="round" opacity="0.6"/>
    <path d="M16 15 C17.7 15 19 16.3 19 18 C19 20 18 22 17 24" stroke="#2dd4bf" strokeWidth="1.5" fill="none" strokeLinecap="round" opacity="0.45"/>
  </svg>
))
Fingerprint.displayName = "Fingerprint"

/** Automation Rules - three horizontal slider tracks with control knobs. Replaces SlidersHorizontal. */

export const Lock: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="6" cy="16" r="3.5" fill="#2dd4bf" />
    <circle cx="26" cy="16" r="3.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    <line x1="9.5" y1="16" x2="22.5" y2="16" stroke="#2dd4bf" strokeWidth="1.5" />
    <line x1="16" y1="11" x2="16" y2="21" stroke="#2dd4bf" strokeWidth="2" />
    <line x1="16" y1="14" x2="16" y2="18" stroke="currentColor" strokeWidth="3" opacity="0" />
  </svg>
))
Lock.displayName = "Lock"

/** Access Gate open - gate gap visible. Replaces Unlock. */

export const Unlock: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="6" cy="16" r="3.5" fill="#2dd4bf" />
    <circle cx="26" cy="16" r="3.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    <line x1="9.5" y1="16" x2="14" y2="16" stroke="#2dd4bf" strokeWidth="1.5" />
    <line x1="18" y1="16" x2="22.5" y2="16" stroke="#2dd4bf" strokeWidth="1.5" />
    <line x1="16" y1="11" x2="16" y2="13.5" stroke="#2dd4bf" strokeWidth="2" />
    <line x1="16" y1="18.5" x2="16" y2="21" stroke="#2dd4bf" strokeWidth="2" />
  </svg>
))
Unlock.displayName = "Unlock"

/** Role Graph - diamond role node expanding to resource leaves. Replaces Key, KeyRound. */
