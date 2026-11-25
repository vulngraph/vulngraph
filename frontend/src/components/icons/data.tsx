/**
 * Compute, storage, artifact and signal-channel icons. See icons/shared.tsx for the design system.
 */

import type { LucideProps } from "lucide-react"
import { forwardRef } from "react"
import { bp, type IC } from "./shared"

/** Compute Node - rectangular server node with process ports. Replaces Server. */
export const Server: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <rect x="5" y="9" width="22" height="14" rx="2" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    <line x1="5" y1="14" x2="27" y2="14" stroke="#2dd4bf" strokeWidth="0.75" opacity="0.35" />
    <circle cx="10" cy="11.5" r="1.5" fill="#2dd4bf" opacity="0.5" />
    <circle cx="14" cy="11.5" r="1.5" fill="#2dd4bf" opacity="0.7" />
    <circle cx="18" cy="11.5" r="1.5" fill="#2dd4bf" />
    <circle cx="22" cy="18" r="2" fill="#2dd4bf" opacity="0.4" />
    <circle cx="10" cy="18" r="2" stroke="#2dd4bf" strokeWidth="1" fill="none" opacity="0.4" />
  </svg>
))
Server.displayName = "Server"

/** Data Store - layered persistence node with depth rings. Replaces Database. */
export const Database: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <ellipse cx="16" cy="9" rx="11" ry="4" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    <line x1="5" y1="9" x2="5" y2="23" stroke="#2dd4bf" strokeWidth="1.5" />
    <line x1="27" y1="9" x2="27" y2="23" stroke="#2dd4bf" strokeWidth="1.5" />
    <ellipse cx="16" cy="23" rx="11" ry="4" stroke="#2dd4bf" strokeWidth="1.5" fill="#2dd4bf" fillOpacity="0.08" />
    <ellipse cx="16" cy="16" rx="11" ry="4" stroke="#2dd4bf" strokeWidth="0.75" strokeDasharray="2 2" opacity="0.4" />
    <circle cx="16" cy="9" r="2" fill="#2dd4bf" opacity="0.6" />
  </svg>
))
Database.displayName = "Database"

/** Cloud Cluster - three peer nodes in cloud formation. Replaces Cloud. */
export const Cloud: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="13" r="4" fill="#2dd4bf" opacity="0.8" />
    <circle cx="8" cy="18" r="3" fill="#2dd4bf" opacity="0.5" />
    <circle cx="24" cy="18" r="3" fill="#2dd4bf" opacity="0.5" />
    <line x1="11" y1="15.5" x2="13" y2="16.5" stroke="#2dd4bf" strokeWidth="1" opacity="0.5" />
    <line x1="19" y1="15.5" x2="21" y2="16.5" stroke="#2dd4bf" strokeWidth="1" opacity="0.5" />
    <line x1="11" y1="18" x2="21" y2="18" stroke="#2dd4bf" strokeWidth="0.75" strokeDasharray="2 2" opacity="0.3" />
    <path d="M6 22 Q16 28 26 22" stroke="#2dd4bf" strokeWidth="0.75" fill="none" opacity="0.2" strokeDasharray="2 3" />
  </svg>
))
Cloud.displayName = "Cloud"

/** Dependency Node - hub node with radiating package edges. Replaces Package. */
export const Package: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="16" cy="16" r="4" fill="#2dd4bf" />
    <circle cx="5" cy="8" r="2.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none" opacity="0.6" />
    <circle cx="27" cy="8" r="2.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none" opacity="0.6" />
    <circle cx="5" cy="24" r="2.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none" opacity="0.4" />
    <circle cx="27" cy="24" r="2.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none" opacity="0.4" />
    <line x1="13" y1="13.5" x2="7" y2="10" stroke="#2dd4bf" strokeWidth="1" opacity="0.5" />
    <line x1="19" y1="13.5" x2="25" y2="10" stroke="#2dd4bf" strokeWidth="1" opacity="0.5" />
    <line x1="13" y1="18.5" x2="7" y2="22" stroke="#2dd4bf" strokeWidth="1" opacity="0.35" />
    <line x1="19" y1="18.5" x2="25" y2="22" stroke="#2dd4bf" strokeWidth="1" opacity="0.35" />
  </svg>
))
Package.displayName = "Package"

/** Verified Artifact - document node with check edge. Replaces FileCheck. */
export const FileCheck: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <rect x="7" y="4" width="14" height="18" rx="2" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    <line x1="10" y1="10" x2="18" y2="10" stroke="#2dd4bf" strokeWidth="1" opacity="0.4" />
    <line x1="10" y1="14" x2="18" y2="14" stroke="#2dd4bf" strokeWidth="1" opacity="0.4" />
    <polyline points="10,19 13,22 19,15" stroke="#2dd4bf" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    <circle cx="24" cy="24" r="3" fill="#4ade80" opacity="0.8" />
  </svg>
))
FileCheck.displayName = "FileCheck"

/** Signal Channel - message edge between two nodes. Replaces Mail, Send. */
export const Mail: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="5" cy="16" r="3" fill="#fb923c" opacity="0.7" />
    <line x1="8" y1="16" x2="19" y2="16" stroke="#fb923c" strokeWidth="1.5" />
    <polygon points="24,16 19,12.5 19,19.5" fill="#fb923c" opacity="0.8" />
    <circle cx="27" cy="16" r="2.5" stroke="#fb923c" strokeWidth="1.5" fill="none" opacity="0.5" />
    <line x1="3" y1="12" x2="8" y2="14" stroke="#fb923c" strokeWidth="0.75" strokeDasharray="2 2" opacity="0.4" />
    <line x1="3" y1="20" x2="8" y2="18" stroke="#fb923c" strokeWidth="0.75" strokeDasharray="2 2" opacity="0.4" />
  </svg>
))
Mail.displayName = "Mail"

/** Signal Channel - same as Mail. Replaces Send. */
export const Send: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="5" cy="16" r="3" fill="#fb923c" opacity="0.7" />
    <line x1="8" y1="16" x2="19" y2="16" stroke="#fb923c" strokeWidth="1.5" />
    <polygon points="24,16 19,12.5 19,19.5" fill="#fb923c" opacity="0.8" />
    <circle cx="27" cy="16" r="2.5" stroke="#fb923c" strokeWidth="1.5" fill="none" opacity="0.5" />
    <line x1="3" y1="12" x2="8" y2="14" stroke="#fb923c" strokeWidth="0.75" strokeDasharray="2 2" opacity="0.4" />
    <line x1="3" y1="20" x2="8" y2="18" stroke="#fb923c" strokeWidth="0.75" strokeDasharray="2 2" opacity="0.4" />
  </svg>
))
Send.displayName = "Send"

/** Detection Signal - radiating arcs from source node. Replaces Radio. */
export const Radio: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="7" cy="16" r="3.5" fill="#fb923c" />
    <path d="M13 10 Q20 16 13 22" stroke="#fb923c" strokeWidth="1.5" fill="none" opacity="0.7" strokeLinecap="round" />
    <path d="M17 7 Q26 16 17 25" stroke="#fb923c" strokeWidth="1" fill="none" opacity="0.4" strokeLinecap="round" />
    <path d="M21 5 Q29 16 21 27" stroke="#fb923c" strokeWidth="0.75" fill="none" opacity="0.2" strokeLinecap="round" />
  </svg>
))
Radio.displayName = "Radio"

/** Scanner / Observe - observer + scan rays + target. Replaces Eye, EyeOff. */
export const Eye: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <circle cx="4" cy="16" r="3" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    <line x1="7" y1="14" x2="20" y2="8" stroke="#2dd4bf" strokeWidth="1" opacity="0.5" strokeDasharray="2 2" />
    <line x1="7" y1="16" x2="22" y2="16" stroke="#2dd4bf" strokeWidth="1.5" opacity="0.7" />
    <line x1="7" y1="18" x2="20" y2="24" stroke="#2dd4bf" strokeWidth="1" opacity="0.5" strokeDasharray="2 2" />
    <circle cx="24" cy="16" r="4" fill="#2dd4bf" opacity="0.2" stroke="#2dd4bf" strokeWidth="1.5" />
    <circle cx="24" cy="16" r="1.5" fill="#2dd4bf" />
  </svg>
))
Eye.displayName = "Eye"

/**  Boxes - stacked packages for supply chain. Replaces lucide Boxes. */
export const Boxes: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <rect x="4" y="17" width="10" height="11" rx="1.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    <rect x="18" y="17" width="10" height="11" rx="1.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    <rect x="8" y="4" width="16" height="13" rx="1.5" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    <line x1="4" y1="22" x2="14" y2="22" stroke="#2dd4bf" strokeWidth="0.75" opacity="0.35" />
    <line x1="18" y1="22" x2="28" y2="22" stroke="#2dd4bf" strokeWidth="0.75" opacity="0.35" />
    <line x1="8" y1="9" x2="24" y2="9" stroke="#2dd4bf" strokeWidth="0.75" opacity="0.35" />
    <circle cx="9" cy="19" r="1.5" fill="#2dd4bf" opacity="0.5" />
    <circle cx="23" cy="19" r="1.5" fill="#2dd4bf" opacity="0.5" />
    <circle cx="16" cy="6" r="1.5" fill="#2dd4bf" />
  </svg>
))
Boxes.displayName = "Boxes"

/** Container - layered container image with whale base. Replaces lucide Container. */
export const Container: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    {/* Container body */}
    <rect x="4" y="8" width="24" height="18" rx="2" stroke="#2dd4bf" strokeWidth="1.5" fill="none" />
    {/* Layer dividers */}
    <line x1="4" y1="14" x2="28" y2="14" stroke="#2dd4bf" strokeWidth="0.75" opacity="0.35" />
    <line x1="4" y1="20" x2="28" y2="20" stroke="#2dd4bf" strokeWidth="0.75" opacity="0.35" />
    {/* Top accent dots — image layers */}
    <circle cx="10" cy="11" r="1.5" fill="#2dd4bf" opacity="0.6" />
    <circle cx="16" cy="11" r="1.5" fill="#2dd4bf" opacity="0.8" />
    <circle cx="22" cy="11" r="1.5" fill="#2dd4bf" />
    {/* Registry node */}
    <circle cx="16" cy="5" r="2" fill="#2dd4bf" opacity="0.5" />
    <line x1="16" y1="7" x2="16" y2="8" stroke="#2dd4bf" strokeWidth="1" />
  </svg>
))
Container.displayName = "Container"

/** Agent Memory - chip with pins, suggesting neural substrate. Replaces Cpu. */
export const Cpu: IC = forwardRef<SVGSVGElement, LucideProps>((props, ref) => (
  <svg ref={ref} {...bp(props)}>
    <rect x="8" y="8" width="16" height="16" rx="2" stroke="#2dd4bf" strokeWidth="2" fill="none" />
    <rect x="12" y="12" width="8" height="8" rx="1" fill="#2dd4bf" opacity="0.35" />
    <circle cx="16" cy="16" r="1.5" fill="#2dd4bf" />
    <line x1="4" y1="12" x2="8" y2="12" stroke="#2dd4bf" strokeWidth="1.5" strokeLinecap="round" />
    <line x1="4" y1="16" x2="8" y2="16" stroke="#2dd4bf" strokeWidth="1.5" strokeLinecap="round" />
    <line x1="4" y1="20" x2="8" y2="20" stroke="#2dd4bf" strokeWidth="1.5" strokeLinecap="round" />
    <line x1="24" y1="12" x2="28" y2="12" stroke="#2dd4bf" strokeWidth="1.5" strokeLinecap="round" />
    <line x1="24" y1="16" x2="28" y2="16" stroke="#2dd4bf" strokeWidth="1.5" strokeLinecap="round" />
    <line x1="24" y1="20" x2="28" y2="20" stroke="#2dd4bf" strokeWidth="1.5" strokeLinecap="round" />
    <line x1="12" y1="4" x2="12" y2="8" stroke="#2dd4bf" strokeWidth="1.5" strokeLinecap="round" />
    <line x1="16" y1="4" x2="16" y2="8" stroke="#2dd4bf" strokeWidth="1.5" strokeLinecap="round" />
    <line x1="20" y1="4" x2="20" y2="8" stroke="#2dd4bf" strokeWidth="1.5" strokeLinecap="round" />
    <line x1="12" y1="24" x2="12" y2="28" stroke="#2dd4bf" strokeWidth="1.5" strokeLinecap="round" />
    <line x1="16" y1="24" x2="16" y2="28" stroke="#2dd4bf" strokeWidth="1.5" strokeLinecap="round" />
    <line x1="20" y1="24" x2="20" y2="28" stroke="#2dd4bf" strokeWidth="1.5" strokeLinecap="round" />
  </svg>
))
Cpu.displayName = "Cpu"
