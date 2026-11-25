// Shared DSPM data-classification metadata — used by the Data Security worklist
// (DSPM.tsx) and the shared AssetDetailPanel so a data store looks the same
// wherever it is surfaced.

export const DATA_CLASSES: Record<string, { label: string; cls: string; description: string }> = {
  pii:         { label: "PII",         cls: "text-red border-red/30 bg-red/10",           description: "Personal Identifiable Information — GDPR / CCPA scope" },
  financial:   { label: "Financial",   cls: "text-amber border-amber/30 bg-amber/10",     description: "Payment, billing, or revenue data" },
  credentials: { label: "Credentials", cls: "text-orange border-orange/30 bg-orange/10", description: "Secrets, API keys, passwords, certificates" },
  health:      { label: "Health",      cls: "text-purple-400 border-purple-400/30 bg-purple-400/10", description: "Medical / HIPAA-regulated data" },
  pci:         { label: "PCI",         cls: "text-red border-red/30 bg-red/10",           description: "Payment-card data — PCI DSS scope" },
  internal:    { label: "Internal",    cls: "text-sky border-sky/30 bg-sky/10",           description: "Internal / confidential business data" },
};

// classKey strips the "dataclass:" sentinel prefix from a DataClass node id.
export function classKey(id: string): string {
  return id.replace("dataclass:", "");
}

export function dataClassStyle(id: string) {
  return DATA_CLASSES[classKey(id)] ?? { label: classKey(id), cls: "text-text-3 border-border-subtle bg-surface", description: "" };
}

// confidenceTitle explains a classification's provenance in a tooltip. The
// confidence rides on the ContainsData edge; it is what tells an
// operator-confirmed tag apart from a resource-name substring match.
export function confidenceTitle(confidence: string | undefined): string {
  switch (confidence) {
    case "high":
      return "Asserted: an operator tag on the resource, or the resource type itself (a Secrets Manager entry is a credential by definition). Not a guess.";
    case "medium":
      return "Inferred from the resource NAME only — nothing read this store's contents. Treat it as a lead to verify, not a finding.";
    case "low":
      return "Default floor: no sensitivity signal matched, so the store is classified as internal.";
    default:
      return "Provenance not recorded — the classification carries no confidence, so treat it as unverified.";
  }
}

// isSensitive reports whether any class is genuinely sensitive (i.e. not just the
// "internal" floor every store gets).
export function isSensitive(classes: string[]): boolean {
  return classes.some((c) => classKey(c) !== "internal");
}
