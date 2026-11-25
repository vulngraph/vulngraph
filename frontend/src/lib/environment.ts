import type { Asset } from "./api";

const LABELS: Record<Asset["environment"], string> = {
  prod: "Production",
  staging: "Staging",
  dev: "Development",
  unknown: "Unknown",
};

// environmentLabel renders the server's classification with its evidence, e.g.
// "Production (tag:env)". Unknown is shown as such — never blank, never guessed.
export function environmentLabel(env: Asset["environment"], source: string): string {
  const label = LABELS[env] ?? LABELS.unknown;
  if (source.startsWith("conflict:")) return `${label} (conflicting ${source.slice("conflict:".length)}s)`;
  return source ? `${label} (${source})` : label;
}
