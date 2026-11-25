// Shared formatting/label helpers — one home for display logic that several
// routes/components need, so their behaviour cannot drift apart.

import scoreBands from "../generated/score-bands.json";

// ── Relative time ────────────────────────────────────────────────────────────

// timeAgo renders a relative time string for a timestamp.
//  - "compact": "just now" / "5m" / "2h" / "3d" / "4w" / "1y",
//    "—" for a missing/invalid input. Used by list/table rows that already show
//    the metric name next to it (e.g. "last seen 5m").
//  - "ago": "just now" / "5s ago" / "5m ago" /
//    "2h ago" / "3d ago", falling back to a locale date past a week. Used by
//    activity/audit feeds that read as a sentence on their own.
export function timeAgo(iso?: string, style: "compact" | "ago" = "ago"): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const secs = Math.max(0, Math.floor((Date.now() - then) / 1000));

  if (style === "compact") {
    if (secs < 60) return "just now";
    const mins = Math.floor(secs / 60);
    if (mins < 60) return `${mins}m`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h`;
    const days = Math.floor(hours / 24);
    if (days < 7) return `${days}d`;
    const weeks = Math.floor(days / 7);
    if (weeks < 52) return `${weeks}w`;
    return `${Math.floor(days / 365)}y`;
  }

  if (secs < 10) return "just now";
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

// elapsed renders the duration of a run that started at `started` and either
// finished at `finished` or is still going (clock keeps ticking against now).
//  - "compact" (scan lists): "< 1m" / "5m" / "2h 5m".
//  - "long" (scan detail): "< 1 min" / "5 min" / "2h 5m".
export function elapsed(started: string, finished?: string | null, style: "compact" | "long" = "compact"): string {
  const end = finished ? new Date(finished).getTime() : Date.now();
  const ms = end - new Date(started).getTime();
  const mins = Math.floor(ms / 60000);
  if (style === "long") {
    if (mins < 1) return "< 1 min";
    if (mins < 60) return `${mins} min`;
    return `${Math.floor(mins / 60)}h ${mins % 60}m`;
  }
  if (mins < 1) return "< 1m";
  if (mins < 60) return `${mins}m`;
  return `${Math.floor(mins / 60)}h ${mins % 60}m`;
}

// elapsedRunning renders "still running" duration phrased as an ongoing state:
// "just started" / "5m running" / "2h 5m running".
export function elapsedRunning(started: string): string {
  const ms = Date.now() - new Date(started).getTime();
  const mins = Math.floor(ms / 60000);
  if (mins < 1) return "just started";
  if (mins < 60) return `${mins}m running`;
  return `${Math.floor(mins / 60)}h ${mins % 60}m running`;
}

// ── Score → band → colour ────────────────────────────────────────────────────

export type ScoreBand = "page" | "high" | "pipeline" | "monitor";

function minScore(band: ScoreBand): number {
  const b = scoreBands.bands.find((x) => x.band === band);
  if (!b) throw new Error(`score-bands.json has no ${band} band`);
  return b.min_score;
}

// SCORE_THRESHOLDS is the lowest score in each band, read from
// generated/score-bands.json (cmd/scoreband-gen, from the server's enrich
// thresholds). Prefer the score_band / risk_band / worst_band the API returns;
// these numbers are for score filters and for raw scores that carry no band
// (graph node risk, drift events). Canvas colouring that needs a hex value
// instead of a Tailwind class compares against these too.
export const SCORE_THRESHOLDS = {
  page: minScore("page"),
  high: minScore("high"),
  pipeline: minScore("pipeline"),
} as const;

// scoreToBand maps a raw score with no server band to the band the server
// would give it.
export function scoreToBand(score: number): ScoreBand {
  if (score >= SCORE_THRESHOLDS.page) return "page";
  if (score >= SCORE_THRESHOLDS.high) return "high";
  if (score >= SCORE_THRESHOLDS.pipeline) return "pipeline";
  return "monitor";
}

const BAND_RANK: Record<ScoreBand, number> = { monitor: 1, pipeline: 2, high: 3, page: 4 };

// bandAtLeast reports whether a server band is at or above min. An empty or
// unknown band (never enriched) is below every band.
export function bandAtLeast(band: string | undefined, min: ScoreBand): boolean {
  const r = band && band in BAND_RANK ? BAND_RANK[band as ScoreBand] : 0;
  return r >= BAND_RANK[min];
}

const BAND_TONE: Record<ScoreBand, string> = {
  page: "text-red",
  high: "text-orange",
  pipeline: "text-amber",
  monitor: "text-text-3",
};

// bandTone maps an already-known band (e.g. asset.risk_band) to its text colour.
export function bandTone(band?: string): string {
  return band && band in BAND_TONE ? BAND_TONE[band as ScoreBand] : BAND_TONE.monitor;
}

const BAND_LABEL: Record<ScoreBand, string> = {
  page: "critical",
  high: "high",
  pipeline: "medium",
  monitor: "low",
};

// bandLabel maps the wire-level band name (page/high/pipeline/monitor — the
// enrich pipeline's own vocabulary for what each score range triggers) to the
// severity word people actually read.
export function bandLabel(band?: string): string {
  return band && band in BAND_LABEL ? BAND_LABEL[band as ScoreBand] : "";
}

// scoreTone maps a raw score straight to its text colour class.
export function scoreTone(score: number): string {
  return bandTone(scoreToBand(score));
}

// ── Role → tone ──────────────────────────────────────────────────────────────

const ROLE_TONE: Record<string, string> = {
  admin: "border-red/30 bg-red/10 text-red",
  analyst: "border-amber/30 bg-amber/10 text-amber",
  viewer: "border-border-subtle bg-surface text-text-3",
};

// roleTone maps a user role to badge classes — admin (can mutate cloud
// resources) reads as the highest-salience tone, viewer as the lowest.
export function roleTone(role?: string): string {
  return (role && ROLE_TONE[role]) ?? ROLE_TONE.viewer;
}

// ── Resource id shortening ───────────────────────────────────────────────────

// stripVersionSuffix removes a Go pseudo-version's timestamp+hash suffix
// ("-20210813160813-60bcf6d5ab4a" or a bare 40-char sha) leaving the base semver.
export function stripVersionSuffix(v: string): string {
  return v.replace(/-\d{14}-[0-9a-f]{12,}$/, "").replace(/-[0-9a-f]{40}$/, "");
}

// shortenId makes a resource id human-readable: ARN leaf, pkg: version stripping,
// k8s "cluster/pod/ns/name" tail, GCP "//service/..." tail, or a truncated
// fallback for anything else/too long.
//
//   keepArnType — keep the ARN resource-type segment ("role/MyRole"); the
//     default (false) drops it ("MyRole"). When true, only the ARN/truncate
//     rules apply (no pkg:/k8s/GCP cases).
//   maxLen — length before falling back to a truncated form (default 50; the
//     decision views pass 60).
export function shortenId(id?: string, opts?: { keepArnType?: boolean; maxLen?: number }): string {
  if (!id) return "—";
  const maxLen = opts?.maxLen ?? 50;
  const keepArnType = opts?.keepArnType ?? false;

  if (keepArnType) {
    const arnMatch = id.match(/arn:[^:]+:[^:]+::[^:]*:(.+)/);
    if (arnMatch) return arnMatch[1];
    if (id.length > maxLen) return id.slice(0, maxLen - 3) + "…";
    return id;
  }

  // ARN leaf: arn:…:role/MyRole → MyRole
  const arnLeaf = id.match(/arn:[^:]+:[^:]+::[^:]*:(?:[^/]+\/)(.+)$/);
  if (arnLeaf) return arnLeaf[1];
  // pkg:golang/…/net@v0.0.0-20210813160813-60bc… → net@v0.0.0
  if (id.startsWith("pkg:")) {
    const clean = stripVersionSuffix(id);
    const leaf = clean.match(/\/([^/@]+(?:@[^/]+)?)$/);
    if (leaf) return leaf[1];
  }
  // GCP //…/name → name
  if (id.startsWith("//")) return id.split("/").filter(Boolean).pop() ?? id;
  // k8s: cluster-name/pod/ns/name → name
  const k8s = id.match(/[^/]+\/(?:pod|deploy|service|ns)\/[^/]+\/(.+)$/);
  if (k8s) return k8s[1];
  if (id.length > maxLen) return id.slice(0, 22) + "…" + id.slice(-16);
  return id;
}
