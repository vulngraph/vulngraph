// Structural guard for every frontend Cypher template, pinned to
// src/generated/graph-schema.json (generated from internal/graphschema by
// `go run ./cmd/graphschema-gen`). A preset can reference a valid,
// loaded rel yet still return zero rows with no error — the silent-empty page
// (the original DSPM bug, Identity's FederatedAccess-from-Asset bug, and the
// oidc-escalation-chain score-gate). This test turns three structural causes of
// that into CI failures:
//   1. a rel that is not loaded into Ladybug (or not a rel at all),
//   2. a node label that does not exist in the schema,
//   3. an edge traversed in the wrong DIRECTION (from/to reversed).
// It cannot catch a semantically-empty-but-valid query (e.g. a WHERE filter no
// row satisfies); that class is handled by curating presets not to gate an
// attack-path query on a sparse score (see queryLibrary.ts).
import { describe, expect, it } from "vitest";
import schema from "../generated/graph-schema.json";

const sources = import.meta.glob(["../routes/*.tsx", "./queryLibrary.ts"], {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

const relByName = new Map(schema.rels.map((r) => [r.name, r]));
const loadedRels = new Set(
  schema.rels.filter((r) => r.loaded).map((r) => r.name),
);
// Node-label vocabulary is exactly the endpoints the schema declares, plus the
// Asset subtype labels (graphstore domain.go: EC2Instance/SecurityGroup/
// Subnet/K8sWorkload are expanded labels on Asset nodes — a k8s pod node is
// both :K8sWorkload and an Asset).
const ASSET_FAMILY = new Set(["Asset", "EC2Instance", "SecurityGroup", "Subnet", "K8sWorkload"]);
const knownLabels = new Set<string>([...ASSET_FAMILY]);
for (const r of schema.rels) {
  knownLabels.add(r.from);
  knownLabels.add(r.to);
}
// A rel declared on Asset is traversable from any Asset subtype, so normalize
// the whole family to Asset before comparing edge direction.
const norm = (label: string) => (ASSET_FAMILY.has(label) ? "Asset" : label);

// Cypher reserved keywords that are also node labels: bare `:Group` collides with
// the GROUP BY keyword and fails to parse (HTTP 500), so it MUST be written
// `:\`Group\``. Mirrors graphstore schema.go cypherReservedLabels — a valid,
// loaded label that still 500s unless escaped, invisible to the checks below.
const RESERVED_LABELS = ["Group"];

// Escape-aware: a template literal may contain an escaped backtick (\`) — as in
// the reserved-label escaping `:\`Group\`` — so we must not stop at the first
// inner backtick. Match backtick, then (escaped char | any non-backtick), then
// the closing backtick.
const cypherTemplate = /`(?:\\.|[^`\\])*`/gs;
const relToken = /\[\s*\w*\s*:\s*([A-Za-z_][A-Za-z_|\s]*?)\s*(?:\{[^}]*\})?\s*\]/g;
const nodeToken = /\(\s*(\w+)?\s*:\s*(\w+)/g;
// A directed triple: (l:L?)…-[:R]->…(r:R?) or the <-[:R]- reverse.
const tripleToken =
  /\(\s*(\w+)?\s*(?::\s*(\w+))?[^)]*\)\s*(<-|-)\[\s*\w*\s*:\s*([A-Za-z_|]+)[^\]]*\]\s*(->|-)\s*\(\s*(\w+)?\s*(?::\s*(\w+))?/g;

type Finding = { file: string; tmpl: string; msg: string };

function cypherTemplates(src: string): string[] {
  return (src.match(cypherTemplate) ?? []).filter((t) => t.includes("MATCH "));
}

function lint(file: string, tmpl: string): Finding[] {
  const out: Finding[] = [];
  const head = tmpl.replace(/`/g, "").trim().split("\n")[0].slice(0, 70);
  const add = (msg: string) => out.push({ file, tmpl: head, msg });

  // Reserved labels must be backtick-escaped. `:\`Group\`` puts a backtick right
  // after the colon, so a bare `:Group` (optional whitespace, no backtick) is
  // the only thing that matches here.
  for (const rl of RESERVED_LABELS) {
    if (new RegExp(`:\\s*${rl}\\b`).test(tmpl)) {
      add(`:${rl} is a Cypher reserved keyword — escape it as :\`${rl}\` or the query 500s`);
    }
  }

  // variable -> label bindings across the whole (possibly multi-MATCH) template
  const varLabel = new Map<string, string>();
  for (const m of tmpl.matchAll(nodeToken)) {
    if (m[1]) varLabel.set(m[1], m[2]);
    if (!knownLabels.has(m[2])) add(`unknown node label :${m[2]}`);
  }

  for (const m of tmpl.matchAll(relToken)) {
    for (const rel of m[1].split("|").map((s) => s.trim())) {
      if (!rel) continue;
      if (!relByName.has(rel)) add(`[:${rel}] is not a rel in the schema`);
      else if (!loadedRels.has(rel)) add(`[:${rel}] exists but is not loaded — returns zero rows`);
    }
  }

  for (const m of tmpl.matchAll(tripleToken)) {
    const [, lv, ll, ld, relNames, rd, rv, rl] = m;
    const lLabel = ll || (lv ? varLabel.get(lv) : undefined);
    const rLabel = rl || (rv ? varLabel.get(rv) : undefined);
    let src: string | undefined, dst: string | undefined;
    if (ld === "-" && rd === "->") { src = lLabel; dst = rLabel; }
    else if (ld === "<-" && rd === "-") { src = rLabel; dst = lLabel; }
    else continue; // undirected / malformed — skip
    if (!src || !dst) continue; // endpoints not resolvable to labels
    for (const rel of relNames.split("|")) {
      const r = relByName.get(rel);
      if (!r) continue;
      // Ladybug rel tables are node-type-typed: an Asset-subtype source (K8sWorkload,
      // EC2Instance, …) must use the rel whose FROM is that subtype when a
      // dedicated one exists — e.g. (w:K8sWorkload)-[:ExecutesAs] matches NOTHING
      // (that rel is FROM Asset); the edges live in ExecutesAsK8sWorkload. This is
      // the class the asset-family normalization below would otherwise mask.
      if (src && ASSET_FAMILY.has(src) && src !== "Asset" && r.from === "Asset") {
        const dedicated = schema.rels.find((x) => x.from === src && x.to === r.to && x.loaded);
        if (dedicated) {
          add(`[:${rel}] is FROM Asset — a ${src} source matches nothing; use [:${dedicated.name}]`);
          continue;
        }
      }
      const [df, dt, us, ud] = [norm(r.from), norm(r.to), norm(src), norm(dst)];
      if (df === dt) continue; // symmetric after normalization — can't direction-check
      if (df !== us || dt !== ud) {
        add(`[:${rel}] declared ${r.from}->${r.to} but used ${src}->${dst} (reversed)`);
      }
    }
  }
  return out;
}

describe("frontend Cypher presets are structurally valid vs the loaded schema", () => {
  const templates: { file: string; tmpl: string }[] = [];
  for (const [file, src] of Object.entries(sources)) {
    for (const tmpl of cypherTemplates(src)) templates.push({ file, tmpl });
  }

  it("extraction finds templates (guards against regex rot)", () => {
    expect(templates.length).toBeGreaterThan(10);
  });

  it("no preset references an unloaded/unknown rel, unknown label, or reversed edge", () => {
    const findings = templates.flatMap(({ file, tmpl }) => lint(file, tmpl));
    const detail = findings
      .map((f) => `${f.file}: "${f.tmpl}" — ${f.msg}`)
      .join("\n");
    expect(findings, detail).toEqual([]);
  });
});
