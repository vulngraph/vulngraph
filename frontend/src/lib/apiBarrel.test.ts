// ADR 017: the generated OpenAPI module is imported only through the
// lib/api.ts barrel, so a spec change surfaces in one place.
import { describe, expect, it } from "vitest";

const sources = import.meta.glob(
  [
    "../**/*.{ts,tsx}",
    "!../lib/api.ts",
    "!../lib/api.gen.ts",
    "!../lib/apiBarrel.test.ts",
  ],
  {
    query: "?raw",
    import: "default",
    eager: true,
  },
) as Record<string, string>;

// Any quoted module path ending in api.gen, bare or with a .ts/.js (or
// .mts/.cts/.mjs/.cjs) extension, which bundler module resolution accepts:
// static, side-effect and dynamic imports all name it this way.
const genImport = /["'`][^"'`]*\/api\.gen(\.[cm]?[jt]s)?["'`]/;

describe("api.gen barrel", () => {
  it("scans the source tree", () => {
    expect(Object.keys(sources).length).toBeGreaterThan(20);
  });

  it.each([
    ['import type { paths } from "./api.gen";'],
    ["import '../lib/api.gen';"],
    ['const m = await import("../lib/api.gen.ts");'],
    ['import type { paths } from "../lib/api.gen.js";'],
    ["const m = await import(`../lib/api.gen`);"],
  ])("detects %s", (src) => {
    expect(genImport.test(src)).toBe(true);
  });

  it("ignores other modules", () => {
    expect(genImport.test('import { api } from "../lib/api";')).toBe(false);
    expect(genImport.test('import x from "./api.generated";')).toBe(false);
    expect(genImport.test('import x from "./api.gen.json";')).toBe(false);
  });

  it("imports api.gen only from lib/api.ts", () => {
    const offenders = Object.entries(sources)
      .filter(([, src]) => genImport.test(src))
      .map(([path]) => path);
    expect(offenders).toEqual([]);
  });
});
