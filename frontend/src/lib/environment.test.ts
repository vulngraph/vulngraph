import { expect, test } from "vitest";
import { environmentLabel } from "./environment";

test.each([
  ["prod", "tag:env", "Production (tag:env)"],
  ["staging", "account_id", "Staging (account_id)"],
  ["dev", "namespace", "Development (namespace)"],
  ["unknown", "", "Unknown"],
  ["unknown", "conflict:tag", "Unknown (conflicting tags)"],
] as const)("environmentLabel(%s, %s) → %s", (env, source, want) => {
  expect(environmentLabel(env, source)).toBe(want);
});
