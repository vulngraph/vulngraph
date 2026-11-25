import { expect, test } from "vitest";
import { expiryBounds, expiryStatus, expiryToISO } from "./expiry";

const now = new Date(2026, 9, 7, 15, 30); // 7 Oct 2026, local time

test("the picker defaults to 90 days and is bounded to tomorrow…a year out", () => {
  expect(expiryBounds(now)).toEqual({ initial: "2027-01-05", min: "2026-10-08", max: "2027-10-07" });
});

test("a picked date expires at the end of that local day", () => {
  const iso = expiryToISO("2026-12-01");
  const d = new Date(iso);
  expect([d.getFullYear(), d.getMonth(), d.getDate(), d.getHours(), d.getMinutes()]).toEqual([2026, 11, 1, 23, 59]);
});

test.each([
  [-3 * 86_400_000, "expired", "expired 3d ago"],
  [-60_000, "expired", "expired today"],
  [0, "expired", "expired today"],
  [3_600_000, "soon", "expires today"],
  [5 * 86_400_000, "soon", "expires in 5d"],
  [14 * 86_400_000, "soon", "expires in 14d"],
  [15 * 86_400_000, "ok", "expires in 15d"],
])("expiryStatus(%d ms from now) → %s / %s", (offset, state, label) => {
  expect(expiryStatus(new Date(now.getTime() + offset).toISOString(), now)).toEqual({ state, label });
});
