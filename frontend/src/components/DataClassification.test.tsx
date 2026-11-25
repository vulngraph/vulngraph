import { render, screen } from "@testing-library/react";
import { describe, expect, test } from "vitest";
import { ClassificationBadges } from "./DataClassification";

// a.encrypted is tri-state: 0 observed unencrypted, 1 observed encrypted, 2 never
// observed. `!!row.encrypted` used to render 2 exactly like 1, so an unknown store
// looked clean; only an observed 0 may raise the alarm, and an unknown store is
// marked unknown rather than shown like an encrypted one.
describe("ClassificationBadges encryption", () => {
  test.each([
    { encrypted: 0, badged: true, unknown: false },
    { encrypted: 1, badged: false, unknown: false },
    { encrypted: 2, badged: false, unknown: true },
    { encrypted: undefined, badged: false, unknown: true },
  ])("encrypted=$encrypted badged=$badged unknown=$unknown", ({ encrypted, badged, unknown }) => {
    render(<ClassificationBadges row={{ encrypted, classes: ["dataclass:pii"] }} />);
    expect(screen.queryByText("unencrypted") !== null).toBe(badged);
    expect(screen.queryByText(/no encryption-at-rest/) !== null).toBe(badged);
    expect(screen.queryByTitle(/Encryption unknown/) !== null).toBe(unknown);
  });

  test("an encrypted and an unknown store do not render alike", () => {
    const { container: enc } = render(<ClassificationBadges row={{ encrypted: 1, classes: ["dataclass:pii"] }} />);
    const { container: unk } = render(<ClassificationBadges row={{ encrypted: 2, classes: ["dataclass:pii"] }} />);
    expect(unk.innerHTML).not.toEqual(enc.innerHTML);
  });
});
