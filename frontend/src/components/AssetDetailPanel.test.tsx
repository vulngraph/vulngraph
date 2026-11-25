import { render, screen } from "@testing-library/react";
import { describe, expect, test } from "vitest";
import { TypedAssetSection } from "./AssetDetailPanel";

// An RDS instance row without storage_encrypted (e.g. IaC-declared) is unknown,
// not unencrypted: the red chip used to fire on anything but "true".
describe("TypedAssetSection RDS encryption chip", () => {
  test.each([
    { storage_encrypted: "true", text: "Encrypted ✓" },
    { storage_encrypted: "false", text: "Unencrypted ⚠" },
    { storage_encrypted: undefined, text: "Encryption unknown" },
  ])("storage_encrypted=$storage_encrypted renders $text", ({ storage_encrypted, text }) => {
    const meta: Record<string, string> = { engine: "postgres" };
    if (storage_encrypted !== undefined) meta.storage_encrypted = storage_encrypted;
    render(<TypedAssetSection type="rds_instance" meta={meta} />);
    expect(screen.getByText(text)).toBeInTheDocument();
    if (storage_encrypted !== "false") expect(screen.queryByText("Unencrypted ⚠")).toBeNull();
  });
});
