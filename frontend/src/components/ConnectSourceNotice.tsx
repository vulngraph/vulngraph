import { Link } from "@tanstack/react-router";
import { Plus } from "lucide-react";
import { useConnectors } from "../lib/queries";

// useNoConnectors is true only once the connector list has loaded and is empty.
// A failed or in-flight request is "unknown", never "nothing connected".
export function useNoConnectors(): boolean {
  const connectors = useConnectors();
  return connectors.isSuccess && connectors.data.length === 0;
}

// ConnectSourceNotice tells a reader that the numbers around it come from no
// data at all: with nothing connected there is no inventory to assess, so a
// zero (or a pass) is "not evaluated", not "all clear". The panel is the home
// page's call to action; the banner sits above compliance results.
export function ConnectSourceNotice({ variant }: { variant: "panel" | "banner" }) {
  const action = (
    <Link
      to="/settings"
      className="inline-flex items-center gap-1.5 rounded-md bg-teal px-3 py-1.5 text-[13px] font-medium text-bg hover:opacity-90"
    >
      <Plus className="h-3.5 w-3.5" /> Add a connector
    </Link>
  );

  if (variant === "banner") {
    return (
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-teal/30 bg-teal/5 px-4 py-3">
        <p className="max-w-2xl text-[13px] text-text-2">
          <span className="font-medium text-text">Nothing is connected yet.</span> No inventory
          has been assessed, so these controls have not been evaluated against anything.
        </p>
        {action}
      </div>
    );
  }

  return (
    <div className="glass rounded-xl border border-teal/30 px-5 py-4">
      <h2 className="font-display text-lg font-semibold text-text">Connect your first source</h2>
      <p className="mt-1 mb-3 max-w-2xl text-[13px] text-text-2">
        Nothing is connected yet, so there is no inventory to assess and no benchmark control
        has been evaluated. Add a cloud account, repository or other connector and the first
        sync populates this page.
      </p>
      {action}
    </div>
  );
}
