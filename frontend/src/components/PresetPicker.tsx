import { DropdownMenu, type MenuItem } from "./DropdownMenu";

// PresetPicker collapses a grid of graph-preset cards into one "Query ▾" trigger.
// The active preset's label rides on the trigger and its description renders as
// helper text below, so no vertical space is spent on the presets you aren't on.

export type Preset = {
  id: string;
  label: string;
  desc?: string;
  /** Optional grouping key — presets sharing a badge render under one heading. */
  badge?: string;
};

export function PresetPicker({
  presets,
  activeId,
  onSelect,
  label = "Query",
  className = "",
}: {
  presets: Preset[];
  activeId: string;
  onSelect: (id: string) => void;
  /** Trigger prefix, e.g. "Query". */
  label?: string;
  className?: string;
}) {
  const active = presets.find((p) => p.id === activeId);
  const items: MenuItem[] = presets.map((p) => ({
    id: p.id,
    label: p.label,
    desc: p.desc,
    group: p.badge,
    checked: p.id === activeId,
  }));

  return (
    <DropdownMenu
      className={className}
      label={
        <span className="flex items-baseline gap-1.5">
          <span className="text-text-3">{label}</span>
          <span className="font-medium">{active?.label ?? "select…"}</span>
        </span>
      }
      ariaLabel={`${label}: ${active?.label ?? "none"}`}
      items={items}
      onSelect={onSelect}
      active
      panelWidth="w-80"
      helper={active?.desc}
    />
  );
}
