import { useCallback, useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import { ChevronDown } from "lucide-react";

// DropdownMenu — a dependency-free popover menu primitive.
//
// Collapses sprawling pill rows / preset-card grids into a single trigger. It is
// deliberately small: a trigger button plus an absolutely-positioned panel that
// closes on outside click and Escape, supports arrow-key navigation, optional
// per-item descriptions + check state, optional grouping, and an optional search
// box that filters items as you type.

export type MenuItem = {
  id: string;
  label: string;
  /** Secondary line under the label. */
  desc?: string;
  /** Group heading — items sharing a group render together, groups in first-seen order. */
  group?: string;
  /** Renders a ✓ and marks the item as the current selection. */
  checked?: boolean;
  /** Right-aligned trailing text (counts, badges). */
  meta?: string;
  disabled?: boolean;
  /** Extra text matched by the search box in addition to label/desc/meta. */
  keywords?: string;
};

type Variant = "field" | "ghost" | "icon";

export type DropdownMenuProps = {
  /** Trigger content. Ignored for variant="icon" (use `icon`). */
  label?: ReactNode;
  /** Trigger glyph for variant="icon". */
  icon?: ReactNode;
  items: MenuItem[];
  onSelect: (id: string) => void;
  /** Helper text rendered under the trigger (e.g. the active preset's description). */
  helper?: ReactNode;
  searchable?: boolean;
  searchPlaceholder?: string;
  /** Highlight the trigger as carrying an active (non-default) selection. */
  active?: boolean;
  variant?: Variant;
  /** Panel edge aligned to the trigger. */
  align?: "left" | "right";
  /** Tailwind width class for the panel. */
  panelWidth?: string;
  /** Accessible name — required for variant="icon". */
  ariaLabel?: string;
  title?: string;
  className?: string;
  emptyMessage?: string;
  /** Disable the trigger entirely — a wrapper's pointer-events-none alone
      still leaves it keyboard-focusable and openable. */
  disabled?: boolean;
};

const triggerCls: Record<Variant, string> = {
  field:
    "flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-[12px] transition-colors outline-none focus-visible:border-teal",
  ghost:
    "flex items-center gap-1 rounded px-2 py-1 text-[12px] transition-colors outline-none focus-visible:ring-1 focus-visible:ring-teal/60",
  icon:
    "flex items-center justify-center rounded border border-border-subtle p-1 text-text-3 transition-colors hover:border-teal/40 hover:text-teal outline-none focus-visible:border-teal focus-visible:text-teal",
};

export function DropdownMenu({
  label,
  icon,
  items,
  onSelect,
  helper,
  searchable = false,
  searchPlaceholder = "filter…",
  active = false,
  variant = "field",
  align = "left",
  panelWidth = "w-64",
  ariaLabel,
  title,
  className = "",
  emptyMessage = "No matches",
  disabled = false,
}: DropdownMenuProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState(0);
  const rootRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuId = useId();

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter((it) =>
      `${it.label} ${it.desc ?? ""} ${it.meta ?? ""} ${it.keywords ?? ""} ${it.id}`
        .toLowerCase()
        .includes(q),
    );
  }, [items, query]);

  // Enabled items only — arrow-key navigation skips disabled entries.
  const navigable = useMemo(() => filtered.filter((it) => !it.disabled), [filtered]);

  // Groups in first-seen order; ungrouped items render first under no heading.
  const groups = useMemo(() => {
    const out: { name: string; items: MenuItem[] }[] = [];
    for (const it of filtered) {
      const name = it.group ?? "";
      const bucket = out.find((g) => g.name === name);
      if (bucket) bucket.items.push(it);
      else out.push({ name, items: [it] });
    }
    return out;
  }, [filtered]);

  const close = useCallback((refocus = true) => {
    setOpen(false);
    setQuery("");
    if (refocus) triggerRef.current?.focus();
  }, []);

  // Outside click / Escape. Bound only while open.
  useEffect(() => {
    if (!open) return;
    function onDown(e: MouseEvent) {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        setOpen(false);
        setQuery("");
      }
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        e.stopPropagation();
        close();
      }
    }
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open, close]);

  // On open, park the cursor on the checked item and focus the search box.
  useEffect(() => {
    if (!open) return;
    const idx = navigable.findIndex((it) => it.checked);
    setCursor(idx >= 0 ? idx : 0);
    if (searchable) searchRef.current?.focus();
  }, [open]);

  // Filtering shrinks the list — keep the cursor in range.
  useEffect(() => {
    setCursor((c) => (c >= navigable.length ? 0 : c));
  }, [navigable.length]);

  function pick(it: MenuItem) {
    if (it.disabled) return;
    onSelect(it.id);
    close();
  }

  function onPanelKeyDown(e: React.KeyboardEvent) {
    if (navigable.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setCursor((c) => (c + 1) % navigable.length);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setCursor((c) => (c - 1 + navigable.length) % navigable.length);
    } else if (e.key === "Home") {
      e.preventDefault();
      setCursor(0);
    } else if (e.key === "End") {
      e.preventDefault();
      setCursor(navigable.length - 1);
    } else if (e.key === "Enter") {
      e.preventDefault();
      const it = navigable[cursor];
      if (it) pick(it);
    } else if (e.key === "Tab") {
      close(false);
    }
  }

  const activeTrigger =
    variant === "field"
      ? active
        ? "border-teal/60 bg-teal/5 text-teal"
        : "border-border-subtle bg-bg text-text-3 hover:border-teal/40 hover:text-text-2"
      : variant === "ghost"
        ? active
          ? "bg-surface-3 text-text"
          : "text-text-3 hover:text-text-2"
        : "";

  return (
    <div ref={rootRef} className={className}>
      <div className="relative">
      <button
        ref={triggerRef}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        aria-label={ariaLabel}
        title={title}
        disabled={disabled}
        onClick={() => (open ? close(false) : setOpen(true))}
        onKeyDown={(e) => {
          if (!open && (e.key === "ArrowDown" || e.key === "Enter" || e.key === " ")) {
            e.preventDefault();
            setOpen(true);
          }
        }}
        className={`${triggerCls[variant]} ${activeTrigger}`}
      >
        {variant === "icon" ? (
          (icon ?? <span aria-hidden="true">⋯</span>)
        ) : (
          <>
            <span className="truncate">{label}</span>
            <ChevronDown className="h-3 w-3 shrink-0 opacity-70" aria-hidden="true" />
          </>
        )}
      </button>

      {open && (
        <div
          id={menuId}
          role="menu"
          onKeyDown={onPanelKeyDown}
          className={`absolute top-full z-40 mt-1 ${align === "right" ? "right-0" : "left-0"} ${panelWidth} overflow-hidden rounded-lg border border-border-subtle bg-surface shadow-lg`}
        >
          {searchable && (
            <div className="border-b border-border-subtle p-1.5">
              <input
                ref={searchRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={searchPlaceholder}
                aria-label={searchPlaceholder}
                className="w-full rounded border border-border-subtle bg-bg px-2 py-1 text-[12px] text-text outline-none focus:border-teal"
              />
            </div>
          )}
          <div className="max-h-72 overflow-y-auto py-1">
            {filtered.length === 0 && (
              <p className="px-2.5 py-2 text-[12px] text-text-3">{emptyMessage}</p>
            )}
            {groups.map((g) => (
              <div key={g.name || "_"}>
                {g.name && (
                  <p className="px-2.5 pt-1.5 pb-0.5 text-[11px] uppercase tracking-wide text-text-3">
                    {g.name}
                  </p>
                )}
                {g.items.map((it) => {
                  const navIdx = navigable.indexOf(it);
                  const focused = navIdx >= 0 && navIdx === cursor;
                  return (
                    <button
                      key={it.id}
                      type="button"
                      role="menuitemradio"
                      aria-checked={!!it.checked}
                      disabled={it.disabled}
                      tabIndex={-1}
                      onMouseEnter={() => navIdx >= 0 && setCursor(navIdx)}
                      onClick={() => pick(it)}
                      className={`flex w-full items-start gap-2 px-2.5 py-1.5 text-left transition-colors disabled:opacity-40 ${
                        focused ? "bg-surface-3" : ""
                      } ${it.checked ? "text-teal" : "text-text-2"}`}
                    >
                      <span className="w-3 shrink-0 text-[12px] leading-5" aria-hidden="true">
                        {it.checked ? "✓" : ""}
                      </span>
                      <span className="min-w-0 flex-1">
                        <span className="flex items-baseline gap-2">
                          <span className="min-w-0 flex-1 truncate text-[12px] font-medium">{it.label}</span>
                          {it.meta && (
                            <span className="shrink-0 tabular-nums text-[11px] text-text-3">{it.meta}</span>
                          )}
                        </span>
                        {it.desc && (
                          <span className="mt-0.5 block text-[11px] leading-snug text-text-3 line-clamp-2">
                            {it.desc}
                          </span>
                        )}
                      </span>
                    </button>
                  );
                })}
              </div>
            ))}
          </div>
        </div>
      )}
      </div>
      {helper && (
        <p className="mt-1 max-w-md text-[11px] leading-snug text-text-3">{helper}</p>
      )}
    </div>
  );
}
