import React, { useCallback, useEffect, useRef } from "react";

// SlideOver — the one right-hand drawer primitive. Owns the overlay, the panel
// chrome, Escape-to-close, body scroll lock and a real focus trap so every
// drawer in the app behaves identically. Detail panels compose their own
// header/body inside `children` and hand any sticky bar to `footer`.
//
// z-index scale: overlay 40, panel 50. The chat drawer deliberately sits below
// (30/39) so an open detail panel always wins.

const FOCUSABLE = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[tabindex]:not([tabindex='-1'])",
].join(",");

interface Props {
  open: boolean;
  onClose: () => void;
  title?: string;
  /** CSS width of the panel — e.g. "520px". Capped at the viewport. */
  width?: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
}

export function SlideOver({ open, onClose, title, width = "480px", children, footer }: Props) {
  const panelRef = useRef<HTMLDivElement>(null);
  const restoreRef = useRef<HTMLElement | null>(null);

  // Escape closes — listener added on open, removed on close.
  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  // Body scroll lock while open.
  useEffect(() => {
    if (!open) return;
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { document.body.style.overflow = previous; };
  }, [open]);

  // Focus the panel on open; restore focus to whatever was focused before.
  useEffect(() => {
    if (!open) return;
    restoreRef.current = document.activeElement as HTMLElement | null;
    panelRef.current?.focus();
    return () => {
      const el = restoreRef.current;
      restoreRef.current = null;
      if (el && el.isConnected) el.focus();
    };
  }, [open]);

  // Trap Tab inside the panel. Focus never leaves the drawer while it is open.
  const onKeyDown = useCallback((e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== "Tab") return;
    const panel = panelRef.current;
    if (!panel) return;
    const items = Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE))
      .filter((el) => el.offsetParent !== null || el === document.activeElement);
    if (items.length === 0) {
      e.preventDefault();
      panel.focus();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    if (e.shiftKey) {
      if (active === first || active === panel || !panel.contains(active)) {
        e.preventDefault();
        last.focus();
      }
    } else if (active === last) {
      e.preventDefault();
      first.focus();
    }
  }, []);

  if (!open) return null;

  return (
    <>
      {/* Overlay — click outside closes */}
      <div
        aria-hidden="true"
        onClick={onClose}
        className="fixed inset-0 z-40 bg-black/40 backdrop-blur-[2px]"
      />

      {/* Panel */}
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={title ?? "Panel"}
        tabIndex={-1}
        onKeyDown={onKeyDown}
        className="slide-over-panel fixed top-0 right-0 bottom-0 z-50 flex max-w-full flex-col outline-none"
        style={{ width }}
      >
        <div className="flex min-h-0 flex-1 flex-col">{children}</div>
        {footer}
      </div>
    </>
  );
}
