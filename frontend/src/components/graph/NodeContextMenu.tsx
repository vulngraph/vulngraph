import { useEffect } from "react";

export type MenuAction = { label: string; onClick: () => void; danger?: boolean; disabled?: boolean };

// NodeContextMenu is a small right-click menu anchored at viewport coordinates.
// Closes on outside click, scroll, or Escape (the parent owns open state).
export function NodeContextMenu({
  x,
  y,
  title,
  actions,
  onClose,
}: {
  x: number;
  y: number;
  title?: string;
  actions: MenuAction[];
  onClose: () => void;
}) {
  useEffect(() => {
    const close = () => onClose();
    // Defer so the opening right-click doesn't immediately close it.
    const id = setTimeout(() => window.addEventListener("click", close), 0);
    window.addEventListener("scroll", close, true);
    return () => {
      clearTimeout(id);
      window.removeEventListener("click", close);
      window.removeEventListener("scroll", close, true);
    };
  }, [onClose]);

  // Keep the menu on-screen near the right/bottom edges.
  const left = Math.min(x, window.innerWidth - 180);
  const top = Math.min(y, window.innerHeight - (actions.length + 1) * 30 - 12);

  return (
    <div
      className="fixed z-50 w-44 overflow-hidden rounded-lg border border-border-strong bg-bg/98 py-1 text-[11px] shadow-xl backdrop-blur-sm"
      style={{ left, top }}
      onClick={(e) => e.stopPropagation()}
    >
      {title && <div className="truncate border-b border-border-subtle px-3 py-1 text-[11px] text-text-3" title={title}>{title}</div>}
      {actions.map((a) => (
        <button
          key={a.label}
          disabled={a.disabled}
          onClick={() => { a.onClick(); onClose(); }}
          className={`block w-full px-3 py-1.5 text-left disabled:opacity-30 ${a.danger ? "text-red hover:bg-red/10" : "text-text-2 hover:bg-surface-3"}`}
        >
          {a.label}
        </button>
      ))}
    </div>
  );
}
