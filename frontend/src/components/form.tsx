import { useRef, useState, type ReactNode } from "react";
import { Button } from "./ui";

// Shared form language for the admin/Settings sections. Superset of ui.tsx's
// Field: adds select support, help text, and inline error rendering with the
// one canonical focus treatment (focus:border-teal focus:outline-none).

type BaseProps = {
  label: string;
  help?: string;
  error?: string;
  className?: string;
  required?: boolean;
};

type InputVariant = BaseProps & {
  as?: "input";
  type?: string;
  value?: string | number;
  placeholder?: string;
  disabled?: boolean;
  min?: number;
  max?: number;
  step?: number;
  autoComplete?: string;
  onChange?: (e: React.ChangeEvent<HTMLInputElement>) => void;
};

type TextareaVariant = BaseProps & {
  as: "textarea";
  value?: string;
  placeholder?: string;
  disabled?: boolean;
  onChange?: (e: React.ChangeEvent<HTMLTextAreaElement>) => void;
};

type SelectVariant = BaseProps & {
  as: "select";
  value?: string;
  disabled?: boolean;
  children: ReactNode;
  onChange?: (e: React.ChangeEvent<HTMLSelectElement>) => void;
};

export type FormFieldProps = InputVariant | TextareaVariant | SelectVariant;

const CONTROL_BASE =
  "w-full rounded border bg-surface px-2 py-1 text-[13px] text-text focus:border-teal focus:outline-none disabled:opacity-60";

// Border colour responds to error state; everything else (radius, focus ring)
// stays the same across the three control kinds.
function borderCls(error?: string) {
  return error ? "border-red/50" : "border-border-subtle";
}

let idCounter = 0;
function useFieldId(label: string) {
  const ref = useRef<string | undefined>(undefined);
  if (!ref.current) {
    idCounter += 1;
    ref.current = `field-${label.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-${idCounter}`;
  }
  return ref.current;
}

export function FormField(props: FormFieldProps) {
  const { label, help, error, className = "", required } = props;
  const id = useFieldId(label);
  const helpId = help ? `${id}-help` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy = [helpId, errorId].filter(Boolean).join(" ") || undefined;

  let control: ReactNode;
  if (props.as === "textarea") {
    control = (
      <textarea
        id={id}
        value={props.value}
        placeholder={props.placeholder}
        disabled={props.disabled}
        required={required}
        onChange={props.onChange}
        aria-describedby={describedBy}
        aria-invalid={!!error}
        className={`min-h-[4rem] font-mono ${CONTROL_BASE} ${borderCls(error)}`}
      />
    );
  } else if (props.as === "select") {
    control = (
      <select
        id={id}
        value={props.value}
        disabled={props.disabled}
        onChange={props.onChange}
        aria-describedby={describedBy}
        aria-invalid={!!error}
        className={`${CONTROL_BASE} ${borderCls(error)}`}
      >
        {props.children}
      </select>
    );
  } else {
    control = (
      <input
        id={id}
        type={props.type ?? "text"}
        value={props.value}
        placeholder={props.placeholder}
        disabled={props.disabled}
        required={required}
        min={props.min}
        max={props.max}
        step={props.step}
        autoComplete={props.autoComplete}
        onChange={props.onChange}
        aria-describedby={describedBy}
        aria-invalid={!!error}
        className={`${CONTROL_BASE} ${borderCls(error)}`}
      />
    );
  }

  // Help/error text lives OUTSIDE the <label> and is wired in only via
  // aria-describedby. An implicit <label> exposes ALL of its text content as
  // part of the control's accessible NAME, not just the leading span — nest
  // the help copy inside it and screen readers announce "Password At least
  // 8 characters." as the field's name, not "Password" with a description.
  return (
    <div className={`block ${className}`}>
      <label htmlFor={id}>
        <span className="mb-1 block text-[12px] uppercase text-text-3">{label}</span>
        {control}
      </label>
      {help && !error && (
        <span id={helpId} className="mt-1 block text-[12px] text-text-3">
          {help}
        </span>
      )}
      {error && (
        <span id={errorId} className="mt-1 block text-[12px] text-red">
          {error}
        </span>
      )}
    </div>
  );
}

// SuccessNote is the shared success-state surface for admin forms — a small
// green box, matching the treatment Users.tsx originated.
export function SuccessNote({ message }: { message: string }) {
  return (
    <p className="rounded border border-emerald/30 bg-emerald/10 px-2 py-1.5 text-[12px] text-emerald">
      {message}
    </p>
  );
}

// FormActions is the button row shared by every admin form: Cancel then
// Primary, in that order, with an optional inline reason for why the primary
// action is disabled (never hidden behind a title-only tooltip).
export function FormActions({
  submitLabel,
  onCancel,
  cancelLabel = "Cancel",
  isPending = false,
  disabled = false,
  disabledReason,
  align = "left",
  onSubmit,
  type = "submit",
}: {
  submitLabel: string;
  onCancel?: () => void;
  cancelLabel?: string;
  isPending?: boolean;
  disabled?: boolean;
  disabledReason?: string;
  align?: "left" | "right";
  onSubmit?: () => void;
  type?: "submit" | "button";
}) {
  return (
    <div className={`flex flex-wrap items-center gap-2 ${align === "right" ? "justify-end" : ""}`}>
      {onCancel && (
        <Button variant="ghost" type="button" onClick={onCancel} disabled={isPending}>
          {cancelLabel}
        </Button>
      )}
      <Button variant="primary" type={type} onClick={onSubmit} disabled={disabled || isPending}>
        {isPending ? "Saving…" : submitLabel}
      </Button>
      {disabled && disabledReason && (
        <span className="text-[12px] text-text-3">{disabledReason}</span>
      )}
    </div>
  );
}

// ConfirmButton is the two-click destructive pattern: first click arms a
// "Confirm <verb>?" state that resets after a short timeout if not confirmed.
export function ConfirmButton({
  label,
  verb,
  onConfirm,
  isPending = false,
  className = "",
  resetMs = 4000,
}: {
  label: string;
  verb?: string;
  onConfirm: () => void;
  isPending?: boolean;
  className?: string;
  resetMs?: number;
}) {
  const [armed, setArmed] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  function arm() {
    setArmed(true);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setArmed(false), resetMs);
  }

  function click() {
    if (!armed) {
      arm();
      return;
    }
    if (timer.current) clearTimeout(timer.current);
    setArmed(false);
    onConfirm();
  }

  return (
    <button
      type="button"
      onClick={click}
      disabled={isPending}
      className={
        armed
          ? `rounded border border-red/50 bg-red/10 px-2 py-1 text-[11px] text-red transition-colors disabled:opacity-50 ${className}`
          : `rounded border border-border-subtle px-2 py-1 text-[11px] text-text-2 transition-colors hover:border-red/50 hover:text-red disabled:opacity-50 ${className}`
      }
    >
      {armed ? `Confirm ${verb ?? label.toLowerCase()}?` : label}
    </button>
  );
}
