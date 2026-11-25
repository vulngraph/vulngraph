import { useRef, useState } from "react";
import { Sparkles, Loader2, ArrowRight, X } from "lucide-react";
import { api, type NLResult } from "../lib/api";
import { NODE_LABELS } from "../lib/queryLibrary";

// ── NLQBar — natural language → Cypher ───────────────────────────────────────
// Posts the question to POST /api/graph/nl, the one server-side NL→Cypher path
// (the server owns the schema prompt — the frontend must not carry a copy).
// The response carries `generated_cypher` plus the executed result, so we show
// the Cypher for review first and only hand it to the caller when the analyst
// confirms with "Run in graph". The already-computed result is passed along as
// the third onQuery argument so callers can skip re-executing it.

const NL_PATH = "/api/graph/nl";
const MAX_NODES = 500;
const MAX_EDGES = 2000;

interface Props {
  onQuery: (cypher: string, label: string, result?: NLResult) => void;
  placeholder?: string;
  className?: string;
}

type Status = "idle" | "loading" | "done" | "error";

// Describes what the server-side run returned, so the preview says more than
// just "here's some Cypher".
function summarize(res: NLResult): string {
  const rows = res.rows?.length ?? 0;
  if ((res.nodes?.length ?? 0) === 0 && rows > 0) {
    return `${rows} row${rows === 1 ? "" : "s"}${res.truncated ? " (capped)" : ""}`;
  }
  const n = res.nodes?.length ?? 0;
  const e = res.edges?.length ?? 0;
  return `${n} node${n === 1 ? "" : "s"} · ${e} edge${e === 1 ? "" : "s"}${res.truncated ? " (capped)" : ""}`;
}

export function NLQBar({ onQuery, placeholder, className = "" }: Props) {
  const [input, setInput] = useState("");
  const [status, setStatus] = useState<Status>("idle");
  const [preview, setPreview] = useState<{ cypher: string; label: string; result: NLResult } | null>(null);
  const [error, setError] = useState("");
  const abortRef = useRef<AbortController | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  async function submit(question: string) {
    question = question.trim();
    if (!question || status === "loading") return;

    setStatus("loading");
    setPreview(null);
    setError("");

    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;

    try {
      const data = await api.post<NLResult>(
        NL_PATH,
        { question, max_nodes: MAX_NODES, max_edges: MAX_EDGES },
        { signal: ctrl.signal },
      );
      const cypher = (data.generated_cypher ?? "").trim();
      if (!cypher) {
        throw new Error("No Cypher came back — try rephrasing the question");
      }

      setPreview({ cypher, label: summarize(data), result: data });
      setStatus("done");
    } catch (err: unknown) {
      if ((err as Error).name === "AbortError") { setStatus("idle"); return; }
      setError((err as Error).message ?? "Unknown error");
      setStatus("error");
    }
  }

  function handleKey(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      submit(input);
    }
  }

  function runPreview() {
    if (!preview) return;
    onQuery(preview.cypher, preview.label, preview.result);
    setInput("");
    setPreview(null);
    setStatus("idle");
  }

  function dismiss() {
    abortRef.current?.abort();
    setStatus("idle");
    setPreview(null);
    setError("");
    inputRef.current?.focus();
  }

  return (
    <div className={`rounded-xl border border-border-subtle bg-surface ${className}`}>
      {/* Input row */}
      <div className="flex items-center gap-2 px-3 py-2">
        <Sparkles className="h-3.5 w-3.5 shrink-0 text-purple-400" />
        <input
          ref={inputRef}
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder={placeholder ?? "Ask AI — e.g. 'show me Lambdas whose roles can escalate to another role'"}
          disabled={status === "loading"}
          className="flex-1 bg-transparent text-[12px] text-text placeholder-text-3 focus:outline-none disabled:opacity-50"
        />
        {status === "loading" ? (
          <button onClick={dismiss} className="flex items-center gap-1 text-[11px] text-text-3 hover:text-text-2">
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
            <span>stop</span>
          </button>
        ) : (
          <button
            onClick={() => submit(input)}
            disabled={!input.trim()}
            className="flex items-center gap-1 rounded border border-purple-400/30 bg-purple-400/10 px-2 py-1 text-[11px] font-medium text-purple-400 transition-opacity hover:opacity-80 disabled:opacity-30"
          >
            Generate <ArrowRight className="h-3 w-3" />
          </button>
        )}
      </div>

      {/* Preview: generated query + run button */}
      {status === "done" && preview && (
        <div className="border-t border-border-subtle px-3 py-2">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0 flex-1">
              <p className="mb-1 text-[11px] text-text-3 leading-snug">{preview.label}</p>
              <pre className="overflow-x-auto rounded bg-surface-2 px-2 py-1.5 font-mono text-[11px] text-teal leading-relaxed">
                {preview.cypher}
              </pre>
            </div>
            <button onClick={dismiss} className="shrink-0 mt-0.5 text-text-3 hover:text-text-2">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
          <div className="mt-2 flex justify-end">
            <button
              onClick={runPreview}
              className="flex items-center gap-1.5 rounded bg-teal px-3 py-1.5 text-[11px] font-medium text-black transition-opacity hover:opacity-90"
            >
              <Sparkles className="h-3 w-3" />
              Run in graph
            </button>
          </div>
        </div>
      )}

      {/* Error — with the graph's node vocabulary as a rephrasing hint */}
      {status === "error" && (
        <div className="border-t border-border-subtle px-3 py-2">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[11px] text-red">{error}</span>
            <button onClick={dismiss} className="shrink-0 text-text-3 hover:text-text-2"><X className="h-3.5 w-3.5" /></button>
          </div>
          <p className="mt-1 text-[11px] text-text-3">
            Try naming what you're after — the graph knows {NODE_LABELS.join(", ")}.
          </p>
        </div>
      )}
    </div>
  );
}
