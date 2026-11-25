import { ExternalLink, Play } from "lucide-react";
import { router } from "../router";

// ── Markdown renderer ─────────────────────────────────────────────────────────
// Lightweight: code fences, inline code, bold, italic, bullet lists, line breaks.
// Shared by ChatPanel and DecisionDetailPanel so both AI-chat surfaces render
// the same way instead of one showing raw Markdown syntax.

export function renderMarkdown(text: string): React.ReactNode[] {
  const lines = text.split("\n");
  const out: React.ReactNode[] = [];
  let i = 0;
  let key = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block
    if (line.startsWith("```")) {
      const lang = line.slice(3).trim().toLowerCase();
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      const codeText = codeLines.join("\n");
      const isCypher = lang === "cypher";
      out.push(
        <div key={key++} style={{ position: "relative", margin: "6px 0" }}>
          <div style={{
            display: "flex", alignItems: "center", justifyContent: "space-between",
            padding: "4px 10px 2px",
            background: isCypher ? "rgba(13,148,136,0.12)" : "rgba(255,255,255,0.04)",
            borderRadius: "6px 6px 0 0",
            border: `1px solid ${isCypher ? "rgba(13,148,136,0.2)" : "rgba(255,255,255,0.08)"}`,
            borderBottom: "none",
          }}>
            <span style={{
              fontSize: "11px", fontFamily: "monospace",
              color: isCypher ? "var(--graph-teal)" : "var(--graph-text-3)",
              textTransform: "uppercase", letterSpacing: "0.08em",
            }}>{lang || "code"}</span>
            {isCypher && (
              <button
                onClick={() => {
                  window.dispatchEvent(new CustomEvent("graph:run-cypher", { detail: { cypher: codeText } }));
                  void router.navigate({ to: "/investigate/graph" });
                }}
                title="Run this query in the Graph Explorer"
                style={{
                  display: "flex", alignItems: "center", gap: "4px",
                  padding: "2px 7px", borderRadius: "4px",
                  border: "1px solid rgba(13,148,136,0.35)",
                  background: "rgba(13,148,136,0.12)", color: "var(--graph-teal)",
                  fontSize: "11px", fontWeight: 600, cursor: "pointer",
                  transition: "all 0.15s",
                }}
                onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "rgba(13,148,136,0.25)"; }}
                onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "rgba(13,148,136,0.12)"; }}
              >
                <Play style={{ width: "9px", height: "9px", fill: "var(--graph-teal)" }} />
                Run in graph
                <ExternalLink style={{ width: "9px", height: "9px" }} />
              </button>
            )}
          </div>
          <pre style={{
            margin: 0, padding: "8px 10px",
            background: "rgba(0,0,0,0.35)",
            border: "1px solid rgba(255,255,255,0.08)",
            borderRadius: "0 0 6px 6px",
            fontSize: "11px", lineHeight: 1.55, overflowX: "auto",
            color: "var(--graph-text-2)", fontFamily: "monospace",
          }}>
            <code>{codeText}</code>
          </pre>
        </div>
      );
      i++; // skip closing ```
      continue;
    }

    // Bullet list item
    if (line.match(/^[-*•]\s/)) {
      const items: string[] = [];
      while (i < lines.length && lines[i].match(/^[-*•]\s/)) {
        items.push(lines[i].replace(/^[-*•]\s/, ""));
        i++;
      }
      out.push(
        <ul key={key++} style={{ margin: "4px 0 4px 16px", padding: 0, listStyle: "disc" }}>
          {items.map((item, idx) => (
            <li key={idx} style={{ fontSize: "13px", color: "var(--graph-text-2)", lineHeight: 1.6, marginBottom: "2px" }}>
              {inlineFormat(item)}
            </li>
          ))}
        </ul>
      );
      continue;
    }

    // Numbered list
    if (line.match(/^\d+\.\s/)) {
      const items: string[] = [];
      while (i < lines.length && lines[i].match(/^\d+\.\s/)) {
        items.push(lines[i].replace(/^\d+\.\s/, ""));
        i++;
      }
      out.push(
        <ol key={key++} style={{ margin: "4px 0 4px 20px", padding: 0 }}>
          {items.map((item, idx) => (
            <li key={idx} style={{ fontSize: "13px", color: "var(--graph-text-2)", lineHeight: 1.6, marginBottom: "2px" }}>
              {inlineFormat(item)}
            </li>
          ))}
        </ol>
      );
      continue;
    }

    // Empty line → spacing
    if (line.trim() === "") {
      out.push(<div key={key++} style={{ height: "6px" }} />);
      i++;
      continue;
    }

    // Heading (##)
    const headingMatch = line.match(/^(#{1,3})\s+(.*)/);
    if (headingMatch) {
      const level = headingMatch[1].length;
      out.push(
        <div key={key++} style={{
          fontSize: level === 1 ? "14px" : level === 2 ? "13px" : "12.5px",
          fontWeight: 600, color: "var(--graph-text)",
          marginTop: "10px", marginBottom: "3px",
          fontFamily: "var(--font-display)",
        }}>
          {inlineFormat(headingMatch[2])}
        </div>
      );
      i++;
      continue;
    }

    // Normal paragraph line
    out.push(
      <div key={key++} style={{ fontSize: "13px", lineHeight: 1.65, color: "var(--graph-text-2)" }}>
        {inlineFormat(line)}
      </div>
    );
    i++;
  }

  return out;
}

export function inlineFormat(text: string): React.ReactNode {
  // Split on **bold**, *italic*, `code`
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*)/g);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**"))
      return <strong key={i} style={{ color: "var(--graph-text)", fontWeight: 600 }}>{part.slice(2, -2)}</strong>;
    if (part.startsWith("*") && part.endsWith("*"))
      return <em key={i}>{part.slice(1, -1)}</em>;
    if (part.startsWith("`") && part.endsWith("`"))
      return <code key={i} style={{
        background: "rgba(0,0,0,0.3)", border: "1px solid rgba(255,255,255,0.1)",
        borderRadius: "3px", padding: "1px 4px",
        fontFamily: "monospace", fontSize: "11px", color: "var(--graph-teal)",
      }}>{part.slice(1, -1)}</code>;
    return part;
  });
}
