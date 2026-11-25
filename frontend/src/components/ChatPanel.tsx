import { useCallback, useEffect, useRef, useState } from "react";
import { Check, Copy, Plus, Square, X } from "lucide-react";
import { MessageCircle as MsgIcon } from "./icons";
import { renderMarkdown } from "../lib/markdown";
import { readEventStream } from "../lib/sse";
import { streamPost } from "../lib/api";
import { copyText } from "../lib/clipboard";
import { openChatStore, type ChatStore } from "../lib/chatStorage";

// ── ChatPanel — Ask Vulngraph AI ────────────────────────────────────────────────
// Full-height slide-out panel. Streams SSE from POST /api/chat.
// Sessions stored per user in localStorage (lib/chatStorage); multiple
// conversations, clear per session.

const MAX_PER_SESSION = 100;

type Role = "user" | "assistant";

interface Message {
  id: string;
  role: Role;
  content: string;
  streaming?: boolean;
  // error marks a failed assistant turn (content holds any partial text).
  // Failed turns are shown but never resent as conversation history.
  error?: string;
}

interface Session {
  id: string;
  title: string;     // first user message, truncated
  messages: Message[];
  updatedAt: number;
  // context is the page/finding/asset the session is bound to (set when opened
  // from a detail view). Sent with every request so follow-ups keep it.
  context?: string;
}

// ── Persistence ───────────────────────────────────────────────────────────────

function loadSessions(store: ChatStore): Session[] {
  try {
    const raw = JSON.parse(store.load("sessions") ?? "[]");
    return Array.isArray(raw) ? raw : [];
  } catch { return []; }
}

function saveSessions(store: ChatStore, sessions: Session[]) {
  // Strip streaming flags before persisting.
  const clean = sessions.map((s) => ({
    ...s,
    messages: s.messages
      .filter((m) => !m.streaming)
      .slice(-MAX_PER_SESSION)
      .map(({ id, role, content, error }) => ({ id, role, content, error })),
  }));
  store.save("sessions", JSON.stringify(clean));
}

// toHistory is what a new turn resends as context: never a failed turn and
// never a blank one (a turn stopped before any text) — the backend drops
// those anyway, and the error text is not something the assistant said.
function toHistory(messages: Message[]): Array<{ role: Role; content: string }> {
  return messages
    .filter((m) => !m.error && !m.streaming && m.content.trim() !== "")
    .map(({ role, content }) => ({ role, content }));
}

function uid() { return Math.random().toString(36).slice(2, 10); }

function newSession(): Session {
  return { id: uid(), title: "New chat", messages: [], updatedAt: Date.now() };
}

// ── Typing cursor ─────────────────────────────────────────────────────────────
function Cursor() {
  return (
    <span aria-hidden="true" style={{
      display: "inline-block", width: "2px", height: "0.85em",
      background: "var(--graph-teal)", borderRadius: "1px",
      verticalAlign: "text-bottom", marginLeft: "2px",
      animation: "chat-cursor-blink 0.8s step-end infinite",
    }} />
  );
}

// ── CopyButton ────────────────────────────────────────────────────────────────
function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    void copyText(text).then((ok) => {
      if (!ok) return;
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }
  return (
    <button
      onClick={copy}
      title="Copy response"
      style={{
        display: "flex", alignItems: "center", justifyContent: "center",
        width: "22px", height: "22px", borderRadius: "4px",
        border: "1px solid rgba(255,255,255,0.08)",
        background: "transparent", color: "var(--graph-text-3)",
        cursor: "pointer", transition: "all 0.15s ease", flexShrink: 0,
      }}
      onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "rgba(255,255,255,0.06)"; (e.currentTarget as HTMLButtonElement).style.color = "var(--graph-text)"; }}
      onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "transparent"; (e.currentTarget as HTMLButtonElement).style.color = "var(--graph-text-3)"; }}
    >
      {copied ? <Check style={{ width: "11px", height: "11px" }} /> : <Copy style={{ width: "11px", height: "11px" }} />}
    </button>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
const SUGGESTED = [
  "What are my highest-risk internet-exposed assets?",
  "Which IAM roles have privilege escalation paths?",
  "Show me repos deploying to exposed k8s workloads",
  "What's my CIEM attack surface?",
];

// ChatPanel holds one user's conversations. AppShell keys it by userId, so a
// different user signing in remounts it with that user's own history.
export function ChatPanel({ userId }: { userId: string }) {
  const [open, setOpen]       = useState(false);
  const [showSessions, setShowSessions] = useState(false);
  const [store] = useState(() => openChatStore(userId));
  const [sessions, setSessions]         = useState<Session[]>(() => loadSessions(store));
  const [activeId, setActiveId]         = useState<string | null>(() => store.load("active"));
  const [input, setInput]     = useState("");
  const [streaming, setStreaming] = useState(false);
  const [unread, setUnread]   = useState(0);
  const panelRef = useRef<HTMLDivElement>(null);
  const fabRef   = useRef<HTMLButtonElement>(null);

  const bottomRef   = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const abortRef    = useRef<AbortController | null>(null);
  // Keep a ref to current messages to avoid stale closure in send()
  const sessionsRef = useRef(sessions);
  useEffect(() => { sessionsRef.current = sessions; }, [sessions]);
  // Pending message from chat-open events — sent once the panel is open and send is live
  const pendingMsgRef = useRef<string | null>(null);
  const pendingCtxRef = useRef<string | null>(null); // page/finding context from graph:chat-open
  const openRef       = useRef(false);
  const sendRef       = useRef<(text: string) => void>(() => {});
  useEffect(() => { openRef.current = open; }, [open]);
  const activeIdRef   = useRef<string | null>(activeId);
  useEffect(() => { activeIdRef.current = activeId; }, [activeId]);

  // Derive active session
  const activeSession = sessions.find((s) => s.id === activeId) ?? null;
  const messages = activeSession?.messages ?? [];

  // Scroll on new messages
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Focus + clear unread on open; also fire any pending auto-send. Gated on
  // activeId so the send always has a session to write into — the session is
  // created by a separate [open, activeId] effect, and firing before it commits
  // dropped the message (the Verify / Ask AI one-click race).
  useEffect(() => {
    if (!open) return;
    setUnread(0);
    const pending = pendingMsgRef.current;
    if (pending && activeId) {
      pendingMsgRef.current = null;
      // sendRef is always current (updated after send is declared below)
      setTimeout(() => sendRef.current(pending), 0);
    } else if (!pending) {
      setTimeout(() => textareaRef.current?.focus(), 60);
    }
  }, [open, activeId]);

  // Persist sessions
  useEffect(() => {
    if (!streaming) saveSessions(store, sessions);
  }, [store, streaming, sessions]);
  useEffect(() => { store.save("active", activeId); }, [store, activeId]);

  // Click outside the panel or press Escape to close it. The launcher button is
  // excluded so its own click toggles instead of closing and reopening. Closing
  // keeps the session and any in-flight reply.
  useEffect(() => {
    if (!open) return;
    const onPointerDown = (e: MouseEvent) => {
      const target = e.target as Node;
      if (panelRef.current?.contains(target) || fabRef.current?.contains(target)) return;
      setOpen(false);
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  // External open+auto-send (from asset rows, detail panels, finding clusters, etc.)
  useEffect(() => {
    function onChatOpen(e: Event) {
      const detail = (e as CustomEvent<{ message?: string; context?: string }>).detail;
      let switched = false;
      if (detail?.context) {
        // Each subject gets its own thread: continue the active session only if
        // it's already bound to this exact subject (or is still blank); any other
        // subject starts a fresh session so contexts never bleed across threads.
        const cur = sessionsRef.current.find((s) => s.id === activeIdRef.current);
        const sameSubject = cur?.context === detail.context;
        const blank = cur && !cur.context && cur.messages.length === 0;
        if (!sameSubject && !blank) {
          const s = newSession();
          setSessions((prev) => [...prev, s]);
          setActiveId(s.id);
          switched = true;
        }
        pendingCtxRef.current = detail.context; // bind the (new or blank) session to this subject
      }
      if (detail?.message) {
        if (openRef.current && !switched) {
          // Panel already open on the right session — send immediately via current ref
          sendRef.current(detail.message);
        } else {
          // Store message; the open-effect fires it once the panel is open, the
          // session switch has committed, and send is current.
          pendingMsgRef.current = detail.message;
        }
      }
      setOpen(true);
    }
    window.addEventListener("graph:chat-open", onChatOpen);
    return () => window.removeEventListener("graph:chat-open", onChatOpen);
  }, []);

  // Ensure there's always an active session when opening
  useEffect(() => {
    if (open && !activeId) {
      const existing = sessionsRef.current;
      if (existing.length > 0) {
        setActiveId(existing[existing.length - 1].id);
      } else {
        const s = newSession();
        setSessions([s]);
        setActiveId(s.id);
      }
    }
  }, [open, activeId]);

  function startNewSession() {
    const s = newSession();
    setSessions((prev) => [...prev, s]);
    setActiveId(s.id);
    setShowSessions(false);
    setInput("");
    setTimeout(() => textareaRef.current?.focus(), 60);
  }

  function switchSession(id: string) {
    setActiveId(id);
    setShowSessions(false);
  }

  function deleteSession(id: string, e: React.MouseEvent) {
    e.stopPropagation();
    setSessions((prev) => {
      const next = prev.filter((s) => s.id !== id);
      if (activeId === id) {
        const newActive = next[next.length - 1]?.id ?? null;
        setActiveId(newActive);
      }
      return next;
    });
  }

  // Build a brief page-context prefix for the first message in a new chat.
  function buildPageContext(): string {
    const path = window.location.pathname;
    if (path.includes("/explore"))  return "[User is on the Graph Explorer tab] ";
    if (path.includes("/findings")) return "[User is on the Findings/Signals tab] ";
    if (path.includes("/assets"))   {
      const match = path.match(/\/assets\/(.+)/);
      return match ? `[User is viewing asset: ${match[1]}] ` : "[User is on the Assets tab] ";
    }
    if (path.includes("/identity")) return "[User is on the Identity tab] ";
    if (path.includes("/dspm"))     return "[User is on the DSPM/Data tab] ";
    if (path.includes("/domains"))  return "[User is on the Domains/Attack Surface tab] ";
    if (path.includes("/scans"))    return "[User is on the Scans tab] ";
    return "";
  }

  const send = useCallback(async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || streaming) return;

    // Get or create an active session using the ref (avoids stale closure)
    let currentSessions = sessionsRef.current;
    let currentActiveId = activeId;

    if (!currentActiveId || !currentSessions.find((s) => s.id === currentActiveId)) {
      const s = newSession();
      currentSessions = [...currentSessions, s];
      currentActiveId = s.id;
      setSessions(currentSessions);
      setActiveId(currentActiveId);
    }

    const sid = currentActiveId;
    const session = currentSessions.find((s) => s.id === sid)!;

    // Bind the session to a subject the first time it's used: an explicit context
    // from graph:chat-open (a finding/asset) wins; otherwise the coarse route hint.
    // Sent as the request `context` on EVERY turn (below) so follow-ups keep it,
    // instead of being baked into just the first message.
    const sessionContext = session.context ?? (pendingCtxRef.current || buildPageContext() || undefined);
    pendingCtxRef.current = null;

    const userMsg: Message    = { id: uid(), role: "user",      content: trimmed };
    const assistantId = uid();
    const assistantMsg: Message = { id: assistantId, role: "assistant", content: "", streaming: true };

    // Title = first user message (truncated)
    const title = session.messages.length === 0 ? trimmed.slice(0, 50) : session.title;

    setSessions((prev) => prev.map((s) =>
      s.id === sid
        ? { ...s, title, updatedAt: Date.now(), context: s.context ?? sessionContext, messages: [...s.messages, userMsg, assistantMsg] }
        : s
    ));
    setInput("");
    setStreaming(true);
    if (!open) setUnread((n) => n + 1);

    const ctrl = new AbortController();
    abortRef.current = ctrl;

    // History stays clean (no context baked into message content); the page/finding
    // context rides as a separate `context` field so it applies to every turn.
    const history = toHistory([...session.messages, userMsg]);

    // Applies fn to this turn's assistant message; returning null removes it.
    const updateAssistant = (fn: (m: Message) => Message | null) => {
      setSessions((prev) => prev.map((s) =>
        s.id === sid
          ? {
              ...s,
              messages: s.messages.flatMap((m) => {
                if (m.id !== assistantId) return [m];
                const next = fn(m);
                return next ? [next] : [];
              }),
            }
          : s
      ));
    };

    try {
      const stream = await streamPost(
        "/api/chat",
        { messages: history, context: sessionContext },
        { signal: ctrl.signal },
      );

      // Resolves only on the server's done event; an error event or a stream
      // that just stops rejects, so a failure never reads as a finished reply.
      await readEventStream(stream, (delta) => {
        updateAssistant((m) => ({ ...m, content: m.content + delta }));
      });
    } catch (err: unknown) {
      if ((err as { name?: string }).name === "AbortError") {
        // Stopped by user: keep any partial text as the reply; a reply with no
        // text yet is dropped rather than left as an empty bubble.
        updateAssistant((m) => (m.content.trim() ? { ...m, streaming: false } : null));
        setStreaming(false);
        return;
      }
      const errText = err instanceof Error && err.message ? err.message : "Connection failed";
      updateAssistant((m) => ({ ...m, error: errText, streaming: false }));
      setStreaming(false);
      return;
    }

    updateAssistant((m) => ({ ...m, streaming: false }));
    setStreaming(false);
  }, [streaming, open, activeId]);

  // Keep sendRef current so the chat-open/auto-send paths (which run from event
  // handlers and effects with stale closures) always call the latest send.
  useEffect(() => { sendRef.current = (text) => { void send(text); }; }, [send]);

  function stopStreaming() {
    abortRef.current?.abort();
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void send(input);
    }
  }

  const hasMessages = messages.length > 0;
  const sortedSessions = [...sessions].sort((a, b) => b.updatedAt - a.updatedAt);

  return (
    <>
      <style>{`
        @keyframes chat-cursor-blink { 0%,100%{opacity:1} 50%{opacity:0} }
        @keyframes ping { 75%,100%{transform:scale(2);opacity:0} }
        @media(prefers-reduced-motion:reduce){.chat-inner{animation:none!important}}
      `}</style>

      {/* ── FAB trigger ── */}
      <button
        ref={fabRef}
        aria-label={open ? "Close AI assistant" : "Open AI assistant"}
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        style={{
          position: "fixed", bottom: "24px", right: "24px", zIndex: 30,
          width: "48px", height: "48px", borderRadius: "50%",
          background: "linear-gradient(135deg,#0d9488,#0f766e)",
          border: "1px solid rgba(13,148,136,0.35)",
          boxShadow: "0 0 20px rgba(13,148,136,0.3),0 4px 16px rgba(0,0,0,0.5)",
          display: "flex", alignItems: "center", justifyContent: "center",
          cursor: "pointer", color: "#f4f4f5",
          transition: "box-shadow 0.2s,transform 0.15s",
        }}
        onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.transform = "scale(1.07)"; }}
        onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.transform = "scale(1)"; }}
      >
        {open ? <X style={{ width: "20px", height: "20px" }} /> : <MsgIcon className="h-5 w-5" />}
        {!open && unread > 0 && (
          <span style={{
            position: "absolute", top: "-4px", right: "-4px",
            minWidth: "18px", height: "18px", padding: "0 4px", borderRadius: "9px",
            background: "#ef4444", color: "#fff", fontSize: "11px", fontWeight: 600,
            display: "flex", alignItems: "center", justifyContent: "center",
          }}>
            {unread > 9 ? "9+" : unread}
          </span>
        )}
      </button>

      {/* ── Panel ── */}
      {open && (
        <div
          ref={panelRef}
          className="chat-inner"
          role="dialog"
          aria-label="Ask Vulngraph AI"
          style={{
            position: "fixed", top: 0, right: 0, bottom: 0, width: "460px",
            zIndex: 39, display: "flex", flexDirection: "column",
            background: "rgba(5,5,7,0.97)", backdropFilter: "blur(24px) saturate(160%)",
            borderLeft: "1px solid rgba(255,255,255,0.07)",
            boxShadow: "-8px 0 48px rgba(0,0,0,0.6)",
            animation: "slide-over-in 0.22s cubic-bezier(0.22,1,0.36,1) both",
          }}
        >
          {/* ── Header ── */}
          <div style={{
            display: "flex", alignItems: "center", justifyContent: "space-between",
            padding: "13px 14px", borderBottom: "1px solid rgba(255,255,255,0.07)",
            flexShrink: 0,
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              {/* live pulse */}
              <span style={{ position: "relative", display: "inline-flex", width: "8px", height: "8px" }}>
                <span style={{
                  position: "absolute", inset: 0, borderRadius: "50%",
                  background: "var(--graph-teal)", opacity: 0.4,
                  animation: "ping 2s cubic-bezier(0,0,0.2,1) infinite",
                }} />
                <span style={{ position: "relative", width: "8px", height: "8px", borderRadius: "50%", background: "var(--graph-teal)" }} />
              </span>
              <span style={{
                fontFamily: "var(--font-display)", fontSize: "13px", fontWeight: 600,
                letterSpacing: "-0.015em", color: "var(--graph-text)",
              }}>
                Vulngraph AI
              </span>
              {/* Session switcher button */}
              {sessions.length > 0 && (
                <button
                  onClick={() => setShowSessions((v) => !v)}
                  title="Conversation history"
                  style={{
                    fontSize: "11px", color: showSessions ? "var(--graph-teal)" : "var(--graph-text-3)",
                    background: showSessions ? "rgba(13,148,136,0.12)" : "transparent",
                    border: "1px solid " + (showSessions ? "rgba(13,148,136,0.3)" : "rgba(255,255,255,0.07)"),
                    borderRadius: "5px", padding: "2px 7px", cursor: "pointer",
                    transition: "all 0.15s",
                  }}
                >
                  {sessions.length} {sessions.length === 1 ? "chat" : "chats"}
                </button>
              )}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              {/* New chat */}
              <button
                onClick={startNewSession}
                title="New chat"
                style={{
                  display: "flex", alignItems: "center", justifyContent: "center",
                  width: "28px", height: "28px", borderRadius: "6px",
                  border: "1px solid rgba(255,255,255,0.07)", background: "transparent",
                  color: "var(--graph-text-3)", cursor: "pointer", transition: "all 0.15s",
                }}
                onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "rgba(13,148,136,0.12)"; (e.currentTarget as HTMLButtonElement).style.color = "var(--graph-teal)"; (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(13,148,136,0.3)"; }}
                onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "transparent"; (e.currentTarget as HTMLButtonElement).style.color = "var(--graph-text-3)"; (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(255,255,255,0.07)"; }}
              >
                <Plus style={{ width: "14px", height: "14px" }} />
              </button>
              {/* Close */}
              <button
                onClick={() => setOpen(false)}
                aria-label="Close"
                style={{
                  display: "flex", alignItems: "center", justifyContent: "center",
                  width: "28px", height: "28px", borderRadius: "6px",
                  border: "1px solid rgba(255,255,255,0.07)", background: "transparent",
                  color: "var(--graph-text-3)", cursor: "pointer", transition: "all 0.15s",
                }}
                onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "rgba(255,255,255,0.06)"; (e.currentTarget as HTMLButtonElement).style.color = "var(--graph-text)"; }}
                onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "transparent"; (e.currentTarget as HTMLButtonElement).style.color = "var(--graph-text-3)"; }}
              >
                <X style={{ width: "14px", height: "14px" }} />
              </button>
            </div>
          </div>

          {/* ── Session list (slide-down) ── */}
          {showSessions && (
            <div style={{
              borderBottom: "1px solid rgba(255,255,255,0.07)",
              background: "rgba(0,0,0,0.2)", flexShrink: 0,
              maxHeight: "220px", overflowY: "auto",
            }}>
              {sortedSessions.map((s) => (
                <div
                  key={s.id}
                  onClick={() => switchSession(s.id)}
                  style={{
                    display: "flex", alignItems: "center", justifyContent: "space-between",
                    padding: "8px 14px", cursor: "pointer",
                    background: s.id === activeId ? "rgba(13,148,136,0.1)" : "transparent",
                    borderLeft: s.id === activeId ? "2px solid var(--graph-teal)" : "2px solid transparent",
                    transition: "background 0.15s",
                  }}
                  onMouseEnter={(e) => { if (s.id !== activeId) (e.currentTarget as HTMLDivElement).style.background = "rgba(255,255,255,0.03)"; }}
                  onMouseLeave={(e) => { if (s.id !== activeId) (e.currentTarget as HTMLDivElement).style.background = "transparent"; }}
                >
                  <div style={{ minWidth: 0 }}>
                    <div style={{
                      fontSize: "12px", fontWeight: s.id === activeId ? 500 : 400,
                      color: s.id === activeId ? "var(--graph-text)" : "var(--graph-text-2)",
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                      maxWidth: "340px",
                    }}>
                      {s.title || "New chat"}
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--graph-text-3)", marginTop: "1px" }}>
                      {s.messages.filter((m) => m.role === "user").length} messages ·{" "}
                      {new Date(s.updatedAt).toLocaleDateString()}
                    </div>
                  </div>
                  <button
                    onClick={(e) => deleteSession(s.id, e)}
                    title="Delete"
                    style={{
                      flexShrink: 0, display: "flex", alignItems: "center", justifyContent: "center",
                      width: "22px", height: "22px", borderRadius: "4px",
                      border: "none", background: "transparent", color: "var(--graph-text-3)",
                      cursor: "pointer", opacity: 0, transition: "opacity 0.15s",
                    }}
                    onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.opacity = "1"; (e.currentTarget as HTMLButtonElement).style.color = "#ef4444"; }}
                    onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.opacity = "0"; }}
                  >
                    <X style={{ width: "11px", height: "11px" }} />
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* ── Messages ── */}
          <div style={{
            flex: 1, overflowY: "auto", padding: "16px",
            display: "flex", flexDirection: "column", gap: "14px",
          }}>
            {!hasMessages && (
              <div style={{
                display: "flex", flexDirection: "column", alignItems: "center",
                gap: "20px", marginTop: "32px", textAlign: "center",
              }}>
                <svg width="48" height="48" viewBox="0 0 48 48" fill="none" aria-hidden="true" style={{ opacity: 0.3 }}>
                  <circle cx="24" cy="12" r="5" stroke="var(--graph-teal)" strokeWidth="1.5" />
                  <circle cx="10" cy="36" r="5" stroke="var(--graph-text-3)" strokeWidth="1.5" />
                  <circle cx="38" cy="36" r="5" stroke="var(--graph-text-3)" strokeWidth="1.5" />
                  <line x1="24" y1="17" x2="10" y2="31" stroke="rgba(255,255,255,0.1)" strokeWidth="1" strokeDasharray="3 2" />
                  <line x1="24" y1="17" x2="38" y2="31" stroke="rgba(255,255,255,0.1)" strokeWidth="1" strokeDasharray="3 2" />
                </svg>
                <div>
                  <p style={{ fontSize: "13px", fontWeight: 500, color: "var(--graph-text-2)", marginBottom: "6px", fontFamily: "var(--font-display)" }}>
                    Ask anything about your security posture.
                  </p>
                  <p style={{ fontSize: "11px", color: "var(--graph-text-3)", lineHeight: 1.6 }}>
                    Queries your live asset graph, findings, and cloud APIs.
                  </p>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: "6px", width: "100%" }}>
                  {SUGGESTED.map((q) => (
                    <button
                      key={q}
                      onClick={() => void send(q)}
                      disabled={streaming}
                      style={{
                        padding: "8px 12px", borderRadius: "8px",
                        border: "1px solid rgba(13,148,136,0.2)",
                        background: "rgba(13,148,136,0.05)",
                        color: "var(--graph-text-2)", fontSize: "11px",
                        textAlign: "left", cursor: "pointer", lineHeight: 1.45,
                        transition: "all 0.15s",
                      }}
                      onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "rgba(13,148,136,0.12)"; (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(13,148,136,0.35)"; (e.currentTarget as HTMLButtonElement).style.color = "var(--graph-text)"; }}
                      onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.background = "rgba(13,148,136,0.05)"; (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(13,148,136,0.2)"; (e.currentTarget as HTMLButtonElement).style.color = "var(--graph-text-2)"; }}
                    >
                      {q}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {messages.map((msg) => {
              const isUser = msg.role === "user";
              return (
                <div key={msg.id} style={{ display: "flex", flexDirection: "column", alignItems: isUser ? "flex-end" : "flex-start", gap: "4px" }}>
                  <div style={{
                    maxWidth: "92%",
                    padding: isUser ? "8px 12px" : "10px 13px",
                    borderRadius: isUser ? "12px 12px 3px 12px" : "3px 12px 12px 12px",
                    background: isUser ? "rgba(63,63,70,0.85)" : "rgba(255,255,255,0.04)",
                    border: isUser ? "1px solid rgba(63,63,70,0.6)" : "1px solid rgba(255,255,255,0.07)",
                    fontSize: "13px", lineHeight: 1.6,
                    color: isUser ? "var(--graph-text)" : "var(--graph-text-2)",
                    wordBreak: "break-word",
                  }}>
                    {isUser ? (
                      <span style={{ whiteSpace: "pre-wrap" }}>{msg.content}</span>
                    ) : msg.streaming && msg.content.length === 0 ? (
                      <span style={{ display: "flex", gap: "3px", alignItems: "center", height: "16px" }}>
                        {[0,1,2].map((i) => (
                          <span key={i} style={{
                            width: "4px", height: "4px", borderRadius: "50%",
                            background: "var(--graph-teal)", opacity: 0.6,
                            animation: `chat-cursor-blink 1.2s ease-in-out ${i * 0.2}s infinite`,
                          }} />
                        ))}
                      </span>
                    ) : (
                      <>
                        {msg.content && renderMarkdown(msg.content)}
                        {msg.streaming && <Cursor />}
                        {msg.error && (
                          <div role="alert" style={{ color: "#f87171", marginTop: msg.content ? "6px" : 0 }}>
                            ⚠ {msg.error}
                          </div>
                        )}
                      </>
                    )}
                  </div>
                  {/* Copy button on completed assistant messages */}
                  {!isUser && !msg.streaming && !msg.error && msg.content && (
                    <CopyButton text={msg.content} />
                  )}
                </div>
              );
            })}
            <div ref={bottomRef} />
          </div>

          {/* ── Input ── */}
          <div style={{
            padding: "11px 13px 13px",
            borderTop: "1px solid rgba(255,255,255,0.07)",
            flexShrink: 0,
          }}>
            <div style={{ display: "flex", gap: "8px", alignItems: "flex-end" }}>
              <textarea
                ref={textareaRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                disabled={streaming}
                placeholder="Ask about your security posture…"
                rows={1}
                style={{
                  flex: 1, resize: "none", padding: "8px 10px", borderRadius: "8px",
                  border: "1px solid rgba(255,255,255,0.09)",
                  background: "rgba(255,255,255,0.04)", color: "var(--graph-text)",
                  fontSize: "13px", lineHeight: 1.5, fontFamily: "var(--font-body)",
                  outline: "none", transition: "border-color 0.15s",
                  maxHeight: "120px", overflowY: "auto", minHeight: "36px",
                }}
                onFocus={(e) => { e.currentTarget.style.borderColor = "rgba(13,148,136,0.5)"; }}
                onBlur={(e)  => { e.currentTarget.style.borderColor = "rgba(255,255,255,0.09)"; }}
                onInput={(e) => {
                  const el = e.currentTarget;
                  el.style.height = "auto";
                  el.style.height = `${Math.min(el.scrollHeight, 120)}px`;
                }}
              />
              {streaming ? (
                <button
                  onClick={stopStreaming}
                  title="Stop generating"
                  style={{
                    height: "36px", padding: "0 12px", borderRadius: "8px",
                    border: "1px solid rgba(239,68,68,0.35)",
                    background: "rgba(239,68,68,0.1)", color: "#ef4444",
                    fontSize: "12px", fontWeight: 600, cursor: "pointer",
                    display: "flex", alignItems: "center", gap: "5px",
                    flexShrink: 0, transition: "all 0.15s",
                  }}
                >
                  <Square style={{ width: "10px", height: "10px", fill: "#ef4444" }} />
                  Stop
                </button>
              ) : (
                <button
                  onClick={() => void send(input)}
                  disabled={!input.trim()}
                  style={{
                    height: "36px", padding: "0 14px", borderRadius: "8px",
                    border: "none",
                    background: !input.trim() ? "rgba(13,148,136,0.25)" : "linear-gradient(135deg,#0d9488,#0f766e)",
                    color: !input.trim() ? "rgba(255,255,255,0.3)" : "#f4f4f5",
                    fontSize: "12px", fontWeight: 600,
                    cursor: !input.trim() ? "not-allowed" : "pointer",
                    flexShrink: 0, fontFamily: "var(--font-body)", transition: "all 0.15s",
                  }}
                >
                  Ask
                </button>
              )}
            </div>
            <p style={{ fontSize: "11px", color: "var(--graph-text-3)", margin: "5px 0 0", lineHeight: 1.4 }}>
              Enter to send · Shift+Enter for newline
            </p>
          </div>
        </div>
      )}
    </>
  );
}
