import { http, HttpResponse } from "msw";
import { render, waitFor, act, screen, fireEvent } from "@testing-library/react";
import { beforeEach, expect, test } from "vitest";
import { server } from "../test/setup";
import { ChatPanel } from "./ChatPanel";

// Minimal SSE body: one text delta, then done. The panel reads a fetch stream.
function chatHandler() {
  return http.post("/api/chat", () =>
    HttpResponse.text('data: {"type":"text","text":"ok"}\n\ndata: [DONE]\n\n', {
      headers: { "Content-Type": "text/event-stream" },
    }),
  );
}

type StoredSession = { context?: string; messages: Array<{ role: string; content: string; error?: string }> };

function storedSessions(userId = "u1"): StoredSession[] {
  return JSON.parse(localStorage.getItem(`graph.chat.${userId}.sessions`) ?? "[]");
}

function openChat(message: string, context: string) {
  act(() => {
    window.dispatchEvent(new CustomEvent("graph:chat-open", { detail: { message, context } }));
  });
}

beforeEach(() => {
  localStorage.clear();
});

test("a different subject opens a fresh session; the same subject continues it", async () => {
  server.use(chatHandler());
  render(<ChatPanel userId="u1" />);

  // Ask about asset A — first session, bound to A's context.
  openChat("Investigate asset: web-lb. What is the risk?", "asset:web-lb");
  await waitFor(() => {
    const s = storedSessions();
    expect(s).toHaveLength(1);
    expect(s[0].context).toBe("asset:web-lb");
    expect(s[0].messages.filter((m) => m.role === "user")).toHaveLength(1);
  });

  // Verify finding B while A's chat is open — must NOT append to A's thread.
  openChat("Verify this finding against live state.", "finding:sg-open-to-world");
  await waitFor(() => {
    const s = storedSessions();
    expect(s).toHaveLength(2);
    expect(s[1].context).toBe("finding:sg-open-to-world");
    // A's thread untouched.
    expect(s[0].messages.filter((m) => m.role === "user")).toHaveLength(1);
  });

  // Same subject again — continues the existing thread, no third session.
  openChat("Anything else suspicious?", "finding:sg-open-to-world");
  await waitFor(() => {
    const s = storedSessions();
    expect(s).toHaveLength(2);
    expect(s[1].messages.filter((m) => m.role === "user")).toHaveLength(2);
  });
});

type ChatBody = { messages: Array<{ role: string; content: string }> };

// Each request gets the next scripted response; request bodies are recorded.
function scriptedChat(responses: Array<() => Response>) {
  const bodies: ChatBody[] = [];
  server.use(
    http.post("/api/chat", async ({ request }) => {
      bodies.push((await request.json()) as ChatBody);
      return responses[bodies.length - 1]();
    }),
  );
  return bodies;
}

const sse = (body: string) => () =>
  HttpResponse.text(body, { headers: { "Content-Type": "text/event-stream" } });

async function failedTurnIsShownButNotResent(failure: () => Response, shown: string) {
  const bodies = scriptedChat([failure, sse('data: {"type":"text","text":"fine"}\n\ndata: {"type":"done"}\n\n')]);
  render(<ChatPanel userId="u1" />);

  openChat("first question", "asset:a");
  await waitFor(() => {
    const msgs = storedSessions()[0]?.messages ?? [];
    expect(msgs).toHaveLength(2);
    expect(msgs[1].error).toContain(shown);
  });

  openChat("second question", "asset:a");
  await waitFor(() => expect(bodies).toHaveLength(2));
  expect(bodies[1].messages).toEqual([
    { role: "user", content: "first question" },
    { role: "user", content: "second question" },
  ]);
}

test("an error event marks the turn failed and keeps it out of history", async () => {
  await failedTurnIsShownButNotResent(
    sse('data: {"type":"text","text":"partial"}\n\ndata: {"type":"error","message":"the AI provider request failed"}\n\n'),
    "the AI provider request failed",
  );
});

test("a stream that ends without done is a failure, not an empty reply", async () => {
  await failedTurnIsShownButNotResent(sse(""), "cut off");
});

test("an error status before streaming shows the problem detail", async () => {
  await failedTurnIsShownButNotResent(
    () => HttpResponse.json({ status: 503, detail: "the AI provider request failed — try again" }, { status: 503 }),
    "try again",
  );
});

test("transcripts are stored per user, and another user's panel starts empty", async () => {
  server.use(chatHandler());
  const first = render(<ChatPanel userId="u1" />);
  openChat("what does u1 own?", "asset:a");
  await waitFor(() => expect(storedSessions("u1")[0]?.messages).toHaveLength(2));
  first.unmount();

  render(<ChatPanel userId="u2" />);
  act(() => {
    window.dispatchEvent(new CustomEvent("graph:chat-open", { detail: {} }));
  });
  await screen.findByPlaceholderText(/ask/i);
  expect(screen.queryByText("what does u1 own?")).not.toBeInTheDocument();
  expect(storedSessions("u1")[0].messages[0].content).toBe("what does u1 own?");
  expect(storedSessions("u2").flatMap((s) => s.messages)).toEqual([]);
});

test("clicking outside or pressing Escape closes the panel; clicking inside does not", async () => {
  server.use(chatHandler());
  render(
    <>
      <p>page content</p>
      <ChatPanel userId="u1" />
    </>,
  );

  act(() => {
    window.dispatchEvent(new CustomEvent("graph:chat-open", { detail: { message: "hi", context: "x" } }));
  });
  const dialog = await screen.findByRole("dialog", { name: "Ask Vulngraph AI" });

  fireEvent.mouseDown(dialog);
  expect(screen.getByRole("dialog")).toBeInTheDocument();

  fireEvent.mouseDown(screen.getByText("page content"));
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());

  act(() => {
    window.dispatchEvent(new CustomEvent("graph:chat-open", { detail: { message: "again", context: "y" } }));
  });
  await screen.findByRole("dialog");
  fireEvent.keyDown(document, { key: "Escape" });
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
});
