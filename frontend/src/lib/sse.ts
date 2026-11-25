// Reader for the streaming protocol POST /api/chat and
// POST /api/decisions/{id}/refine share (server side: pkg/sse):
// {"type":"text","text":…} deltas, then exactly one terminal
// {"type":"done"} or {"type":"error","message":…}. A stream that ends without
// a terminal event was cut (proxy timeout, server crash) and is a failure,
// never a short-but-complete reply.

export const STREAM_CUT_MESSAGE = "The response was cut off before it finished. Try again.";
const STREAM_ERROR_FALLBACK = "The AI request failed. Try again.";

type StreamEvent = { type?: string; text?: string; delta?: string; message?: string };

// readEventStream feeds every text delta to onText and resolves when the
// server signals completion. It rejects with an Error whose message is fit to
// show the user when the server reports a failure or the stream is cut.
export async function readEventStream(
  body: ReadableStream<Uint8Array>,
  onText: (text: string) => void,
): Promise<void> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  let data: string[] = [];

  // Returns true once a terminal success event has been seen.
  const dispatch = (): boolean => {
    if (data.length === 0) return false;
    const payload = data.join("\n").trim();
    data = [];
    if (payload === "[DONE]") return true;
    let evt: StreamEvent;
    try {
      evt = JSON.parse(payload) as StreamEvent;
    } catch {
      return false; // malformed event — skip it
    }
    if (evt.type === "done") return true;
    if (evt.type === "error") throw new Error(evt.message || STREAM_ERROR_FALLBACK);
    const delta = evt.text ?? evt.delta;
    if (delta) onText(delta);
    return false;
  };

  // Per the SSE spec an event is its data: lines up to a blank line.
  const feed = (line: string): boolean => {
    if (line.endsWith("\r")) line = line.slice(0, -1);
    if (line === "") return dispatch();
    if (line.startsWith("data:")) {
      const value = line.slice(5);
      data.push(value.startsWith(" ") ? value.slice(1) : value);
    }
    return false;
  };

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split("\n");
      buf = lines.pop() ?? "";
      for (const line of lines) {
        if (feed(line)) return;
      }
    }
    buf += decoder.decode();
    if (buf && feed(buf)) return;
    if (dispatch()) return;
  } finally {
    reader.cancel().catch(() => { /* already closed */ });
  }
  throw new Error(STREAM_CUT_MESSAGE);
}
