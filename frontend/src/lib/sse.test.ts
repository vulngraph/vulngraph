import { expect, test } from "vitest";
import { readEventStream, STREAM_CUT_MESSAGE } from "./sse";

function streamOf(...chunks: string[]): ReadableStream<Uint8Array> {
  const enc = new TextEncoder();
  return new ReadableStream({
    start(c) {
      for (const chunk of chunks) c.enqueue(enc.encode(chunk));
      c.close();
    },
  });
}

async function collect(...chunks: string[]): Promise<string> {
  let text = "";
  await readEventStream(streamOf(...chunks), (t) => { text += t; });
  return text;
}

test("text deltas then done resolves with the text", async () => {
  await expect(collect('data: {"type":"text","text":"Hel"}\n\n', 'data: {"type":"text","text":"lo"}\n\ndata: {"type":"done"}\n\n'))
    .resolves.toBe("Hello");
});

test("an event split across network chunks is reassembled", async () => {
  await expect(collect('data: {"type":"te', 'xt","text":"ok"}\n', '\ndata: {"type":"done"}\n\n')).resolves.toBe("ok");
});

test("[DONE] counts as completion", async () => {
  await expect(collect('data: {"type":"text","text":"ok"}\n\ndata: [DONE]\n\n')).resolves.toBe("ok");
});

test("an error event rejects with its message", async () => {
  await expect(collect('data: {"type":"text","text":"Hel"}\n\ndata: {"type":"error","message":"provider failed"}\n\n'))
    .rejects.toThrow("provider failed");
});

test("a stream that ends without done is a failure, even with text", async () => {
  await expect(collect('data: {"type":"text","text":"Hel"}\n\n')).rejects.toThrow(STREAM_CUT_MESSAGE);
});

test("an empty 200 body is a failure", async () => {
  await expect(collect()).rejects.toThrow(STREAM_CUT_MESSAGE);
});

test("multi-line data is joined per the SSE spec", async () => {
  await expect(collect('data: {"type":"text",\ndata: "text":"joined"}\n\ndata: {"type":"done"}')).resolves.toBe("joined");
});
