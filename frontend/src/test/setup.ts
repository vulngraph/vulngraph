import "@testing-library/jest-dom/vitest";
import { configure } from "@testing-library/react";
import { afterAll, afterEach, beforeAll } from "vitest";
import { setupServer } from "msw/node";

// findBy*/waitFor give up after 1s by default, which a route that lazy-loads
// and fetches through MSW can exceed on a loaded CI runner.
configure({ asyncUtilTimeout: 5000 });

// jsdom has no scrollTo; TanStack Router's scroll restoration calls it on every
// navigation. Stub it so router-driven tests don't log noise.
window.scrollTo = () => {};

// jsdom has no scrollIntoView; the Explore cypher workbench scrolls results into
// view after a query runs. Stub it so those tests don't throw.
Element.prototype.scrollIntoView = () => {};

// jsdom has no ResizeObserver; ReactFlow (the GraphView) requires it. A no-op
// observer lets the graph mount in tests (it can't measure, but it renders).
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver =
  globalThis.ResizeObserver ?? (ResizeObserverStub as unknown as typeof ResizeObserver);

// jsdom has no IntersectionObserver; the Settings sidebar uses it for active
// section tracking. A no-op stub lets Settings mount without errors.
class IntersectionObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.IntersectionObserver =
  globalThis.IntersectionObserver ?? (IntersectionObserverStub as unknown as typeof IntersectionObserver);

import { defaultHandlers } from "./handlers";

// Shared MSW server — default handlers cover endpoints every page hits on mount.
// Individual tests add their own handlers via server.use() before rendering.
export const server = setupServer(...defaultHandlers);

// AbortController comes from jsdom, but fetch/Request come from Node (undici),
// which rejects a signal from another realm ("Expected signal to be an instance
// of AbortSignal"). Strip the signal before it reaches Node's fetch and honour
// it here instead, so aborts still reject with the caller's AbortError.
function withForeignSignal(inner: typeof fetch): typeof fetch {
  return (input, init) => {
    const signal = init?.signal;
    if (!signal) return inner(input, init);
    const rest = { ...init, signal: undefined };
    return new Promise<Response>((resolve, reject) => {
      if (signal.aborted) return reject(signal.reason);
      signal.addEventListener("abort", () => reject(signal.reason), { once: true });
      inner(input, rest).then(resolve, reject);
    });
  };
}

let mswFetch: typeof fetch;
beforeAll(() => {
  server.listen({ onUnhandledRequest: "error" });
  mswFetch = globalThis.fetch;
  globalThis.fetch = withForeignSignal(mswFetch);
});
afterEach(() => server.resetHandlers());
afterAll(() => {
  globalThis.fetch = mswFetch;
  server.close();
});
