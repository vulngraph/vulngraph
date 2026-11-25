import type { ReactNode } from "react";
import { QueryClientProvider, type QueryClient } from "@tanstack/react-query";
import { RouterProvider, createMemoryHistory, createRouter } from "@tanstack/react-router";
import { render } from "@testing-library/react";
import { routeTree } from "../router";
import { createQueryClient } from "../lib/queryClient";

// testClient builds a QueryClient with the app's global error handling (401 →
// login) but no retries/cache leakage between tests.
export function testClient(): QueryClient {
  return createQueryClient({ defaultOptions: { queries: { retry: false } } });
}

// renderWithClient wraps a component in a fresh QueryClient (no retries/cache
// leakage between tests). Use for components that don't navigate.
export function renderWithClient(ui: ReactNode, client: QueryClient = testClient()) {
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

// renderApp mounts the real route tree at a path with in-memory history — for
// components that use <Link> or useParams, and for exercising routing/auth-gating
// end to end. The caller must mock GET /api/auth/me (AppShell gates on it).
export function renderApp(initialPath: string, client: QueryClient = testClient()) {
  const router = createRouter({
    routeTree,
    history: createMemoryHistory({ initialEntries: [initialPath] }),
  });
  const result = render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return { ...result, router, client };
}
