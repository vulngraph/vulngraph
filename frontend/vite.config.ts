import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Builds into web/dist, which the Go binary embeds via go:embed and serves.
export default defineConfig(({ mode }) => {
  // Dev-only API proxy target. Defaults to the local Go server, so a plain
  // `bun run dev` never touches a remote. To develop the frontend against a
  // deployed backend, set GRAPH_API_TARGET (as an env var or in a gitignored
  // frontend/.env.local — see .env.example), e.g.:
  //   GRAPH_API_TARGET=https://graph.example.com bun run dev
  const env = loadEnv(mode, process.cwd(), "");
  const apiTarget = env.GRAPH_API_TARGET || "http://localhost:8080";
  const isRemote = /^https:/i.test(apiTarget);
  // DEV-ONLY: inject a deployed instance's session cookie so it skips the
  // oauth2-proxy redirect. Get the value from DevTools at the target origin:
  //   Application → Cookies → graph_session
  // Set GRAPH_SESSION_COOKIE in frontend/.env.local (gitignored).
  const sessionCookie = env.GRAPH_SESSION_COOKIE;
  // DEV-ONLY: inject X-Auth-Request-Email header so the backend auto-creates
  // a session (requires oauth2Proxy: true on the backend). Use with kubectl
  // port-forward: the header bypasses nginx/oauth2-proxy entirely since
  // you're talking directly to the pod. Zero cookie setup.
  //   kubectl -n <namespace> port-forward deploy/graph-serve 8080:8080 &
  //   GRAPH_DEV_EMAIL=you@example.com bun run dev
  const devEmail = env.GRAPH_DEV_EMAIL;

  return {
    plugins: [react(), tailwindcss()],
    build: { outDir: "../web/dist", emptyOutDir: true },
    server: {
      proxy: {
        "/api": {
          target: apiTarget,
          changeOrigin: isRemote,
          secure: isRemote,
          // DEV-ONLY, remote target only: rewrite the backend's session cookie so
          // it sticks on http://localhost (strips Secure, downgrades SameSite).
          // This weakens cookie protections and MUST never run against a real
          // origin — it is skipped entirely for the local default target.
          configure: (proxy) => {
            proxy.on("proxyReq", (proxyReq) => {
              // Inject X-Auth-Request-Email so the backend auto-creates a session
              // (port-forward workflow — talks directly to the pod, no nginx).
              if (devEmail) proxyReq.setHeader("X-Auth-Request-Email", devEmail);
              // Inject a prod session cookie when targeting a remote HTTPS origin
              // protected by oauth2-proxy (avoids the Google OAuth redirect).
              if (sessionCookie && isRemote) {
                proxyReq.setHeader("Cookie", `graph_session=${sessionCookie}`);
              }
            });
            // Rewrite Set-Cookie so it sticks on http://localhost.
            // DEV-ONLY — never runs against the local default target.
            proxy.on("proxyRes", (proxyRes) => {
              const cookies = proxyRes.headers["set-cookie"];
              if (cookies) {
                proxyRes.headers["set-cookie"] = cookies.map((c) =>
                  c.replace(/;\s*Secure/gi, "").replace(/;\s*SameSite=\w+/gi, "; SameSite=Lax"),
                );
              }
            });
          },
        },
      },
    },
    test: {
      environment: "jsdom",
      globals: true,
      setupFiles: ["./src/test/setup.ts"],
      // Above the 5s async-util timeout in setup.ts, so a slow lookup fails
      // with its own message rather than as a test timeout.
      testTimeout: 15000,
      // forks isolation prevents MSW handler cross-contamination when test files
      // run in the same worker — without this, handlers from one file can
      // intercept requests in another, causing non-deterministic failures.
      pool: "forks",
    },
  };
});
