import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  redirect,
} from "@tanstack/react-router";
import { AppShell } from "./components/AppShell";
import { Home } from "./routes/Home";
import { Findings } from "./routes/Findings";
import { FindingDetail } from "./routes/FindingDetail";
import { Assets } from "./routes/Assets";
import { AssetDetail } from "./routes/AssetDetail";
import { Decisions } from "./routes/Decisions";
import { Compliance } from "./routes/Compliance";
import { Explore } from "./routes/Explore";
import { Settings } from "./routes/Settings";
import { Investigate } from "./routes/Investigate";
import { Cost } from "./routes/Cost";
import { Identity } from "./routes/Identity";
import { DSPM } from "./routes/DSPM";
import { DomainMonitor } from "./routes/DomainMonitor";
import { Drift } from "./routes/Drift";

const rootRoute = createRootRoute({
  component: () => (
    <AppShell>
      <Outlet />
    </AppShell>
  ),
});

function route<const P extends string>(
  path: P,
  component: () => React.ReactNode,
  parent: { id: string } = rootRoute,
) {
  return createRoute({ getParentRoute: () => parent as typeof rootRoute, path, component });
}

// Redirect bare "/" to "/home".
const rootRedirect = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  beforeLoad: () => { throw redirect({ to: "/home" }); },
});

// /investigate/home is not a real route — redirect to the top-level Home page.
const investigateHomeRedirect = createRoute({
  getParentRoute: () => rootRoute,
  path: "/investigate/home",
  beforeLoad: () => { throw redirect({ to: "/home" }); },
});

// Short top-level aliases for pages that live under /investigate.
const findingsRedirect = createRoute({
  getParentRoute: () => rootRoute,
  path: "/findings",
  beforeLoad: () => { throw redirect({ to: "/investigate/findings" }); },
});
const assetsRedirect = createRoute({
  getParentRoute: () => rootRoute,
  path: "/assets",
  beforeLoad: () => { throw redirect({ to: "/investigate/assets" }); },
});
const exploreRedirect = createRoute({
  getParentRoute: () => rootRoute,
  path: "/explore",
  beforeLoad: () => { throw redirect({ to: "/investigate/graph" }); },
});
const connectorsRedirect = createRoute({
  getParentRoute: () => rootRoute,
  path: "/connectors",
  beforeLoad: () => { throw redirect({ to: "/settings" }); },
});
// Investigate sub-paths that alias a Findings view — carry the view along so
// the link lands on the matching tab, not the default.
function findingsViewRedirect(oldPath: string, view: string) {
  return createRoute({
    getParentRoute: () => rootRoute,
    path: oldPath,
    beforeLoad: () => {
      throw redirect({ to: "/investigate/findings", search: { view } as Record<string, string> });
    },
  });
}
const signalsRedirect = findingsViewRedirect("/investigate/signals", "signals");
const hygieneRedirect = findingsViewRedirect("/investigate/hygiene", "hygiene");
const timelineRedirect = findingsViewRedirect("/investigate/timeline", "timeline");

// Investigate layout route — renders sub-nav + Outlet for child routes.
const investigateRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/investigate",
  component: Investigate,
  beforeLoad: ({ location }) => {
    if (location.pathname === "/investigate" || location.pathname === "/investigate/") {
      throw redirect({ to: "/investigate/graph" });
    }
  },
});

function investigateChild<const P extends string>(path: P, component: () => React.ReactNode) {
  return createRoute({ getParentRoute: () => investigateRoute, path, component });
}


export const routeTree = rootRoute.addChildren([
  rootRedirect,
  investigateHomeRedirect,
  findingsRedirect,
  assetsRedirect,
  exploreRedirect,
  connectorsRedirect,
  signalsRedirect,
  hygieneRedirect,
  timelineRedirect,

  route("/home", Home),
  route("/decisions", Decisions),
  route("/compliance", Compliance),
  route("/settings", Settings),


  investigateRoute.addChildren([
    investigateChild("/graph", Explore),
    investigateChild("/findings", Findings),
    investigateChild("/findings/$id", FindingDetail),
    investigateChild("/drift", Drift),
    investigateChild("/assets", Assets),
    investigateChild("/assets/$id", AssetDetail),
    investigateChild("/identity", Identity),
    investigateChild("/dspm", DSPM),
    investigateChild("/domains", DomainMonitor),
    investigateChild("/cost", Cost),
  ]),
]);

export const router = createRouter({ routeTree });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
