import { screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

test("the shown client configs include an Authorization header for the auth-gated endpoint", async () => {
  server.use(meHandler("viewer"));

  renderApp("/settings?sub=mcp");

  const snippets = await screen.findAllByText(/Authorization/);
  expect(snippets.length).toBeGreaterThan(0);
  expect(screen.getAllByText(/Bearer <your API key>/).length).toBeGreaterThan(0);
});

test("the tool count is not a literal claim of a total", async () => {
  server.use(meHandler("viewer"));

  renderApp("/settings?sub=mcp");

  await screen.findByText("Available tools");
  expect(screen.queryByText(/Available tools \(\d+\)/)).not.toBeInTheDocument();
});
