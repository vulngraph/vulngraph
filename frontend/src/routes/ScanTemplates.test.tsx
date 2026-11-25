import { screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

test("the AI Generate tab is offered to admins", async () => {
  server.use(meHandler("admin"));
  renderApp("/scans/templates");

  expect(await screen.findByRole("button", { name: /AI Generate/ })).toBeInTheDocument();
});

test("non-admins get the editor and test tabs but no AI Generate", async () => {
  server.use(meHandler("analyst"));
  renderApp("/scans/templates");

  expect(await screen.findByRole("button", { name: /Editor & Lint/ })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /Test against URL/ })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /AI Generate/ })).not.toBeInTheDocument();
});
