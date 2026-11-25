import { http, HttpResponse } from "msw";
import { screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

const summary = {
  month: "2026-10",
  since: "2026-10-01T00:00:00Z",
  until: "2026-11-01T00:00:00Z",
  monthly_budget_usd: 100,
  interactive_budget_usd: 0,
  spent_usd: 42.5,
  interactive_spent_usd: 2.5,
  background_spent_usd: 40,
  unrecorded_usd: 0,
  default_price_used_for_models: ["llama3"],
  lines: [
    {
      purpose: "reason",
      model: "claude-opus-4-8",
      interactive: false,
      calls: 1200,
      unreported_calls: 3,
      failed_calls: 0,
      input_tokens: 1000,
      output_tokens: 500,
      cache_read_tokens: 10,
      cache_write_tokens: 5,
      cost_usd: 40,
    },
  ],
};

test("admins see spend against each monthly budget", async () => {
  server.use(meHandler("admin"), http.get("/api/llm/usage", () => HttpResponse.json(summary)));
  renderApp("/settings?sub=llmusage");

  expect(await screen.findByText("All LLM spend")).toBeInTheDocument();
  expect(screen.getByText("$42.50")).toBeInTheDocument();
  expect(screen.getByText("/ $100.00")).toBeInTheDocument();
  expect(screen.getByText("/ unlimited")).toBeInTheDocument();
  expect(screen.getByText("(3 est.)")).toBeInTheDocument();
  expect(screen.getByText("llama3")).toBeInTheDocument();
});

test("non-admins are not shown LLM usage", async () => {
  server.use(meHandler("viewer"));
  renderApp("/settings?sub=llmusage");
  expect(await screen.findByText("Admin access required to view LLM usage.")).toBeInTheDocument();
  expect(screen.queryByRole("link", { name: /LLM Usage/ })).not.toBeInTheDocument();
});
