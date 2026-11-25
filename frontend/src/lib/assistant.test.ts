import { expect, test, vi } from "vitest";
import { openAssistant } from "./assistant";

test("openAssistant builds a message from subject + facts + question", () => {
  const spy = vi.fn();
  window.addEventListener("graph:chat-open", spy);

  openAssistant({
    subject: "Investigate asset: web-lb",
    facts: ["type: load_balancer", "risk score: 72", "internet-exposed"],
    question: "What is the risk?",
  });

  const detail = (spy.mock.calls[0][0] as CustomEvent).detail;
  expect(detail.message).toBe(
    "Investigate asset: web-lb · type: load_balancer · risk score: 72 · internet-exposed. What is the risk?",
  );
  // Without an explicit context the subject becomes the thread binding.
  expect(detail.context).toBe("Investigate asset: web-lb");
  window.removeEventListener("graph:chat-open", spy);
});

test("openAssistant passes context through and works with question-only", () => {
  const spy = vi.fn();
  window.addEventListener("graph:chat-open", spy);

  openAssistant({ question: "What is the root cause?", context: "Finding: X; severity: high" });

  const detail = (spy.mock.calls[0][0] as CustomEvent).detail;
  expect(detail.message).toBe("What is the root cause?");
  expect(detail.context).toBe("Finding: X; severity: high");
  window.removeEventListener("graph:chat-open", spy);
});
