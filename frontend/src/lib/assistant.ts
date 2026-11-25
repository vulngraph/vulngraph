// openAssistant — the single way to hand a subject off to the AI assistant.
//
// Every "Ask AI" affordance across the app funnels through here so the chat is
// seeded consistently. It dispatches the `graph:chat-open` CustomEvent that
// ChatPanel listens for: `message` seeds the first question, and the optional
// `context` binds the chat session to this subject across follow-up turns.
//
// Build the message from a subject + supporting facts + a question, e.g.
//   openAssistant({
//     subject: "Investigate asset: web-lb",
//     facts: ["type: load_balancer", "risk score: 72", "internet-exposed"],
//     question: "What is the risk and what attack paths lead to it?",
//   })
// →  message: "Investigate asset: web-lb · type: load_balancer · risk score: 72
//              · internet-exposed. What is the risk and what attack paths lead to it?"
export function openAssistant(opts: {
  subject?: string;
  facts?: string[];
  question: string;
  context?: string;
}): void {
  const lead = [opts.subject, ...(opts.facts ?? [])].filter(Boolean).join(" · ");
  const message = lead ? `${lead}. ${opts.question}` : opts.question;
  // The context identifies the subject so ChatPanel can give each subject its
  // own thread (fresh session on a new subject, continue on the same one).
  // Default it to the subject line — callers only override for richer bindings.
  const context = opts.context ?? opts.subject;
  window.dispatchEvent(
    new CustomEvent("graph:chat-open", {
      detail: context ? { message, context } : { message },
    }),
  );
}
