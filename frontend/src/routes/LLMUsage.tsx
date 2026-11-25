import { useLLMUsage, useIsAdmin, useMe } from "../lib/queries";
import type { LLMUsageSummary } from "../lib/api";
import { Empty, ErrorNote, Loading } from "../components/ui";

const usd = (v: number) => `$${v.toFixed(2)}`;
const count = (v: number) => v.toLocaleString();

// BudgetLine shows spend against one monthly cap; a cap of 0 is unlimited.
function BudgetLine({ label, spent, budget, gates }: { label: string; spent: number; budget: number; gates: string }) {
  const pct = budget > 0 ? Math.min(100, (spent / budget) * 100) : 0;
  return (
    <div className="glass rounded-xl px-4 py-3">
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-xs text-text-2">{label}</span>
        <span className="font-mono text-sm text-text">
          {usd(spent)} <span className="text-text-3">/ {budget > 0 ? usd(budget) : "unlimited"}</span>
        </span>
      </div>
      {budget > 0 && (
        <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-surface-2" role="progressbar" aria-label={label} aria-valuenow={Math.round(pct)}>
          <div className={pct >= 100 ? "h-full bg-red" : "h-full bg-teal"} style={{ width: `${pct}%` }} />
        </div>
      )}
      <div className="mt-1 text-[11px] text-text-3">{gates}</div>
    </div>
  );
}

function UsageBody({ data }: { data: LLMUsageSummary }) {
  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <BudgetLine
          label="All LLM spend"
          spent={data.spent_usd}
          budget={data.monthly_budget_usd}
          gates="Caps background work (reasoning, adjudication, CT triage, agents). LLM_MONTHLY_BUDGET_USD."
        />
        <BudgetLine
          label="Interactive spend"
          spent={data.interactive_spent_usd}
          budget={data.interactive_budget_usd}
          gates="Caps chat, NL query, refine and template generation only. LLM_INTERACTIVE_MONTHLY_BUDGET_USD."
        />
      </div>
      {data.unrecorded_usd > 0 && (
        <ErrorNote message={`${usd(data.unrecorded_usd)} of spend could not be written to the ledger; it still counts against the budgets.`} />
      )}
      {data.default_price_used_for_models.length > 0 && (
        <p className="text-[11px] text-text-3">
          Priced at the high fallback rate (add to LLM_PRICES for accurate costs):{" "}
          <span className="font-mono">{data.default_price_used_for_models.join(", ")}</span>
        </p>
      )}
      {data.lines.length === 0 ? (
        <Empty message="No LLM calls recorded this month." />
      ) : (
        <div className="glass overflow-x-auto rounded-xl">
          <table className="w-full text-xs">
            <thead className="text-left text-[11px] uppercase tracking-wider text-text-3">
              <tr>
                <th className="px-4 py-2 font-medium">Purpose</th>
                <th className="px-4 py-2 font-medium">Model</th>
                <th className="px-4 py-2 text-right font-medium">Calls</th>
                <th className="px-4 py-2 text-right font-medium">Input</th>
                <th className="px-4 py-2 text-right font-medium">Output</th>
                <th className="px-4 py-2 text-right font-medium">Cached</th>
                <th className="px-4 py-2 text-right font-medium">Est. cost</th>
              </tr>
            </thead>
            <tbody>
              {data.lines.map((l) => (
                <tr key={`${l.purpose}/${l.model}`} className="border-t border-border-subtle/40">
                  <td className="px-4 py-2 text-text">
                    {l.purpose}
                    {l.interactive && <span className="ml-1.5 text-[10px] text-text-3">interactive</span>}
                  </td>
                  <td className="px-4 py-2 font-mono text-text-2">{l.model}</td>
                  <td className="px-4 py-2 text-right font-mono text-text-2">
                    {count(l.calls)}
                    {l.unreported_calls > 0 && (
                      <span className="ml-1 text-amber" title="Calls with no provider-reported usage, charged at their worst case">
                        ({count(l.unreported_calls)} est.)
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-right font-mono text-text-2">{count(l.input_tokens)}</td>
                  <td className="px-4 py-2 text-right font-mono text-text-2">{count(l.output_tokens)}</td>
                  <td className="px-4 py-2 text-right font-mono text-text-2">{count(l.cache_read_tokens + l.cache_write_tokens)}</td>
                  <td className="px-4 py-2 text-right font-mono text-text">{usd(l.cost_usd)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// Rendered as the LLM Usage section inside Settings (admin-only: cost data).
export function LLMUsageSection() {
  const { isLoading: meLoading } = useMe();
  const isAdmin = useIsAdmin();
  const { data, isLoading, isError, error } = useLLMUsage(isAdmin);

  if (meLoading) return <Loading />;
  if (!isAdmin) return <Empty message="Admin access required to view LLM usage." />;
  return (
    <div>
      <h2 className="mb-1 font-display text-sm text-text">LLM usage{data && <span className="ml-2 font-mono text-[11px] text-text-3">{data.month}</span>}</h2>
      <p className="mb-3 text-[11px] text-text-3">Estimated from the configured price table, not an invoice. Months are UTC.</p>
      {isLoading ? <Loading /> : isError ? <ErrorNote message={(error as Error).message} /> : data && <UsageBody data={data} />}
    </div>
  );
}
