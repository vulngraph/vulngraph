import { Link, useParams } from "@tanstack/react-router";
import { useScan, useScanFindings } from "../lib/queries";
import type { ScanRunFinding } from "../lib/api";
import { BackLink, Card, ErrorNote, Loading, SeverityBadge, ScoreBadge } from "../components/ui";
import { elapsed as elapsedBase } from "../lib/format";

const elapsed = (started: string, finished?: string | null) => elapsedBase(started, finished, "long");

function TagChip({ tag }: { tag: string }) {
  const colors: Record<string, string> = {
    exposure: "border-amber/40 bg-amber/10 text-amber",
    misconfig: "border-orange-500/40 bg-orange-500/10 text-orange-400",
    kubernetes: "border-teal/40 bg-teal/10 text-teal",
    network: "border-blue-400/40 bg-blue-400/10 text-blue-400",
    cloud: "border-violet-400/40 bg-violet-400/10 text-violet-300",
    dns: "border-cyan-400/40 bg-cyan-400/10 text-cyan-400",
    storage: "border-emerald/40 bg-emerald/10 text-emerald",
    bucket: "border-emerald/40 bg-emerald/10 text-emerald",
    http: "border-indigo-400/40 bg-indigo-400/10 text-indigo-300",
    linux: "border-yellow-500/40 bg-yellow-500/10 text-yellow-400",
  };
  const cls = colors[tag] ?? "border-border-subtle bg-surface-2 text-text-3";
  return (
    <span className={`rounded border px-2 py-0.5 text-[11px] font-medium ${cls}`}>
      {tag}
    </span>
  );
}


export function ScanDetail() {
  const { id } = useParams({ from: "/scans/$id" });
  const { data, isLoading, isError, error } = useScan(id);
  // Fetch findings from the scan's time window — only for completed/cancelled/failed scans.
  const findingsQuery = useScanFindings(
    data && data.status !== "running" ? id : ""
  );
  const findings: ScanRunFinding[] = findingsQuery.data?.findings ?? [];

  return (
    <div className="space-y-4">
      <BackLink to="/scans" label="All scans" />

      {isLoading && <Loading />}
      {isError && <ErrorNote message={(error as Error).message} />}

      {data && (
        <>
          {/* Header */}
          <div className="flex items-start justify-between">
            <div>
              <h1 className="flex items-center gap-2 font-display text-lg text-text">
                {data.status === "running" && (
                  <span className="h-2 w-2 animate-pulse rounded-full bg-teal" />
                )}
                Scan #{id.slice(-8)}
              </h1>
              <p className="mt-0.5 text-[11px] text-text-3">
                {data.scanner_name ?? "nuclei"} ·{" "}
                Started {new Date(data.started_at).toLocaleString()}
                {data.finished_at && (
                  <span className="ml-2">· {elapsed(data.started_at, data.finished_at)}</span>
                )}
                {data.status === "running" && (
                  <span className="ml-2 text-teal">{elapsed(data.started_at)} elapsed</span>
                )}
              </p>
            </div>
          </div>

          {/* Stats row */}
          <div className="grid grid-cols-4 gap-3">
            <Card>
              <div className="text-[11px] uppercase text-text-3">Targets</div>
              <div className="mt-1 font-display text-2xl text-text">{data.target_count}</div>
              <div className="text-[11px] text-text-3">URLs / IPs scanned</div>
            </Card>
            <Card>
              <div className="text-[11px] uppercase text-text-3">Findings</div>
              <div className={`mt-1 font-display text-2xl ${data.finding_count > 0 ? "text-amber" : "text-text"}`}>
                {data.finding_count}
              </div>
              <div className="text-[11px] text-text-3">vulnerabilities matched</div>
            </Card>
            <Card>
              <div className="text-[11px] uppercase text-text-3">Templates fired</div>
              <div className="mt-1 font-display text-2xl text-text">
                {data.template_count ?? "—"}
              </div>
              <div className="text-[11px] text-text-3">distinct templates matched</div>
            </Card>
            <Card>
              <div className="text-[11px] uppercase text-text-3">Duration</div>
              <div className="mt-1 font-display text-2xl text-text">
                {data.finished_at ? elapsed(data.started_at, data.finished_at) : "—"}
              </div>
              <div className="text-[11px] text-text-3">
                {data.status === "running" ? "still running" : "total"}
              </div>
            </Card>
          </div>

          {data.error && (
            <div className="rounded border border-red/30 bg-red/10 px-3 py-2 text-[11px] text-red">
              {data.error}
            </div>
          )}

          {/* Template tags */}
          {data.template_tags && data.template_tags.length > 0 && (
            <Card>
              <div className="mb-2 text-[11px] uppercase tracking-wide text-text-3">
                Template categories used
              </div>
              <div className="flex flex-wrap gap-1.5">
                {data.template_tags.map((t) => <TagChip key={t} tag={t} />)}
              </div>
              <p className="mt-2 text-[11px] text-text-3">
                Tags drive which nuclei templates ran — e.g. &ldquo;exposure&rdquo; covers
                open paths, &ldquo;misconfig&rdquo; covers default creds and debug endpoints.{" "}
                <Link to="/scans/templates" className="text-teal hover:underline">
                  Write a custom template →
                </Link>
              </p>
            </Card>
          )}

          {/* Running banner */}
          {data.status === "running" && (
            <div className="rounded-lg border border-teal/30 bg-teal/10 px-4 py-3 text-[11px] text-text-2">
              <strong className="text-text">Nuclei is actively scanning</strong> — running templates
              against {data.target_count} endpoints. Large scans can take up to an hour.
              Findings appear in the{" "}
              <Link to="/investigate/findings" className="text-teal hover:underline">Findings tab</Link>{" "}
              as they&apos;re detected.
            </div>
          )}

          {/* Target URLs */}
          {data.target_urls && data.target_urls.length > 0 && (
            <Card>
              <div className="mb-2 text-[11px] uppercase tracking-wide text-text-3">
                Scanned targets ({data.target_urls.length})
              </div>
              <div className="max-h-48 overflow-y-auto rounded border border-border-subtle/40 bg-surface-2 p-2">
                {data.target_urls.slice(0, 100).map((url) => (
                  <div
                    key={url}
                    className="border-b border-border-subtle/20 py-0.5 font-mono text-[11px] text-text-2 last:border-0"
                  >
                    {url}
                  </div>
                ))}
                {data.target_urls.length > 100 && (
                  <div className="pt-1 text-[11px] text-text-3">
                    +{data.target_urls.length - 100} more
                  </div>
                )}
              </div>
            </Card>
          )}

          {/* Findings from this scan */}
          {data.status !== "running" && (
            <div>
              <div className="mb-2 font-display text-sm text-text">
                Findings from this scan
                {findings.length > 0 && (
                  <span className="ml-2 text-[11px] text-amber">({findings.length})</span>
                )}
              </div>
              {findingsQuery.isLoading && <Loading />}
              {findings.length > 0 ? (
                <div className="glass overflow-hidden rounded-lg">
                  {findings.map((f) => (
                    <Link
                      key={f.id}
                      to="/investigate/findings/$id"
                      params={{ id: f.id }}
                      className="flex items-center gap-3 border-b border-border-subtle/40 px-4 py-2.5 last:border-0 hover:bg-surface/50"
                    >
                      <SeverityBadge severity={f.severity} />
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-xs text-text">{f.title}</div>
                        <div className="truncate text-[11px] text-text-3">
                          {f.resource_id
                            ? <span className="font-mono">{f.resource_id}</span>
                            : <span className="italic">{f.check_id}</span>}
                        </div>
                      </div>
                      {f.score > 0 && <ScoreBadge score={f.score} band={f.score_band} />}
                    </Link>
                  ))}
                  {findings.length < (data?.finding_count ?? 0) && (
                    <div className="px-4 py-2.5 text-[11px] text-text-3">
                      Showing {findings.length} of {data.finding_count} — open{" "}
                      <Link to="/investigate/findings" className="text-teal hover:underline">Findings</Link> for the rest
                    </div>
                  )}
                </div>
              ) : !findingsQuery.isLoading && data.status === "completed" ? (
                <div className="rounded-lg border border-border-subtle bg-surface px-4 py-3 text-[11px] text-text-2">
                  <strong className="text-text">No vulnerabilities found</strong> — nuclei ran
                  against {data.target_count} endpoints and found no matching patterns.
                </div>
              ) : data.status === "cancelled" ? (
                <div className="rounded-lg border border-border-subtle bg-surface px-4 py-3 text-[11px] text-text-2">
                  <strong className="text-text">Scan was cancelled</strong> — stopped before
                  completing all {data.target_count} targets. Any findings up to that point appear
                  in the <Link to="/investigate/findings" className="text-teal hover:underline">Findings tab</Link>.
                </div>
              ) : data.status === "failed" ? (
                <div className="rounded-lg border border-red/30 bg-red/10 px-4 py-3 text-[11px] text-text-2">
                  <strong className="text-text">Scan failed</strong>
                  {data.error ? ` — ${data.error}` : " — check worker logs for details."}.
                </div>
              ) : null}
            </div>
          )}
        </>
      )}
    </div>
  );
}
