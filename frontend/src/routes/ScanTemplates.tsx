import { useState, useEffect, useRef } from "react";
import { useValidateTemplate, useTestTemplate, useGenerateTemplate, useIsAdmin } from "../lib/queries";
import { Button, ErrorNote, Loading, PageHeader } from "../components/ui";

const STARTER_TEMPLATE = `id: my-custom-check
info:
  name: My Custom Security Check
  author: security-graph
  severity: medium
  description: Describe what this checks for
  tags: exposure,misconfig

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "something-to-match"
        part: body
`;

const TEMPLATE_EXAMPLES = [
  {
    label: "S3 public bucket",
    yaml: `id: s3-public-read
info:
  name: S3 Bucket Public Read Check
  author: security-graph
  severity: high
  tags: s3,cloud,exposure

http:
  - method: GET
    path:
      - "{{BaseURL}}/?list-type=2"
    matchers:
      - type: word
        words: ["ListBucketResult"]
`,
  },
  {
    label: "Open redirect",
    yaml: `id: open-redirect-check
info:
  name: Open Redirect Detection
  author: security-graph
  severity: medium
  tags: redirect,exposure

http:
  - method: GET
    path:
      - "{{BaseURL}}/?url=https://evil.example.com"
      - "{{BaseURL}}/?redirect=https://evil.example.com"
    redirects: true
    max-redirects: 2
    matchers:
      - type: regex
        regex: ["Location: https://evil\\.example\\.com"]
        part: header
`,
  },
  {
    label: "K8s dashboard",
    yaml: `id: k8s-dashboard-exposed
info:
  name: Kubernetes Dashboard Exposed
  author: security-graph
  severity: critical
  tags: kubernetes,exposure

http:
  - method: GET
    path:
      - "{{BaseURL}}/#/login"
    matchers:
      - type: word
        words: ["kubernetes-dashboard"]
`,
  },
];

function ValidationBadge({ valid, errorCount }: { valid: boolean; errorCount: number }) {
  if (valid) {
    return (
      <span className="inline-flex items-center gap-1 text-[11px] text-emerald">
        <span className="text-base">✓</span> Valid template
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 text-[11px] text-red">
      <span className="text-base">✗</span> {errorCount} error{errorCount !== 1 ? "s" : ""}
    </span>
  );
}

export function ScanTemplates() {
  const [yaml, setYaml] = useState(STARTER_TEMPLATE);
  const [targetURL, setTargetURL] = useState("");
  const [description, setDescription] = useState("");
  const [tab, setTab] = useState<"editor" | "test" | "generate">("editor");
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const validate = useValidateTemplate();
  const test = useTestTemplate();
  const generate = useGenerateTemplate();
  // Generation (LLM budget) and linting (a nuclei engine per call) are
  // admin-only server-side.
  const isAdmin = useIsAdmin();
  const tabs = isAdmin ? (["editor", "test", "generate"] as const) : (["editor", "test"] as const);

  // Debounced validation on yaml change
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      if (isAdmin && yaml.trim()) validate.mutate(yaml);
    }, 600);
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current); };
  }, [yaml, isAdmin]);

  function handleGenerate() {
    if (!description.trim()) return;
    generate.mutate(description, {
      onSuccess: (data) => {
        if (data.yaml) {
          setYaml(data.yaml);
          setTab("editor");
        }
      },
    });
  }

  const validation = validate.data;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Template Editor"
        subtitle={`Write, lint, and test nuclei templates.${isAdmin ? " AI-generate from a description." : ""}`}
      />

      {/* Tab nav */}
      <div className="flex gap-4 border-b border-border-subtle">
        {tabs.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`pb-2 text-[11px] font-medium capitalize transition-colors ${
              tab === t
                ? "border-b-2 border-teal text-teal"
                : "text-text-3 hover:text-text-2"
            }`}
          >
            {t === "editor" ? "📝 Editor & Lint" : t === "test" ? "🚀 Test against URL" : "✨ AI Generate"}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-[1fr_280px] gap-4">
        {/* Left: YAML editor */}
        <div className="space-y-3">
          {tab === "generate" ? (
            <div className="space-y-3">
              <div>
                <label className="mb-1 block text-[11px] text-text-2">
                  Describe what you want to detect
                </label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="e.g. Check if an S3 bucket allows public read access via ACL&#10;e.g. Detect if the Kubernetes dashboard is exposed without authentication&#10;e.g. Find open redirect vulnerabilities via common redirect parameters"
                  rows={5}
                  className="w-full resize-none rounded border border-border-subtle bg-surface px-3 py-2 text-[11px] text-text placeholder-text-3 focus:border-teal focus:outline-none"
                />
              </div>
              <Button
                onClick={handleGenerate}
                disabled={generate.isPending || !description.trim()}
                variant="primary"
              >
                {generate.isPending ? (
                  <span className="flex items-center gap-2">
                    <span className="h-3 w-3 animate-spin rounded-full border border-t-transparent border-white" />
                    Generating… (self-corrects up to 3×)
                  </span>
                ) : "Generate template with AI"}
              </Button>
              {generate.isError && (
                <ErrorNote message={(generate.error as Error).message} />
              )}
              {generate.data && (
                <div className={`rounded border px-3 py-2 text-[11px] ${
                  generate.data.validation.valid
                    ? "border-emerald/30 bg-emerald/10 text-emerald"
                    : "border-amber/30 bg-amber/10 text-amber"
                }`}>
                  {generate.data.validation.valid ? (
                    <>
                      ✓ Valid template generated
                      {generate.data.attempts > 1 && (
                        <span className="ml-2 text-emerald/70">
                          (self-corrected in {generate.data.attempts} attempts)
                        </span>
                      )}
                      {" — switched to editor tab."}
                    </>
                  ) : (
                    <>
                      ⚠ Generated but still has issues after {generate.data.attempts} attempt{generate.data.attempts !== 1 ? "s" : ""} — review in editor.
                    </>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-[11px] text-text-2">Nuclei template YAML</label>
                {validate.isPending && (
                  <span className="text-[11px] text-text-3">linting…</span>
                )}
                {validation && !validate.isPending && (
                  <ValidationBadge
                    valid={validation.valid}
                    errorCount={validation.errors?.length ?? 0}
                  />
                )}
              </div>
              <textarea
                value={yaml}
                onChange={(e) => setYaml(e.target.value)}
                rows={24}
                spellCheck={false}
                className="w-full resize-none rounded border border-border-subtle bg-surface-2 px-3 py-2 font-mono text-[11px] text-text placeholder-text-3 focus:border-teal focus:outline-none"
                style={{ tabSize: 2 }}
              />

              {/* Validation errors */}
              {validation && !validation.valid && validation.errors && (
                <div className="rounded border border-red/30 bg-red/10 p-2">
                  {validation.errors.map((e: { line?: number; message?: string }, i: number) => (
                    <div key={i} className="flex items-start gap-2 text-[11px] text-red">
                      {e.line ? <span className="font-mono text-[11px]">L{e.line}</span> : null}
                      <span>{e.message ?? "Unknown error"}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Template info when valid */}
              {validation?.valid && validation.info && (
                <div className="rounded border border-emerald/30 bg-emerald/10 p-3 text-[11px]">
                  <div className="flex items-center gap-2 text-emerald">
                    <span className="font-mono font-medium">{validation.info.id}</span>
                    <span className="rounded border border-emerald/40 px-1.5 py-0.5 text-[11px]">
                      {validation.info.severity}
                    </span>
                    {(validation.info.protocols as string[] | undefined)?.map((p: string) => (
                      <span key={p} className="text-[11px] text-emerald/70">{p}</span>
                    ))}
                  </div>
                  <div className="mt-0.5 text-emerald/80">{validation.info.name}</div>
                  {validation.info.tags && validation.info.tags.length > 0 && (
                    <div className="mt-1 flex gap-1">
                      {(validation.info.tags as string[]).map((t: string) => (
                        <span key={t} className="rounded bg-emerald/20 px-1.5 py-0.5 text-[11px] text-emerald">
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Test form */}
          {tab === "test" && (
            <div className="space-y-3">
              <div>
                <label className="mb-1 block text-[11px] text-text-2">Target URL</label>
                <input
                  type="url"
                  value={targetURL}
                  onChange={(e) => setTargetURL(e.target.value)}
                  placeholder="https://example.com"
                  className="w-full rounded border border-border-subtle bg-surface px-3 py-2 text-[11px] text-text placeholder-text-3 focus:border-teal focus:outline-none"
                />
              </div>
              <Button
                variant="primary"
                disabled={test.isPending || !targetURL.trim() || !yaml.trim()}
                onClick={() => test.mutate({ yaml, target: targetURL })}
              >
                {test.isPending ? <><Loading />Running…</> : "Run template against URL"}
              </Button>
              {test.isError && <ErrorNote message={(test.error as Error).message} />}
              {test.data && (
                <div className="space-y-2">
                  <div className="text-[11px] text-text-2">
                    {test.data.count > 0 ? (
                      <span className="text-amber">{test.data.count} match{test.data.count !== 1 ? "es" : ""}</span>
                    ) : (
                      <span className="text-text-3">No matches found</span>
                    )} against <span className="font-mono">{test.data.target}</span>
                  </div>
                  {test.data.results.map((r, i) => (
                    <div key={i} className="rounded border border-amber/30 bg-amber/10 p-2 text-[11px]">
                      <div className="font-medium text-amber">{r.name}</div>
                      <div className="text-text-3">
                        {r.template_id} · {r.severity} · {r.matched_url}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right: example library */}
        <div className="space-y-3">
          <div className="text-[11px] uppercase tracking-wide text-text-3">Example templates</div>
          {TEMPLATE_EXAMPLES.map((ex) => (
            <button
              key={ex.label}
              onClick={() => { setYaml(ex.yaml); setTab("editor"); }}
              className="w-full rounded border border-border-subtle bg-surface px-3 py-2 text-left text-[11px] text-text-2 hover:border-teal hover:bg-surface-2 hover:text-text"
            >
              {ex.label}
            </button>
          ))}

          <div className="mt-4 rounded border border-border-subtle/40 bg-surface-2 p-3 text-[11px] text-text-3">
            <div className="mb-1 font-medium text-text-2">How it works</div>
            <ol className="list-inside list-decimal space-y-1">
              <li>Write or generate a template</li>
              <li>Lint checks the structure and loads it through nuclei</li>
              <li>Test fires it against one URL</li>
            </ol>
            <div className="mt-2">Templates are not saved. Full scans use the pinned nuclei-templates release, chosen by asset type or a scan profile's tags.</div>
            <div className="mt-2">
              <a
                href="https://docs.projectdiscovery.io/templates/introduction"
                target="_blank"
                rel="noopener noreferrer"
                className="text-teal hover:underline"
              >
                Nuclei template docs →
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
