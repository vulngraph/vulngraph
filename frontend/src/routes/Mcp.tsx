import { useState } from "react";
import { Card } from "../components/ui";
import { copyText } from "../lib/clipboard";

// Mirrors the tools registered in internal/app/mcp (mcp.go's NewHandler plus
// tools_cloud.go, tools_suppress.go, tools_alert.go, tools_investigate.go) —
// keep in lockstep with those files when a tool is added, removed, or reworded.
const MCP_TOOLS = [
  { name: "graph_query",          description: "Answer a natural-language question about the asset graph: translates it to a query and runs it, returning matching assets + relationships." },
  { name: "get_asset_context",    description: "Asset details plus its blast radius (reachable assets), for triaging an asset's vulnerabilities." },
  { name: "list_findings",        description: "List security findings, optionally filtered by source and severity." },
  { name: "get_finding_context",  description: "Full context for one finding: the reasoning decision (action + rationale), blast radius, provenance, score-factor breakdown, and peer findings on the same resource." },
  { name: "get_compliance",       description: "Current CIS control coverage." },
  { name: "get_graph_stats",      description: "Node counts (assets, IAM roles, repos) in the security knowledge graph and whether the graph engine is ready." },
  { name: "suppress_finding",     description: "Suppress a low-urgency finding with a reason and an expiry (1–30 days), after which it is triaged again. Refused for critical, must-fix, urgent or unscored findings. Admin only." },
  {
    name: "execute_action",
    description: "Execute a cloud remediation action on a read_write connector (sg_rule_remove, iam_key_disable, ec2_stop/start, s3_block_public, gcp_sa_key_disable, gcp_firewall_remove, azure_nsg_rule_remove). Admin only. Every real execution needs an approval_token minted by a different admin (POST /api/executor/approvals); without one only dry_run=true is accepted.",
  },
  { name: "run_cypher",           description: "Execute a read-only Ladybug Cypher query against the security asset graph — precise graph pattern queries (privilege escalation paths, supply-chain exposure, blast radius, DNS chains)." },
  { name: "investigate_resource", description: "Full investigation context for a resource (asset ID, IP, EC2 instance ID, ARN, or hostname): asset details, findings with signal scores, blast radius, graph neighborhood, and a summary. Use this first for a GuardDuty alert or any security alert." },
  { name: "get_alert_context",   description: "Graph context for a SIEM alert: pass any mix of IPs, ARNs (incl. assumed-role sessions), instance IDs, hostnames, emails, or namespace/name; each resolves to assets with a match type and confidence, plus exposure, blast radius, open findings (must-fix called out) and privilege-escalation evidence. Unresolved identifiers are reported, and known=false means not measured." },
  { name: "search_assets",       description: "Search for assets by IP, hostname, instance ID, ARN, resource type, or free text — returns matching assets with risk scores and finding counts." },
  { name: "live_aws_describe",    description: "Query AWS live in real-time using a connector's credentials (describe_instance, describe_security_group, list_role_policies, list_attached_role_policies, describe_bucket). Returns fresh data, not cached scan results." },
  { name: "get_cloudtrail_events",description: "Recent CloudTrail API events for a resource or principal — what AWS API calls were made in the last N hours, including source_ip and principal_arn. Used for GuardDuty alert investigation." },
  { name: "list_connectors",      description: "List every connector (any provider, enabled or disabled) with its ID, type, enabled flag and sync status." },
];

export function MCPSection() {
  const [copied, setCopied] = useState<string | null>(null);
  const origin = window.location.origin;
  const mcpUrl = `${origin}/api/mcp`;

  function copy(text: string, key: string) {
    void copyText(text).then((ok) => {
      if (!ok) return;
      setCopied(key);
      setTimeout(() => setCopied(null), 1800);
    });
  }

  const claudeConfig = JSON.stringify({
    mcpServers: {
      graph: {
        command: "npx",
        args: ["-y", "mcp-remote", mcpUrl, "--header", "Authorization:Bearer <your API key>"],
        env: {},
      },
    },
  }, null, 2);

  const cursorConfig = JSON.stringify({
    mcpServers: {
      graph: {
        url: mcpUrl,
        type: "http",
        headers: {
          Authorization: "Bearer <your API key>",
        },
      },
    },
  }, null, 2);

  return (
    <div>
      <h2 className="mb-3 font-display text-sm text-text">
        MCP — connect LLMs to your data
      </h2>
      <Card>
        <p className="mb-4 text-[11px] leading-relaxed text-text-2">
          Vulngraph exposes a{" "}
          <span className="font-mono text-teal">JSON-RPC 2.0</span> Model Context Protocol server at{" "}
          <button
            onClick={() => copy(mcpUrl, "url")}
            className="font-mono text-teal hover:underline"
          >
            {mcpUrl}
          </button>
          <span className="ml-1 inline-block w-14 text-[11px] text-emerald">{copied === "url" ? "copied" : ""}</span>
          . Connect Claude, Cursor, or any MCP-compatible client to query your security data in plain language. The
          endpoint requires authentication — mint an API key under Settings → API Keys and substitute it for{" "}
          <span className="font-mono text-teal">&lt;your API key&gt;</span> below.
        </p>

        <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-2">
          <ConfigSnippet
            label="Claude Desktop (macOS: ~/Library/Application Support/Claude/claude_desktop_config.json — Windows: %APPDATA%\Claude\claude_desktop_config.json)"
            value={claudeConfig}
            copied={copied === "claude"}
            onCopy={() => copy(claudeConfig, "claude")}
          />
          <ConfigSnippet
            label="Cursor (.cursor/mcp.json)"
            value={cursorConfig}
            copied={copied === "cursor"}
            onCopy={() => copy(cursorConfig, "cursor")}
          />
        </div>

        <div className="border-t border-border-subtle pt-3">
          <div className="mb-2 text-[11px] uppercase tracking-wide text-text-3">Available tools</div>
          <div className="grid grid-cols-1 gap-1.5 md:grid-cols-2">
            {MCP_TOOLS.map((t) => (
              <div key={t.name} className="rounded border border-border-subtle bg-bg/40 px-2.5 py-1.5">
                <div className="font-mono text-[11px] text-teal">{t.name}</div>
                <div className="mt-0.5 text-[11px] leading-relaxed text-text-3">{t.description}</div>
              </div>
            ))}
          </div>
        </div>
      </Card>
    </div>
  );
}

function ConfigSnippet({ label, value, copied, onCopy }: { label: string; value: string; copied: boolean; onCopy: () => void }) {
  return (
    <div>
      <div className="mb-1 flex items-center justify-between gap-2">
        <span className="text-[11px] text-text-3">{label}</span>
        <button onClick={onCopy} className="w-10 shrink-0 text-right text-[11px] text-teal hover:underline">
          {copied ? "✓" : "copy"}
        </button>
      </div>
      <pre className="overflow-auto rounded border border-border-subtle bg-bg p-2 font-mono text-[11px] leading-relaxed text-text-2">{value}</pre>
    </div>
  );
}
