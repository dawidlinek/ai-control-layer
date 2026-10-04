/**
 * Tools & MCP: the rows of the table and the readers behind them.
 *
 * - MCP tools come from `GET /admin/v1/mcp/tools` (+ servers). The contract has no description, "who can use it",
 *   facts or approval history for a tool, so the demo details (ToolsMcp prototype) live in `DETAILS` below, keyed by
 *   tool id; unknown tools fall back to text built from the typed fields.
 * - OpenCode built-ins are not MCP tools and no admin endpoint lists them. They are checked per call through
 *   `/v1/decide` (policy `tools.yaml`, ids `opencode.<tool>`); `BUILTINS` mirrors that managed config, read-only.
 */
import type { ToolStatus } from "@/components/rogatka";
import type { McpServerInfo, McpToolInfo } from "@/lib/api/types";

export type { ToolStatus };
export type ToolRule = "allowed" | "needs approval" | "denied" | "—";

export interface ToolDetails {
  about?: string;
  facts?: Array<[string, string]>;
  who?: string[];
  approvedBy?: string;
  incident?: string;
}

export interface ToolRow {
  id: string;
  name: string;
  server: string;
  serverLabel: string;
  status: ToolStatus;
  rule: ToolRule;
  who: string[];
  labels: string[];
  /** Names the tool appears under in traffic events (`EventSummary.tool`). */
  eventNames: string[];
  kind: "mcp" | "builtin";
  mcp?: McpToolInfo;
  serverInfo?: McpServerInfo;
  details: ToolDetails;
}

const DETAILS: Record<string, ToolDetails> = {
  "docs-search.search_docs": {
    about: "Searches internal documentation. Hidden from every agent since its description changed after approval.",
    facts: [
      ["Inputs", "query, context (new)"],
      ["Approved by", "m.zielinska · 1 Oct"],
    ],
    who: ["developers", "research-bot"],
    approvedBy: "m.zielinska",
    incident: "inc-0057",
  },
  "github.search_code": {
    about: "Searches code in company GitHub repositories the person can already see.",
    facts: [
      ["Inputs", "query, repo"],
      ["Approved by", "k.wojcik · 20 Sep"],
    ],
    who: ["developers"],
    approvedBy: "k.wojcik",
  },
  "github.create_pr": {
    about: "Opens a pull request. Changes code others will review, so each call needs a confirmation.",
    facts: [
      ["Inputs", "repo, branch, title, body"],
      ["Approved by", "k.wojcik · 20 Sep"],
    ],
    who: ["developers"],
    approvedBy: "k.wojcik",
  },
  "bank.query": {
    about: "Read-only queries on client records. Only 4 columns are visible and personal data in results is pseudonymised.",
    facts: [
      ["Inputs", "sql (single SELECT)"],
      ["Approved by", "m.zielinska · 15 Sep"],
    ],
    who: ["credit-analysts", "research-bot"],
    approvedBy: "m.zielinska",
  },
  "mail.send": {
    about: "Sends an e-mail. Irreversible and leaves the company, so every call needs a person to approve it.",
    facts: [
      ["Inputs", "to, subject, body"],
      ["Allowed recipients", "@corp.example"],
    ],
    who: ["research-bot"],
    approvedBy: "k.wojcik",
  },
  "web.search": {
    about: "Searches the web. Results are untrusted, so they are scanned for injections before the agent reads them.",
    facts: [
      ["Inputs", "query"],
      ["Approved by", "k.wojcik · 12 Sep"],
    ],
    who: ["research-bot"],
    approvedBy: "k.wojcik",
  },
};

const BUILTIN_SERVER = "OpenCode";

function builtin(
  id: string,
  status: ToolStatus,
  rule: ToolRule,
  who: string[],
  labels: string[],
  details: ToolDetails,
  eventNames: string[],
): ToolRow {
  return {
    id,
    name: id.replace(/^opencode\./, ""),
    server: BUILTIN_SERVER,
    serverLabel: status === "denied" ? "OpenCode · local" : "OpenCode · local, checked by Rogatka",
    status,
    rule,
    who,
    labels,
    eventNames,
    kind: "builtin",
    details,
  };
}

export const BUILTINS: ToolRow[] = [
  builtin(
    "opencode.bash",
    "built-in",
    "allowed",
    ["developers", "credit-analysts"],
    ["exec", "filesystem", "network"],
    {
      about:
        "Runs shell commands on the developer’s machine. Every command is checked by Rogatka before it runs; dangerous ones are blocked or need approval.",
      facts: [
        ["Where", "OpenCode plugin → /v1/decide"],
        ["Blocked always", "rm -rf /, curl | sh, skip-permission flags"],
        ["Needs approval", "infra commands, git push after secrets"],
        ["Exceptions", "Anna Nowak denied (g-0415)"],
      ],
    },
    ["bash", "opencode.bash"],
  ),
  builtin(
    "opencode.read",
    "built-in",
    "allowed",
    ["developers", "credit-analysts"],
    ["reads untrusted", "touches sensitive", "filesystem"],
    {
      about: "Reads a file in the workspace. Repository content is untrusted and may hold secrets, so a read raises the session label.",
      facts: [
        ["Where", "OpenCode plugin → /v1/decide"],
        ["Scope", "workspace only"],
      ],
    },
    ["read", "opencode.read"],
  ),
  builtin(
    "opencode.edit",
    "built-in",
    "allowed",
    ["developers", "credit-analysts"],
    ["filesystem"],
    {
      about: "Edits a file in the workspace. Writes outside the workspace are blocked.",
      facts: [
        ["Where", "OpenCode plugin → /v1/decide"],
        ["Scope", "workspace only, write"],
      ],
    },
    ["edit", "opencode.edit"],
  ),
  builtin(
    "opencode.webfetch",
    "denied",
    "denied",
    [],
    ["network"],
    {
      about: "Fetching arbitrary web pages from the coding agent is switched off in the company OpenCode config.",
      facts: [
        ["Where", "managed OpenCode config"],
        ["Setting", "permission.webfetch: deny"],
        ["Can a user change it", "no"],
      ],
    },
    ["webfetch", "opencode.webfetch"],
  ),
];

const LABEL_TEXT: Record<string, string> = {
  reads_untrusted: "reads untrusted",
  touches_sensitive: "touches sensitive",
  external_egress: "external",
  irreversible: "irreversible",
};

export function statusOf(t: McpToolInfo, server: McpServerInfo | undefined): ToolStatus {
  if (server && !server.allowed) return "denied";
  switch (t.status) {
    case "pinned":
      return "approved";
    case "pending_approval":
      return "not approved";
    default:
      return "quarantined";
  }
}

export function ruleOf(tier: McpToolInfo["tier"]): ToolRule {
  switch (tier) {
    case "allow":
      return "allowed";
    case "confirm":
    case "must":
      return "needs approval";
    case "deny":
      return "denied";
    default:
      return "—";
  }
}

export function toRow(t: McpToolInfo, servers: readonly McpServerInfo[]): ToolRow {
  const serverInfo = servers.find((s) => s.id === t.server);
  const details = DETAILS[t.id] ?? {};
  return {
    id: t.id,
    name: t.name,
    server: t.server,
    serverLabel: `${t.server} · MCP`,
    status: statusOf(t, serverInfo),
    rule: ruleOf(t.tier),
    who: details.who ?? [],
    labels: t.labels.map((l) => LABEL_TEXT[l] ?? l),
    eventNames: Array.from(new Set([t.id, t.name, `${t.server}.${t.name}`])),
    kind: "mcp",
    mcp: t,
    serverInfo,
    details,
  };
}

export function aboutOf(r: ToolRow): string {
  if (r.details.about) return r.details.about;
  const base = `${r.name} is a tool on the ${r.server} MCP server.`;
  if (r.status === "quarantined") return `${base} It is hidden from every agent since its description changed after approval.`;
  if (r.status === "not approved") return `${base} Agents do not see it until an admin approves it.`;
  if (r.status === "denied") return `${base} The server is not allowed, so nobody can use it.`;
  return base;
}

/** "a41f0c9e" stays as is; long hashes become `9c1e…a07b`. */
export { shortHash } from "@/features/threats/artifact-copy";

export interface DiffLine {
  sign: "+" | "-" | " ";
  text: string;
}

/** Parse a unified-ish description diff: lines starting with "+" / "-" are added / removed, the rest is context. */
export function parseDiff(diff: string | null | undefined): DiffLine[] {
  if (!diff) return [];
  return diff
    .split("\n")
    .filter((l) => !l.startsWith("+++") && !l.startsWith("---") && !l.startsWith("@@"))
    .map((l) => {
      const c = l.charAt(0);
      if (c === "+" || c === "-") return { sign: c, text: l.slice(1) };
      return { sign: " " as const, text: c === " " ? l.slice(1) : l };
    });
}
