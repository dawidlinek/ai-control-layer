/**
 * Mock data: approvals (from docs/ux/design-reference/ApprovalsQueue.dc.html).
 * 3 waiting (apr-0193, apr-0194, apr-0195) and 1 already decided (apr-0190). Secrets are masked.
 */
import { demoClock, inMinutes, inSeconds, minutesAgo } from "../time";
import { seeded } from "./registry";
import type { Approval } from "./types";

function seed(): Approval[] {
  return [
    {
      id: "apr-0193",
      status: "pending",
      approver_scope: "admin",
      created_at: demoClock("14:12:05"),
      expires_at: inSeconds(9 * 60 + 40),
      requested_by: "j.kowalski",
      session_id: "s_9e21",
      trace_id: "tr_9b21e4",
      tool: "bash",
      server: "opencode",
      arguments_preview: "git push origin feature/loan-calc",
      reason: "Rule of Two: untrusted content, a secret and an external target in one session",
      rule_ids: ["SEC-FLOW-01"],
      risk_score: 0.78,
      decided_by: null,
      decided_at: null,
      elevation: null,
    },
    {
      id: "apr-0194",
      status: "pending",
      approver_scope: "user",
      created_at: demoClock("14:09:30"),
      expires_at: inSeconds(6 * 60 + 12),
      requested_by: "research-bot",
      session_id: "s_77c1",
      trace_id: "tr_8f2a11",
      tool: "email.send",
      server: "mail",
      arguments_preview: 'email.send(to="contact@partner-leasing.pl")',
      reason: "irreversible tool; recipient outside @corp.example",
      rule_ids: ["AUTHZ-TOOL-01"],
      risk_score: 0.58,
      decided_by: null,
      decided_at: null,
      elevation: null,
    },
    {
      id: "apr-0195",
      status: "pending",
      approver_scope: "admin",
      created_at: demoClock("14:11:40"),
      expires_at: inSeconds(7 * 60 + 55),
      requested_by: "p.zielinski",
      session_id: "s_7d02",
      trace_id: "tr_8e9b70",
      tool: "bash",
      server: "opencode",
      arguments_preview: "terraform apply -auto-approve",
      reason: "irreversible command (infrastructure)",
      rule_ids: ["AUTHZ-TOOL-01"],
      risk_score: 0.46,
      decided_by: null,
      decided_at: null,
      elevation: null,
    },
    {
      id: "apr-0190",
      status: "approved",
      approver_scope: "admin",
      created_at: demoClock("13:20:02"),
      expires_at: minutesAgo(35),
      requested_by: "p.zielinski",
      session_id: "s_7d02",
      trace_id: "tr_7a1c02",
      tool: "fs.write",
      server: "opencode",
      arguments_preview: "fs.write(path=../shared/notes.md)",
      reason: "write outside the workspace",
      rule_ids: ["AUTHZ-TOOL-01"],
      risk_score: 0.33,
      decided_by: "k.wojcik",
      decided_at: minutesAgo(15),
      elevation: { scope: "tool:opencode.write", until: inMinutes(0) },
    },
  ];
}

export const approvals = seeded(seed);
