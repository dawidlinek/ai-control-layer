/**
 * Mock data: approvals (from docs/ux/design-reference/ApprovalsQueue.dc.html).
 * 3 waiting (apr-0193, apr-0194, apr-0195) and 3 decided in the last 24 h (apr-0190, apr-0188, apr-0185).
 * Secrets are masked (‹SECRET:api_key›), personal data only as placeholders.
 *
 * The contract's `Approval` has no structured "what it wants to do" / "why it was held" fields, so the demo
 * puts them into the two free-text fields it does have, in a small line format the panel reads with
 * tolerant readers (`src/features/approvals/readers.ts`). A real gateway that sends a one-line
 * `arguments_preview` and a one-line `reason` still renders correctly.
 *
 * `arguments_preview`:  line 1 = the exact command / call; then `Key: value` detail lines; then a blank line,
 *                       an optional `--- <preview title>` line and preview lines (first char = `+`, `-`, `~` or space).
 * `reason`:             line 1 = short reason ("Rule of Two"); then one line per source:
 *                       `<flag> | <what happened> | <ISO time or "now"> | <trace id (optional)>`.
 */
import { demoClock, inSeconds } from "../time";
import { seeded } from "./registry";
import type { Approval } from "./types";

const lines = (...l: string[]) => l.join("\n");

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
      arguments_preview: lines(
        "git push origin feature/loan-calc",
        "Remote: github.com/jk-priv/loan-calc",
        "Changes: 3 commits · 2 files",
        "Secret scan: 1 API key (masked below)",
        "Client: OpenCode · developers",
        "Device: dev-jk-01",
        "Data class: confidential",
        "",
        "--- config/settings.py",
        ' DATABASE_URL = env("DATABASE_URL")',
        '-SCORING_API_KEY = env("SCORING_API_KEY")',
        '+SCORING_API_KEY = "‹SECRET:api_key›"',
        "+SCORING_TIMEOUT_S = 30",
      ),
      reason: lines(
        "Rule of Two",
        `untrusted | read README.md from the cloned repo | ${demoClock("14:10:41")} | tr_9a8810`,
        `sensitive | read config/settings.py with an API key | ${demoClock("14:11:20")} | tr_9b1f07`,
        "external | push to a remote outside the company | now | tr_9b21e4",
      ),
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
      arguments_preview: lines(
        'email.send(to="contact@partner-leasing.pl")',
        "To: contact@partner-leasing.pl",
        "Subject: Q3 SME lending summary",
        "Client: agent for Anna Nowak",
        "Data class: internal",
        "",
        "--- Message (personal data masked)",
        " Dzień dobry,",
        " w załączeniu podsumowanie dla <PERSON_1> …",
        " Pozdrawiam, research-bot",
      ),
      reason: lines(
        "irreversible tool",
        `sensitive | read client records from core-banking | ${demoClock("14:08:02")} | tr_8f1d40`,
        "external | recipient outside the allowed domain | now | tr_8f2a11",
      ),
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
      arguments_preview: lines(
        "terraform apply -auto-approve",
        "Workspace: staging",
        "Plan: 2 to add · 1 to change · 0 to destroy",
        "Client: OpenCode · developers",
        "Device: dev-pz-01",
        "Data class: internal",
        "",
        "--- terraform plan (summary)",
        "+aws_s3_bucket.reports_archive",
        "+aws_s3_bucket_policy.reports_archive",
        "~aws_iam_role.ci_runner (tags)",
      ),
      reason: "irreversible command",
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
      expires_at: demoClock("13:30:02"),
      requested_by: "p.zielinski",
      session_id: "s_7d02",
      trace_id: "tr_7a1c02",
      tool: "fs.write",
      server: "opencode",
      arguments_preview: lines("fs.write /shared/templates/report.docx", "Client: OpenCode · developers", "Device: dev-pz-01"),
      reason: "write outside workspace",
      rule_ids: ["AUTHZ-TOOL-01"],
      risk_score: 0.33,
      decided_by: "k.wojcik",
      decided_at: demoClock("13:22:40"),
      elevation: { scope: "tool:opencode.fs.write", until: demoClock("13:37:40") },
    },
    {
      id: "apr-0188",
      status: "denied",
      approver_scope: "user",
      created_at: demoClock("12:02:15"),
      expires_at: demoClock("12:12:15"),
      requested_by: "research-bot",
      session_id: "s_77c1",
      trace_id: "tr_6e0a51",
      tool: "http.post",
      server: "web",
      arguments_preview: lines("http.post https://paste.example/api", "Client: agent for Anna Nowak"),
      reason: "external sink",
      rule_ids: ["SEC-EXFIL-01"],
      risk_score: 0.71,
      decided_by: "m.zielinska",
      decided_at: demoClock("12:04:02"),
      elevation: null,
    },
    {
      id: "apr-0185",
      status: "expired",
      approver_scope: "user",
      created_at: demoClock("10:47:00"),
      expires_at: demoClock("10:57:00"),
      requested_by: "research-bot",
      session_id: "s_6b20",
      trace_id: "tr_5d7e19",
      tool: "email.send",
      server: "mail",
      arguments_preview: lines('email.send(to="<EMAIL_1>")', "Client: agent for Anna Nowak"),
      reason: "irreversible tool",
      rule_ids: ["AUTHZ-TOOL-01"],
      risk_score: 0.52,
      decided_by: null,
      decided_at: demoClock("10:57:00"),
      elevation: null,
    },
  ];
}

export const approvals = seeded(seed);
