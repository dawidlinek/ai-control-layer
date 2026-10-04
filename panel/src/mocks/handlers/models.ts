/** MSW handlers: models domain (connectors, kill switch, models). */
import { http, HttpResponse, type HttpHandler } from "msw";
import { connectors, models } from "../db/models";
import { policyStatus } from "../db/policy";
import type { components } from "@/lib/api/schema";
import { adminPath, problem } from "./helpers";

type KillSwitchRequest = components["schemas"]["KillSwitchRequest"];

/** In the demo, flipping a kill switch is a policy change: bump the live version (v8 -> v9) like a publish would. */
function bumpPolicyVersion(): void {
  const n = Number(/^v(\d+)$/.exec(policyStatus.version)?.[1] ?? NaN);
  if (!Number.isFinite(n)) return;
  policyStatus.version = `v${n + 1}`;
  policyStatus.source = "panel";
  policyStatus.loaded_at = new Date().toISOString();
}

export const modelsHandlers: HttpHandler[] = [
  http.get(adminPath("/connectors"), () => HttpResponse.json(connectors.items)),

  http.post(adminPath("/connectors/:id/kill-switch"), async ({ params, request }) => {
    const c = connectors.items.find((x) => x.id === params.id);
    if (!c) return problem(404, "connector not found");
    const body = (await request.json()) as Partial<KillSwitchRequest>;
    if (typeof body.engaged !== "boolean" || !body.reason?.trim()) return problem(422, "engaged and reason are required");
    if (body.engaged !== c.kill_switch) {
      c.kill_switch = body.engaged;
      c.healthy = body.engaged ? null : true;
      c.last_error = body.engaged ? `kill switch: ${body.reason.trim()}` : null;
      bumpPolicyVersion();
    }
    return HttpResponse.json(c);
  }),

  http.get(adminPath("/models"), () => HttpResponse.json(models.items)),
];
