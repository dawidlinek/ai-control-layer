/**
 * MSW handlers: insights domain (repeated-task clusters, publish a skill).
 * Publishing adds the skill to the policy: it bumps the mock policy version (v8 -> v9), like the gateway would.
 */
import { http, HttpResponse, type HttpHandler } from "msw";
import { insightClusters } from "../db/insights";
import { policyStatus } from "../db/policy";
import { adminPath, problem, queryOf } from "./helpers";

interface PublishBody {
  skill_id?: string;
  model?: string;
  preset?: string;
  groups?: string[];
  reason?: string;
}

function bumpPolicyVersion(): string {
  const n = Number(/^v(\d+)$/.exec(policyStatus.version)?.[1] ?? 0);
  policyStatus.version = `v${n + 1}`;
  policyStatus.loaded_at = new Date().toISOString();
  policyStatus.source = "panel";
  return policyStatus.version;
}

export const insightsHandlers: HttpHandler[] = [
  http.get(adminPath("/insights/clusters"), ({ request }) => {
    const group = queryOf(request).get("group");
    return HttpResponse.json(insightClusters.items.filter((c) => (group ? c.group === group : true)));
  }),

  http.post(adminPath("/insights/clusters/:id/publish"), async ({ params, request }) => {
    const cluster = insightClusters.items.find((c) => c.id === params.id);
    if (!cluster) return problem(404, "cluster not found");
    if (cluster.status === "published") return problem(409, "this skill is already published");
    const body = (await request.json().catch(() => ({}))) as PublishBody;
    if (!body.skill_id || !body.model || !body.groups?.length || !body.reason?.trim()) {
      return problem(422, "skill_id, model, groups and reason are required");
    }
    const version = bumpPolicyVersion();
    cluster.status = "published";
    cluster.draft_skill = {
      ...cluster.draft_skill,
      name: body.skill_id,
      model: body.model,
      preset: body.preset ?? "strict",
      groups: body.groups,
      runs_30d: 0,
      published_version: version,
    };
    return HttpResponse.json(cluster);
  }),
];
