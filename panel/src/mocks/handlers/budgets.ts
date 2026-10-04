/** MSW handlers: budgets domain (budget tree, breakers, breaker reset). */
import { http, HttpResponse, type HttpHandler } from "msw";
import { budgetNodes } from "../db/budgets";
import type { BreakerState, BudgetTree } from "../db/types";
import { adminPath, problem } from "./helpers";

export const budgetsHandlers: HttpHandler[] = [
  http.get(adminPath("/budgets"), () => {
    const tree: BudgetTree = { generated_at: new Date().toISOString(), nodes: budgetNodes.items };
    return HttpResponse.json(tree);
  }),

  // Static path before the parametrised reset route.
  http.get(adminPath("/budgets/breakers"), () =>
    HttpResponse.json(budgetNodes.items.map((n) => n.breaker).filter((b): b is BreakerState => !!b)),
  ),

  http.post(adminPath("/budgets/breakers/:id/reset"), ({ params }) => {
    const id = decodeURIComponent(String(params.id));
    const node = budgetNodes.items.find((n) => n.breaker?.id === id);
    if (!node?.breaker) return problem(404, "breaker not found");
    if (node.breaker.state === "closed") return problem(409, "breaker is already closed");
    node.breaker = { id, state: "closed", opened_at: null, cooldown_until: null, reason: null };
    return HttpResponse.json(node.breaker);
  }),
];
