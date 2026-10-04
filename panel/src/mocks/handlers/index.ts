/**
 * All mock handlers. One file per domain (events, incidents, approvals, users, grants, policy, models, tools,
 * feed, budgets, overview, insights): screen agents edit only their own domain's `db/<domain>.ts` and
 * `handlers/<domain>.ts`, never this file.
 */
import type { HttpHandler } from "msw";
import { approvalsHandlers } from "./approvals";
import { budgetsHandlers } from "./budgets";
import { eventsHandlers } from "./events";
import { feedHandlers } from "./feed";
import { grantsHandlers } from "./grants";
import { incidentsHandlers } from "./incidents";
import { insightsHandlers } from "./insights";
import { modelsHandlers } from "./models";
import { overviewHandlers } from "./overview";
import { policyHandlers } from "./policy";
import { toolsHandlers } from "./tools";
import { usersHandlers } from "./users";

// Importing the db modules registers their reset functions (see ../db/registry.ts).
import "../db/approvals";
import "../db/budgets";
import "../db/events";
import "../db/feed";
import "../db/grants";
import "../db/incidents";
import "../db/insights";
import "../db/models";
import "../db/overview";
import "../db/policy";
import "../db/tools";
import "../db/users";

export const handlers: HttpHandler[] = [
  ...eventsHandlers,
  ...incidentsHandlers,
  ...approvalsHandlers,
  ...usersHandlers,
  ...grantsHandlers,
  ...policyHandlers,
  ...modelsHandlers,
  ...toolsHandlers,
  ...feedHandlers,
  ...budgetsHandlers,
  ...overviewHandlers,
  ...insightsHandlers,
];
