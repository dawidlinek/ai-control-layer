/**
 * Mock data: users, groups (People / Groups tabs of Users & groups). Personas from HANDOFF section 6.
 * The Users screen agent extends this with effective access, activity, API keys and group settings.
 */
import { daysAgo, minutesAgo } from "../time";
import { seeded } from "./registry";
import type { Group, User } from "./types";

type UserSeed = {
  username: string;
  name: string;
  groups: string[];
  preset: User["preset"];
  kind?: User["kind"];
  roles?: string[];
  stats: { requests: number; tokens_in: number; tokens_out: number; blocks: number; usd: number; last: string };
};

const USERS: UserSeed[] = [
  { username: "k.wojcik", name: "Katarzyna Wójcik", groups: ["security"], preset: "strict", roles: ["acl-admin"], stats: { requests: 212, tokens_in: 84_100, tokens_out: 31_900, blocks: 2, usd: 0.41, last: minutesAgo(1) } },
  { username: "m.zielinska", name: "Magdalena Zielińska", groups: ["security"], preset: "strict", roles: ["acl-admin"], stats: { requests: 148, tokens_in: 52_400, tokens_out: 20_100, blocks: 0, usd: 0.22, last: minutesAgo(12) } },
  { username: "j.kowalski", name: "Jan Kowalski", groups: ["developers"], preset: "balanced", stats: { requests: 1_204, tokens_in: 1_420_000, tokens_out: 388_000, blocks: 7, usd: 3.12, last: minutesAgo(1) } },
  { username: "a.nowak", name: "Anna Nowak", groups: ["credit-analysts"], preset: "strict", stats: { requests: 486, tokens_in: 310_000, tokens_out: 96_000, blocks: 3, usd: 0.64, last: minutesAgo(2) } },
  { username: "p.zielinski", name: "Piotr Zieliński", groups: ["developers"], preset: "balanced", stats: { requests: 902, tokens_in: 960_000, tokens_out: 271_000, blocks: 1, usd: 1.84, last: minutesAgo(5) } },
  { username: "m.lis", name: "Marta Lis", groups: ["credit-analysts"], preset: "strict", stats: { requests: 301, tokens_in: 198_000, tokens_out: 61_000, blocks: 0, usd: 0.37, last: minutesAgo(9) } },
  { username: "t.wisniewski", name: "Tomasz Wiśniewski", groups: ["credit-analysts"], preset: "strict", stats: { requests: 177, tokens_in: 120_000, tokens_out: 40_000, blocks: 1, usd: 0.21, last: daysAgo(1) } },
  { username: "e.grabowska", name: "Ewa Grabowska", groups: ["operations"], preset: "balanced", stats: { requests: 64, tokens_in: 41_000, tokens_out: 12_000, blocks: 0, usd: 0.08, last: daysAgo(2) } },
  { username: "research-bot", name: "research-bot", groups: ["agents"], preset: "strict", kind: "agent", stats: { requests: 640, tokens_in: 410_000, tokens_out: 120_000, blocks: 4, usd: 0.95, last: minutesAgo(2) } },
];

function seedUsers(): User[] {
  return USERS.map((u) => ({
    id: `u_${u.username.replace(/[^a-z0-9]/gi, "")}`,
    subject: u.kind === "agent" ? `agent-${u.username}` : `kc-${u.username.replace(".", "-")}`,
    username: u.username,
    email: u.kind === "agent" ? null : `${u.username}@corp.example`,
    display_name: u.name,
    kind: u.kind ?? "user",
    groups: u.groups,
    roles: u.roles ?? [],
    first_seen: daysAgo(90),
    last_seen: u.stats.last,
    disabled: false,
    preset: u.preset,
    stats_7d: {
      window: "7d",
      requests: u.stats.requests,
      tokens_in: u.stats.tokens_in,
      tokens_out: u.stats.tokens_out,
      blocks: u.stats.blocks,
      usd: u.stats.usd,
      gpu_seconds: 0,
      last_active: u.stats.last,
    },
  }));
}

function seedGroups(): Group[] {
  const g = (
    name: string,
    members: number,
    preset: Group["preset"],
    budget: number,
    tokens: [number, number],
    spend: number,
    line: number,
  ): Group => ({
    name,
    description: "",
    preset,
    members,
    source: "both",
    settings: { preset, models: ["auto"], tools: [], max_cloud_data_class: "internal", daily_budget_usd: budget },
    stats_today: { window: "today", requests: 0, tokens_in: tokens[0], tokens_out: tokens[1], blocks: 0, usd: spend, gpu_seconds: 0, last_active: null },
    policy_file: "groups.yaml",
    policy_line: line,
  });
  return [
    g("developers", 14, "balanced", 5, [212_000, 64_000], 3.12, 20),
    g("credit-analysts", 9, "strict", 2, [88_000, 27_000], 0.9, 34),
    g("operations", 12, "balanced", 1, [14_000, 4_000], 0.2, 48),
    g("security", 6, "strict", 1, [30_000, 11_000], 0.31, 58),
  ];
}

export const users = seeded(seedUsers);
export const groups = seeded(seedGroups);

export function findUser(idOrName: string): User | undefined {
  return users.items.find((u) => u.id === idOrName || u.username === idOrName || u.subject === idOrName);
}
