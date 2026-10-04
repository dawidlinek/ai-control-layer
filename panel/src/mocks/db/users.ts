/**
 * Mock data: users and groups (People / Groups tabs of Users & groups). Personas from HANDOFF section 6,
 * numbers from docs/ux/design-reference/UsersGroups.dc.html. 41 people = the members of the four groups
 * (developers 14, credit-analysts 9, operations 12, security 6); research-bot is an agent principal (not a person).
 * Group settings use the HANDOFF 7.1 lineup: developers have no cloud model by group (Jan's grant g-0412 adds `smart`).
 */
import { daysAgo, demoClock, demoClockYesterday, hoursAgo, minutesAgo } from "../time";
import { seeded } from "./registry";
import type { Group, User } from "./types";

type Stats = { requests: number; tokens_in: number; tokens_out: number; blocks: number; usd: number; last: string };

type UserSeed = {
  username: string;
  name: string;
  email?: string;
  group: string;
  kind?: User["kind"];
  roles?: string[];
  stats: Stats;
};

const PRESET: Record<string, User["preset"]> = {
  developers: "balanced",
  "credit-analysts": "strict",
  operations: "balanced",
  security: "strict",
  agents: "strict",
};

/** The named personas (prototype rows, in prototype order). */
const NAMED: UserSeed[] = [
  { username: "j.kowalski", name: "Jan Kowalski", email: "jan.kowalski@corp.example", group: "developers", stats: { requests: 1_214, tokens_in: 1_200_000, tokens_out: 310_000, blocks: 3, usd: 3.12, last: demoClock("14:02:41") } },
  { username: "a.nowak", name: "Anna Nowak", email: "anna.nowak@corp.example", group: "credit-analysts", stats: { requests: 842, tokens_in: 640_000, tokens_out: 150_000, blocks: 1, usd: 0.64, last: demoClock("14:03:12") } },
  { username: "p.zielinski", name: "Piotr Zieliński", email: "piotr.zielinski@corp.example", group: "developers", stats: { requests: 1_530, tokens_in: 1_800_000, tokens_out: 420_000, blocks: 0, usd: 1.84, last: demoClock("14:00:10") } },
  { username: "m.lis", name: "Marta Lis", email: "marta.lis@corp.example", group: "credit-analysts", stats: { requests: 611, tokens_in: 380_000, tokens_out: 96_000, blocks: 0, usd: 0.37, last: demoClock("13:59:10") } },
  { username: "t.wisniewski", name: "Tomasz Wiśniewski", email: "tomasz.wisniewski@corp.example", group: "credit-analysts", stats: { requests: 402, tokens_in: 210_000, tokens_out: 52_000, blocks: 0, usd: 0.21, last: demoClockYesterday("16:40:00") } },
  { username: "e.grabowska", name: "Ewa Grabowska", email: "ewa.grabowska@corp.example", group: "operations", stats: { requests: 288, tokens_in: 150_000, tokens_out: 40_000, blocks: 0, usd: 0.08, last: demoClock("12:40:00") } },
  { username: "k.wojcik", name: "Katarzyna Wójcik", email: "k.wojcik@corp.example", group: "security", roles: ["acl-admin"], stats: { requests: 96, tokens_in: 40_000, tokens_out: 11_000, blocks: 0, usd: 0.05, last: minutesAgo(0) } },
  { username: "m.zielinska", name: "Magdalena Zielińska", email: "m.zielinska@corp.example", group: "security", roles: ["acl-admin"], stats: { requests: 120, tokens_in: 52_000, tokens_out: 14_000, blocks: 0, usd: 0.06, last: demoClock("14:04:00") } },
];

/** The rest of the 41 people (quieter users), so the group member counts and the "People 41" tab add up. */
const OTHERS: Array<[string, string, string]> = [
  // developers: 12 more
  ["Michał Wójtowicz", "m.wojtowicz", "developers"],
  ["Paweł Kaczmarek", "p.kaczmarek", "developers"],
  ["Agnieszka Mazur", "a.mazur", "developers"],
  ["Krzysztof Krawczyk", "k.krawczyk", "developers"],
  ["Łukasz Piotrowski", "l.piotrowski", "developers"],
  ["Joanna Pawlak", "j.pawlak", "developers"],
  ["Marcin Michalski", "m.michalski", "developers"],
  ["Natalia Król", "n.krol", "developers"],
  ["Tomasz Jabłoński", "t.jablonski", "developers"],
  ["Kamil Wróbel", "k.wrobel", "developers"],
  ["Aleksandra Dudek", "a.dudek", "developers"],
  ["Rafał Adamczyk", "r.adamczyk", "developers"],
  // credit-analysts: 6 more
  ["Barbara Nowicka", "b.nowicka", "credit-analysts"],
  ["Monika Sikora", "m.sikora", "credit-analysts"],
  ["Adam Baran", "a.baran", "credit-analysts"],
  ["Karolina Rutkowska", "k.rutkowska", "credit-analysts"],
  ["Grzegorz Michalak", "g.michalak", "credit-analysts"],
  ["Beata Szewczyk", "b.szewczyk", "credit-analysts"],
  // operations: 11 more
  ["Dariusz Ostrowski", "d.ostrowski", "operations"],
  ["Iwona Tomaszewska", "i.tomaszewska", "operations"],
  ["Robert Pietrzak", "r.pietrzak", "operations"],
  ["Elżbieta Jasińska", "e.jasinska", "operations"],
  ["Jacek Zawadzki", "j.zawadzki", "operations"],
  ["Renata Bąk", "r.bak", "operations"],
  ["Sławomir Jakubowski", "s.jakubowski", "operations"],
  ["Dorota Sadowska", "d.sadowska", "operations"],
  ["Wojciech Duda", "w.duda", "operations"],
  ["Halina Włodarczyk", "h.wlodarczyk", "operations"],
  ["Artur Wilk", "a.wilk", "operations"],
  // security: 4 more
  ["Patrycja Chmielewska", "p.chmielewska", "security"],
  ["Mariusz Borkowski", "m.borkowski", "security"],
  ["Ewelina Sokołowska", "e.sokolowska", "security"],
  ["Damian Szczepański", "d.szczepanski", "security"],
];

const AGENT: UserSeed = {
  username: "research-bot",
  name: "research-bot",
  group: "agents",
  kind: "agent",
  stats: { requests: 640, tokens_in: 410_000, tokens_out: 120_000, blocks: 4, usd: 0.95, last: minutesAgo(2) },
};

const ascii = (s: string) =>
  s
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/ł/g, "l")
    .replace(/Ł/g, "L");

function otherSeeds(): UserSeed[] {
  return OTHERS.map(([name, username, group], i) => {
    const requests = 40 + ((i * 37) % 260);
    const tokens_in = requests * (380 + ((i * 53) % 400));
    return {
      username,
      name,
      email: `${ascii(name).toLowerCase().replace(" ", ".")}@corp.example`,
      group,
      stats: {
        requests,
        tokens_in,
        tokens_out: Math.round(tokens_in * 0.27),
        blocks: i % 9 === 4 ? 1 : 0,
        usd: Math.round(tokens_in / 1_000) / 1_000,
        last: i % 5 === 0 ? daysAgo(2 + (i % 4)) : hoursAgo(1 + (i % 7)),
      },
    };
  });
}

function toUser(u: UserSeed): User {
  return {
    id: `u_${u.username.replace(/[^a-z0-9]/gi, "")}`,
    subject: u.kind === "agent" ? `agent-${u.username}` : `kc-${ascii(u.name).toLowerCase().replace(/\s+/g, "-")}`,
    username: u.username,
    email: u.kind === "agent" ? null : (u.email ?? `${u.username}@corp.example`),
    display_name: u.name,
    kind: u.kind ?? "user",
    groups: [u.group],
    roles: u.roles ?? [],
    first_seen: daysAgo(90),
    last_seen: u.stats.last,
    disabled: false,
    preset: PRESET[u.group] ?? "balanced",
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
  };
}

function seedUsers(): User[] {
  return [...NAMED, ...otherSeeds(), AGENT].map(toUser);
}

type GroupSeed = {
  name: string;
  description: string;
  preset: NonNullable<Group["preset"]>;
  models: string[];
  tools: string[];
  cloud: "none" | "public" | "internal";
  budget: number;
  tokens: [number, number];
  requests: number;
  spend: number;
  line: number;
};

const GROUPS: GroupSeed[] = [
  {
    name: "developers",
    description: "Developers (OpenCode). No cloud model by default; a personal grant (e.g. smart) adds one.",
    preset: "balanced",
    models: ["auto", "fast", "local"],
    tools: ["opencode.read", "opencode.edit", "opencode.write", "opencode.bash", "web.fetch"],
    cloud: "internal",
    budget: 5,
    tokens: [2_400_000, 610_000],
    requests: 3_120,
    spend: 2.1,
    line: 20,
  },
  {
    name: "credit-analysts",
    description: "Bank credit analysts (LibreChat + OpenCode)",
    preset: "strict",
    models: ["auto", "local", "local/loan-memo"],
    tools: ["opencode.read", "opencode.edit", "opencode.bash", "bank.query"],
    cloud: "internal",
    budget: 2,
    tokens: [1_100_000, 260_000],
    requests: 1_480,
    spend: 0.74,
    line: 9,
  },
  {
    name: "operations",
    description: "Operations (LibreChat)",
    preset: "balanced",
    models: ["auto", "local"],
    tools: ["web.fetch", "mail.send"],
    cloud: "internal",
    budget: 1,
    tokens: [310_000, 80_000],
    requests: 402,
    spend: 0.21,
    line: 48,
  },
  {
    name: "security",
    description: "Security team (panel analysts)",
    preset: "strict",
    models: ["auto", "local"],
    tools: ["opencode.read", "web.fetch"],
    cloud: "public",
    budget: 1,
    tokens: [92_000, 25_000],
    requests: 216,
    spend: 0.07,
    line: 58,
  },
];

function seedGroups(): Group[] {
  const people = seedUsers();
  return GROUPS.map((g) => ({
    name: g.name,
    description: g.description,
    preset: g.preset,
    members: people.filter((u) => u.kind === "user" && u.groups.includes(g.name)).length,
    source: "both",
    settings: { preset: g.preset, models: [...g.models], tools: [...g.tools], max_cloud_data_class: g.cloud, daily_budget_usd: g.budget },
    stats_today: {
      window: "today",
      requests: g.requests,
      tokens_in: g.tokens[0],
      tokens_out: g.tokens[1],
      blocks: 0,
      usd: g.spend,
      gpu_seconds: 0,
      last_active: minutesAgo(1),
    },
    policy_file: "groups.yaml",
    policy_line: g.line,
  }));
}

export const users = seeded(seedUsers);
export const groups = seeded(seedGroups);

export function findUser(idOrName: string): User | undefined {
  return users.items.find((u) => u.id === idOrName || u.username === idOrName || u.subject === idOrName);
}

export function findGroup(name: string): Group | undefined {
  const n = name.replace(/^\//, "");
  return groups.items.find((g) => g.name === n);
}

/** Models (aliases / skills) a group can be given in the panel, in display order. Cloud ones carry `cloud: true`. */
export const MODEL_CATALOGUE: ReadonlyArray<{ id: string; cloud: boolean }> = [
  { id: "auto", cloud: false },
  { id: "fast", cloud: false },
  { id: "local", cloud: false },
  { id: "smart", cloud: true },
  { id: "smart-pro", cloud: true },
  { id: "local/loan-memo", cloud: false },
];

/** Tools a group can be given in the panel (tool ids as in tools.yaml). */
export const TOOL_CATALOGUE: readonly string[] = [
  "opencode.read",
  "opencode.edit",
  "opencode.write",
  "opencode.bash",
  "web.fetch",
  "mail.send",
  "bank.query",
];
