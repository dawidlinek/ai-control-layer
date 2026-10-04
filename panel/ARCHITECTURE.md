# Rogatka Dashboard: conventions for screen agents

The admin panel of Rogatka (repo `ai-control-layer`). Source of truth for scope: `docs/ux/HANDOFF.md`
(wins over older UX docs); for colour, type and brand marks: `docs/ux/STYLEGUIDE.md` (agreed 2026-10-04, wins over HANDOFF section 3-4). Design prototypes: `docs/ux/design-reference/*.dc.html` (read for copy, data, markup;
they are **not** production code). API: `contracts/admin-api.openapi.yaml` (read-only for you).

Stack: Next.js 15 (App Router) + TypeScript strict, Tailwind v4, shadcn/ui on Radix (`radix-ui`), lucide-react,
TanStack Query + Table, nuqs, react-hook-form + zod, Recharts, Monaco (`@monaco-editor/react` + `monaco-yaml`,
installed, the Policies agent wires it), Auth.js v5 (Keycloak), MSW, openapi-typescript + openapi-fetch, Vitest +
Testing Library, Playwright. Package manager: pnpm (`pnpm -C panel ...`). Never use npm/yarn.

## Commands (run from the repo root with `pnpm -C panel <script>`)

| Script | What |
|---|---|
| `dev` | Next dev server. Mock mode: `NEXT_PUBLIC_API_MOCKING=enabled pnpm -C panel dev` (no gateway, no Keycloak, demo user signed in) |
| `build` / `start` | Production build (standalone output) / serve it |
| `lint` / `typecheck` | `eslint .` / `tsc --noEmit` |
| `test` | Vitest (jsdom, MSW node server). `pnpm -C panel exec vitest run src/features/traffic` for one folder |
| `e2e` | Playwright, chromium only, starts `pnpm dev` on port 3100 in mock mode. Install once: `pnpm -C panel exec playwright install chromium` |
| `gen:api` | Regenerate `src/lib/api/schema.d.ts` from `../contracts/admin-api.openapi.yaml` (commit the result) |

Definition of done for a screen: `typecheck`, `lint`, `test`, `build` and `e2e` pass; the screen matches its prototype
(spacing, sizes, copy, data), works in light (default) and dark, and has tests for each interaction listed in HANDOFF section 5.

## Folder layout

```
panel/
  src/
    app/
      layout.tsx, globals.css            root layout (fonts, theme cookie, providers), design tokens
      (dash)/layout.tsx                  auth guard + AppShell; every screen route is below this group
      (dash)/<route>/page.tsx            THIN: metadata + <FeatureScreen />, nothing else
      admin/v1/[...path]/route.ts        server proxy to the gateway (adds the bearer token, streams SSE)
      api/auth/[...nextauth]/route.ts    Auth.js
      sign-in, signed-out                standalone pages
    features/<screen>/                   YOUR code: components, hooks (api.ts), helpers, *.test.tsx next to the code
    components/
      ui/                                shadcn-style primitives (button, input, dialog, dropdown-menu, popover, select, switch, tooltip, checkbox, separator)
      rogatka/                           shared product primitives (list below); import from "@/components/rogatka"
      shell/                             top bar, sidebar nav, profile menu, shortcuts (owned by the foundation)
    lib/
      api/{client,hooks,sse,types,schema.d.ts}.ts   typed client, query keys + shared hooks, SSE hook, `Resp<T>` types
      auth/                              roles, user context (`useRole`, `RequireRole`), server helpers
      decisions.ts, format.ts, utils.ts  decision/severity vocabulary + icons, time/number formatting, `cn`
    mocks/
      db/<domain>.ts                     typed, mutable, in-memory demo data
      handlers/<domain>.ts               MSW handlers for that domain
      time.ts                            fixtures relative to "now"
    test/{render,router}.tsx             `renderApp()` test helper, `next/navigation` stand-in
  e2e/<screen>.spec.ts                   Playwright specs
```

Routes (already exist as "being built" placeholders; replace the page body, keep the file thin):
`/`, `/traffic`, `/incidents`, `/approvals`, `/users`, `/grants`, `/policies`, `/models`, `/tools`, `/threats`,
`/budgets`, `/insights`, `/sessions/[id]`. Tabs (People | Groups, Rules | YAML | History, ...) are **not** routes:
keep them in the URL as `?tab=` (nuqs).

Own only your screen: `src/features/<screen>/`, your `app/(dash)/<route>/page.tsx`, your mock domain
(`mocks/db/<domain>.ts`, `mocks/handlers/<domain>.ts`) and `e2e/<screen>.spec.ts`. If a shared primitive or the shell
needs a change, make the smallest additive change and say so in your report. Do not touch `gateway/`, `policy/`,
`contracts/`.

## Fetching data

Typed client `api` (`lib/api/client.ts`, openapi-fetch) + TanStack Query. Always `unwrap()` the result: it throws
`ApiError` (with `status` and the server's `detail`) and returns `Resp<T>`: the response type with every field
required (the contract marks fields with server defaults optional, but the gateway always sends them; nullable stays
nullable). Do not write `?? []` for those.

```ts
// src/features/incidents/api.ts
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, unwrap } from "@/lib/api/client";
import { queryKeys } from "@/lib/api/hooks";

export function useIncident(id: string | null) {
  return useQuery({
    queryKey: queryKeys.incidents.detail(id ?? ""),
    enabled: !!id,
    queryFn: async ({ signal }) =>
      unwrap(await api.GET("/admin/v1/incidents/{incident_id}", { params: { path: { incident_id: id! } }, signal })),
  });
}

export function useAssignToMe() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (v: { id: string; username: string }) =>
      unwrap(await api.PATCH("/admin/v1/incidents/{incident_id}", { params: { path: { incident_id: v.id } }, body: { assignee: v.username } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.incidents.all }),
  });
}
```

Conventions:

- **Query keys**: `[domain, kind, ...params]`. Shared keys live in `queryKeys` (`lib/api/hooks.ts`: policy, events, incidents,
  approvals, users). Add yours to `queryKeys` in one small additive edit, or keep them in `features/<screen>/api.ts` with the same shape.
  Invalidate a whole domain with `[domain]`.
- Hooks live in `features/<screen>/api.ts`. Components never call `api` directly.
- Always pass `signal` from `queryFn`. Filters belong in the query key.
- **Live updates**: `useEventStream({ prependTo: [queryKeys.events.list(filters)], invalidate: [...] })` (`lib/api/sse.ts`) subscribes to
  `/admin/v1/events/stream` and prepends to the lists you name; incident / approval events invalidate those caches (and the sidebar badges).
- **Counts** for the sidebar come from `useNavCounts()`; after a mutation that changes them, invalidate `queryKeys.incidents.all` / `queryKeys.approvals.all`.
- The browser calls `/admin/v1/...` on the panel origin. The route handler adds the bearer token and proxies to `ROGATKA_GATEWAY_URL`. Never call the gateway or Keycloak from the browser.
- Loading / empty / error: use `DataTable`'s `loading`, `error`, `emptyTitle` props, or `LoadingRows`, `EmptyState`, `ErrorState` (with `onRetry={query.refetch}`).

### Not enough in the contract?

Do not change `contracts/`. Build the screen against what exists, derive what you can client-side, and list the gap in
your report (the foundation report already lists those noticed so far, see the end of this file).

## URL state (nuqs)

Filters, search text, active tab, page, page size and the selected row live in the query string. The `NuqsAdapter` is
already mounted. Use `useQueryState` / `useQueryStates` with the parsers from `nuqs`:

```ts
const [tab, setTab] = useQueryState("tab", parseAsStringLiteral(["open", "resolved", "all"] as const).withDefault("open"));
const [decisions, setDecisions] = useQueryState("decision", parseAsArrayOf(parseAsString).withDefault([]));
const [q, setQ] = useQueryState("q", parseAsString.withDefault("").withOptions({ limitUrlUpdates: debounce(300) }));
const [page, setPage] = useQueryState("page", parseAsInteger.withDefault(1));
const [sel, setSel] = useSelectedId();            // ?sel=<id>, from @/components/rogatka
```

Names to keep consistent across screens: `sel`, `tab`, `q`, `page`, `size`, `range` (`15m|1h|24h|7d`), `decision`, `point`, `group`, `rule`, `severity`.
Cross-screen links carry filters, e.g. RuleChip links to `/policies?rule=SEC-PII-01`, "All activity in Traffic" to `/traffic?q=...`.
Reset `page` to 1 when a filter changes. In tests use `renderApp(ui, { searchParams: "?sel=tr_8f3a2c" })`; add `urlMemory: true` when the test clicks filters / tabs / rows and the screen must read its own URL updates back (the in-memory URL then remembers them; `onUrlUpdate` still reports each change).

## The list + sidebar pattern

Every screen except Overview: title, filter row, table, pagination; clicking a row opens a right sidebar
(`flex: 1 1 440px`) with the selection in `?sel=`; the list is full width when closed. Sidebar order: header, one plain
sentence, key facts, type-specific sections, actions.

```tsx
"use client";
import { useQueryState, parseAsStringLiteral } from "nuqs";
import {
  DataTable, FactsGrid, FilterRow, ListWithSidebar, PageHeader, Pagination, PlainSentence, SegmentedTabs,
  SeverityChip, SidebarActions, SidebarBlock, SidebarHeader, SidebarSection, useSelectedId,
} from "@/components/rogatka";
import { Button } from "@/components/ui/button";

export function IncidentsScreen() {
  const [sel, setSel] = useSelectedId();
  const [tab, setTab] = useQueryState("tab", parseAsStringLiteral(["open", "resolved", "all"] as const).withDefault("open"));
  const incidents = useIncidents();                              // features/incidents/api.ts
  const rows = (incidents.data ?? []).filter((i) => tab === "all" || (tab === "open") === (i.status !== "resolved"));
  const selected = rows.find((i) => i.id === sel);

  return (
    <>
      <PageHeader title="Incidents" />
      <FilterRow>
        <SegmentedTabs ariaLabel="Status" value={tab} onChange={setTab}
          tabs={[{ value: "open", label: "Open", count: 7 }, { value: "resolved", label: "Resolved", count: 2 }, { value: "all", label: "All", count: 9 }]} />
      </FilterRow>
      <ListWithSidebar
        open={!!selected} onClose={() => void setSel(null)} sidebarLabel="Incident"
        list={<>
          <DataTable ariaLabel="Incidents" data={rows} columns={columns} getRowId={(i) => i.id}
            selectedId={sel} onRowClick={(i) => void setSel(i.id)} keyboardNav
            loading={incidents.isPending} error={incidents.error} onRetry={() => void incidents.refetch()} />
          <Pagination page={1} pageCount={1} pageSize={25} onPageChange={() => {}} />
        </>}
        sidebar={selected && <>
          <SidebarHeader label="Incident" title={selected.id} copyText={selected.id} />
          <SidebarBlock>
            <SeverityChip severity={selected.severity} size="md" />
            <PlainSentence>{String(selected.detail.summary)}</PlainSentence>
            <FactsGrid facts={[{ label: "Type", value: selected.category }, { label: "Assignee", value: selected.assignee ?? "unassigned" }]} />
          </SidebarBlock>
          <SidebarSection title="Do something">...</SidebarSection>
          <SidebarActions><Button variant="primary">Keep quarantined and close</Button></SidebarActions>
        </>}
      />
    </>
  );
}
```

Notes: `DataTable` columns are TanStack `ColumnDef`s; use `meta: { className, headerClassName }` for mono / width / ellipsis
(a truncating column needs a max width, e.g. `className: "max-w-[220px]"` with `<Truncate>`). Clicks on links and buttons
inside a row do not select it. `keyboardNav` adds `j` / `k` / `Enter`. `Esc` closes the sidebar. `ListWithSidebar` renders the
sidebar only when `open` is true. Selection that no longer exists in the data (filtered out) should close the sidebar: derive `selected` from the visible rows as above.

## Write actions: show the result inline

Every action that changes policy says so ("Saved as policy v9", "writes groups.yaml"). Publish / approve / grant / assign flows
show the result **inline in the sidebar where the action was**, in a `StatusBox`, never a toast:

```tsx
const decide = useDecideApproval();
...
{decide.isSuccess && <StatusBox variant="success" title="Approved once">It shows as an elevation on Jan Kowalski’s access page.</StatusBox>}
{decide.isError && <StatusBox variant="error" title="Could not approve">{decide.error.message}</StatusBox>}
```

Disable the button while pending, keep the form values on error, invalidate the affected query keys on success.
Deny is the primary (solid red, `variant="danger"`) button in approvals. Org-locked items are read-only with the lock icon (`RuleChip locked`).
Forms: react-hook-form + zod (`@hookform/resolvers/zod`); required reason fields block submit with an inline message.

## Role gating

Roles come from Keycloak realm roles in the access token: `acl-admin` > `acl-analyst` > `acl-viewer`; none = the "No access"
page. In the browser: `useRole()` ("admin" | "analyst" | "viewer"), `useHasRole(min)`, `<RequireRole min="admin" fallback={...}>`.
Rule of thumb: viewers read; analysts triage (assign, acknowledge, approve / deny, add notes); admins change policy,
groups, grants, connectors, tools, budgets. Hide the action, or render it disabled with a title, via `fallback`.
This is UX only; the gateway enforces roles. Dev / mock mode: `?role=viewer|analyst|admin` overrides the role for the tab;
the default demo user is Katarzyna Wójcik, `acl-admin`. Test with `renderApp(ui, { user: { ...DEV_USER, role: "viewer", roles: ["acl-viewer"] } })`.

## Mock API (MSW)

`NEXT_PUBLIC_API_MOCKING=enabled` starts the MSW service worker (`public/mockServiceWorker.js`) before the app renders and
makes the demo user the signed-in user (`ROGATKA_AUTH=dev`). Vitest uses the same handlers via `msw/node` (`vitest.setup.ts`).

Per domain (`events`, `incidents`, `approvals`, `users`, `grants`, `policy`, `models`, `tools`, `feed`, `budgets`, `overview`,
`insights`) there are two files you own for your screen, and `handlers/index.ts` already imports all of them:

1. `src/mocks/db/<domain>.ts`: typed demo data. Use the response types from `@/lib/api/types` (`Incident`, `Approval`, ...; add yours there
   if missing) so fixtures are as complete as real responses. Make it mutable and resettable:
   ```ts
   import { minutesAgo } from "../time";
   import { seeded } from "./registry";
   import type { Grant } from "@/lib/api/types";
   function seed(): Grant[] { return [ /* ... */ ]; }
   export const grants = seeded(seed);          // grants.items is the live array; reset after each test is automatic
   ```
   For a single object use `registerReset(() => Object.assign(obj, seedObj()))` (see `db/policy.ts`).
2. `src/mocks/handlers/<domain>.ts`: `export const grantsHandlers: HttpHandler[] = [http.get(adminPath("/grants"), ...)]`.
   Helpers in `handlers/helpers.ts`: `adminPath("/x/:id")`, `problem(status, detail)` (FastAPI-shaped error), `queryOf`, `intParam`, `MOCK_USER`.
   Implement the filters your screen uses (query params in the contract), write endpoints that mutate the db (so the UI shows the result),
   and 404 / 409 for impossible cases. Register routes with static paths before parametrised ones (`/events/stream` before `/events/:id`).

Rules for fixtures:

- **Time is relative to now**: `import { minutesAgo, hoursAgo, inMinutes, demoClock } from "../time"`. `demoClock("14:03:12")` keeps the
  prototype's spacing (prototype "now" is 14:05:00), so "today", "38 m" and countdowns look right at any hour.
- Use the HANDOFF section 6 personas, ids and rule ids (Anna Nowak `tr_8f3a2c`, Jan's `apr-0193`, `FEED-PKG-0007`, `inc-0057`, ...). Rule ids must match
  `^[A-Z][A-Z0-9]*(-[A-Z0-9_.]+)+$`.
- Model lineup per HANDOFF 7.1: Gemini Flash, Gemini Pro, local Qwen ~27B (`qwen3.8-27b`). No Bielik.
- **Never put raw sensitive values in fixtures.** Only masked values (`PESEL ***-**-**123`, `PL** **** … 2874`),
  placeholders (`<PERSON_1>`, `<PESEL_1>`, `<IBAN_1>`), and `‹SECRET:api_key›`. No real-looking PESEL, IBAN, key or token, even in test code.
- Push a live event in a test or demo: `pushMockEvent(makeEvent({...}))` (`handlers/events.ts`, `db/events.ts`).
- Tests: `server.use(http.get(adminPath("/incidents"), () => HttpResponse.json([])))` overrides one route for a test; unhandled requests fail the test.

## Components

### Shared product primitives, `@/components/rogatka`

| Component | Props (all optional unless marked *) | Use |
|---|---|---|
| `DecisionBadge` | `decision*: Decision`, `size?: "sm"\|"md"\|"lg"` (sm = table row, md = sidebar, lg = legend), `children?` (trailing count) | Icon + mono label in the tint style. Never colour alone. All 9 decisions |
| `DecisionChips` | `decisions*: Decision[]`, `size?` | Wrapped list of badges; `—` when empty |
| `SeverityChip` | `severity*: "critical"\|"high"\|"medium"\|"low"\|"info"`, `size?` | Icon + label (`info` shows as low) |
| `RuleChip` | `ruleId*`, `locked?`, `href?: string \| false` | Mono chip, links to `/policies?rule=<ID>`; lock icon for org locks |
| `PlaceholderChip` | `children*` | `<PESEL_1>` style placeholder (pseudonymise tint) |
| `MaskedValue` | `value*` (already masked), `label?` | `PESEL ***-**-**123` |
| `EffectChip` | `effect*: "allow"\|"deny"\|"budget"` | Grant effect: allow / deny in the decision tints, budget neutral |
| `ToolStatusChip` | `status*: ToolStatus` (`approved`, `quarantined`, `not approved`, `built-in`, `denied`) | Tool status pill: tinted for the first three, outlined for built-in / denied |
| `ToggleChip` | `label*`, `on*`, `onChange?`, `disabled?` | `✓ allowed` / `+ not` (role switch) |
| `StatusBox` | `variant?: "success"\|"info"\|"warning"\|"error"`, `title?`, `children?` | Inline result of an action; error is an alert |
| `FactsGrid` | `facts*: {label, value, mono?}[]` | 2-column key facts; values ellipsise |
| `PlainSentence` | `children*` | The one sentence at the top of a sidebar (16 px / 500 / 1.45; templates, never an LLM) |
| `PageHeader` | `title*`, `subtitle?`, `actions?` | h1 22 px / 600 / -0.01em + right-hand actions |
| `Card` | `title?`, section props | Overview card (surface, 1 px border, 8 px radius, 16 px padding, no shadow) |
| `SidebarSection` | `title*`, `aside?`, `children*` | Section with 11 px / 700 / uppercase / .1em muted label and bottom border |
| `SidebarHeader` | `label*`, `title?`, `copyText?`, `actions?`, `onClose?` | First row of a sidebar; the x closes (uses the context of `ListWithSidebar`) |
| `SidebarBlock` / `SidebarActions` | `children*` | Unlabelled intro block / action footer |
| `ListWithSidebar` | `list*`, `sidebar*`, `open*`, `onClose*`, `sidebarLabel*` | The list + sidebar layout; Esc closes |
| `useSelectedId()` | returns `[sel, setSel]` | `?sel=` via nuqs |
| `FilterRow`, `FilterSpacer` | children | Row under the title; spacer pushes the rest right |
| `SegmentedTabs` | `tabs*: {value,label,count?}[]`, `value*`, `onChange*`, `ariaLabel?` | Tabs with counts (role tab) |
| `Segmented` | `options*: {value,label,disabled?}[]`, `value*`, `onChange*`, `ariaLabel*`, `size?`, `disabled?` | Option switch (Dark/Light, 15m/1h/24h/7d, strictness); `aria-pressed` buttons. `disabled` (whole control) or `option.disabled` (one button) sets `disabled` + `aria-disabled` and never calls `onChange` |
| `FilterMenuButton` | `label*`, `options*: {value,label}[]`, `selected*: string[]`, `onChange*`, `multiple?` (default true), `icon?` | Button with a caret opening a checkable menu; highlighted when active |
| `SearchInput` | `value*`, `onChange*`, `placeholder?`, `ariaLabel?` | Inset field with magnifier (`/` focuses it) |
| `LabeledSwitch` | `label*`, `checked*`, `onCheckedChange*` | "Hide allowed", "Assigned to me" |
| `DataTable<T>` | `data*`, `columns*`, `getRowId*`, `ariaLabel*`, `selectedId?`, `onRowClick?`, `loading?`, `error?`, `onRetry?`, `emptyTitle?`, `emptyMessage?`, `keyboardNav?`, `minWidth?` | TanStack table in the Rogatka look; `Truncate` helper |
| `Pagination` | `page*`, `onPageChange*`, `pageSize*`, `pageCount?` or `hasNext?`, `onPageSizeChange?`, `pageSizes?` | "Rows per page 25 v", `< 1 2 3 ... N >`. The contract has no totals: use `hasNext` for cursor lists |
| `DiffBox` | `title?`, `lines*: {sign: "+"\|"-"\|"~"\|" ", text}[]`, `addedTone?: "good"\|"bad"`, `removedTone?: "bad"\|"good"`, `ariaLabel?` | Bordered mono diff (git diff, plan, tool description). `addedTone="bad"` paints added lines red (rug pull); rows carry `data-sign` |
| `useNow(intervalMs = 1000, active = true)`, `secondsUntil(iso, now)` | returns ms since epoch | Re-rendering clock for countdowns and relative labels; `active = false` stops the timer |
| `StepTimeline` | `steps*: {id,name,result,meta?,changed?,detail?}[]`, `defaultOpenId?` / `openId?`+`onOpenChange?` | Trace "How the decision was made". Brand motif: 2 px accent rail, 12 px hollow accent ring per step, 14 px filled dot for the last step; `changed` only bolds the step |
| `BrandLockup`, `LogoTile`, `BrandTag` | `tag?` (default "Dashboard"), `size?` | Logo: Szlaban mark on an ink tile + "Rogatka" 600 + red filled tag. Used by the top bar, sign-in, signed-out, no-access |
| `Meter` | `value*`, `max*`, `label*`, `forecast?`, `danger?` | Usage bar: ink, orange >= 80 %, red (block) at the limit or `danger`; `meterState()` |
| `Avatar` | `name*`, `size?` | Initials; `initialsOf()` |
| `TimeCell`, `RelativeTime` | `iso*` | Mono time + "today" / compact age ("38 m"); helpers `formatTime`, `formatDay`, `formatWhen`, `formatAge` also in `@/lib/format` |
| `EmptyState`, `ErrorState`, `LoadingRows` | see source | Empty / error (with retry) / skeleton |
| `PathIcon`, `ICON_PATHS`, `RogatkaMark` | `path*`, `size?`, `strokeWidth?` | Stroke icons from the prototype paths; use lucide-react for everything else |

`@/components/ui`: `Button` (`variant`: `primary` ink fill (inverted light fill in dark), `danger` `accent-text` fill with white label (Deny only), `secondary` 1 px `border-strong` (default), `ghost`; `size`: `md` / `sm` 34 px, `lg` 38 px, `icon`; `asChild`; no red primary buttons),
`Input`, `Textarea`, `Label`, `Dialog*`, `DropdownMenu*`, `Popover*`, `Select` (`SelectTrigger`, `SelectValue`, `SelectContent`, `SelectItem`, `SelectGroup`, `SelectLabel`, `SelectSeparator`; Radix Select, trigger styled like the inset form fields; use `onValueChange`, and `Controller` inside react-hook-form), `Switch`, `Tooltip*`, `Checkbox`, `Separator`.
Need another shadcn component (tabs, sheet...)? `pnpm -C panel dlx shadcn@latest add <name>`, then replace its colour classes with ours:

| shadcn class | Ours |
|---|---|
| `bg-background` / `text-foreground` | `bg-bg` / `text-text` |
| `bg-card`, `bg-popover` | `bg-surface` |
| `bg-muted` / `text-muted-foreground` | `bg-raised` / `text-muted` |
| `bg-accent` (hover surface) | `bg-raised`; our `bg-accent` is the brand red (marks only) |
| `bg-primary text-primary-foreground` | `bg-ink text-on-ink` |
| `bg-destructive` | `bg-dec-block` |
| `border-input`, `border` | `border-border` (`border-border-strong` for emphasis) |
| `ring-ring` | the global `:focus-visible` outline already applies |

### Tokens and class names (`src/app/globals.css`)

CSS variables (**light default**, `:root[data-theme="dark"]` overrides; values in `docs/ux/STYLEGUIDE.md` section 2) mapped to Tailwind colours:
`bg-bg`, `bg-surface` (cards, sidebar, table), `bg-raised` (hover, quiet panels = `surface-subtle` `#f6f6f4`), `bg-inset` (inputs, code), `border-border` (`#d9dce3`),
`border-border-strong` (`#c3c9d1`, inputs and chips), `bg-ink` / `text-on-ink` (`#111`, inverted in dark: primary buttons, logo tile, checked checkbox / switch, normal meter),
`text-text` (`#111`), `text-text-secondary` (`#3d4450`), `text-muted` (`#56606b`).
Brand red (marks only: logo tag, 2 px header rule, active-nav bar, timeline rail and rings, stat-block top rule): `bg-accent` / `border-accent` (`#e3322b`; dark `#f0554d`),
`text-accent-text` / `bg-accent-text` (`#c4261f`, red text below 24 px and the Deny fill with `text-on-accent`), `bg-accent-pressed` (`#8f1b16`), `bg-accent-50` (`#fff5f4`), `text-on-accent`.
`text-accent` is kept for old call sites and resolves to `accent-text` (see the rule in `globals.css`), so small red text is always AA.
Selection and focus are **neutral, never red**: `bg-accent-soft` (ink at 6 %) is the selected row / active tab / hover-on-selection fill, `border-accent-line` (ink at 45 %) its border,
the global focus ring is `--ink`, the selected table row has a 3 px ink bar. Red on screen therefore keeps meaning block / high severity.
Decisions `text-dec-allow|monitor|redact|pseudonymise|sanitize|downgrade|route-local|require-approval|block` (same suffixes for `bg-`), severities `text-sev-critical|high|medium|low`
(unchanged from HANDOFF section 4). Radii: chips 4 px (`rounded-[4px]`), controls 6 px, cards 8-10 px; cards are 1 px border, no shadow or gradient (shadow only on popovers and dialogs).
Fonts: `font-sans` (Instrument Sans 400/500/600/700, Google Fonts via `next/font`), `font-mono` (IBM Plex Mono: ids, times, numbers, code, decision labels).
Scale: base 14 px / 1.45; page title 22 px / 600 / -0.01em; plain sentence 16 px / 500 / 1.45; table cells 14 px; controls 13.5-14 px; mono 12-13 px;
section label `text-[11px] font-bold uppercase tracking-[.1em] text-muted`; Overview stat numbers 36 px / 700 / -0.03em under a 2 px accent top rule.
Theme: cookie `rogatka-theme`; missing = light.
Tint chips: set `style={{ "--c": "var(--dec-block)" }}` and class `tint` (text = colour, background 14 % / 10 %, border 32 % / 30 %).
Charts (Recharts) take colours from the CSS variables (`var(--dec-block)`), never hard-coded hex, so both themes work. `lib/decisions.ts` has `DECISION_VAR`, `DECISION_BG_CLASS`,
`DECISION_TEXT_CLASS`, `SEVERITY_VAR`, icon paths. Tailwind only sees literal class names: never build `text-dec-${x}` dynamically, use the maps.
Never hard-code colours in components; add a token if you need one (tell the foundation owner).

Accessibility: visible focus ring is global; every icon-only button needs `aria-label`; menus and dialogs come from Radix (keyboard works);
tables have `aria-label`; do not convey state by colour alone (decisions already carry icon + label).

Keyboard (global, in the shell): `?` help, `g` then `o t i a u g p m l k b n` go to a screen, `/` focus the page search field; in tables `j` / `k` / `Enter` (`keyboardNav`); `Esc` closes a sidebar.

## Copy rules

- The product is **Rogatka**, the panel is **Rogatka Dashboard**. Never "AI Control Layer" in UI copy.
- UI language is English. Demo data may be Polish (PESEL, IBAN, NIP are Polish validators).
- Decisions are always the nine words: `allow`, `monitor`, `redact`, `pseudonymise`, `sanitize`, `downgrade`, `route_local`, `require_approval`, `block`
  (rendered with `DecisionBadge`, mono). Severities: `critical`, `high`, `medium`, `low`.
- Plain sentences, deterministic, filled from the decision record (templates per rule / decision type), never LLM-written. Say what happened and what it
  means for the person ("Anna Nowak's prompt contained a PESEL, an IBAN and a name. They were replaced with placeholders ..."). Sentence case, no jargon in the first line.
- Every action that changes policy says so: "Saved as policy v9", "writes groups.yaml", "creates a new policy version".
- Button labels are verbs ("Publish as v9", "Approve once", "Keep quarantined and close"); destructive / irreversible ones say what they do. Ellipsis (`…`) when a dialog or form follows.
- Counts and times: mono font, `1 284` with a narrow no-break space (`formatNumber`), `today 14:03`, ages `38 m`, countdown `9:40`.
- No posture score, no status strip, no LIVE badge, no bell, no header search box (HANDOFF section 2).
- **No raw sensitive values anywhere** (UI, fixtures, tests, logs): masked values and placeholders only.

## Foundation notes

- Auth: Auth.js v5 + Keycloak. Tokens live only in the encrypted session cookie; the browser gets name, e-mail, username, roles, groups. The proxy route reads the access token
  from the cookie and refreshes it when expired. Config: `AUTH_SECRET`, `AUTH_KEYCLOAK_ID`, `AUTH_KEYCLOAK_SECRET`, `AUTH_KEYCLOAK_ISSUER` (+ optional
  `AUTH_KEYCLOAK_INTERNAL_ISSUER` inside Docker), `ROGATKA_GATEWAY_URL`. See `.env.example` and `deploy/compose.panel.yml`.
- Theme: cookie `rogatka-theme` (missing = light), rendered by the server on `<html data-theme>` (no flash). `useTheme()` from `components/shell/theme`.
- Mock mode vs real: `NEXT_PUBLIC_API_MOCKING` is inlined at build time (the MSW layer is not in normal builds); `ROGATKA_AUTH` is read at runtime.
- Docker: `panel/Dockerfile` (standalone output, non-root), `deploy/compose.panel.yml` (profile `panel`, port 3000).

## API gaps seen in `contracts/admin-api.openapi.yaml` (for the orchestrator; build around them)

1. **No totals / pagination** on list endpoints (`/users`, `/grants`, `/incidents`, `/approvals`, ...): only `limit` (events have `before_seq`). The designs show "N of M", page numbers and tab counts. Workaround: fetch with a high limit and paginate client-side; use `Pagination hasNext` for events.
2. **No count endpoint** for the sidebar badges: the panel lists all incidents and pending approvals and counts client-side. Suggest `GET /admin/v1/metrics/counts` -> `{ open_incidents, pending_approvals }` (or totals in a header).
3. `EventSummary` has no command preview (the Traffic "Model / tool" column shows `bash: git push` in the design; the contract has `tool: "bash"` only), no `client_ref.label`, and no per-event `ms` for the trace header.
4. `Incident` has no `type` label or "who" string beyond `category` / `subject`, and no evidence structure: the rug-pull diff and breaker state must come from `detail` (free-form map). Suggest typed `detail` per `category`.
5. `Approval` has no approver label ("Security team" / "Team lead"), data class, client, "what it wants to do" details, preview or why-held sources; only `arguments_preview`, `reason`, `rule_ids`, `approver_scope`.
6. Request / response models mark every field with a server default optional (Pydantic validation mode); responses always contain them. Panel type `Resp<T>` works around it. Suggest generating the schema in serialization mode.
7. No endpoint for **Keycloak members of a group** or the "Open Keycloak" link target; `Group.members` is a count only.
8. `/admin/v1/me` returns `EffectiveAccess`, not the caller's identity / roles; the panel takes identity and roles from the token.
