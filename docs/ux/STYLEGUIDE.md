# Rogatka style guide

*Written 2026-10-04 from the pitch deck (canvas "Rogatka Pitch Styles", page "Pitch deck":
https://claude.ai/artifact/67ntw5fn6dG5UbvWEgo4Ch). The deck uses last year's HackNation look: white, black type, one
red accent. This guide describes that look and how to carry it into Rogatka Dashboard.*

**Status:** proposal. `HANDOFF.md` §3–4 still describes the dashboard as dark-first with a blue accent (`#4C8DFF`) and
IBM Plex Sans. Where the two disagree and the change has been agreed, this guide wins and `HANDOFF.md` should be updated.
Layout, screens and interaction rules in `HANDOFF.md` stay as they are; this guide changes the look, not the scope.

---

## 1. Brand

| Item | Value |
|---|---|
| Product | **Rogatka** (a toll-gate barrier at a town's entrance) |
| Admin panel | **Rogatka Dashboard** |
| Tagline | *Every AI request passes the gate.* |
| Positioning line | *Deterministic gates decide. AI escalates.* |
| Logo | Barrier mark "Szlaban" (SVG in `HANDOFF.md` §1), white on a black rounded tile (40 px, radius 9) |
| Lockup | Tile + "Rogatka" (600) above a red tag. Slides: tag "AI Control Layer". Dashboard: tag "Dashboard" |

The red tag is a filled accent box with white text and 1–4 px padding, the way last year's "Prawo dla **Ciebie**" logo
used a red box on its last word.

## 2. Colour

Light is the default. Red is the only brand colour; everything else is neutral.

### Neutrals (light)

| Token | Hex | Use |
|---|---|---|
| `bg` | `#ffffff` | Page background |
| `surface-subtle` | `#f6f6f4` | Quiet panels: chat mock, code blocks, info strips |
| `border` | `#d9dce3` | Card and table borders, row dividers |
| `border-strong` | `#c3c9d1` | Inputs, chips |
| `ink` | `#111111` | Text, emphasis borders (1.5–2 px), primary buttons, logo tile |
| `text-secondary` | `#3d4450` | Body copy under headings |
| `text-muted` | `#56606b` | Labels, timestamps, captions |

### Accent (red)

| Token | Hex | Use |
|---|---|---|
| `accent` | `#e3322b` | Fills, rules (2 px lines), large text ≥ 24 px, dots on timelines, full-bleed slides |
| `accent-text` | `#c4261f` | Red text below 24 px; button fill when it carries white text |
| `accent-pressed` | `#8f1b16` | Hover/pressed on `accent-text` |
| `accent-50` | `#fff5f4` | Highlighted card background (e.g. the gateway band in diagrams) |
| `accent-100` / `200` / `300` | `#fdeceb` / `#f9d3d0` / `#f4b2ac` | Escalation ramp (one-way escalation slide); never for text |

**Contrast:** `#e3322b` on white is 4.4:1, just under AA for small text, and the same for white text on it. Use
`accent-text` for anything smaller than 24 px, and for buttons with white labels. Slides can use `accent` freely
because their text is large.

**Alternative accent:** `#2178c4` ("bank blue") is wired into every slide's Tweaks as an option. Not adopted; listed so
nobody reinvents it.

### Red means two things: rules for the dashboard

On slides, red is brand. In the dashboard, red already means **block / high severity**. To keep that meaning clear:

- Primary actions use **`ink`** (black button, white text), not red. The one exception stays from `HANDOFF.md`:
  **Deny** in approvals is solid red.
- Brand red appears only as **marks**: the logo tag, the 2 px header rule, the active-nav indicator bar, section labels,
  timeline dots.
- Never put brand red next to a decision badge as decoration.

### Decision colours (light, unchanged from `HANDOFF.md` §4)

`allow #15803d` · `monitor #475569` · `redact #7e22ce` · `pseudonymise #6d28d9` · `sanitize #0f766e` ·
`downgrade #a16207` · `route_local #1d4ed8` · `require_approval #c2410c` · `block #b91c1c` · `critical #be123c`.
Always icon + mono label, never colour alone.

### Dark surfaces

Product screenshots and code blocks on slides are dark, and the dashboard keeps a dark theme. Reuse `HANDOFF.md` §4 dark
tokens (`bg #0e1013`, `surface #15181c`, `border #272c33`, `text #e7e9ec`, `muted #9ba4ae`, terminal `#0f1115`). In
dark mode the accent becomes `#f0554d` (5.4:1 on `#0e1013`).

## 3. Typography

| Role | Font | Weights |
|---|---|---|
| UI, headings, body | **Instrument Sans** (Google Fonts) | 400, 500, 600, 700 |
| IDs, rule IDs, numbers, code, decision labels, timestamps | **IBM Plex Mono** | 400, 500 |

Instrument Sans replaces IBM Plex Sans (closest free match to last year's decks). Keep Plex Mono.

### Slide scale (1280 × 720)

| Style | Size / weight / tracking / line-height |
|---|---|
| Hero wordmark | 230–300 px / 600–700 / −0.03 to −0.045 em / 0.84–1, often outlined (2 px stroke, transparent fill) |
| Statement | 96–108 px / 700 / −0.045 em / 0.95 |
| Slide title | 40–46 px / 600 / −0.02 em / 1.06–1.08 |
| Big number | 52 px / 700 / −0.03 em / 1 |
| Card title | 18–23 px / 700 |
| Body | 15–19 px / 500–600 / 1.4–1.45 |
| Section label | 12–13 px / 600–700 / UPPERCASE / 0.06–0.1 em, in `accent` |
| Mono detail | 11–15 px / 400–500 |

### Dashboard scale (proposed)

| Style | Value |
|---|---|
| Page title | 22 px / 600 / −0.01 em |
| Sidebar sentence (plain-language first line) | 16 px / 500 / 1.45 |
| Section label | 11 px / 700 / UPPERCASE / 0.1 em, `text-muted` (accent only for the active section) |
| Body, table cells | 14 px / 400 / 1.45 (up from 13 px) |
| Mono (IDs, times, numbers) | 12–13 px |
| Stat number (Overview) | 32–40 px / 700 / −0.03 em |

## 4. Layout motifs

| Motif | Spec | Dashboard use |
|---|---|---|
| Header strip | Team left, event right, 13 px / 700; a 2 px accent rule under the right half | Top bar: 2 px accent rule along its bottom edge, right of the logo |
| Footer rule | 2 px accent line, left 440 px, 16 px from the bottom | None |
| Margins | 56 px slide margins, 32 px for chrome | Keep `HANDOFF.md` spacing |
| Cards | White, 1 px `border`, radius 10; emphasis cards 1.5 px `ink` border | Same: tables and sidebars in 1 px `border`, radius 8–10 |
| Numbered items | `01`–`08` in mono, `accent`, above a 1 px `ink` top rule | Feature lists, onboarding steps |
| Timeline | 2 px accent rail, 12 px hollow ring per step (2 px accent), 14 px filled dot for the final step | Session view and decision trace |
| Stat block | 2 px accent top rule, big number, one-line caption | Overview KPIs (without a posture score) |
| Full-bleed red | One slide at a time (problem, closing) or one red panel per slide | Not in the UI |
| Outlined wordmark | Huge text, `-webkit-text-stroke: 2px`, transparent fill | Not in the UI |
| Tilted device mockup | Dark screen with a 10 px bezel, rotated −8° to −10° | Not in the UI |
| Taped note | White card rotated 3°, two translucent tape strips | Not in the UI |

## 5. Components

- **Decision badge:** icon + mono label, tint style from `HANDOFF.md` §3. On white slides: 1.5 px border in the
  decision colour, white fill.
- **Rule chip:** mono 12 px, 1 px border, radius 4, padding 2 × 6; links to the rule in Policies.
- **Placeholder chip:** `<PESEL_1>`, `<IBAN_1>`, `<PERSON_1>` in mono, `pseudonymise` colour.
- **Masked value:** `9203•••••43`, `PL61 •••• 2874`, mono, with bullets, never raw values.
- **Plain-language first line:** every detail view starts with one sentence ("Anna Nowak's prompt contained a PESEL,
  an IBAN and a name…"), filled from a template, never written by an LLM.
- **Buttons:** primary black (`ink`, white text, radius 6, ≥ 34 px); secondary 1 px `border-strong`; destructive
  `accent-text` fill (Deny only).
- **Icons:** 24 px stroke icons, 1.8–2 px, round caps and joins, `currentColor`. No emoji.

## 6. Copy

- Plain English, short sentences, one idea per line.
- Name the rule: every block or hold shows its rule ID in mono (`SEC-FLOW-01`).
- Real numbers only, with the source nearby. Unknowns are `[PLACEHOLDER]`s, never invented figures.
- "Rogatka" in all product copy, never "AI Control Layer" except as the challenge name or logo tag.
- Polish data (PESEL, NIP, IBAN) stays Polish; the UI is English.

## 7. Do / don't

| Do | Don't |
|---|---|
| One accent; red marks and black actions | Red primary buttons in the dashboard (red means block) |
| Lots of white space, thin rules | Gradients, shadows as decoration, coloured card fills |
| Mono for anything a machine produced | Mono for sentences |
| Decision colour + icon + label | Colour alone |
| `accent-text` for small red text | `#e3322b` text under 24 px |
| Dark only for screenshots, code and terminals | Dark cards as decoration on white slides |
