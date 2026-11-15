# DESIGN.md — SentinelAI console design system

The design authority for `frontend/`. Rewritten for wave H (2026-11-14, branch
`phase3/wave-h-premium`); it replaces the layered v1 / v2 / explainable / motion / palette
sections of the earlier file (history: `git log -- frontend/DESIGN.md`, `docs/session-notes.md`).
Change this file in the same commit as a token or a base component.

Quality bar: a console that would pass as a shipped product from a design-led company. The way
there is restraint. Typography, spacing and alignment carry the design; colour is reserved for
meaning; nothing moves unless the movement explains something.

## 1. Audit of the wave G console (what was wrong)

Source: the wave G screenshot set of every screen in both themes (`docs/ui/wave-g/`, taken from the
same code as `main` at the start of this wave) and a read of the four stylesheets. The patterns that
made the console read as generated:

| Pattern | Where it was |
|---|---|
| Grain / fine-line texture | every screen (fixed body background layer) |
| Glass (translucent panels, `backdrop-filter`) | top bar, tour, toasts, chat panel; translucent blocks on Overview and About |
| Decorative glow | primary button hover, chat button, Overview "look first" cards, About stage rings, High glyph |
| Pulse (looping) | High severity glyph outside tables, chat button ring, About stage wave and packets |
| Shimmer (looping) | every skeleton |
| Hover tilt | About screen cards |
| Count-up numbers | Overview status row, About hero counters |
| Spring / overshoot easing | chat panel, floating layers |
| More than one accent | lime (logo, nav, buttons, links, focus, chat) next to red, amber, green, teal, copper, rose; lime links inside data tables |
| Mono caps kickers ("01 · THE PROBLEM") | About sections |
| Centred hero cliches | About hero: big title, six ringed nodes, three counter cards, two buttons |
| Cards inside cards | Overview "look first" cards inside a chart block; About counters inside the hero panel; Executive tiles inside sections |
| Too many borders | Overview: every block boxed, plus boxed status cells, boxed legends; Incidents detail: six stacked bordered strips before the tabs; dashed "demo data" badge |
| Uneven radii | 2 px controls, 4 px panes, 10-12 px About panels, round chat button, pill chips |
| Inconsistent spacing | page padding 12 / 16 / 24 by screen; block gaps 8 / 12 / 16; About uses its own scale |
| No page pattern | titles at four sizes and positions; Overview title shares a line with mono metadata; Incidents has no title row at all |
| Stacked secondary detail | Overview: What / Why paragraphs under every chart, then "More detail" with five more charts; Incidents: summary, why-severity, entities, strip all above the tabs |
| System fonts | Segoe UI / Consolas: no typographic identity; numbers in mono bold in the middle of sans text |
| Flat navigation | twelve rail items in one list with no grouping; search and navigation are separate |

Per screen:

- **Sign in**: grain, boxed schematic of six bordered stages (borders on borders), lime button.
- **About**: every pattern in the table except tables: kickers, ringed glowing nodes, looping packets,
  counter cards in a panel, tilt cards, spring reveals, its own radii and spacing.
- **Overview**: count-up, glowing cards with a coloured edge, four boxed status cells, What / Why
  text under each chart, legend chips, a second page of charts under "More detail".
- **Executive**: tiles in sections (card in card), mixed heading sizes, chart draw-in plus counters.
- **Study**: banner + explainer + selector + empty state stacked with equal weight.
- **Incidents**: no page title; detail header is six bordered strips; chips with borders for every
  fact; pulsing High glyph in the header; 24 px rows with 12 px type feel cramped next to 13 px text.
- **Alerts**: facet sidebar where every value is a full-width button row with a bar; three toolbars.
- **Approvals / Reports / Audit / Users / Settings / Ask**: plain, but each has its own header layout,
  button sizes (24 px) and paddings; forms use raised-fill inputs with strong borders everywhere.
- **Chat**: 52 px lime button with a pulse ring and glow; glass panel that springs open.

## 2. Principles

1. **Restraint.** No grain, scanline, glass blur, glow, pulse, tilt, gradient, gradient text or
   count-up. An effect that carries no information is removed, not toned down.
2. **Type carries the design.** One UI family and one mono family, six sizes, tabular numerals,
   tight tracking on headings, sentence case everywhere (no upper-case labels).
3. **One page pattern.** Title, the one question the screen answers, primary action on the right;
   then sections with headers; secondary detail behind tabs or a disclosure, never stacked.
4. **Colour means something.** Neutral surfaces; severity and detector identity are the only hues.
   The accent is ink (section 3).
5. **One of each.** One radius scale, one button hierarchy, one card, one table, one icon set.
6. **Motion with purpose.** 150-250 ms, one curve, each animation once. Nothing loops.

## 3. Tokens (`src/tokens.css`, the only file with raw colours and sizes)

### Colour

Three elevation levels, `--bg` < `--surface` < `--raised`, plus `--selected`. Regions are separated
by one hairline (`--border`); surfaces in the page flow have **no shadow**. The single shadow token
`--shadow-overlay` is for floating layers only (menu, dialog, command palette, chat panel, toast);
they keep the hairline too, because a shadow alone disappears on the dark theme.

| Token | Dark | Light | Use |
|---|---|---|---|
| `--bg` | `#151311` | `#f3f0e8` | page |
| `--surface` | `#1d1a17` | `#fbf9f4` | cards, panes, tables, inputs |
| `--raised` | `#26221e` | `#ece8de` | hover, table header, skeleton |
| `--selected` | `#322d26` | `#e7e1d1` | selected row, pressed toggle |
| `--border` | `#332f2a` | `#ddd7ca` | hairlines (separation only) |
| `--border-strong` | `#7d766b` | `#7a7266` | input outlines, hover outlines (>= 3:1) |
| `--text` / `--text-muted` / `--text-faint` | `#ece8df` / `#a39d91` / `#9a9488` | `#1b1815` / `#514b43` / `#625b52` | text (all >= 4.5:1 on the four surfaces) |
| `--accent` / `--on-accent` | `#f4f1ea` / `#151311` | `#1b1815` / `#fbf9f4` | primary button, focus ring, active tab / nav mark |
| `--sev-high` / `-medium` / `-low` | `#ff6b57` / `#e8a33a` / `#a39a8c` | `#9b1036` / `#8a5a00` / `#5e574e` | severity; High also error / dropped |
| `--verified`, `--online` | `#46c46a` | `#0b6a4a` | verifier kept; model reachable dot |
| `--det-wazuh` / `-suricata` / `-aminer` / `-sigma` | `#f08a4b` / `#f7b3d6` / `#2fa89f` / `#a39d91` | `#a3440a` / `#6b1d49` / `#04687a` / `#625b52` | detector identity |
| `--heat-1..4` | `#2b2723` .. `#5a5248` | `#e6e1d5` .. `#b3a893` | heat cells: a neutral ramp, the count is printed in every cell |
| `--grid`, `--ref`, `--mark`, `--scrim` | | | gridlines, reference lines, matched span in a log line, dialog backdrop |

**The accent decision.** Wave G used a phosphor lime. At small doses it still read as a second
brand colour competing with six semantic hues (red, amber, green, teal, copper, rose), and its
light-theme olive was muddy. Every free hue is either taken by a semantic colour or banned (blue,
indigo, purple: the palette guard). The quiet accent is therefore **ink**: the highest-contrast
neutral (bone on dark, near-black on light). Primary button = ink fill; focus ring = 2 px ink
outline with 2 px offset; active tab and nav item = ink mark + medium weight on a raised fill;
links = text colour with an underline. Result: any hue on screen is data.

**Never colour alone** (unchanged): severity = glyph + word; detector = mark + name (dash pattern
on graph edges); verifier status = tag + text (strike or dashed rule for dropped). Detector and
severity tokens keep the wave G values, so the measured contrast (>= 4.5:1 on the four surfaces,
both themes) and colour-blind separation (Machado 2009 simulation, OKLab distance, `palette.test.ts`)
still hold. PDF colours (`DETECTOR_PRINT` in `backend/app/outputs/reports.py`) mirror the light
detector tokens.

### Type

- UI: **Geist** (`"Geist Variable"`); data: **Geist Mono** (`"Geist Mono Variable"`). Both are
  open-source (OFL), self-hosted through `@fontsource-variable/*` (imported in `main.tsx`, bundled by
  Vite; no network font request). Mono is for ids, IPs, rule ids, hashes, timestamps and log lines,
  not for ordinary numbers.
- Scale (size / line height): `--fs-micro` 11/16 (column headers, units), `--fs-small` 12/16 (dense
  rows, tags, meta), `--fs-body` 13/20 (body, controls), `--fs-title` 15/24 (section and pane
  titles), `--fs-heading` 20/28 (page title, KPI value), `--fs-display` 32/40 (About hero only).
  No other size.
- Weights 400, 500 (controls, tabs, active items), 600 (headings, KPI values). Headings use
  `--track-tight` (-0.02em). Micro labels use `--track-label` (0.04em) and stay sentence case.
- `font-variant-numeric: tabular-nums` is set on `body`: every number is tabular.

### Space, radius, layout

- Spacing: 4 / 8 scale `--sp-4, 8, 12, 16, 24, 32, 48, 64` (`--sp-2` only for optical gaps inside a
  control). Card padding 16; gap between cards 16; gap between page sections 32; page gutter 24.
- Radius: `--radius-s` 4 (buttons, inputs, tags), `--radius-m` 6 (cards, panes), `--radius-l` 10
  (overlays), `--radius-full` (dots, the chat button). Nothing else.
- Controls 28 px (`--control-h`), large 36 px (`--control-h-lg`: sign-in, About actions, tabs).
  Rows: compact 28 px / 12 px type, comfortable 36 px / 13 px type (`rowHeight` in `App.tsx` must
  match `--row-h`).
- Layout: rail 224 px (collapsed 52 px), top bar 48 px, content max width 1280 px, 12-column grid
  (`.grid-12`, `.col-3 .. .col-12`, 16 px gap; one column below 900 px).
- Supported widths: 1366 px and 390 px with no horizontal page scroll.

### Motion

`--ease` cubic-bezier(0.2, 0, 0, 1) is the only curve. `--dur-fast` 150 ms (hover, press, focus),
`--dur-mid` 200 ms (tabs, accordions, panels, page enter, list rows), `--dur-slow` 250 ms (overlays,
scroll reveals, chart draw-in), `--stagger` 30 ms. Only `opacity` and `transform` animate (plus
colour on hover). Allowed: page and panel enter, short-list row enter (never the windowed tables),
chart draw-in once on first view, tab and accordion change, button press (scale 0.98), scroll
reveals on About, the About pipeline flow (plays once per view, replay on request). Nothing loops:
no `infinite`. `prefers-reduced-motion: reduce` sets every duration to 0 and the last block of
`system.css` switches all animation and transition off.

## 4. Components (base layer: `base.css`, `system.css`, `components/ui.tsx`)

| Component | Rule |
|---|---|
| `PageHeader` | every screen: optional breadcrumb, `h1`, one-line purpose (the question the screen answers), actions right. `bar` variant sits above a split pane |
| `Page`, `Section` | scrolling page with max width; a section = `h2` + optional one-line description + content |
| Buttons | `primary` (ink fill; one per view), default = secondary (hairline, surface), `ghost` (no outline; toolbars, icon buttons), `danger` (secondary in the High colour). `.lg` 36 px. `.segmented` for 2-3 exclusive options |
| Card | `.card`: surface + hairline + 6 px radius + 16 px padding. One style. Never a card inside a card: inside a card use hairline dividers |
| `Kpi` in `.kpi-row` | one card split by hairlines: label, value (20 px, 600), one line of context. No icon, no trend arrow without a trend, no animation |
| `DefGrid` | key facts as label over value (incident header, entity, approval) |
| `Tabs` | underline tabs, roving tabindex, arrow keys; the panel enters with `.tab-enter` |
| `Disclosure` | native `details` with a rotating chevron |
| `DataTable` | the one table: sticky header, fixed row height from density, windowed, hover row, selected row = `--selected` + 2 px mark, footer with count |
| Tags | `SeverityCell` (glyph + word), `DetectorTag` (mark + name), `StatusTag` (hairline tag) |
| States | skeleton (still bars in the shape of the content, `aria-busy`), empty (what fills it), empty after filter (with "Clear filters"), error (status + API message + Retry, old data kept), forbidden, model offline. Designed for every data view |
| `Dialog`, toast | overlay radius, hairline + `--shadow-overlay`, `--scrim` backdrop |
| `Term` | word + "?" with a tooltip (hover and focus); definitions only from `content/glossary.ts` |
| Icons | `icons.tsx` only: 16 px grid, 1.5 px stroke, round caps, `currentColor`. No emoji, no filled glyphs except the severity bars |

Charts (`src/charts/`, `ChartFrame`): each states the decision it supports as its question line;
labelled axes with units; legend with mark + name; tooltip on hover and focus (text nodes only);
a visually hidden table with the same numbers; draw-in once. No pie, no 3D, no gradient fill, no
looping. Bars per bin for alert volume (a line would interpolate between bins that do not exist).

## 5. Information architecture

Rail, grouped and collapsible, items the role cannot use are not rendered:

- **Understand**: About, Study
- **Monitor**: Overview, Executive
- **Investigate**: Incidents, Alerts, Ask
- **Respond**: Approvals, Reports
- **Govern**: Audit, Users, Settings

Top bar: brand, data source, command palette trigger, notifications, user menu. **Command palette**
(Ctrl+K, also `s`): one input that merges global search (alert id, IP, rule id, incident id),
navigation (every screen) and actions (theme, density, tour, sign out); arrow keys, Enter, Esc;
focus trapped, returns to the opener.

Screens (each answers one question, stated in its header):

| Screen | Question | Structure |
|---|---|---|
| About | What is this system and how far has the study got? | product page (section 7) |
| Study | What do the finished runs say so far? | status, then runs by study part in tabs |
| Overview | What needs attention right now? | KPI row; one primary chart (alerts over time); "Incidents to look at first" as a list; the rest in tabs (ATT&CK, entities, detectors, kill chain, alerts) |
| Executive | Is the situation under control? | KPI row, trend, top risks, print layout |
| Incidents | Which incident do I open, and what happened in it? | master-detail: list left; detail = header (severity, what happened, definition grid of key facts), time strip, tabs (alerts and evidence, ATT&CK, graph, findings, response) |
| Alerts | Which alerts match? | facets left, folded table, evidence right |
| Ask | What does the model say, and what did the verifier keep? | question, answers with citations |
| Approvals | What is waiting for a second person? | queue + detail with the rules stated before the controls |
| Reports | What was written up? | list + preview tabs + downloads |
| Audit | Who did what? | filters, activity chart, table |
| Users, Settings | | forms in sections |

Exempt from `PageHeader`: About (its hero is the header, section 7), the error page (a single
message and a way back) and Sign in (no shell).

Kept from earlier waves, restyled only: glossary and `<Term>`, the deterministic "What happened"
sentence, folded alert repeats, distinct incident labels, data vs created dates, the six-stop tour,
Professor demo mode, notifications, keyboard shortcuts (`j` / `k` / Enter / Esc / `/` / `?` / `g x` /
`c` / `d` / `t`), skip link, role-based rendering, all states of section 4.

## 6. Time strip, tables and performance

The incident time strip stays a `<canvas>` of binned counts per detector with a hidden table; the
ATT&CK lanes are binned; the entity graph is capped at 60 nodes before layout; tables are windowed.
The 11,208-alert incident must stay responsive (frame time recorded in `docs/session-notes.md`).
Nothing in Incidents or Alerts animates beyond hover, tab change and panel enter.

## 7. About as a product page

Sections, with a sticky section nav and quiet scroll reveals: hero (one sentence, one supporting
line, a live mini-view of the product fed by the API, two actions); "How it works" as a flow where
alerts move once through the five stages and each stage expands on click; the study as an
interactive diagram (alert source switch, the fixed agent, the four arms); the verifier demo on a
labelled SAMPLE line; a feature grid by category (Detect, Investigate, Respond, Govern); honest
results status and limits; the glossary. Every number comes from the API; schematic parts are
labelled SCHEMATIC, sample text SAMPLE. No number is invented and results never show before a real
run exists.

## 8. Floating help chat

A round button bottom right (ink fill, no pulse, no glow) with a status dot (`--online` reachable,
amber busy, grey glossary only) and an unread count; the panel is an overlay (radius `--radius-l`,
hairline + `--shadow-overlay`), enters with fade-rise, traps focus, Esc closes and returns focus.
Offline it answers from the glossary and says so. Bottom sheet below 640 px.

## 9. Safety and data rules in the UI (unchanged)

- Alert fields, log lines, rule names and model output are untrusted: text nodes only, no
  `dangerouslySetInnerHTML`, no Markdown or HTML rendering, no links made from log text;
  highlighting through `splitHighlight` and `<mark>`.
- Platform outputs only: no labels, phases or per-case scores. Study shows run-level aggregates
  from `scores.json` with the "dev scenarios, pilot numbers, not paper results" banner.
- Numbers come from the API with thousands separators and units; times are UTC. No placeholder data.
- The JWT lives in memory. Passwords are never typed for other users in the browser.
- Nothing executes without an approved approval; the executor is simulated and says so.

## 10. Guards (tests in `src/lib/`)

- `palette.test.ts`, `charts.test.ts`: contrast of every text-like token on the four surfaces in
  both themes; colour-blind separation of detector and severity colours; no raw colour outside
  `tokens.css`; no blue / indigo / purple hue in it.
- `guard.test.ts`: fails on banned effects in any stylesheet: `backdrop-filter`, blur or
  drop-shadow filters, `infinite` animations, any `box-shadow` other than `var(--shadow-overlay)`
  or a zero-blur hairline, gradients, `background-clip: text`, a `font-size`, `border-radius` or
  duration that is not a token.

## 11. Checklist per screen

1. Header pattern present; the screen's question is stated in one line.
2. One primary button at most; one card style; no card in a card.
3. Only the six type sizes; numbers tabular; sentence case.
4. Spacing only from the scale; aligned to the 12-column grid.
5. Skeleton, empty, empty-after-filter, error states exist and were looked at.
6. Keyboard-only use works; focus is always visible; tab order follows reading order.
7. Both themes pass contrast; colour is never the only carrier.
8. No horizontal scroll at 1366 px and 390 px; 0 console errors.
9. Nothing loops; reduced motion shows the final state.
10. Untrusted text is escaped; no invented number.

## 12. What the skill returned and what was kept

`ui-ux-pro-max` was run on 2026-11-14 (`--design-system`, density 8, motion 3, variance 2;
`typography` and `ux` searches). Kept: the "Minimalism & Swiss" style family (grid, type, no
ornament), the accessibility requirements (4.5:1 text, keyboard, visible focus, reduced motion),
keyboard navigation with tab order = visual order, skip link, "no emoji as icons". Rejected: the
"Trust & Authority" landing pattern (logo carousel, Contact Sales), the navy + green palette (blue
is banned here), Inter and the Fira / IBM Plex pairings from Google Fonts (the brief asks for a
self-hosted family that is not Inter; Geist + Geist Mono chosen), the GSAP scroll reveal (CSS and
IntersectionObserver cover it without a dependency). The command-palette query returned only
generic keyboard rows; the palette follows the WAI-ARIA combobox / listbox pattern instead.

Stack: React 19 + TypeScript + Vite 8, plain CSS with tokens, no UI kit, no chart, router,
virtualisation, icon or animation library. The only runtime dependencies besides React are the two
`@fontsource-variable` font packages (added in wave H with the user's brief).
