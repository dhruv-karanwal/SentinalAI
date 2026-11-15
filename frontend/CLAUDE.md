# frontend/CLAUDE.md — local rules (root CLAUDE.md is the index)

The analyst console (Wave D). `DESIGN.md` in this folder is the design authority: read it
before changing anything visual, and change it in the same commit as a token or component.

## Commands (from `frontend/`)

```bash
npm install            # react, react-dom, vite, @vitejs/plugin-react, typescript, @fontsource-variable/geist(-mono)
npm run dev            # http://127.0.0.1:5173, proxies /api to the API on 127.0.0.1:8000
npm run typecheck      # tsc --noEmit, strict + noUncheckedIndexedAccess
npm test               # node --test over src/lib/*.test.ts (Node >= 22.18 strips the types)
npm run build          # typecheck + vite build into dist/ (git-ignored)
# screenshots for the per-screen loop (headless Chrome or Edge already on the machine):
node scripts/shots.mjs steps.json ../data/processed/ui-shots   # needs SENTINEL_UI_DEV_PASSWORD
# steps: goto, wait, key, eval, report, theme, density, size, motion (reduced-motion), shot, signin,
#        signout, tabwalk
```

The API must run for the console to show anything: `python -m app.main serve` from `backend/`
with `SENTINEL_JWT_SECRET` set. For UI work use a copy of the stores
(`SENTINEL_DATA_DIR=../data/processed/ui-dev`) so approvals, reports and audit rows made while
testing never land in `data/platform/`. Test accounts and the JWT secret for that copy live in
the git-ignored `.env.ui-dev`; never print or commit them.

## Layout

```
index.html              sets data-theme / data-density before first paint
src/tokens.css          the ONLY file with raw colour values (DESIGN.md section 3)
src/base.css            reset, type, buttons, forms, tags, states, Term (tokens only, like every sheet below)
src/system.css          wave H base components: card, PageHeader, Page, Section, Tabs, Kpi, DefGrid, Disclosure
src/shell.css           rail (grouped, collapsible, drawer on phones), top bar, command palette, menus, chat
src/dash.css            Overview, Executive, Study, charts
src/work.css            Incidents, Alerts, Approvals, Reports, Ask, Audit, Users, Settings, split panes
src/about.css           About product page and its components
src/icons.tsx           the whole icon set (16 px, 1.5 px stroke, currentColor) + SeverityGlyph
src/api.ts              typed client, in-memory token, PERMISSIONS mirror of backend auth.py
src/hooks.ts            AppContext, hash routing (#/screen?id=..&ev=..), useLoad, nav events
src/lib/                pure logic with tests: format, virtual (windowing), bins (strip), highlight,
                        scale (scales, ticks, bins), graph (force layout + graph.fixture.json + placeLabels),
                        contrast (WCAG + CVD simulation + OKLab), study, explain (glossary search, whatHappened, incident labels, folded runs),
                        motion (easing, stepper), chat (reducer, focus trap, error notes, storage),
                        nav (rail groups, palette ranking), flow (About pipeline marks); guard.test.ts = style guard
src/content/            glossary.ts (the ONE glossary: Term tooltips, About, chat fallback) and about.ts
                        (pipeline stages, study question, screen guide, limits, tour stops, suggested questions)
src/charts/             SVG charts: ChartFrame (question, legend, tooltip, hidden table), TimeBars, Bars
                        (HBars, StackedHBars, DotPairs, MiniBar), Attack (HeatStrip, ChainStrip, Lanes), EntityGraph
src/components/         DataTable, SplitPane, TimeStrip (canvas), EvidencePane, Findings, ui, AlertQueryTable,
                        AlertRunsTable (folded repeats), CommandPalette (Ctrl+K: search, navigation, actions),
                        GlobalSearch, Notifications, Term (+ Explain), Tour, HelpChat (floating button + panel),
                        motion (Reveal, useSeen, DrawOnView), narrow (phone-width columns), about/ (MiniView,
                        PipelineFlow, StudyDiagram, VerifierDemo)
src/screens/            About, Overview, Incidents, Alerts, Approvals, Reports, Ask, Executive, Study, Audit, Users,
                        Entity, Settings (+ SecurityNotes), ErrorPage, SignIn
src/App.tsx             shell (top bar, rail), global shortcuts, toasts, ScreenBoundary
scripts/shots.mjs       DevTools-protocol screenshot runner (no dependency)
```

## Rules

- **Charts** go through `ChartFrame` (question line, legend, tooltip, hidden table) and the scales in
  `lib/scale.ts`; colours only from `TONE_VAR` (tokens). A chart that cannot state the decision it
  supports does not ship. Counts are printed in heat cells; detector edges carry a dash pattern.
- **No new dependencies** without the user's say: no UI kit, CSS framework, chart, router,
  virtualisation or icon package. The table, strip and router are written here on purpose.
- **Untrusted text.** Alert fields, log lines, rule names and model output are rendered as text
  nodes only. Never `dangerouslySetInnerHTML`, never Markdown or HTML rendering, never turn log
  text into links. Highlighting goes through `splitHighlight` and `<mark>`.
- **Tokens only.** No hex value outside `tokens.css` (enforced by `lib/palette.test.ts`, which also rejects blue hues and
  checks detector / severity / accent separation under simulated colour-blindness). A new colour needs a contrast
  measurement (4.5:1 text, 3:1 control) on bg, surface, raised and selected, in both themes,
  recorded in DESIGN.md.
- **Never colour alone:** severity = glyph + word, detector = mark + name, verifier status = tag
  + text. Severity and detector identity are the only saturated colours; the accent is ink
  (a neutral, DESIGN.md 3; `palette.test.ts` checks its chroma) for focus, links and the primary action,
  never a data colour in a chart.
- **Tables:** every list goes through `DataTable` (fixed row height from the density setting,
  windowed). Column tracks must fit the pane at 1366 px: fixed px tracks plus `minmax(0, 1fr)`;
  a `minmax(96px, ...)` track overflows the row. Check `scrollWidth > clientWidth` on `.dt-row`.
- **Keyboard:** the screen's main table takes `primary` (j / k / Enter / c from anywhere).
  Selecting a row must not move focus out of the table; focus moves to a detail only on Enter or
  from a citation link (`focusKey` on `EvidencePane`).
- **States:** every data view has skeleton, empty (says what fills it), empty-after-filter,
  error (status + API message + Retry, previous data kept), forbidden and, where a model is
  needed, model offline. No spinner over a blank page; `ScreenBoundary` catches render errors.
- **Honest numbers:** counts come from the API with thousands separators and units; times are
  UTC ISO with the relative time in the hover text. No placeholder data in the app. The console
  shows platform outputs only: no labels. The Study page is the one exception for study numbers: it
  renders run-level aggregates from `scores.json` (never per-case or per-alert labels), with the
  "dev scenarios, pilot numbers, not paper results" banner.
- **Restraint** (DESIGN.md 2; `lib/guard.test.ts` checks every stylesheet and inline style): no grain,
  glass / `backdrop-filter`, glow, pulse, gradient, tilt, count-up or `infinite` animation; the only shadow
  is `var(--shadow-overlay)` on floating layers; font sizes, radii, durations and easing only from tokens.
  Motion is 150-250 ms, `transform` / `opacity`, each animation once, nothing in Incidents / Alerts beyond
  hover, tab change and panel enter, off under `prefers-reduced-motion`. Use `Reveal`, `useSeen`,
  `DrawOnView` from `components/motion.tsx`. No animation library.
- **Page pattern** (DESIGN.md 4): every screen starts with `PageHeader` (title, the one question it
  answers, actions right); secondary detail goes behind `Tabs` or `Disclosure`, never stacked; one card
  style, never a card in a card; one primary button per view.
- The session token is kept in memory (a reload signs out). Theme, density, time format, split
  position, the chosen and default data source, the overview log toggle and saved alert filters are
  the only things in `localStorage`.
- Changing theme or density sets the `<html>` attribute *before* the React state, because the
  canvas strip reads tokens in an effect that runs before the parent's effects.
- The permission table in `api.ts` only decides what to show; the API decides what is allowed,
  and a 403 is displayed.

- **Explain, don't decorate** (DESIGN.md 12): a new term goes into `content/glossary.ts` (definition at
  most two sentences, "why it matters here"), never inline in a screen; new sections get a What / Why
  pair. The "What happened" sentence and incident labels are deterministic (`lib/explain.ts`), never
  model output. A screen that the help chat should understand publishes a plain-text summary with
  `useScreenContext`; it holds only numbers the screen already shows.
- **Help chat and the model:** the status dot only calls `GET /copilot/status` (lists models, never
  generates); answers only `POST /copilot/ask` with `mode: "explain"` (one request, <= 300
  output tokens, 429 when busy). Never test it against the real model while a pilot runs; screenshots
  of the online state use a fetch mock labelled MOCK FOR SCREENSHOT.
- The chat's open state, size and last 40 messages are in `sessionStorage` (`sentinel.chat`).
- Demo mode (`sentinel.demo`, on unless set to 0), the Overview detail tab (`sentinel.overview.tab`) and
  the collapsed rail (`sentinel.rail`) are also in `localStorage`.

## Gotchas

- Overview and Executive read `/overview` and `/executive` (aggregates only); the first call after an
  API restart builds the scenario index (2.5-4.4 s on the dev stores), so the page shows its skeleton.
- `GET /incidents?scenario=...` returns every incident with its full timeline (7.8 MB for
  russellmitchell, 11.5 MB for shaw on the dev stores). Fine locally; a summary endpoint is the
  fix if it ever matters.
- `/alerts` pages at most 500 rows and has no total: the Alerts footer takes the total from
  `/alerts/stats` and only when no host filter is set. Server order is time ascending; the list
  is not client-sortable because only part of it is loaded.
- The copilot returns verifier detail (`claims`, `dropped_citations`, `dropped_claims`); the
  `Finding` component still copes with an API that sends counts only.
- Vite serves an intermediate file state if two writes to one module land within its watcher
  debounce; if a screen breaks after a scripted edit, reload once before debugging.
- The facet sidebar styles every `button` as a full-width grid row; a `<Term>` "?" inside a facet or
  legend needs the reset in `base.css` (`.facet .term-q`).
- `TimeBars` labels its y axis "<unit> per <bin>"; `unit` defaults to `alerts`, so a chart of anything
  else (Audit: `entries`) must pass it. Durations from `fmtDuration` / `fmtStep` use no-break spaces
  (` `) between number and unit; tests compare with that character.
- `Dialog` closes through the native `<dialog>` (`ref.current.close()`, Esc), so the browser returns
  focus to the opener; never unmount an open dialog directly.
- Sign out sits in the user menu (`.user-btn`): `shots.mjs` opens the menu and waits a render before
  clicking it.
- Below 700 px (`useNarrow`) list and detail stack and tables drop secondary columns; on Alerts the
  table scrolls inside its pane under the facets. Users is admin-only (`user.manage`): a manager
  sees "No such page".
- `element.focus()` from a script does not open a `<Term>` tooltip in headless Chrome (no focus
  event without a focused window); test it with a real Tab key press (`shots.mjs` `key` step).
- The in-app Browser pane scales a 1366 px viewport down to its own width, so its screenshots
  are too small to judge type; use `scripts/shots.mjs` for the visual loop.
- Another session may own the dev pair on 5173 / 8000. For a second pair, run the API with
  `serve --port 8001` and Vite with `SENTINEL_API_URL=http://127.0.0.1:8001` on 5174, and point
  `shots.mjs` at it with `SENTINEL_UI_URL`.
- `shots.mjs` keeps `sessionStorage` between steps: clear `sentinel.chat` before a chat step, or a
  click on the button may close a panel restored by the previous step.
