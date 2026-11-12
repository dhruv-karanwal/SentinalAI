# DESIGN.md — SentinelAI analyst console

Design spec for the Wave D dashboard. Written before any markup (2026-11-10). The UI design
brief from the user is the authority; where the `ui-ux-pro-max` skill output disagrees with the
brief, the brief wins (section 9 lists what was taken and what was rejected).

Keep this file and `frontend/CLAUDE.md` in step with the code: a token or component change is
made here in the same commit.

## 1. Users and tasks

| Role (API role) | Task | What they need first |
|---|---|---|
| SOC analyst (`analyst`) | Triage the incident queue, open an incident, read the evidence, set status, request an action, ask the copilot | The highest-severity open incident; then its alerts, raw log lines and findings without leaving the page |
| Manager (`manager`, `admin`) | Review pending approvals (four-eyes: cannot decide own request), decide with a reason, execute once, read the audit log | Pending approvals with requester, action, target and incident; the evidence behind the request |
| Executive (`executive`) | Read incident status and reports. Read-only, no raw records (`read.raw` is not granted) | Open incidents by severity and status; report downloads |

The UI shows only what the role may do. A control the role cannot use is not rendered (not
disabled-and-mysterious); a 403 from the API is shown as an error state, never swallowed.

## 2. Screens and information hierarchy

Shell on every screen: left rail (text labels with a 16 px icon: Incidents, Alerts, Approvals,
Reports, Ask, Audit; Ask and Audit only for roles that may use them) and a slim top bar (data
source selector with its stored alert count, user and role, density toggle, theme toggle,
shortcut list, sign out). No breadcrumbs. Skip link to main content is the first tab stop.

1. **Incidents** (landing page). Split pane.
   - Left: incident table. Default sort: severity (High first), then status (open first), then
     `last_ts` descending; the top row is selected on load. Columns: severity, status, last seen
     (UTC), alerts, duration, first entity (+n). The id, first seen and detectors are in the
     detail (the list pane is about 590 px wide at 1366 px). Filters: severity buttons with
     counts, status, text filter on id / host / IP.
   - Right: incident detail for the selected row.
     1. Header: severity, status control, id (copy), time range, alert count, triage gap used.
     2. Time-axis strip (section 6).
     3. Three tabs under the strip:
        - **Alerts and evidence**: the incident's alerts (windowed table, sortable, filtered by
          the strip's time range; "Group by rule" turns the 11,208-alert burst into a short
          list of rules with counts). Selecting an alert opens its evidence *below* the table,
          log lines first, then fields, so the list stays in view and the arrow keys walk
          through evidence.
        - **Findings**: the question box and the copilot's answers for this incident: cited
          alert ids as links into the evidence, verified claims, and everything the verifier
          dropped with its reason. Model offline state when no endpoint is configured.
        - **Response**: the incident's report (created on request), ATT&CK techniques (native
          ids and the fixed rule table only), playbook recommendations with "Request approval",
          and the approval requests of this incident.
   - Esc closes the evidence. Evidence is never a page navigation.
2. **Alerts**. Split pane: alert table (time, detector, severity as the detector reports it,
   rule id, rule name, host, source IP) with detector / host / time filters and full-text search
   (`/alerts/search`); right: the evidence view of the selected alert.
3. **Approvals**. Table: status, action, target, incident, requested by, requested at (UTC),
   decided by, executed at. Detail pane: the request, the incident link, decision form (reason
   required), execute button (approved only, once). States the executor is simulated.
4. **Reports**. Table of reports; detail has three tabs (techniques and actions, timeline with
   the evidence below the table, citations) and JSON / CSV / PDF downloads.
5. **Ask** (copilot). The questions asked in this session (memory only) with their answers,
   the same citation links and verifier markings as the Findings tab, evidence in a side
   overlay. "Model offline" state when no endpoint is configured.
6. **Audit** (manager, admin). Read-only table: time, user, role, action, target.
7. **Sign in**. Username and password form; errors next to the field; no decoration.

v1 had no overview page. v2 (section 11) adds one, but it is a page of decision charts over
the stored alerts and incidents, not stat cards: one compact status row, then charts that each
link to a filtered table. Counts still also live where they are acted on.

## 3. Tokens

Tokens are CSS custom properties on `:root[data-theme="dark"]` (default) and
`:root[data-theme="light"]`. Components use tokens only; no raw hex outside `tokens.css`.

### Colour

| Token | Dark | Light | Use |
|---|---|---|---|
| `--bg` | `#0f1113` | `#f6f7f8` | page |
| `--surface` | `#15181b` | `#ffffff` | panes, tables |
| `--raised` | `#1c2024` | `#eceef1` | row hover, table header, inputs |
| `--selected` | `#1f2a3a` | `#dde8f8` | selected row (plus a 2 px accent bar at the row start) |
| `--border` | `#2a2f35` | `#d5d9de` | 1 px hairlines between regions (separators, not controls) |
| `--border-strong` | `#6f7883` | `#77818c` | control outlines (inputs, buttons, toggles) |
| `--text` | `#e3e6ea` | `#1b1f24` | primary text |
| `--text-muted` | `#a3abb5` | `#4a545f` | secondary text, column headers |
| `--text-faint` | `#8a939e` | `#5d6772` | units, placeholders, timestamps' relative part |
| `--accent` | `#5b9dff` | `#1f5fbf` | focus ring, primary action, links, selection bar. Nothing else |
| `--on-accent` | `#0b1220` | `#ffffff` | text on a primary button |
| `--sev-high` | `#f0624d` | `#b42318` | severity High; also destructive / error text |
| `--sev-medium` | `#e0a030` | `#8a5600` | severity Medium |
| `--sev-low` | `#8f9aa6` | `#56606b` | severity Low |
| `--det-wazuh` | `#2bb39a` | `#086a58` | detector identity |
| `--det-suricata` | `#d18ab8` | `#a3407a` | detector identity |
| `--det-aminer` | `#d9c74a` | `#756600` | detector identity |
| `--det-sigma` | `#9aa3ad` | `#5c6670` | detector identity (hollow mark) |
| `--mark` | `#4a3d0c` | `#ffe58a` | highlighted matched span in a log line (plus an underline in `--sev-medium`) |

Measured contrast (WCAG 2 relative luminance, computed 2026-11-10 for every text-like token on
`--bg`, `--surface`, `--raised` and `--selected`):

- Text tokens, accent, severity and detector colours: minimum 4.52:1 dark (`--sev-high` on
  `--selected`), 4.64:1 light (`--det-aminer` on `--selected`). All >= 4.5:1.
- `--on-accent` on `--accent`: 6.88 dark, 6.09 light. `--text` on `--mark`: 8.54 / 13.27.
- `--border-strong` against the three surfaces: minimum 3.66 dark, 3.41 light (>= 3:1).
- `--border` hairlines are 1.3-1.4:1 by design: they separate regions and carry no information.

Not yet checked: a colour-vision-deficiency simulation. Detector hues are taken from the
Okabe-Ito family (bluish green, reddish purple, yellow, plus a neutral), and no colour is the
only carrier of meaning (below); run a CVD simulation on the first rendered screenshots.

**Never colour alone.**
- Severity = glyph + word. High: three stacked bars filled; Medium: two of three; Low: one of
  three (the `sev-*` icons), always followed by the word. It is the first column, so position
  also carries it.
- Detector = its own row in the strip (labelled) and a text label in tables. Sigma ticks are
  hollow.
- Verifier status = text tag ("dropped: quote not found in log line") and a strike or dashed
  rule, not a colour change alone.

### Type

- Sans: `system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif`.
- Mono: `ui-monospace, Consolas, Menlo, monospace`. Used for alert ids, incident ids, IPs, rule
  ids, hashes, timestamps and every log line.
- No web fonts, no font files.
- Scale (px / line height): 11/16 (column headers, units; upper case not used), 12/16 (compact
  table rows, tags), 13/20 (default body and comfortable rows), 14/20 (pane titles), 16/24
  (screen title). Weights 400 and 600 only.
- `font-variant-numeric: tabular-nums` on every numeric column and on timestamps.

### Spacing, radius, elevation, motion

- Spacing scale: 2, 4, 8, 12, 16, 24 px. Nothing larger inside the app frame.
- Row height: compact 24 px, comfortable 32 px (density toggle, stored per user in
  `localStorage`). Fixed row heights are what the virtualiser relies on.
- Radius: 2 px (tags, inputs, buttons), 4 px (panes, menus, dialog). Nothing rounder.
- Borders: 1 px hairlines. Shadow: none, except one `0 1px 2px rgb(0 0 0 / 0.3)` on floating
  layers (menu, dialog, toast).
- Motion: 100 ms `ease-out` for hover, focus and pane open; nothing above 150 ms; no animated
  counters; skeletons do not shimmer. `prefers-reduced-motion: reduce` sets all durations to 0.
- Focus: 2 px `--accent` outline with 1 px offset on every focusable element; never removed.
- Layout: rail 176 px (56 px below 1024 px), top bar 36 px, split per screen (Incidents
  50 / 50, Alerts 60 / 40, Reports 34 / 66) with a draggable, keyboard-operable divider whose
  position is remembered. Minimum supported width 1366 px with no horizontal scroll;
  below 1024 px the detail pane takes the full width (no phone layout is promised).

## 4. Components

| Component | Notes |
|---|---|
| `AppShell`, `Rail`, `TopBar` | rail items are links with `aria-current` |
| `DataTable` | sticky header, fixed column widths (`table-layout: fixed` semantics on a grid), sortable headers (`aria-sort`), row hover, single selection, own fixed-row-height virtualiser (only visible rows + overscan in the DOM), footer with row count |
| `SplitPane` | list / detail; divider is a `separator` with arrow-key resize |
| `EvidencePane` | log lines first (span highlight with `<mark>`, copy per line, cut at 600 characters with "Show all"), then alert fields, then the raw alert JSON collapsed |
| `TimeStrip` | section 6 |
| `Finding` | text, citation links, claim list with verifier status |
| `SeverityCell`, `DetectorTag`, `StatusTag` | glyph or mark + text |
| `Time` | absolute UTC ISO (`2022-01-24T03:01:07Z`), relative time in `title` and on focus |
| `Mono`, `CopyButton`, `Truncate` | truncation with click to expand; copy for ids and log lines |
| `FilterBar`, `SearchInput` | `/` focuses search |
| `Button` (primary, default, danger), `Select`, `TextInput`, `Textarea`, `Toggle` | visible labels; errors under the field with `aria-describedby` |
| `Dialog` | decision reason, confirm execute; focus trapped, Esc closes |
| `ShortcutHelp` | `?` opens the list |
| `SkeletonRows`, `EmptyState`, `ErrorState`, `ErrorNotice`, `ModelOffline`, `ScreenBoundary` | section 5; the boundary replaces a screen that throws while rendering |
| `Toast` | `role="status"`; errors use `role="alert"` |
| `Icon` | one file, `icons.tsx`: about 20 hand-authored inline SVGs, 16 px, 1.5 px stroke, `currentColor`, `aria-hidden` unless it is the only label |

Keyboard (global unless a text field has focus): `j` / `k` or arrow keys move the row
selection, `Enter` moves focus to the detail of the selected row or opens a citation, `Esc` closes the evidence pane or dialog, `/`
focuses search, `?` shows shortcuts, `g i` / `g a` / `g p` / `g r` go to Incidents / Alerts /
Approvals / Reports, `c` copies the selected id, `d` toggles density, `t` toggles the theme.
Tab order follows the reading order: skip link, top bar, rail, list (filters, table), divider,
detail. A table is one tab stop; its sortable headers are buttons after it.

## 5. States

Every screen implements all of these; copy is plain and literal.

| State | Behaviour | Example copy |
|---|---|---|
| Loading | skeleton rows with the table's own column widths and row height, `aria-busy`; never a spinner over a blank page | (no text) |
| Empty | one line saying what is missing and the command or action that fills it | "No incidents for russellmitchell. Run triage (Incidents > Build) or `app.main triage --scenario russellmitchell`." |
| Empty after filter | says the filter caused it, with "Clear filters" | "No alerts match detector = suricata, host = 10.143.2.4." |
| Error | HTTP status, the API's message, a Retry button; the previous data stays visible if there is any | "Could not load incidents: 503 from /incidents. Retry" |
| Forbidden | which permission is missing | "Your role (executive) cannot read raw alert records." |
| Session expired | 401 returns to Sign in and keeps the current location | "Session expired. Sign in again." |
| Model offline | shown wherever findings or Ask need a model; the rest of the screen works | "No model endpoint is configured. Findings and Ask are unavailable; alerts, incidents and evidence are not affected." |
| Truncated | whenever the API caps a list (reports: 500 timeline rows) | "Showing 500 of 11,208 rows (10,708 omitted by the report limit)." |
| Simulated | on every approval execution | "Simulated: no connector is called." |

## 6. Time-axis strip

Above the findings in incident detail. One labelled row per detector present (Wazuh, Suricata,
AMiner, Sigma), a shared UTC axis with start, end and duration printed in mono. Alerts are
1 px ticks in the detector colour; when more than one alert falls on a pixel column the column
is drawn as a bar whose height is the count (log scale, scale stated in the axis label), so an
11,208-alert burst is one canvas pass over binned counts, not 11,208 nodes. Drawn on a
`<canvas>` with a visually hidden table of the same bins for screen readers. Drag or
shift+arrow selects a time range and filters the alert table below; activating a tick selects
that alert in the table. It exists to show bursts and gaps; it has no other decoration.

## 7. Safety and data rules in the UI

- Log lines, rule names and every other field from alerts are untrusted text: rendered as text
  nodes only. No `dangerouslySetInnerHTML`, no HTML or Markdown rendering of alert or model
  output; highlighting splits the string and wraps the match in `<mark>`. URLs in log text are
  not turned into links.
- The UI shows platform outputs only. It never shows labels, phases or study scores, and it
  never talks to held-out scenarios (the API already enforces dev-only replay).
- Numbers come from the API. No placeholder figures, no lorem ipsum; fixtures used for
  screenshots are named `synthetic_*` and labelled SYNTHETIC on screen.
- The JWT is kept in memory (lost on reload) rather than `localStorage`.
- Counts use thousands separators (`11,208`); durations and sizes always carry a unit.

## 8. Checklist (run per screen, result recorded in `docs/session-notes.md`)

1. A first-time analyst finds the highest-severity open incident in under 5 seconds.
2. Keyboard-only use works.
3. Focus is always visible.
4. No horizontal scroll at 1366 px width.
5. Large lists (10,000+ rows) stay responsive.
6. Untrusted log text is escaped.
7. Both themes pass contrast.
8. Nothing on the screen exists only for decoration.
9. No item from the brief's "Avoid" list is present.
10. (v2) Every chart has a text alternative (hidden table) and states the decision it supports.
11. (v2) Colour is never the only encoding (glyph, word, dash pattern, shape or printed count).
12. (v2) A 10,000-alert incident renders its detail in under 2 seconds.
13. (v2) The chart module has unit tests for scales, ticks and edge cases (empty, one point, huge).
14. (v2) Log and rule text stays escaped in tooltips (text nodes only).

Loop per screen: build, render a screenshot with `scripts/shots.mjs` (Playwright is not
installed; the script drives the headless Chrome or Edge already on the machine and also prints
horizontal-scroll, row-overflow, DOM-size and Tab-order checks), critique against the list, fix,
re-render; at most 3 passes. Results: `docs/session-notes.md`.

## 9. What the skill returned and what was kept

`ui-ux-pro-max` was run on 2026-11-10 (`--design-system` with density 9, motion 1, variance 2,
plus `ux`, `chart` and `react` searches).

Kept:
- Style family "Minimalism & Swiss": grid-based, functional, high contrast, no ornament.
- Dense spacing scale; accessibility requirements (4.5:1 text, keyboard, visible focus,
  reduced motion); no emoji as icons.
- UX rows: full keyboard operation with tab order = visual order; skip link; never colour
  alone; errors announced (`role="alert"`) and placed at the field; stable skeletons with
  `aria-busy`; empty states that say what to do.
- React row: window long lists; stable ids as keys.
- Chart row: above 10,000 points aggregate to intervals and draw on canvas; give a table
  fallback (applied to the strip).

Rejected, with the reason:
- "Enterprise Gateway" landing pattern (hero, client logos, Contact Sales): not an app pattern.
- Fira Code / Fira Sans from Google Fonts: the brief forbids web fonts and downloads.
- Blue foreground and blue-tinted borders palette: the brief asks for neutral greys with one
  accent; the palette above was built and contrast-measured instead.
- Hover transitions of 150-300 ms and the GSAP scroll reveal: the brief caps motion at 150 ms
  and forbids gratuitous animation.
- Line chart for time data: the strip is a tick / bin plot per detector, which is what shows
  bursts and gaps.
- 44 px touch targets and mobile-first breakpoints: this is a desktop console with 24 / 32 px
  rows; pointer targets are the full row width, and every action has a keyboard path.
- Heroicons / Lucide: the brief asks for a small hand-authored icon set.

## 10. Stack

React 19 + TypeScript + Vite 8, plain CSS with the tokens above (no Tailwind, no component kit,
no chart library, no router, no virtualisation package: `DataTable`, `TimeStrip` and the hash
router are written here). Installed 2026-11-10 after the user's go: 23 packages, 69 MB of
`node_modules`. Pure logic is tested with Node's built-in test runner (no test dependency).

## 11. v2 (2026-11-12): product shell, overview and charts

Brief: "make it look and work like a finished product, informative through graphics". The v1
Incidents screen (dense table, split pane, detector strip) stays the visual reference: same
tokens, same 24 / 32 px rows, same hairlines; v2 adds screens and charts in that language.

### 11.1 Shell

- **Rail** (top to bottom): Overview (default after sign-in; executives land on Executive),
  Incidents, Alerts, Approvals, Reports, Ask, Study, Audit, Users (admin); Settings and Help at
  the bottom. Items the role cannot use are not rendered.
- **Top bar**: brand mark + name, data source with stored count, environment badge
  ("Dataset replay: demo data"), global search (alert id, IP, rule id, incident id; Ctrl+K or
  `s` focuses it), notification bell with a count, user and role, sign out. Density, theme and
  time format live in Settings (the `d` and `t` keys still work).
- **Footer** on every screen: version, data source (AIT-ADS replay, scenario), API status, link
  to the security notes.
- **Page titles**: `<screen> · SentinelAI`; favicon = the brand mark (inline SVG data URL).
- **Brand mark**: original SVG, a shield outline with signal arcs inside; one colour
  (`currentColor`), 16 / 24 / 40 px. No stock icon.
- **Error page**: one `state` block for unknown routes, render errors and API outages, saying
  what happened, what still works, and a link back.

### 11.2 Sign in

Split layout at >= 1024 px: the form column (420 px) on the left, the pipeline schematic on the
right. Form: mark, "SentinelAI", one line ("Security operations console for the AIT-ADS alert
replay"), environment badge, username, password with a show / hide toggle, caps-lock warning
under the field (`getModifierState`), role hint ("Your role comes from your account: analyst,
manager, admin or executive"), errors announced (`role="alert"`): wrong credentials (401), API
unreachable (0), any other status with its message; "Session expired" banner above the form.
Schematic: six boxes Ingest, Normalize, Detect, Investigate, Report, Review joined by arrows,
each with the real component names under it (replay collector, stream; alert normalizer,
enrichment; Wazuh, Suricata, AMiner, Sigma, triage; single agent, LangGraph graph, verifier;
reports JSON / CSV / PDF; approvals four-eyes, audit). Hairline boxes, no gradient, no
illustration, no marketing copy.

### 11.3 Chart rules (every chart)

1. It supports a decision, stated as the chart's question line ("Where did alert volume spike?").
2. Labelled axes with units (alerts, alerts per bin, UTC time, share in %).
3. Direct labels or a legend with mark + name; colour is never the only carrier (detector series
   also differ by stack position and are named in legend and tooltip; severity bars carry the
   glyph and word; graph edges carry a dash pattern per detector).
4. Tooltip with exact values on hover and on keyboard focus; tooltip content is text nodes only
   (log and rule text stays escaped).
5. A visually hidden `<table>` with the same numbers (the text alternative).
6. Both themes through tokens; nothing decorative, no 3D, no pie, no animated counters, no
   gradients, no transitions on data.
7. Empty data says what fills it; one point and huge values render (scales are unit-tested).
8. Every overview chart links to the filtered table under it (click, or Enter on a focused mark).

Chart module: `src/lib/scale.ts` (linear, log, band and time scales, nice ticks, time ticks,
compact numbers; pure, tested), `src/lib/graph.ts` (deterministic force layout: initial
positions from a hash of the node id, fixed iteration count, no randomness; tested),
`src/charts/` (React SVG: `ChartFrame` with question line, legend, tooltip and hidden table;
`TimeBars`, `HBars`, `StackedHBars`, `HeatStrip`, `ChainStrip`, `EntityGraph`, `Lanes`,
`DotPairs`). No chart library, no CDN.

### 11.4 Chart tokens

Detector and severity colours are reused (section 3). New tokens:

| Token | Dark | Light | Use |
|---|---|---|---|
| `--grid` | `#262b31` | `#e3e6ea` | gridlines (separation only, carries no value) |
| `--heat-1` .. `--heat-4` | `#1b2c40` `#1f3d5f` `#244f7e` `#2a62a0` | `#e3edf9` `#c3d8f2` `#9dbfe9` `#76a2dc` | ATT&CK heat cells; the count is printed in every non-empty cell in `--text`, so shade is never alone |
| `--ref` | `#c9ced4` | `#3a4149` | baseline reference lines on the study charts (dashed) |

Contrast of text on the heat steps and of `--ref` on the surfaces is computed by
`src/lib/contrast.test.ts` from the hex values in `tokens.css` (WCAG relative luminance); the
test fails below 4.5:1 for text and 3:1 for marks.

### 11.5 Screens added or changed

- **Overview** (`/overview`): status row (open incidents by severity, alerts stored, oldest
  unreviewed High with its age in the queue, pending approvals), then: alerts over time stacked
  by detector (linear / log toggle, incident-start markers on the time axis, brush to filter
  the table below); incident severity x status stacked bars and age in queue; ATT&CK heat strip
  (tactic columns, technique cells, click filters alerts); top hosts and top source IPs (bar
  tone = highest incident severity the entity appears in, glyph + word in the label; click opens
  the entity view); detector comparison (alerts, share mapped to ATT&CK, share with IOC match,
  duplicate rate; IOC says "no indicator list loaded" instead of 0 % when none is loaded);
  kill-chain strip for the scenario or a chosen incident (tactics in ATT&CK order, empty cells
  for gaps). Under the charts: the alert table filtered by whatever chart was used.
- **Entity view** (`/entity?kind=host|ip&value=`): counts by detector, first / last seen,
  activity bars, top rules, incidents that contain the entity.
- **Incident detail**: one-glance summary strip (severity, the triage rule in plain words with
  its inputs, first / last seen, detectors agreeing); ATT&CK lanes under the strip (one lane per
  tactic, binned ticks); a Graph tab (hosts and source IPs as nodes, alert count as edge width,
  detector as edge colour + dash, capped at 60 nodes with "Show more", focusable nodes, click
  filters the alert table); Findings with cited alerts as chips, verified / dropped tags and
  the matched span marked in the evidence line.
- **Alerts**: facet sidebar (detector, level, rule id, ATT&CK technique, host) with counts and
  inline bars, saved filters (localStorage, per viewer), CSV export of the filtered view.
- **Reports**: preview with the embedded timeline and entity graph (SVG); the PDF draws the same
  two charts with reportlab from the same data and the same layout algorithm (ported to
  Python, cross-checked by a test); printable executive summary.
- **Approvals**: queue table + side pane (proposed action, evidence, audit trail of that
  approval); the self-approval block and the reason requirement are stated in the pane before
  the controls, not discovered from an error.
- **Audit**: filters (user, action, text) and an activity-over-time bar chart.
- **Executive** (`/executive`, read-only): severity trend, top risks, ATT&CK coverage strip,
  time to review, open approvals, a plain-language caption under each chart; print stylesheet.
- **Study** (`/study`): renders `scores.json` of matched runs only (FakeClient runs are excluded
  and counted). Coverage bars with cite-all / top-k / noise reference lines, citation
  precision, unsupported-claim rate before and after the verifier as paired dots, tokens and
  latency per arm, detector-by-arm heat table. Banner: "dev scenarios, pilot numbers, not paper
  results". No confidence intervals (the files have none). Empty state before any run.
- **Settings** (theme, density, time format, default scenario), **Users** (admin: list,
  create, deactivate, reset; passwords only from `SENTINEL_NEW_USER_PASSWORD` on the API host,
  never typed in the browser), **Notifications** (pending approvals for deciders, decisions on
  your own requests, failed runs), **Help** (shortcuts and what each screen is for).

The console still shows no labels. The Study page shows run-level aggregates from result files
(rates over cases), never a per-alert or per-case label.

### 11.6 Performance

The 11,208-alert incident must render its detail (strip, lanes, graph, table) in under 2 s:
lanes and strip are binned, the graph is capped at 60 nodes before layout, the table is
windowed. Server aggregates come from an in-memory per-scenario index (rebuilt when the stored
alert count changes), so the charts never ship raw records.

### 11.7 v2 skill run

`ui-ux-pro-max` was run again on 2026-11-12 (`--design-system` density 9, motion 1, variance
2; `chart` searches for time series, heatmap and network graph; `ux` searches for login errors
and chart focus). Kept: Swiss / minimal style; chart rows "never colour alone", "table
fallback", "focus reveals hover values", "print values in heat cells", "network graph: the
adjacency table is the accessible source of truth, SVG up to 100 nodes"; login rows "password
visibility toggle" and "errors announced". Rejected again: the Enterprise Gateway landing
pattern, Fira fonts from Google Fonts, the blue-tinted palette, 150-300 ms hovers and the GSAP
scroll reveal, line charts for alert volume (bars per bin show bursts; a line interpolates
between bins that do not exist), Heroicons / Lucide, pie charts (forbidden by the brief).
