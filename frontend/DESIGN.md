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
Reports, Ask, Audit) and a slim top bar (scenario / data source selector, user and role, theme
toggle, density toggle). No breadcrumbs. Skip link to main content is the first tab stop.

1. **Incidents** (landing page). Split pane.
   - Left: incident table. Default sort: severity (High first), then status (open first), then
     `last_ts` descending. Columns: severity, status, incident id, first seen (UTC), duration,
     alerts (count), detectors, entities (host / source IP).
   - Right: incident detail for the selected row.
     1. Header: severity, status control, id (copy), time range, alert count, triage gap used.
     2. Time-axis strip (section 6).
     3. Findings (when a run or copilot answer exists): each finding with its cited alert ids as
        links; dropped citations and dropped claims listed with the verifier's reason.
     4. Alerts of the incident (virtualised table; for the dense bursts, 11,208 alerts in 222 s
        on russellmitchell, grouped by rule id with counts, expandable).
     5. ATT&CK techniques (native ids only) and playbook recommendations with "Request approval".
   - Evidence pane: opens over the right third when an alert id is activated; shows the alert
     fields and raw log lines, matched span highlighted. Esc closes it and returns focus.
2. **Alerts**. Split pane: alert table (time, detector, severity as the detector reports it,
   rule id, rule name, host, source IP) with detector / host / time filters and full-text search
   (`/alerts/search`); right: the evidence view of the selected alert.
3. **Approvals**. Table: status, action, target, incident, requested by, requested at (UTC),
   decided by, executed at. Detail pane: the request, the incident link, decision form (reason
   required), execute button (approved only, once). States the executor is simulated.
4. **Reports**. Table of reports per incident; detail shows the JSON body sections (timeline,
   citations, techniques, recommendations); download CSV / PDF.
5. **Ask** (copilot). Question box scoped to an incident or case; answer rendered as findings
   with the same citation links and verifier markings. "Model offline" state when no endpoint
   is configured.
6. **Audit** (manager, admin). Read-only table: time, user, role, action, target.
7. **Sign in**. Username and password form; errors next to the field; no decoration.

There is no overview page of stat cards. Counts live where they are acted on (table footers,
filter chips, the strip).

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
| `--mark` | `#4a3d0c` | `#ffe58a` | highlighted matched span in a log line |

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
- Layout: rail 176 px (56 px collapsed), top bar 36 px, split 46 % / 54 % with a draggable,
  keyboard-operable divider. Minimum supported width 1366 px with no horizontal scroll;
  below 1024 px the detail pane takes the full width (no phone layout is promised).

## 4. Components

| Component | Notes |
|---|---|
| `AppShell`, `Rail`, `TopBar` | rail items are links with `aria-current` |
| `DataTable` | sticky header, fixed column widths (`table-layout: fixed` semantics on a grid), sortable headers (`aria-sort`), row hover, single selection, own fixed-row-height virtualiser (only visible rows + overscan in the DOM), footer with row count |
| `SplitPane` | list / detail; divider is a `separator` with arrow-key resize |
| `EvidencePane` | alert fields + log lines; span highlight with `<mark>`; copy per line |
| `TimeStrip` | section 6 |
| `Finding` | text, citation links, claim list with verifier status |
| `SeverityCell`, `DetectorTag`, `StatusTag` | glyph or mark + text |
| `Time` | absolute UTC ISO (`2022-01-24T03:01:07Z`), relative time in `title` and on focus |
| `Mono`, `CopyButton`, `Truncate` | truncation with click to expand; copy for ids and log lines |
| `FilterBar`, `SearchInput` | `/` focuses search |
| `Button` (primary, default, danger), `Select`, `TextInput`, `Textarea`, `Toggle` | visible labels; errors under the field with `aria-describedby` |
| `Dialog` | decision reason, confirm execute; focus trapped, Esc closes |
| `ShortcutHelp` | `?` opens the list |
| `SkeletonRows`, `EmptyState`, `ErrorState`, `ModelOffline` | section 5 |
| `Toast` | `role="status"`; errors use `role="alert"` |
| `Icon` | one file, `icons.tsx`: about 20 hand-authored inline SVGs, 16 px, 1.5 px stroke, `currentColor`, `aria-hidden` unless it is the only label |

Keyboard (global unless a text field has focus): `j` / `k` or arrow keys move the row
selection, `Enter` opens the row or citation, `Esc` closes the evidence pane or dialog, `/`
focuses search, `?` shows shortcuts, `g i` / `g a` / `g p` / `g r` go to Incidents / Alerts /
Approvals / Reports, `c` copies the selected id, `d` toggles density, `t` toggles the theme.
Tab order follows the visual order: rail, top bar, list, detail.

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

Loop per screen: build, render a screenshot (Playwright is not installed here; headless Chrome
or Edge, both present on this machine), critique against the list, fix, re-render; at most 3
passes.

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

## 10. Stack (proposed, not installed)

React + TypeScript + Vite, plain CSS with the tokens above (no Tailwind, no component kit, no
chart library, no virtualisation package: `DataTable` and `TimeStrip` are written here). This
keeps the npm download to the toolchain itself. Nothing is installed until the user says go.
