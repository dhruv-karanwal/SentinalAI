# frontend/CLAUDE.md — local rules (root CLAUDE.md is the index)

The analyst console (Wave D). `DESIGN.md` in this folder is the design authority: read it
before changing anything visual, and change it in the same commit as a token or component.

## Commands (from `frontend/`)

```bash
npm install            # react, react-dom, vite, @vitejs/plugin-react, typescript (nothing else)
npm run dev            # http://127.0.0.1:5173, proxies /api to the API on 127.0.0.1:8000
npm run typecheck      # tsc --noEmit, strict + noUncheckedIndexedAccess
npm test               # node --test over src/lib/*.test.ts (Node >= 22.18 strips the types)
npm run build          # typecheck + vite build into dist/ (git-ignored)
# screenshots for the per-screen loop (headless Chrome or Edge already on the machine):
node scripts/shots.mjs steps.json ../data/processed/ui-shots   # needs SENTINEL_UI_DEV_PASSWORD
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
src/app.css             component styles, tokens only
src/icons.tsx           the whole icon set (16 px, 1.5 px stroke, currentColor) + SeverityGlyph
src/api.ts              typed client, in-memory token, PERMISSIONS mirror of backend auth.py
src/hooks.ts            AppContext, hash routing (#/screen?id=..&ev=..), useLoad, nav events
src/lib/                pure logic with tests: format, virtual (windowing), bins (strip), highlight
src/components/         DataTable, SplitPane, TimeStrip (canvas), EvidencePane, Findings, ui
src/screens/            Incidents, Alerts, Approvals, Reports, Ask, Audit, SignIn
src/App.tsx             shell (top bar, rail), global shortcuts, toasts, ScreenBoundary
scripts/shots.mjs       DevTools-protocol screenshot runner (no dependency)
```

## Rules

- **No new dependencies** without the user's say: no UI kit, CSS framework, chart, router,
  virtualisation or icon package. The table, strip and router are written here on purpose.
- **Untrusted text.** Alert fields, log lines, rule names and model output are rendered as text
  nodes only. Never `dangerouslySetInnerHTML`, never Markdown or HTML rendering, never turn log
  text into links. Highlighting goes through `splitHighlight` and `<mark>`.
- **Tokens only.** No hex value outside `tokens.css`. A new colour needs a contrast
  measurement (4.5:1 text, 3:1 control) on bg, surface, raised and selected, in both themes,
  recorded in DESIGN.md.
- **Never colour alone:** severity = glyph + word, detector = mark + name, verifier status = tag
  + text. Severity and detector identity are the only saturated colours; the accent is for
  focus, links and the primary action.
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
  shows platform outputs only: no labels, no study scores.
- **Motion** at most 100 ms (`--dur`), zero with `prefers-reduced-motion`.
- The session token is kept in memory (a reload signs out). Theme, density, split position and
  the chosen data source are the only things in `localStorage`.
- Changing theme or density sets the `<html>` attribute *before* the React state, because the
  canvas strip reads tokens in an effect that runs before the parent's effects.
- The permission table in `api.ts` only decides what to show; the API decides what is allowed,
  and a 403 is displayed.

## Gotchas

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
- The in-app Browser pane scales a 1366 px viewport down to its own width, so its screenshots
  are too small to judge type; use `scripts/shots.mjs` for the visual loop.
