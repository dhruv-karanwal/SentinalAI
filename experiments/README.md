# Experiments

- `config/study.json` — the study configuration: the **frozen** dev /
  held-out scenario split (decided 2026-10-31, before any test run), the
  variant seed and random-control references (per-detector by default;
  `random-fused` only as a degenerate manifest), and the case settings
  (seed, padding, alert cap, truncation rule, benign cases per attack
  case). Read it with `app.study.config.load_study_config`; do not edit the
  split.

Experiment code lives in `backend/app/study/` and runs through the CLI
(`python -m app.main variants ...`, `python -m app.main cases ...`).
Outputs go to `data/processed/` (git-ignored). Results that are reported
must record the exact config and command, and must follow
`docs/research-methodology.md`.
