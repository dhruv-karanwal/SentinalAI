# Experiments

- `config/study.json` — the study configuration: the **frozen** dev /
  held-out scenario split (decided 2026-10-31, before any test run), the
  study-sample seed, size and stratification, and the random-control
  references. Read it with `app.study.config.load_study_config`; do not edit
  the split.

Experiment code lives in `backend/app/study/` and is run through the CLI
(`python -m app.main variants ...`). Outputs go to `data/processed/`
(git-ignored). Results that are reported must record the exact config and
command, and must follow `docs/research-methodology.md`.
