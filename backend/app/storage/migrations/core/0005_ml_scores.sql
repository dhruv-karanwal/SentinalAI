-- C4 (2026-11-15): operational ML scores attached to stored alerts (never to ground truth).
-- One row per (alert, model version, model). Scores do not change triage severity.
CREATE TABLE ml_scores (
    alert_id TEXT NOT NULL,
    model_version TEXT NOT NULL,
    model TEXT NOT NULL,
    score REAL NOT NULL,
    flag INTEGER NOT NULL,
    in_sample INTEGER NOT NULL,
    explanation {{JSON}} NOT NULL,
    scored_utc {{TS}} NOT NULL,
    PRIMARY KEY (alert_id, model_version, model)
);
