-- Truth area: dataset labels. Never reachable from agent tool paths
-- (separate SQLite file; PostgreSQL schema "truth", no grant to sentinel_agent).
CREATE TABLE {{S}}ground_truth (
    alert_id TEXT PRIMARY KEY,
    scenario TEXT NOT NULL,
    time_label TEXT NOT NULL,
    event_label TEXT,
    event_label_available INTEGER NOT NULL,
    event_label_source TEXT
);
