-- Core area: everything agents, the API and the UI may read. No labels here.
CREATE TABLE alerts (
    alert_id TEXT PRIMARY KEY,
    scenario TEXT NOT NULL,
    detector TEXT NOT NULL,
    detector_type TEXT NOT NULL,
    kind TEXT NOT NULL,
    ts {{TS}} NOT NULL,
    rule_id TEXT,
    rule_name TEXT,
    severity INTEGER,
    host_ip TEXT,
    source TEXT NOT NULL,
    enrichment {{JSON}} NOT NULL,
    record {{JSON}} NOT NULL,
    ingested_utc {{TS}} NOT NULL
);
CREATE INDEX alerts_scenario_ts ON alerts (scenario, ts);
CREATE INDEX alerts_host_ts ON alerts (host_ip, ts);
CREATE TABLE cases (
    case_id TEXT PRIMARY KEY,
    scenario TEXT NOT NULL,
    window_start {{TS}} NOT NULL,
    window_end {{TS}} NOT NULL,
    detail {{JSON}} NOT NULL
);
CREATE TABLE runs (
    run_id TEXT PRIMARY KEY,
    scenario TEXT NOT NULL,
    variant TEXT NOT NULL,
    agent TEXT NOT NULL,
    model_id TEXT NOT NULL,
    started_utc {{TS}} NOT NULL,
    summary {{JSON}} NOT NULL
);
CREATE TABLE agent_transcripts (
    id {{ID}},
    run_id TEXT NOT NULL REFERENCES runs (run_id),
    case_index INTEGER NOT NULL,
    agent_name TEXT NOT NULL,
    transcript {{JSON}} NOT NULL
);
CREATE TABLE incidents (
    incident_id TEXT PRIMARY KEY,
    scenario TEXT NOT NULL,
    first_ts {{TS}} NOT NULL,
    last_ts {{TS}} NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    alert_ids {{JSON}} NOT NULL,
    detail {{JSON}} NOT NULL,
    created_utc {{TS}} NOT NULL
);
CREATE TABLE reports (
    report_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents (incident_id),
    body {{JSON}} NOT NULL,
    object_key TEXT,
    created_utc {{TS}} NOT NULL
);
CREATE TABLE feedback (
    id {{ID}},
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    notes TEXT,
    username TEXT NOT NULL,
    created_utc {{TS}} NOT NULL
);
CREATE TABLE approvals (
    id {{ID}},
    incident_id TEXT NOT NULL REFERENCES incidents (incident_id),
    action {{JSON}} NOT NULL,
    status TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    reviewer TEXT,
    reason TEXT,
    created_utc {{TS}} NOT NULL,
    decided_utc {{TS}}
);
CREATE TABLE audit_log (
    id {{ID}},
    ts {{TS}} NOT NULL,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    detail {{JSON}} NOT NULL
);
CREATE TABLE users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_utc {{TS}} NOT NULL
);
CREATE TABLE memory (
    id {{ID}},
    session_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value {{JSON}} NOT NULL,
    created_utc {{TS}} NOT NULL
);
