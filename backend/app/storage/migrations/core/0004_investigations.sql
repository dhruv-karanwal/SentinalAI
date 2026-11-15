-- C2 (2026-11-15): product investigations of an incident (single agent or LangGraph graph).
-- No foreign key to incidents: a triage rebuild re-creates incidents, and an investigation
-- must stay readable as a record of what was run. result holds steps, verification and output.
CREATE TABLE investigations (
    investigation_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    workflow TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    model_id TEXT,
    started_utc {{TS}} NOT NULL,
    completed_utc {{TS}},
    result {{JSON}},
    error TEXT
);
CREATE INDEX investigations_incident ON investigations (incident_id);
