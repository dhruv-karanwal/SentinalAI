-- Wave D: record the (simulated) execution of an approved action, at most once.
ALTER TABLE approvals ADD COLUMN executed_utc {{TS}};
ALTER TABLE approvals ADD COLUMN executed_by TEXT;
