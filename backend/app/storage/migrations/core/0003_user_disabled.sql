-- Console v2: an admin can deactivate an account (login and existing tokens are refused).
ALTER TABLE users ADD COLUMN disabled_utc {{TS}};
