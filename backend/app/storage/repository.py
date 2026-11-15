"""Typed access to the core and truth storage areas.

Two classes on purpose:

- :class:`Repository` wraps a *core*-area database: alerts, cases, runs,
  transcripts, incidents, reports, feedback, approvals, audit log, users,
  memory. It has no method that touches labels, and it refuses a truth-area
  database. Agent tools get an :class:`AlertReader`, a read-only view of it.
- :class:`TruthStore` wraps the *truth*-area database (ground truth). Only
  scoring and the study read it; nothing in ``app.agent`` or ``app.api``
  imports it (pinned by the leak tests).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Iterator, Sequence
from typing import Any

from app.schemas.alert import Alert, GroundTruth
from app.storage.db import Database, decode_json, encode_json, utc_now

AUDIT_ACTIONS_READ_ONLY = frozenset({"login"})


class Repository:
    def __init__(self, db: Database) -> None:
        if db.area != "core":
            raise ValueError("Repository needs a core-area database (labels live in TruthStore)")
        self.db = db

    # --- alerts --------------------------------------------------------------------------
    def upsert_alert(self, alert: Alert, enrichment: dict[str, Any], source: str) -> bool:
        """Insert an alert; returns False if the id was already stored (idempotent replay)."""
        if self.db.query("SELECT 1 FROM alerts WHERE alert_id = ?", (alert.alert_id,)):
            return False
        self.db.execute(
            "INSERT INTO alerts (alert_id, scenario, detector, detector_type, kind, ts, rule_id, "
            "rule_name, severity, host_ip, source, enrichment, record, ingested_utc) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (alert.alert_id, alert.scenario, alert.detector.value, alert.detector_type.value,
             alert.kind.value, alert.timestamp.isoformat(), alert.rule_id, alert.rule_name,
             alert.severity, str(alert.host_ip) if alert.host_ip else None, source,
             encode_json(enrichment), alert.model_dump_json(), utc_now()))
        return True

    @staticmethod
    def _alert_row(row: dict[str, Any]) -> dict[str, Any]:
        row = dict(row)
        row["enrichment"] = decode_json(row["enrichment"])
        row["record"] = decode_json(row["record"])
        row["ts"] = str(row["ts"])
        return row

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        rows = self.db.query("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
        return self._alert_row(rows[0]) if rows else None

    def alert_model(self, alert_id: str) -> Alert | None:
        row = self.get_alert(alert_id)
        return Alert.model_validate(row["record"]) if row else None

    def list_alerts(self, *, scenario: str | None = None, detector: str | None = None,
                    host_ip: str | None = None, since: str | None = None, until: str | None = None,
                    limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        for column, value in (("scenario", scenario), ("detector", detector), ("host_ip", host_ip)):
            if value is not None:
                where.append(f"{column} = ?")
                params.append(value)
        if since is not None:
            where.append("ts >= ?")
            params.append(since)
        if until is not None:
            where.append("ts < ?")
            params.append(until)
        clause = f" WHERE {' AND '.join(where)}" if where else ""
        rows = self.db.query(f"SELECT * FROM alerts{clause} ORDER BY ts, alert_id LIMIT ? OFFSET ?",
                             (*params, int(limit), int(offset)))
        return [self._alert_row(r) for r in rows]

    def iter_alert_models(self, scenario: str, batch: int = 5000) -> Iterator[Alert]:
        """Every stored alert of a scenario as ``Alert``, in (ts, alert_id) order, paged."""
        offset = 0
        while True:
            rows = self.db.query("SELECT record FROM alerts WHERE scenario = ? "
                                 "ORDER BY ts, alert_id LIMIT ? OFFSET ?", (scenario, batch, offset))
            for r in rows:
                yield Alert.model_validate(decode_json(r["record"]))
            if len(rows) < batch:
                return
            offset += batch

    def iter_alert_rows(self, scenario: str, batch: int = 5000) -> Iterator[dict[str, Any]]:
        """Every stored alert row of a scenario (decoded), in (ts, alert_id) order, paged."""
        offset = 0
        while True:
            rows = self.db.query("SELECT * FROM alerts WHERE scenario = ? ORDER BY ts, alert_id "
                                 "LIMIT ? OFFSET ?", (scenario, batch, offset))
            for r in rows:
                yield self._alert_row(r)
            if len(rows) < batch:
                return
            offset += batch

    def get_alerts(self, alert_ids: Sequence[str], chunk: int = 500) -> list[dict[str, Any]]:
        """Rows for ``alert_ids`` in the order given (unknown ids are skipped)."""
        found: dict[str, dict[str, Any]] = {}
        ids = list(dict.fromkeys(alert_ids))
        for i in range(0, len(ids), chunk):
            part = ids[i:i + chunk]
            marks = ", ".join("?" for _ in part)
            for r in self.db.query(f"SELECT * FROM alerts WHERE alert_id IN ({marks})", tuple(part)):
                found[str(r["alert_id"])] = self._alert_row(r)
        return [found[i] for i in ids if i in found]

    def count_alerts(self, scenario: str | None = None) -> dict[str, int]:
        clause, params = (" WHERE scenario = ?", (scenario,)) if scenario else ("", ())
        rows = self.db.query(f"SELECT detector, COUNT(*) AS n FROM alerts{clause} GROUP BY detector",
                             params)
        return {str(r["detector"]): int(r["n"]) for r in rows}

    def list_scenarios(self) -> list[dict[str, Any]]:
        """Stored scenarios with their alert counts, by name (the console's data-source list)."""
        rows = self.db.query("SELECT scenario, COUNT(*) AS n FROM alerts GROUP BY scenario ORDER BY scenario")
        return [{"scenario": str(r["scenario"]), "alerts": int(r["n"])} for r in rows]

    # --- cases and runs ----------------------------------------------------------------
    def put_case(self, case_id: str, scenario: str, window_start: str, window_end: str,
                 detail: dict[str, Any]) -> None:
        self.db.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
        self.db.execute("INSERT INTO cases (case_id, scenario, window_start, window_end, detail) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (case_id, scenario, window_start, window_end, encode_json(detail)))

    def list_cases(self, scenario: str | None = None) -> list[dict[str, Any]]:
        clause, params = (" WHERE scenario = ?", (scenario,)) if scenario else ("", ())
        rows = self.db.query(f"SELECT * FROM cases{clause} ORDER BY window_start", params)
        return [{**r, "detail": decode_json(r["detail"]), "window_start": str(r["window_start"]),
                 "window_end": str(r["window_end"])} for r in rows]

    def put_run(self, run_id: str, scenario: str, variant: str, agent: str, model_id: str,
                started_utc: str, summary: dict[str, Any]) -> None:
        self.db.execute("DELETE FROM agent_transcripts WHERE run_id = ?", (run_id,))
        self.db.execute("DELETE FROM runs WHERE run_id = ?", (run_id,))
        self.db.execute("INSERT INTO runs (run_id, scenario, variant, agent, model_id, started_utc, "
                        "summary) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (run_id, scenario, variant, agent, model_id, started_utc, encode_json(summary)))

    def add_transcript(self, run_id: str, case_index: int, agent_name: str,
                       transcript: Any) -> int:
        return self.db.insert("INSERT INTO agent_transcripts (run_id, case_index, agent_name, "
                              "transcript) VALUES (?, ?, ?, ?)",
                              (run_id, case_index, agent_name, encode_json(transcript)))

    def list_runs(self) -> list[dict[str, Any]]:
        rows = self.db.query("SELECT * FROM runs ORDER BY started_utc DESC")
        return [{**r, "summary": decode_json(r["summary"]), "started_utc": str(r["started_utc"])}
                for r in rows]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        rows = self.db.query("SELECT * FROM runs WHERE run_id = ?", (run_id,))
        if not rows:
            return None
        run = {**rows[0], "summary": decode_json(rows[0]["summary"]),
               "started_utc": str(rows[0]["started_utc"])}
        run["transcripts"] = [
            {**t, "transcript": decode_json(t["transcript"])}
            for t in self.db.query("SELECT case_index, agent_name, transcript FROM agent_transcripts "
                                   "WHERE run_id = ? ORDER BY case_index, id", (run_id,))]
        return run

    # --- incidents, reports, approvals, feedback --------------------------------------------
    def put_incident(self, incident: dict[str, Any]) -> None:
        self.db.execute("DELETE FROM incidents WHERE incident_id = ?", (incident["incident_id"],))
        self.db.execute(
            "INSERT INTO incidents (incident_id, scenario, first_ts, last_ts, severity, status, "
            "alert_ids, detail, created_utc) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (incident["incident_id"], incident["scenario"], incident["first_ts"], incident["last_ts"],
             incident["severity"], incident.get("status", "open"), encode_json(incident["alert_ids"]),
             encode_json(incident.get("detail", {})), utc_now()))

    @staticmethod
    def _incident_row(r: dict[str, Any]) -> dict[str, Any]:
        return {**r, "alert_ids": decode_json(r["alert_ids"]), "detail": decode_json(r["detail"]),
                "first_ts": str(r["first_ts"]), "last_ts": str(r["last_ts"]),
                "created_utc": str(r["created_utc"])}

    def list_incidents(self, scenario: str | None = None,
                       severity: str | None = None) -> list[dict[str, Any]]:
        where: list[str] = []
        params: list[Any] = []
        if scenario:
            where.append("scenario = ?")
            params.append(scenario)
        if severity:
            where.append("severity = ?")
            params.append(severity)
        clause = f" WHERE {' AND '.join(where)}" if where else ""
        rows = self.db.query(f"SELECT * FROM incidents{clause} ORDER BY first_ts", params)
        return [self._incident_row(r) for r in rows]

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        rows = self.db.query("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
        return self._incident_row(rows[0]) if rows else None

    def set_incident_status(self, incident_id: str, status: str) -> None:
        self.db.execute("UPDATE incidents SET status = ? WHERE incident_id = ?", (status, incident_id))

    # --- ML scores (C4) ---------------------------------------------------------------------
    def put_ml_scores(self, model_version: str, rows: Sequence[dict[str, Any]]) -> int:
        with self.db.transaction():
            for r in rows:  # re-scoring with the same version replaces the row
                self.db.execute("DELETE FROM ml_scores WHERE alert_id = ? AND model_version = ? AND model = ?",
                                (r["alert_id"], model_version, r["model"]))
                self.db.execute("INSERT INTO ml_scores (alert_id, model_version, model, score, flag, "
                                "in_sample, explanation, scored_utc) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                (r["alert_id"], model_version, r["model"], float(r["score"]),
                                 int(bool(r["flag"])), int(bool(r["in_sample"])),
                                 encode_json(r["explanation"]), r["scored_utc"]))
        return len(rows)

    def ml_scores(self, alert_ids: Sequence[str], chunk: int = 500) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        ids = list(alert_ids)
        for i in range(0, len(ids), chunk):
            part = ids[i:i + chunk]
            rows = self.db.query("SELECT * FROM ml_scores WHERE alert_id IN (" + ",".join("?" * len(part))
                                 + ") ORDER BY model_version, model, alert_id", part)
            out.extend({**r, "flag": bool(r["flag"]), "in_sample": bool(r["in_sample"]),
                        "explanation": decode_json(r["explanation"]), "scored_utc": str(r["scored_utc"])}
                       for r in rows)
        return out

    # --- investigations (C2) -------------------------------------------------------------
    def start_investigation(self, incident_id: str, workflow: str, requested_by: str,
                            model_id: str | None) -> str:
        """Insert a running investigation; ValueError if one is already running for the incident."""
        investigation_id = f"inv-{uuid.uuid4().hex[:16]}"
        with self.db.transaction():
            running = self.db.query("SELECT investigation_id FROM investigations WHERE incident_id = ? "
                                    "AND status = 'running'", (incident_id,))
            if running:
                raise ValueError(f"investigation {running[0]['investigation_id']} is already running "
                                 "for this incident")
            self.db.execute("INSERT INTO investigations (investigation_id, incident_id, workflow, status, "
                            "requested_by, model_id, started_utc) VALUES (?, ?, ?, 'running', ?, ?, ?)",
                            (investigation_id, incident_id, workflow, requested_by, model_id, utc_now()))
        return investigation_id

    def finish_investigation(self, investigation_id: str, status: str, result: dict[str, Any] | None,
                             error: str | None) -> None:
        self.db.execute("UPDATE investigations SET status = ?, result = ?, error = ?, completed_utc = ? "
                        "WHERE investigation_id = ? AND status = 'running'",
                        (status, None if result is None else encode_json(result), error, utc_now(),
                         investigation_id))

    def interrupt_running_investigations(self) -> int:
        """At API start: a 'running' row from an earlier process can never finish."""
        rows = self.db.query("SELECT investigation_id FROM investigations WHERE status = 'running'")
        for r in rows:
            self.finish_investigation(r["investigation_id"], "interrupted", None,
                                      "the API process stopped while this investigation ran")
        return len(rows)

    @staticmethod
    def _investigation_row(r: dict[str, Any]) -> dict[str, Any]:
        return {**r, "result": None if r["result"] is None else decode_json(r["result"]),
                "started_utc": str(r["started_utc"]),
                "completed_utc": None if r["completed_utc"] is None else str(r["completed_utc"])}

    def get_investigation(self, investigation_id: str) -> dict[str, Any] | None:
        rows = self.db.query("SELECT * FROM investigations WHERE investigation_id = ?", (investigation_id,))
        return self._investigation_row(rows[0]) if rows else None

    def list_investigations(self, incident_id: str | None = None) -> list[dict[str, Any]]:
        clause, params = (" WHERE incident_id = ?", (incident_id,)) if incident_id else ("", ())
        rows = self.db.query(f"SELECT investigation_id, incident_id, workflow, status, requested_by, "
                             f"model_id, started_utc, completed_utc, error FROM investigations{clause} "
                             f"ORDER BY started_utc DESC", params)
        return [{**r, "started_utc": str(r["started_utc"]),
                 "completed_utc": None if r["completed_utc"] is None else str(r["completed_utc"])}
                for r in rows]

    def put_report(self, incident_id: str, body: dict[str, Any],
                   object_key: str | None = None) -> str:
        report_id = f"rep-{uuid.uuid4().hex[:16]}"
        self.db.execute("INSERT INTO reports (report_id, incident_id, body, object_key, created_utc) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (report_id, incident_id, encode_json(body), object_key, utc_now()))
        return report_id

    def list_reports(self, incident_id: str | None = None) -> list[dict[str, Any]]:
        clause, params = (" WHERE incident_id = ?", (incident_id,)) if incident_id else ("", ())
        rows = self.db.query(f"SELECT * FROM reports{clause} ORDER BY created_utc DESC", params)
        return [{**r, "body": decode_json(r["body"]), "created_utc": str(r["created_utc"])}
                for r in rows]

    def get_report(self, report_id: str) -> dict[str, Any] | None:
        rows = self.db.query("SELECT * FROM reports WHERE report_id = ?", (report_id,))
        return ({**rows[0], "body": decode_json(rows[0]["body"]),
                 "created_utc": str(rows[0]["created_utc"])} if rows else None)

    def request_approval(self, incident_id: str, action: dict[str, Any], requested_by: str) -> int:
        return self.db.insert("INSERT INTO approvals (incident_id, action, status, requested_by, "
                              "created_utc) VALUES (?, ?, 'pending', ?, ?)",
                              (incident_id, encode_json(action), requested_by, utc_now()))

    def decide_approval(self, approval_id: int, approved: bool, reviewer: str, reason: str) -> None:
        rows = self.db.query("SELECT status FROM approvals WHERE id = ?", (approval_id,))
        if not rows:
            raise KeyError(f"no approval {approval_id}")
        if rows[0]["status"] != "pending":
            raise ValueError(f"approval {approval_id} is already {rows[0]['status']}")
        if not reason.strip():
            raise ValueError("a decision needs a reason")
        self.db.execute("UPDATE approvals SET status = ?, reviewer = ?, reason = ?, decided_utc = ? "
                        "WHERE id = ?", ("approved" if approved else "rejected", reviewer, reason,
                                         utc_now(), approval_id))

    def list_approvals(self, status: str | None = None) -> list[dict[str, Any]]:
        clause, params = (" WHERE status = ?", (status,)) if status else ("", ())
        rows = self.db.query(f"SELECT * FROM approvals{clause} ORDER BY id", params)
        return [{**r, "action": decode_json(r["action"]), "created_utc": str(r["created_utc"]),
                 "decided_utc": None if r["decided_utc"] is None else str(r["decided_utc"]),
                 "executed_utc": None if r.get("executed_utc") is None else str(r["executed_utc"])}
                for r in rows]

    def mark_executed(self, approval_id: int, executor: str) -> bool:
        """Record the execution of an approved action once; False if it was not approved or ran before."""
        with self.db.transaction():
            rows = self.db.query("SELECT status, executed_utc FROM approvals WHERE id = ?", (approval_id,))
            if not rows or rows[0]["status"] != "approved" or rows[0]["executed_utc"] is not None:
                return False
            self.db.execute("UPDATE approvals SET executed_utc = ?, executed_by = ? WHERE id = ? "
                            "AND executed_utc IS NULL", (utc_now(), executor, approval_id))
        return True

    def get_approval(self, approval_id: int) -> dict[str, Any] | None:
        rows = [a for a in self.list_approvals() if a["id"] == approval_id]
        return rows[0] if rows else None

    def add_feedback(self, target_type: str, target_id: str, verdict: str, notes: str | None,
                     username: str) -> int:
        return self.db.insert("INSERT INTO feedback (target_type, target_id, verdict, notes, username, "
                              "created_utc) VALUES (?, ?, ?, ?, ?, ?)",
                              (target_type, target_id, verdict, notes, username, utc_now()))

    def list_feedback(self) -> list[dict[str, Any]]:
        return [{**r, "created_utc": str(r["created_utc"])}
                for r in self.db.query("SELECT * FROM feedback ORDER BY id")]

    # --- audit, users, memory ---------------------------------------------------------------
    def audit(self, username: str, role: str, action: str, target: str | None,
              detail: dict[str, Any] | None = None) -> int:
        return self.db.insert("INSERT INTO audit_log (ts, username, role, action, target, detail) "
                              "VALUES (?, ?, ?, ?, ?, ?)",
                              (utc_now(), username, role, action, target, encode_json(detail or {})))

    def audit_entries(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.db.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (int(limit),))
        return [{**r, "detail": decode_json(r["detail"]), "ts": str(r["ts"])} for r in rows]

    def put_user(self, username: str, password_hash: str, role: str) -> None:
        self.db.execute("DELETE FROM users WHERE username = ?", (username,))
        self.db.execute("INSERT INTO users (username, password_hash, role, created_utc) "
                        "VALUES (?, ?, ?, ?)", (username, password_hash, role, utc_now()))

    def get_user(self, username: str) -> dict[str, Any] | None:
        rows = self.db.query("SELECT * FROM users WHERE username = ?", (username,))
        return rows[0] if rows else None

    def list_users(self) -> list[dict[str, Any]]:
        """Accounts without their password hashes."""
        rows = self.db.query("SELECT username, role, created_utc, disabled_utc FROM users ORDER BY username")
        return [{"username": r["username"], "role": r["role"], "created_utc": str(r["created_utc"]),
                 "disabled_utc": None if r["disabled_utc"] is None else str(r["disabled_utc"])} for r in rows]

    def set_user_disabled(self, username: str, disabled: bool) -> None:
        self.db.execute("UPDATE users SET disabled_utc = ? WHERE username = ?",
                        (utc_now() if disabled else None, username))

    def set_password(self, username: str, password_hash: str) -> None:
        self.db.execute("UPDATE users SET password_hash = ? WHERE username = ?", (password_hash, username))

    def remember(self, session_id: str, key: str, value: Any) -> int:
        return self.db.insert("INSERT INTO memory (session_id, key, value, created_utc) "
                              "VALUES (?, ?, ?, ?)", (session_id, key, encode_json(value), utc_now()))

    def recall(self, session_id: str, key: str | None = None) -> list[dict[str, Any]]:
        if key is None:
            rows = self.db.query("SELECT key, value FROM memory WHERE session_id = ? ORDER BY id",
                                 (session_id,))
        else:
            rows = self.db.query("SELECT key, value FROM memory WHERE session_id = ? AND key = ? "
                                 "ORDER BY id", (session_id, key))
        return [{"key": r["key"], "value": decode_json(r["value"])} for r in rows]


class AlertReader:
    """Read-only alert access for agent tools: alerts only, no labels, no writes."""

    def __init__(self, repo: Repository) -> None:
        self._repo = repo

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        return self._repo.get_alert(alert_id)

    def list_alerts(self, **filters: Any) -> list[dict[str, Any]]:
        return self._repo.list_alerts(**filters)


class TruthStore:
    def __init__(self, db: Database) -> None:
        if db.area != "truth":
            raise ValueError("TruthStore needs a truth-area database")
        self.db = db

    def put_many(self, truths: Iterable[GroundTruth]) -> int:
        with self.db.transaction():
            return self._put_many(truths)

    def _put_many(self, truths: Iterable[GroundTruth]) -> int:
        n = 0
        for t in truths:
            self.db.execute("DELETE FROM {S}ground_truth WHERE alert_id = ?".format(S=self._s),
                            (t.alert_id,))
            self.db.execute(
                "INSERT INTO {S}ground_truth (alert_id, scenario, time_label, event_label, "
                "event_label_available, event_label_source) VALUES (?, ?, ?, ?, ?, ?)".format(S=self._s),
                (t.alert_id, t.scenario, t.time_label, t.event_label,
                 1 if t.event_label_available else 0, t.event_label_source))
            n += 1
        return n

    @property
    def _s(self) -> str:
        return "truth." if self.db.dialect == "postgres" else ""

    def for_scenario(self, scenario: str) -> list[dict[str, Any]]:
        """Every ground-truth row of one scenario (bulk read for dev scoring)."""
        return self.db.query(f"SELECT * FROM {self._s}ground_truth WHERE scenario = ? "
                             "ORDER BY alert_id", (scenario,))

    def get(self, alert_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for aid in alert_ids:
            rows = self.db.query(f"SELECT * FROM {self._s}ground_truth WHERE alert_id = ?", (aid,))
            if rows:
                out[aid] = rows[0]
        return out
