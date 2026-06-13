"""SQLite provenance ledger. The audit spine of the system.

Every evidence registration, tool execution, finding, and hypothesis is
written here. The report is generated FROM this store. The `finding -> execution`
join is the traceability guarantee the hackathon requires.

This module is a rail. Implement new readers/writers as needed but do not
remove the foreign-key relationship between findings and executions.
"""

from __future__ import annotations
import sqlite3
import json
from contextlib import contextmanager
from datetime import datetime, timezone

from find_evil.engine.schemas import Evidence, ExecResult, Finding, Hypothesis

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY, incident TEXT, goal TEXT, status TEXT,
  stop_reason TEXT, model TEXT, budget_json TEXT,
  started_at TEXT, ended_at TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
  evidence_id TEXT PRIMARY KEY, run_id TEXT, path TEXT, type TEXT,
  sha256 TEXT, size_bytes INTEGER, registered_at TEXT,
  FOREIGN KEY(run_id) REFERENCES runs(run_id)
);
CREATE TABLE IF NOT EXISTS executions (
  execution_id TEXT PRIMARY KEY, run_id TEXT, tool TEXT, command TEXT,
  exit_code INTEGER, stdout_sha256 TEXT, stdout_path TEXT,
  duration_s REAL, status TEXT, started_at TEXT, tokens INTEGER DEFAULT 0,
  FOREIGN KEY(run_id) REFERENCES runs(run_id)
);
CREATE TABLE IF NOT EXISTS findings (
  finding_id TEXT PRIMARY KEY, run_id TEXT, execution_id TEXT,
  severity TEXT, description TEXT, evidence_span TEXT,
  indicators_json TEXT, mitre_json TEXT, verification TEXT, confidence REAL,
  FOREIGN KEY(run_id) REFERENCES runs(run_id),
  FOREIGN KEY(execution_id) REFERENCES executions(execution_id)
);
CREATE TABLE IF NOT EXISTS hypotheses (
  hypothesis_id TEXT PRIMARY KEY, run_id TEXT, statement TEXT, mitre_json TEXT,
  prior REAL, posterior REAL, status TEXT, falsification TEXT, tested_by_json TEXT,
  FOREIGN KEY(run_id) REFERENCES runs(run_id)
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Ledger:
    def __init__(self, db_path: str):
        self.db_path = db_path
        with self._conn() as c:
            c.executescript(_SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # -- writers --------------------------------------------------------
    def start_run(self, run_id, incident, goal, model, budget: dict):
        with self._conn() as c:
            c.execute(
                "INSERT INTO runs(run_id,incident,goal,status,model,budget_json,started_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (run_id, incident, goal, "running", model, json.dumps(budget), _now()),
            )

    def end_run(self, run_id, status, stop_reason):
        with self._conn() as c:
            c.execute(
                "UPDATE runs SET status=?, stop_reason=?, ended_at=? WHERE run_id=?",
                (status, stop_reason, _now(), run_id),
            )

    def add_evidence(self, run_id, ev: Evidence):
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO evidence VALUES(?,?,?,?,?,?,?)",
                (
                    ev.evidence_id,
                    run_id,
                    ev.path,
                    ev.type,
                    ev.sha256,
                    ev.size_bytes,
                    _now(),
                ),
            )

    def add_execution(self, run_id, ex: ExecResult, stdout_path: str, tokens: int = 0):
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO executions"
                "(execution_id,run_id,tool,command,exit_code,stdout_sha256,stdout_path,duration_s,status,started_at,tokens)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    ex.execution_id,
                    run_id,
                    ex.tool,
                    ex.command,
                    ex.exit_code,
                    ex.stdout_sha256,
                    stdout_path,
                    ex.duration_s,
                    ex.status,
                    _now(),
                    tokens,
                ),
            )

    def update_execution_tokens(self, execution_id, tokens: int):
        """Record the LLM token cost of the iteration that produced an execution."""
        with self._conn() as c:
            c.execute(
                "UPDATE executions SET tokens=? WHERE execution_id=?",
                (tokens, execution_id),
            )

    def add_finding(self, run_id, f: Finding):
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO findings"
                "(finding_id,run_id,execution_id,severity,description,evidence_span,"
                "indicators_json,mitre_json,verification,confidence) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    f.finding_id,
                    run_id,
                    f.provenance.execution_id,
                    f.severity.value,
                    f.description,
                    f.provenance.evidence_span,
                    json.dumps(f.indicators),
                    json.dumps(f.mitre_techniques),
                    f.verification.value,
                    f.confidence,
                ),
            )

    def add_hypothesis(self, run_id, h: Hypothesis):
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO hypotheses VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    h.hypothesis_id,
                    run_id,
                    h.statement,
                    json.dumps(h.mitre),
                    h.prior,
                    h.posterior,
                    h.status,
                    h.falsification,
                    json.dumps(h.tested_by),
                ),
            )

    # -- readers --------------------------------------------------------
    def executions(self, run_id) -> list[dict]:
        """Every tool execution for a run, in execution order. This is the
        judge-facing trace: each row is a command with its timestamp, status,
        duration, and the path to its raw output, and execution_id is the key
        that findings join on."""
        with self._conn() as c:
            c.row_factory = sqlite3.Row
            rows = c.execute(
                "SELECT execution_id, tool, command, exit_code, status,"
                " duration_s, stdout_sha256, stdout_path, started_at, tokens"
                " FROM executions WHERE run_id=? ORDER BY started_at, rowid",
                (run_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def findings_with_provenance(self, run_id) -> list[dict]:
        """Join findings to the exact command that produced them. This query IS
        the audit trail. Every row links a claim to a verifiable execution."""
        with self._conn() as c:
            c.row_factory = sqlite3.Row
            rows = c.execute(
                "SELECT f.finding_id, f.severity, f.description, f.evidence_span,"
                " f.verification, f.confidence, e.tool, e.command, e.stdout_path"
                " FROM findings f JOIN executions e ON f.execution_id = e.execution_id"
                " WHERE f.run_id=?",
                (run_id,),
            ).fetchall()
            return [dict(r) for r in rows]
