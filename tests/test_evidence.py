"""Evidence registration tests (M2 second gate bullet).

register_local hashes a real artifact on the analyst host and classifies it by
extension. The engine writes each registered artifact to the ledger so the
report can trace every finding back to the evidence it came from.
"""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

import pytest

from find_evil.evidence.register import EvidenceError, register_local
from find_evil.ledger.store import Ledger

FIXTURES = str(Path("fixtures/sample_case").resolve())
DISK = str(Path("fixtures/sample_case/disk.img").resolve())


def test_register_local_hashes_and_classifies_fixture():
    ev = register_local(DISK, [FIXTURES])
    assert ev.path == DISK
    assert ev.type == "disk_image"
    assert len(ev.sha256) == 64
    assert ev.size_bytes > 0


def test_register_local_rejects_path_outside_allowlist():
    with pytest.raises(EvidenceError):
        register_local("/etc/shadow", [FIXTURES])


def test_register_local_rejects_missing_file():
    with pytest.raises(EvidenceError):
        register_local(str(Path(FIXTURES) / "nope.img"), [FIXTURES])


def test_evidence_persists_to_ledger(tmp_path):
    ev = register_local(DISK, [FIXTURES])
    ledger = Ledger(str(tmp_path / "ev.db"))
    run_id = str(uuid.uuid4())
    ledger.start_run(run_id, "incident", "goal", "model", {})
    ledger.add_evidence(run_id, ev)

    conn = sqlite3.connect(str(tmp_path / "ev.db"))
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM evidence WHERE evidence_id=?", (ev.evidence_id,)
    ).fetchone()
    conn.close()

    assert row is not None
    assert row["run_id"] == run_id
    assert row["sha256"] == ev.sha256
    assert row["type"] == "disk_image"
