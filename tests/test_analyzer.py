"""Analyzer tests. Focus of the M2 gate.

The analyzer turns one tool execution's stdout into grounded findings. Every
finding must carry provenance (the real execution_id plus an evidence_span into
THIS stdout) and must pass the deterministic membership check. The gate feeds
the captured vol_pslist fixture and requires at least one SUPPORTED finding
citing ransom.exe, with the finding-to-execution join persisted to the ledger.

The LLM is faked with a small real class that validates a canned payload against
the analyzer's own schema, so the test exercises the real extraction and
grounding control flow without a network call.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from pydantic import BaseModel

from find_evil.analysis.analyzer import analyze
from find_evil.engine.schemas import ExecResult, Verification
from find_evil.ledger.store import Ledger
from find_evil.tools.executor import _sha


class StubLLM:
    """Returns a canned structured payload, validated against the real schema.

    This is a real object, not a mock. `chat_structured` validates the supplied
    payload against whatever schema the analyzer asks for, so the analyzer's
    extraction schema stays the single source of truth.
    """

    def __init__(self, payload: dict):
        self._payload = payload
        self.structured_calls = 0

    async def chat(self, messages: list[dict]) -> str:
        return ""

    async def chat_structured(self, messages: list[dict], schema: type[BaseModel]):
        self.structured_calls += 1
        return schema.model_validate(self._payload)


def _pslist_execution() -> ExecResult:
    stdout = Path("fixtures/sample_case/vol_pslist.txt").read_text()
    return ExecResult(
        execution_id=str(uuid.uuid4()),
        tool="vol_pslist",
        command="vol.py -f mem.raw windows.pslist",
        exit_code=0,
        stdout=stdout,
        stdout_sha256=_sha(stdout),
        duration_s=0.01,
        status="ok",
    )


async def test_analyze_extracts_supported_finding_citing_ransom_exe():
    execution = _pslist_execution()
    llm = StubLLM(
        {
            "findings": [
                {
                    "description": "Suspicious process ransom.exe spawned vssadmin.exe",
                    "severity": "high",
                    "indicators": {"process": ["ransom.exe"]},
                    "evidence_span": "lines 4-4",
                    "mitre_techniques": [],
                    "confidence": 0.8,
                }
            ]
        }
    )

    findings = await analyze(llm, execution)

    assert len(findings) >= 1
    supported = [f for f in findings if f.verification == Verification.SUPPORTED]
    assert supported, "expected at least one SUPPORTED finding"
    f = supported[0]
    assert "ransom.exe" in f.indicators.get("process", [])
    assert f.provenance.execution_id == execution.execution_id
    assert f.provenance.evidence_span == "lines 4-4"


async def test_analyze_persists_finding_to_ledger_with_provenance(tmp_path):
    """The finding-to-execution join is the audit trail. Persist and read back."""
    execution = _pslist_execution()
    llm = StubLLM(
        {
            "findings": [
                {
                    "description": "ransom.exe present in process list",
                    "severity": "high",
                    "indicators": {"process": ["ransom.exe"]},
                    "evidence_span": "lines 4-4",
                    "confidence": 0.8,
                }
            ]
        }
    )

    ledger = Ledger(str(tmp_path / "m2.db"))
    run_id = str(uuid.uuid4())
    ledger.start_run(run_id, "ransomware", "find evil", "stub-model", {})
    ledger.add_execution(run_id, execution, stdout_path=str(tmp_path / "out.txt"))

    findings = await analyze(llm, execution)
    for finding in findings:
        ledger.add_finding(run_id, finding)

    rows = ledger.findings_with_provenance(run_id)
    assert rows, "expected at least one finding joined to its execution"
    row = rows[0]
    assert row["command"] == execution.command
    assert row["tool"] == "vol_pslist"
    assert "ransom.exe" in row["description"]
    assert row["verification"] == "supported"


async def test_analyze_returns_empty_when_model_finds_nothing():
    execution = _pslist_execution()
    llm = StubLLM({"findings": []})
    findings = await analyze(llm, execution)
    assert findings == []


async def test_analyze_downgrades_ungrounded_indicator():
    """A claimed indicator absent from the cited span must not be SUPPORTED."""
    execution = _pslist_execution()
    llm = StubLLM(
        {
            "findings": [
                {
                    "description": "fabricated process not in output",
                    "severity": "high",
                    "indicators": {"process": ["definitely_not_present.exe"]},
                    "evidence_span": "lines 4-4",
                    "confidence": 0.9,
                }
            ]
        }
    )

    findings = await analyze(llm, execution)
    assert len(findings) == 1
    assert findings[0].verification != Verification.SUPPORTED
