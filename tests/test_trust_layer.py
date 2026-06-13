"""Trust-layer tests (M5): critique pass, constrained summary, execution log.

The critique pass is one cheap LLM review that can only DEMOTE a finding
(supported -> weak -> contradicted); contradicted findings are dropped from the
report. The executive summary is constrained to the verified findings and is
rejected (falling back to a deterministic summary) if it introduces any IOC not
present in the findings. The execution log is read from the ledger and lets a
reader trace any finding to the command that produced it.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel

from find_evil.analysis import verify
from find_evil.analysis.summary import deterministic_summary, summarize
from find_evil.engine.schemas import (
    ExecResult,
    Finding,
    Provenance,
    Severity,
    Verification,
)
from find_evil.ledger.store import Ledger


class VerdictLLM:
    """Returns a canned critique verdict validated against the real schema."""

    def __init__(self, verdict: str):
        self._verdict = verdict

    async def chat(self, messages: list[dict]) -> str:
        return ""

    async def chat_structured(self, messages: list[dict], schema: type[BaseModel]):
        return schema.model_validate({"verdict": self._verdict, "reason": "test"})


class ProseLLM:
    """Returns a fixed prose string for chat (used for summary tests)."""

    def __init__(self, text: str):
        self._text = text

    async def chat(self, messages: list[dict]) -> str:
        return self._text

    async def chat_structured(self, messages, schema):  # pragma: no cover - unused
        raise AssertionError("summary path should not call chat_structured")


def _finding(
    desc: str, indicators: dict[str, list[str]], span: str = "lines 1-1"
) -> Finding:
    f = Finding(
        finding_id=str(uuid.uuid4()),
        description=desc,
        severity=Severity.HIGH,
        indicators=indicators,
        provenance=Provenance(execution_id="e1", evidence_span=span),
        verification=Verification.SUPPORTED,
    )
    return f


async def test_critique_drops_contradicted_finding():
    f = _finding("Beacon to 1.2.3.4", {"ip": ["1.2.3.4"]})
    reviewed = await verify.critique(
        VerdictLLM("contradicted"), f, cited_text="benign log line"
    )
    assert reviewed.verification == Verification.CONTRADICTED
    assert verify.keep_for_report(reviewed) is False


async def test_critique_can_demote_supported_to_weak():
    f = _finding("Beacon to 1.2.3.4", {"ip": ["1.2.3.4"]})
    reviewed = await verify.critique(
        VerdictLLM("weak"), f, cited_text="1.2.3.4 seen once"
    )
    assert reviewed.verification == Verification.WEAK
    assert verify.keep_for_report(reviewed) is True


async def test_critique_does_not_upgrade_weak_to_supported():
    f = _finding("Beacon to 1.2.3.4", {"ip": ["1.2.3.4"]})
    f.verification = Verification.WEAK
    reviewed = await verify.critique(VerdictLLM("supported"), f, cited_text="1.2.3.4")
    # Critique only demotes; a weak finding stays weak even if the review says supported.
    assert reviewed.verification == Verification.WEAK


def test_summary_is_grounded_rejects_unlisted_ioc():
    findings = [_finding("Reverse shell to 185.220.101.45", {"ip": ["185.220.101.45"]})]
    grounded = "The host beaconed to 185.220.101.45."
    ungrounded = "The host beaconed to 185.220.101.45 and exfiltrated to 9.9.9.9."
    assert verify.summary_is_grounded(grounded, findings) is True
    assert verify.summary_is_grounded(ungrounded, findings) is False


async def test_summarize_falls_back_when_model_invents_ioc():
    findings = [_finding("Reverse shell to 185.220.101.45", {"ip": ["185.220.101.45"]})]
    # The model hallucinates an extra IP not present in any finding.
    llm = ProseLLM(
        "Attackers used 185.220.101.45 and also 203.0.113.7 for exfiltration."
    )
    summary = await summarize(llm, findings)
    # The ungrounded IP must not survive: we fall back to the deterministic summary.
    assert "203.0.113.7" not in summary
    assert summary == deterministic_summary(findings)


async def test_summarize_keeps_grounded_model_prose():
    findings = [_finding("Reverse shell to 185.220.101.45", {"ip": ["185.220.101.45"]})]
    llm = ProseLLM("The web shell opened a reverse shell to 185.220.101.45.")
    summary = await summarize(llm, findings)
    assert "185.220.101.45" in summary
    assert "reverse shell" in summary.lower()


async def test_summarize_empty_findings_returns_empty():
    assert await summarize(ProseLLM("x"), []) == ""


def test_ledger_executions_reader_orders_and_traces(tmp_path):
    ledger = Ledger(str(tmp_path / "log.db"))
    run_id = str(uuid.uuid4())
    ledger.start_run(run_id, "incident", "goal", "model", {})
    ex = ExecResult(
        execution_id="exec-1",
        tool="strings",
        command="strings -n 6 /cases/x",
        exit_code=0,
        stdout="out",
        stdout_sha256="s",
        duration_s=0.2,
        status="ok",
    )
    ledger.add_execution(run_id, ex, stdout_path="/tmp/x.txt")

    rows = ledger.executions(run_id)
    assert len(rows) == 1
    assert rows[0]["tool"] == "strings"
    assert rows[0]["command"] == "strings -n 6 /cases/x"
    assert rows[0]["status"] == "ok"
    assert rows[0]["started_at"]
