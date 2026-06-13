import pytest
from pydantic import ValidationError
from find_evil.engine.schemas import Finding, Provenance, Severity, ExecResult
from find_evil.ledger.store import Ledger


def test_finding_requires_provenance():
    with pytest.raises(ValidationError):
        Finding(
            finding_id="f1", description="x", severity=Severity.HIGH
        )  # no provenance


def test_finding_to_execution_join(tmp_path):
    led = Ledger(str(tmp_path / "p.db"))
    led.start_run("r1", "inc", "goal", "m", {})
    ex = ExecResult(
        execution_id="e1",
        tool="vol_pslist",
        command="vol -f mem windows.pslist",
        exit_code=0,
        stdout="ransom.exe",
        stdout_sha256="abc",
        duration_s=0.1,
        status="ok",
    )
    led.add_execution("r1", ex, stdout_path="/tmp/e1.txt")
    f = Finding(
        finding_id="f1",
        description="malicious process ransom.exe",
        severity=Severity.CRITICAL,
        indicators={"process": ["ransom.exe"]},
        provenance=Provenance(execution_id="e1", evidence_span="lines 1-1"),
    )
    led.add_finding("r1", f)
    rows = led.findings_with_provenance("r1")
    assert len(rows) == 1
    assert (
        rows[0]["command"] == "vol -f mem windows.pslist"
    )  # every finding traces to its command
