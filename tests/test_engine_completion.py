import pytest
from find_evil.engine.machine import InvestigationEngine
from find_evil.engine.schemas import InvestigationResult


@pytest.mark.asyncio
async def test_completes_with_bad_evidence(settings):
    """Even when evidence registration fails, the run terminates in a result."""
    eng = InvestigationEngine(settings)
    res = await eng.run("ransomware on win10", "find evil", ["/nonexistent/path.E01"])
    assert isinstance(res, InvestigationResult)
    assert res.status in ("degraded", "completed_no_findings")
    assert res.stop_reason  # never empty


@pytest.mark.asyncio
async def test_completes_with_stubbed_phases(settings):
    """With valid evidence but unimplemented triage/hypothesize, the engine
    degrades gracefully and still reaches the report. This is the completion
    guarantee. Once phases are implemented this test still must pass."""
    import os

    ev = os.path.join(settings.fixtures_dir, "disk.img")
    eng = InvestigationEngine(settings)
    res = await eng.run("ransomware on win10", "find evil", [ev])
    assert isinstance(res, InvestigationResult)
    assert res.run_id
    assert res.stop_reason
