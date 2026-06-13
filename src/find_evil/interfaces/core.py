"""The single investigation entrypoint shared by every interface.

One engine, one result type, one report path. The CLI and the MCP adapter both
call investigate() and transport its report verbatim. No interface contains
investigation logic or builds a report of its own. The llm/executor/ledger
keyword arguments are dependency-injection seams for tests and embedding; the
production interfaces do not pass them.
"""

from __future__ import annotations

from find_evil.config.settings import Settings
from find_evil.engine.machine import InvestigationEngine
from find_evil.engine.schemas import InvestigationResult
from find_evil.report.reporter import render_markdown


async def investigate(
    settings: Settings,
    incident: str,
    goal: str,
    evidence_paths: list[str],
    supervised: bool = False,
    *,
    llm=None,
    executor=None,
    ledger=None,
) -> tuple[InvestigationResult, str]:
    """Run one investigation and render its report.

    Returns the InvestigationResult and the rendered markdown report. The report
    is assembled from the same ledger the engine wrote to, so its findings,
    execution log, and summary are exactly what this run produced.
    """
    engine = InvestigationEngine(settings, llm=llm, executor=executor, ledger=ledger)
    result = await engine.run(incident, goal, evidence_paths, supervised)
    report = render_markdown(result, engine.ledger)
    return result, report
