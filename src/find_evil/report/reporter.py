"""Deterministic report assembly from the ledger. One reporter, one result type.

The body is rendered from data. The only model-authored prose is the executive
summary, constrained to the verified findings and passed through the same
critique check. Every finding row prints the command and output span that
produced it (joined from the ledger), which is the traceability guarantee.
"""

from __future__ import annotations
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

from find_evil.engine.schemas import InvestigationResult
from find_evil.ledger.store import Ledger

_TPL = Path(__file__).parent / "templates"


def render_markdown(
    result: InvestigationResult, ledger: Ledger, summary: str = ""
) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TPL)), autoescape=select_autoescape()
    )
    rows = ledger.findings_with_provenance(result.run_id)
    executions = ledger.executions(result.run_id)
    # The summary lives on the result (set by the engine). The explicit argument
    # stays as an override for callers that want to supply their own.
    return env.get_template("report.md.j2").render(
        r=result,
        rows=rows,
        executions=executions,
        summary=summary or result.summary,
    )
