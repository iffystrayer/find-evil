"""Primary interface. One command, mirrors Rob Lee's 'find evil' demo.

    find-evil "ransomware on win10" --evidence /mnt/evidence/win10.E01

Rail: the CLI is a thin adapter. It calls interfaces.core.investigate and
renders the result. It contains NO investigation logic and NO bespoke report
building.
"""

from __future__ import annotations
import asyncio
import typer

from find_evil.config.settings import get_settings
from find_evil.interfaces import core
from find_evil.report.pdf import write_pdf

app = typer.Typer(add_completion=False)


@app.command()
def main(
    incident: str,
    evidence: list[str] = typer.Option([], "--evidence", "-e", help="evidence path(s)"),
    goal: str = typer.Option(
        "Reconstruct the attack chain and identify IOCs.", "--goal"
    ),
    supervised: bool = typer.Option(False, "--supervised"),
    out: str = typer.Option("report.md", "--out", "-o"),
    pdf: str = typer.Option("", "--pdf", help="also write the report to this PDF path"),
):
    settings = get_settings()
    result, report = asyncio.run(
        core.investigate(settings, incident, goal, list(evidence), supervised)
    )
    with open(out, "w") as f:
        f.write(report)
    if pdf:
        write_pdf(report, pdf)
    typer.echo(f"[{result.status}] {result.stop_reason}")
    typer.echo(
        f"findings: {len(result.findings)}  ->  report: {out}"
        + (f" (+ {pdf})" if pdf else "")
    )


if __name__ == "__main__":
    app()
