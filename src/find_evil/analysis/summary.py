"""Constrained executive summary.

The summary is generated from the verified findings only. The model is told to
introduce no new IOCs, and the result is passed through verify.summary_is_grounded.
If the model invents an IOC not present in the findings, we discard its prose and
fall back to a deterministic summary built directly from the findings. The report
summary therefore can never contain a claim absent from the findings table.
"""

from __future__ import annotations

import structlog

from find_evil.analysis import verify
from find_evil.engine.schemas import Finding

log = structlog.get_logger()


def _findings_block(findings: list[Finding]) -> str:
    lines = []
    for f in findings:
        iocs = "; ".join(f"{k}: {', '.join(v)}" for k, v in f.indicators.items() if v)
        suffix = f" [{iocs}]" if iocs else ""
        lines.append(f"- ({f.severity.value}) {f.description}{suffix}")
    return "\n".join(lines)


def deterministic_summary(findings: list[Finding]) -> str:
    """Build a summary purely from the findings, with no model prose.

    Used as the fallback when the model's summary is not grounded. It can only
    restate what the findings already contain.
    """
    if not findings:
        return ""
    n = len(findings)
    severities = sorted({f.severity.value for f in findings})
    iocs: list[str] = []
    for f in findings:
        for vals in f.indicators.values():
            for v in vals:
                if v not in iocs:
                    iocs.append(v)
    ioc_clause = f" Indicators observed: {', '.join(iocs)}." if iocs else ""
    return (
        f"The investigation produced {n} grounded "
        f"finding{'s' if n != 1 else ''} "
        f"(severity: {', '.join(severities)}), each traceable to the command that "
        f"produced it.{ioc_clause}"
    )


async def summarize(llm, findings: list[Finding]) -> str:
    """Produce a grounded executive summary for the verified findings.

    Returns an empty string when there are no findings (the report template then
    shows its own default line). Falls back to deterministic_summary if the model
    introduces any IOC absent from the findings.
    """
    if not findings:
        return ""

    system = (
        "You are writing the executive summary of a DFIR incident report. Use "
        "ONLY the findings provided below. Do not introduce any IP address, "
        "domain, URL, file hash, or filename that does not appear in the "
        "findings. Write 2 to 4 plain sentences for an incident commander. Make "
        "no claim that the findings do not support."
    )
    user = f"Findings:\n{_findings_block(findings)}\n\nWrite the executive summary."

    try:
        summary = (
            await llm.chat(
                [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ]
            )
        ).strip()
    except (
        Exception
    ) as e:  # noqa: BLE001 - never let summary generation break the report
        log.warning("summary_generation_failed", error=str(e))
        return deterministic_summary(findings)

    if not summary or not verify.summary_is_grounded(summary, findings):
        log.info("summary_fallback_to_deterministic")
        return deterministic_summary(findings)
    return summary
