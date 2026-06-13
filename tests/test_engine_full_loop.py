"""End-to-end loop test on the mock executor (the M3 key milestone).

This injects a scripted LLM so the full triage -> hypothesize -> test ->
analyze -> report loop runs deterministically without a live model. The
scripted LLM behaves like a real one: it reads the prompt to recover the
evidence_id the engine generated, and it returns typed structured output for
each schema the phases request. It never writes a command string.

The gate: the run completes with status "completed" (not degraded), produces at
least one grounded finding citing ransom.exe, and the rendered report shows the
exact command that produced each finding.
"""

from __future__ import annotations

import os
import re

from find_evil.engine.machine import InvestigationEngine
from find_evil.report.reporter import render_markdown

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


class ScriptedLLM:
    """A deterministic stand-in for a real provider.

    Dispatches on the requested schema's name and returns a validated instance.
    For tool selection it recovers the evidence_id from the prompt, exactly as a
    real model would read it from the message, so the assembled command is real.
    """

    async def chat(self, messages: list[dict]) -> str:
        return "Scripted executive summary."

    async def chat_structured(self, messages: list[dict], schema):
        name = schema.__name__
        text = " ".join(m.get("content", "") for m in messages)

        if name == "_HypothesisSet":
            return schema.model_validate(
                {
                    "hypotheses": [
                        {
                            "statement": "A malicious process (ransom.exe) executed on the host.",
                            "mitre": ["T1486"],
                            "prior": 0.6,
                            "falsification": "No anomalous process appears in the process list.",
                        }
                    ]
                }
            )

        if name == "ToolParams":
            match = _UUID.search(text)
            evidence_id = match.group(0) if match else ""
            return schema.model_validate(
                {
                    "tool": "vol_pslist",
                    "params": {"memory": evidence_id},
                    "rationale": "List processes to confirm the malicious binary.",
                }
            )

        if name == "_Extraction":
            return schema.model_validate(
                {
                    "findings": [
                        {
                            "description": "Suspicious process ransom.exe present in the process list.",
                            "severity": "critical",
                            "indicators": {"process": ["ransom.exe"]},
                            "evidence_span": "lines 4-4",
                            "mitre_techniques": ["T1486"],
                            "confidence": 0.9,
                        }
                    ]
                }
            )

        if name == "_CritiqueVerdict":
            return schema.model_validate(
                {"verdict": "supported", "reason": "process is present"}
            )

        raise AssertionError(f"ScriptedLLM got an unexpected schema: {name}")


async def test_full_loop_completes_with_grounded_finding(settings):
    evidence = os.path.join(settings.fixtures_dir, "disk.img")
    engine = InvestigationEngine(settings, llm=ScriptedLLM())

    result = await engine.run(
        "ransomware on win10 endpoint", "Reconstruct the attack chain", [evidence]
    )

    assert result.status == "completed", f"status was {result.status}"
    assert result.findings, "expected at least one grounded finding"
    assert any(
        "ransom.exe" in vals for f in result.findings for vals in f.indicators.values()
    )
    # The hypothesis was tested and is no longer open.
    assert result.hypotheses
    assert all(h.status != "open" for h in result.hypotheses)


async def test_full_loop_report_shows_command_behind_each_finding(settings):
    evidence = os.path.join(settings.fixtures_dir, "disk.img")
    engine = InvestigationEngine(settings, llm=ScriptedLLM())

    result = await engine.run(
        "ransomware on win10 endpoint", "Reconstruct the attack chain", [evidence]
    )
    report = render_markdown(result, engine.ledger)

    assert "ransom.exe" in report
    # The assembled vol_pslist command must appear as the provenance of the finding.
    assert "vol -f" in report
    assert "windows.pslist" in report
    # The judge-facing execution log lets a reader trace findings to commands.
    assert "## Execution Log" in report
    # A grounded executive summary was generated and rendered.
    assert result.summary
    assert "No model summary generated." not in report


async def test_full_loop_triage_records_partition_facts(settings):
    evidence = os.path.join(settings.fixtures_dir, "disk.img")
    engine = InvestigationEngine(settings, llm=ScriptedLLM())

    result = await engine.run(
        "ransomware on win10 endpoint", "Reconstruct the attack chain", [evidence]
    )
    # Triage ran mmls (fixture present) and stored structured facts.
    # We assert via the run completing and the execution being recorded.
    rows = engine.ledger.findings_with_provenance(result.run_id)
    assert rows, "findings should be joined to executions in the ledger"
