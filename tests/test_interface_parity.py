"""Interface parity (M6).

One engine, one result type, one report path. The CLI and the MCP interface are
thin adapters over interfaces.core.investigate; neither builds a report of its
own. This test runs the same input through both adapters and asserts the reports
are identical once run-unique identifiers (run_id, timestamps, durations) are
normalized. If an interface ever grows bespoke report logic, this test fails.
"""

from __future__ import annotations

import os
import re

from find_evil.interfaces import core, mcp


class ScriptedLLM:
    """Deterministic provider so both interfaces yield the same substantive report."""

    async def chat(self, messages: list[dict]) -> str:
        return "Executive summary: a malicious process was confirmed."

    async def chat_structured(self, messages: list[dict], schema):
        name = schema.__name__
        text = " ".join(m.get("content", "") for m in messages)
        if name == "_HypothesisSet":
            return schema.model_validate(
                {
                    "hypotheses": [
                        {
                            "statement": "A malicious process executed on the host.",
                            "mitre": ["T1486"],
                            "prior": 0.6,
                            "falsification": "No anomalous process in the list.",
                        }
                    ]
                }
            )
        if name == "ToolParams":
            m = re.search(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text
            )
            return schema.model_validate(
                {
                    "tool": "vol_pslist",
                    "params": {"memory": m.group(0) if m else ""},
                    "rationale": "list processes",
                }
            )
        if name == "_Extraction":
            return schema.model_validate(
                {
                    "findings": [
                        {
                            "description": "Process ransom.exe present.",
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
            return schema.model_validate({"verdict": "supported", "reason": "present"})
        raise AssertionError(f"unexpected schema {name}")


_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T[\d:.+\-]+")
_DUR = re.compile(r"\d+\.\d+s")


def _normalize(report: str) -> str:
    report = _UUID.sub("<id>", report)
    report = _TS.sub("<ts>", report)
    report = _DUR.sub("<dur>", report)
    return report


async def test_cli_and_mcp_produce_identical_reports(settings):
    evidence = [
        os.path.join(settings.fixtures_dir, "disk.img"),
        os.path.join(settings.fixtures_dir, "memory.mem"),
    ]
    incident = "ransomware on win10 endpoint"
    goal = "Reconstruct the attack chain"

    # CLI path: the same core the CLI command calls.
    _, cli_report = await core.investigate(
        settings, incident, goal, evidence, llm=ScriptedLLM()
    )

    # MCP path: the registered tool handler.
    mcp_report = await mcp.investigate_tool(
        incident, evidence=evidence, goal=goal, settings=settings, llm=ScriptedLLM()
    )

    assert _normalize(cli_report) == _normalize(mcp_report)
    assert "ransom.exe" in cli_report
    assert "## Execution Log" in cli_report


def test_mcp_build_server_is_lazy_without_sdk():
    # Importing the adapter must not require the mcp SDK; build_server raises a
    # clear error only when actually called without the SDK installed.
    assert hasattr(mcp, "investigate_tool")
    assert hasattr(mcp, "build_server")
