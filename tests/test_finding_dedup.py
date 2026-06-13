"""Finding dedup (follow-up to M3/M5).

When two hypotheses select the same tool against the same evidence, the analyzer
extracts the same finding twice. Those semantic duplicates must not appear twice
in the report. The hypothesis that re-confirmed the evidence is still marked
confirmed; only the duplicate finding row is suppressed.
"""

from __future__ import annotations

import os

from find_evil.engine.machine import InvestigationEngine


class TwoHypothesisLLM:
    """Returns two hypotheses, both of which select vol_pslist on the memory
    image, so the same ransom.exe finding is extracted twice."""

    def __init__(self):
        self._hypo_calls = 0

    async def chat(self, messages):
        return "summary"

    async def chat_structured(self, messages, schema):
        import re

        name = schema.__name__
        text = " ".join(m.get("content", "") for m in messages)
        if name == "_HypothesisSet":
            return schema.model_validate(
                {
                    "hypotheses": [
                        {
                            "statement": "ransom.exe is malicious",
                            "mitre": ["T1486"],
                            "prior": 0.7,
                            "falsification": "no such process",
                        },
                        {
                            "statement": "a process performed shadow-copy deletion",
                            "mitre": ["T1490"],
                            "prior": 0.6,
                            "falsification": "no vssadmin process",
                        },
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
                    "rationale": "x",
                }
            )
        if name == "_Extraction":
            return schema.model_validate(
                {
                    "findings": [
                        {
                            "description": "ransom.exe present",
                            "severity": "high",
                            "indicators": {"process": ["ransom.exe"]},
                            "evidence_span": "lines 4-4",
                            "confidence": 0.9,
                        }
                    ]
                }
            )
        if name == "_CritiqueVerdict":
            return schema.model_validate({"verdict": "supported", "reason": "ok"})
        raise AssertionError(name)


async def test_duplicate_findings_are_suppressed(settings):
    evidence = [os.path.join(settings.fixtures_dir, "memory.mem")]
    engine = InvestigationEngine(settings, llm=TwoHypothesisLLM())
    result = await engine.run("ransomware", "find evil", evidence)

    assert result.status == "completed"
    ransom = [
        f for f in result.findings if "ransom.exe" in f.indicators.get("process", [])
    ]
    assert len(ransom) == 1, f"expected one ransom.exe finding, got {len(ransom)}"

    # Both hypotheses were still tested and resolved (the re-test confirmed evidence).
    assert len(result.hypotheses) == 2
    assert all(h.status != "open" for h in result.hypotheses)

    # The ledger likewise holds a single row (the report renders from the ledger).
    rows = engine.ledger.findings_with_provenance(result.run_id)
    descs = [r["description"] for r in rows]
    assert descs.count("ransom.exe present") == 1
