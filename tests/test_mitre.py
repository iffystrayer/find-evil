"""Tests for the ported MITRE ATT&CK mapping helper.

The pattern database was ported verbatim from the previous build. The mapping
function is adapted to the current Finding schema (description plus indicators),
which has no `title` field.
"""

from __future__ import annotations

from find_evil.analysis.mitre import map_text_to_mitre, suggest_techniques
from find_evil.engine.schemas import Finding, Provenance, Severity


def test_map_text_to_mitre_matches_powershell():
    techniques = map_text_to_mitre("Encoded PowerShell command spawned a child process")
    ids = [t.technique_id for t in techniques]
    assert "T1059.001" in ids


def test_map_text_to_mitre_dedupes():
    techniques = map_text_to_mitre("c2 network connection to c2 server over c2 channel")
    ids = [t.technique_id for t in techniques]
    assert len(ids) == len(set(ids))


def test_suggest_techniques_from_finding():
    finding = Finding(
        finding_id="f1",
        description="Ransomware encrypted files for impact (file modification)",
        severity=Severity.CRITICAL,
        provenance=Provenance(execution_id="e1", evidence_span="lines 1-2"),
    )
    ids = suggest_techniques(finding)
    assert "T1486" in ids


def test_map_text_to_mitre_returns_empty_on_no_match():
    assert map_text_to_mitre("nothing noteworthy here") == []
