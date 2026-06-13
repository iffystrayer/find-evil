"""MITRE ATT&CK mapping helper.

The pattern database is ported verbatim from the previous build. The mapping
functions are adapted to the current Finding schema, which carries a
`description` and `indicators` rather than a `title`, and which does not depend
on a separate report-schema type. A match yields lightweight MitreTechnique
records and bare technique identifiers suitable for `Finding.mitre_techniques`.

This is a simplified matrix. It maps observed text to the most common DFIR
techniques. It is a hint generator, not an authoritative classification.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from find_evil.engine.schemas import Finding


@dataclass(frozen=True)
class MitreTechnique:
    """A single MITRE ATT&CK technique match."""

    technique_id: str
    technique_name: str
    tactic: str
    description: str


# MITRE ATT&CK mapping database (simplified - in production use full matrix).
# Ported verbatim from the previous build's reporting/mitre.py.
MITRE_PATTERNS: dict[str, list[tuple[str, str, str, str]]] = {
    "powershell": [
        (
            "T1059.001",
            "PowerShell",
            "Execution",
            "Command and Scripting Interpreter: PowerShell",
        ),
    ],
    "cmd.exe": [
        (
            "T1059.003",
            "Windows Command Shell",
            "Execution",
            "Command and Scripting Interpreter: Windows Command Shell",
        ),
    ],
    "suspicious process": [
        (
            "T1055",
            "Process Injection",
            "Defense Evasion",
            "Process injection techniques",
        ),
    ],
    "registry": [
        (
            "T1547.001",
            "Registry Run Keys / Startup Folder",
            "Persistence",
            "Boot or Logon Autostart Execution",
        ),
    ],
    "c2": [
        (
            "T1071",
            "Application Layer Protocol",
            "Command and Control",
            "Application layer protocols for C2",
        ),
    ],
    "network connection": [
        (
            "T1071.001",
            "Web Protocols",
            "Command and Control",
            "Web-based C2 communication",
        ),
    ],
    "persistence": [
        (
            "T1543",
            "Create or Modify System Process",
            "Persistence",
            "System service persistence",
        ),
    ],
    "privilege escalation": [
        (
            "T1068",
            "Exploitation for Privilege Escalation",
            "Privilege Escalation",
            "Exploit vulnerabilities for privilege escalation",
        ),
    ],
    "credential": [
        (
            "T1003",
            "OS Credential Dumping",
            "Credential Access",
            "Dump credentials from operating system",
        ),
    ],
    "file modification": [
        (
            "T1486",
            "Data Encrypted for Impact",
            "Impact",
            "Ransomware and data encryption",
        ),
    ],
    "dll": [
        (
            "T1574.001",
            "DLL Search Order Hijacking",
            "Persistence",
            "DLL hijacking for persistence",
        ),
    ],
}


def map_text_to_mitre(text: str) -> list[MitreTechnique]:
    """Map free text to MITRE ATT&CK techniques by pattern matching.

    Args:
        text: Text to scan (a finding description, tool output excerpt, etc.).

    Returns:
        Matched techniques, de-duplicated by technique_id, ordered by id.
    """
    lowered = text.lower()
    matched: dict[str, MitreTechnique] = {}

    for pattern, techniques in MITRE_PATTERNS.items():
        if pattern in lowered:
            for technique_id, name, tactic, description in techniques:
                if technique_id not in matched:
                    matched[technique_id] = MitreTechnique(
                        technique_id=technique_id,
                        technique_name=name,
                        tactic=tactic,
                        description=description,
                    )

    return [matched[k] for k in sorted(matched)]


def suggest_techniques(finding: "Finding") -> list[str]:
    """Suggest MITRE technique identifiers for a finding.

    Scans the finding description and any indicator values. Returns bare
    technique identifiers suitable for `Finding.mitre_techniques`.

    Args:
        finding: The finding to classify.

    Returns:
        De-duplicated technique identifiers ordered by id.
    """
    parts = [finding.description]
    for values in finding.indicators.values():
        parts.extend(values)
    techniques = map_text_to_mitre(" ".join(parts))
    return [t.technique_id for t in techniques]
