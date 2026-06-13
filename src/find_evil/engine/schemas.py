"""Core contracts shared by every component.

INVARIANT: A Finding without provenance cannot be constructed. This is the
structural guarantee behind the audit-trail and anti-hallucination criteria.
Do not relax `Finding.provenance` to Optional. Tests enforce this.
"""

from __future__ import annotations
from enum import Enum
from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verification(str, Enum):
    SUPPORTED = "supported"
    WEAK = "weak"
    UNVERIFIED = "unverified"
    CONTRADICTED = "contradicted"


class Evidence(BaseModel):
    evidence_id: str
    path: str
    type: str  # disk_image|memory_dump|triage_collection|file
    sha256: str
    size_bytes: int


class ToolParams(BaseModel):
    """The LLM returns ONLY this for command construction. Never a raw command."""

    tool: str
    params: dict[str, str] = Field(default_factory=dict)
    rationale: str = ""


class ExecResult(BaseModel):
    execution_id: str
    tool: str
    command: str
    exit_code: int
    stdout: str
    stdout_sha256: str
    duration_s: float
    status: str  # ok|blocked|timeout|error


class Provenance(BaseModel):
    execution_id: str
    evidence_span: str  # e.g. "lines 412-419" or "bytes 1024-1099"


class Finding(BaseModel):
    finding_id: str
    description: str
    severity: Severity
    indicators: dict[str, list[str]] = Field(default_factory=dict)
    mitre_techniques: list[str] = Field(default_factory=list)
    provenance: Provenance  # REQUIRED. No provenance, no finding.
    verification: Verification = Verification.UNVERIFIED
    confidence: float = 0.0


class Hypothesis(BaseModel):
    hypothesis_id: str
    statement: str
    mitre: list[str] = Field(default_factory=list)
    prior: float = 0.5
    posterior: float = 0.5
    status: str = "open"  # open|confirmed|refuted|inconclusive
    falsification: str = ""
    tested_by: list[str] = Field(default_factory=list)


class InvestigationResult(BaseModel):
    run_id: str
    incident: str
    goal: str
    evidence: list[Evidence] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    timeline: list[dict] = Field(default_factory=list)
    iocs: dict[str, list[str]] = Field(default_factory=dict)
    stop_reason: str = ""
    status: str = "completed"
    duration_s: float = 0.0
    summary: str = ""  # constrained executive summary
    tokens_used: int = 0  # cumulative LLM tokens for the run
    llm_calls: int = 0  # number of LLM calls made
