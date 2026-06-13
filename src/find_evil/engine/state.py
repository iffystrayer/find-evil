from __future__ import annotations
from dataclasses import dataclass, field
import time

from find_evil.engine.schemas import Evidence, Finding, Hypothesis


@dataclass
class Budget:
    max_steps: int
    max_wall_seconds: int
    max_tokens: int
    steps: int = 0
    tokens: int = 0
    _start: float = field(default_factory=time.monotonic)

    def exhausted(self) -> tuple[bool, str]:
        if self.steps >= self.max_steps:
            return True, f"step budget reached ({self.max_steps})"
        if time.monotonic() - self._start >= self.max_wall_seconds:
            return True, f"time budget reached ({self.max_wall_seconds}s)"
        if self.tokens >= self.max_tokens:
            return True, f"token budget reached ({self.max_tokens})"
        return False, ""


@dataclass
class RunState:
    run_id: str
    incident: str
    goal: str
    budget: Budget
    supervised: bool = False
    evidence: list[Evidence] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    triage_facts: dict = field(default_factory=dict)
    degraded: bool = False
    stop_reason: str = ""
