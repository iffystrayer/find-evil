"""The investigation state machine.

COMPLETION GUARANTEE (the load-bearing property): run() is structured so the
report phase ALWAYS executes, even when a phase raises or the budget is hit.
A phase failure marks the run degraded and continues; it never aborts the run.
Returning zero findings is a SUCCESS state, not a failure.

Rail: do not add an early `return`/`raise` that bypasses _report(). Every exit
path goes through the report. tests/test_engine_completion.py enforces this.
"""

from __future__ import annotations
import time
import uuid
import structlog

from find_evil.engine.state import RunState, Budget
from find_evil.engine.schemas import InvestigationResult
from find_evil.config.settings import get_settings
from find_evil.ledger.store import Ledger
from find_evil.tools.executor import build_executor
from find_evil.engine import phases

log = structlog.get_logger()


def _safe_token_usage(llm) -> dict:
    """Cumulative LLM usage, or zeros if the provider does not report it."""
    usage = getattr(llm, "token_usage", None)
    if callable(usage):
        try:
            u = usage()
            return {"total": int(u.get("total", 0)), "calls": int(u.get("calls", 0))}
        except Exception:  # noqa: BLE001 - usage is best effort
            pass
    return {"total": 0, "calls": 0}


def _safe_token_total(llm) -> int:
    return _safe_token_usage(llm)["total"]


class InvestigationEngine:
    def __init__(self, settings=None, llm=None, executor=None, ledger=None):
        self.settings = settings or get_settings()
        self.ledger = ledger or Ledger(self.settings.db_path)
        self.executor = executor or build_executor(self.settings)
        self.llm = llm  # injected; created lazily in phases if None

    async def run(
        self,
        incident: str,
        goal: str,
        evidence_paths: list[str],
        supervised: bool = False,
    ) -> InvestigationResult:
        run_id = str(uuid.uuid4())
        self._current_run_id = run_id  # threaded into phases._execute
        s = self.settings
        state = RunState(
            run_id=run_id,
            incident=incident,
            goal=goal,
            supervised=supervised,
            budget=Budget(s.max_steps, s.max_wall_seconds, s.max_tokens),
        )
        self.ledger.start_run(
            run_id,
            incident,
            goal,
            s.llm_model,
            {"max_steps": s.max_steps, "max_wall_seconds": s.max_wall_seconds},
        )
        start = time.monotonic()

        try:
            # --- REGISTER EVIDENCE (failure -> degraded, still report) ---
            try:
                await phases.register_evidence(self, state, evidence_paths)
            except Exception as e:  # noqa: BLE001
                log.warning("register_failed", error=str(e))
                state.degraded = True
                state.stop_reason = state.stop_reason or f"no usable evidence: {e}"

            # --- TRIAGE (best effort) ---
            if state.evidence:
                try:
                    await phases.triage(self, state)
                except Exception as e:  # noqa: BLE001
                    log.warning("triage_failed", error=str(e))
                    state.degraded = True

                # --- HYPOTHESIZE / TEST / DECIDE loop ---
                while True:
                    done, reason = state.budget.exhausted()
                    if done:
                        state.stop_reason = reason
                        break
                    try:
                        await phases.hypothesize(self, state)
                        cont = await phases.test_next_hypothesis(self, state)
                    except Exception as e:  # noqa: BLE001
                        log.warning("iteration_failed", error=str(e))
                        state.degraded = True
                        cont = False
                    state.budget.steps += 1
                    state.budget.tokens = _safe_token_total(self.llm)
                    if not cont:
                        if not state.stop_reason:
                            state.stop_reason = phases.decide_stop_reason(state)
                        break
        finally:
            # --- REPORT (ALWAYS RUNS) ---
            result = phases.build_result(state, duration_s=time.monotonic() - start)
            status = (
                "degraded"
                if state.degraded
                else ("completed_no_findings" if not result.findings else "completed")
            )
            result.status = status
            # Constrained executive summary. Best effort: a summary failure must
            # never break the completion guarantee, so it degrades to "".
            if result.findings:
                try:
                    result.summary = await phases.summarize(self, result.findings)
                except Exception as e:  # noqa: BLE001
                    log.warning("summary_failed", error=str(e))
            usage = _safe_token_usage(self.llm)
            result.tokens_used, result.llm_calls = usage["total"], usage["calls"]
            self.ledger.end_run(run_id, status, result.stop_reason or "complete")

        return result
