"""Phase implementations.

Each phase reads and writes RunState and the ledger. Phases must NOT raise to
abort the run for ordinary failures; the engine catches and degrades. Raise only
for truly unrecoverable programming errors. The LLM never writes a command
string: it returns typed ToolParams and code assembles the command from the
tool template. Findings are grounded through verify before they are persisted,
and only grounded findings are written to the ledger so the report body can
never show an ungrounded claim.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import structlog
from pydantic import BaseModel, Field

from find_evil.analysis import analyzer, verify
from find_evil.engine.schemas import (
    Hypothesis,
    InvestigationResult,
    ToolParams,
)
from find_evil.engine.state import RunState
from find_evil.evidence.register import register_local, register_remote
from find_evil.tools.command import CommandBuildError, assemble_command, load_metadata
from find_evil.tools.parsers.tsk import TSKParser

log = structlog.get_logger()

_METADATA_PATH = Path(__file__).resolve().parents[1] / "tools" / "metadata.yaml"
_METADATA_CACHE: dict | None = None


# ---- LLM structured-output schemas (the model fills these; code consumes) ----
class _HypothesisItem(BaseModel):
    statement: str
    mitre: list[str] = Field(default_factory=list)
    prior: float = 0.5
    falsification: str = ""


class _HypothesisSet(BaseModel):
    hypotheses: list[_HypothesisItem] = Field(default_factory=list)


# ---- helpers -----------------------------------------------------------------
def _metadata() -> dict:
    global _METADATA_CACHE
    if _METADATA_CACHE is None:
        _METADATA_CACHE = load_metadata(str(_METADATA_PATH))
    return _METADATA_CACHE


def _get_llm(engine):
    """Return the injected LLM, or build one lazily from settings and cache it."""
    if engine.llm is None:
        from find_evil.llm.factory import create_llm_provider

        engine.llm = create_llm_provider(engine.settings)
    return engine.llm


def _llm_tokens(llm) -> int:
    """Cumulative total tokens for an llm, or 0 if it does not report usage."""
    usage = getattr(llm, "token_usage", None)
    if callable(usage):
        try:
            return int(usage()["total"])
        except Exception:  # noqa: BLE001 - usage is best effort
            return 0
    return 0


def _evidence_map(state: RunState) -> dict:
    return {ev.evidence_id: ev for ev in state.evidence}


def _allowlist(engine) -> list[str]:
    return list(engine.settings.evidence_allowlist) + [engine.settings.fixtures_dir]


def _tool_timeout(tool: str, default: int) -> int:
    for t in _metadata().get("tools", []):
        if t["name"] == tool:
            return int(t.get("timeout_s", default))
    return default


def _tools_catalog() -> str:
    """A compact, model-readable description of the available tools and slots."""
    lines = []
    for t in _metadata().get("tools", []):
        slots = ", ".join(
            f"{name} ({spec.get('type')}{'' if spec.get('required') else ', optional'})"
            for name, spec in t.get("slots", {}).items()
        )
        lines.append(f"- {t['name']}: {t['description']} | slots: {slots}")
    return "\n".join(lines)


def _evidence_listing(state: RunState) -> str:
    return "\n".join(
        f"- evidence_id={ev.evidence_id} type={ev.type} name={Path(ev.path).name}"
        for ev in state.evidence
    )


# ---- phases ------------------------------------------------------------------
async def register_evidence(engine, state: RunState, evidence_paths: list[str]) -> None:
    """Register every provided path. In mock mode the allowlist is the fixtures dir.

    In ssh mode the artifact lives on the SIFT VM, so the hash and size are
    computed there via the executor (sha256sum/stat). In mock and local mode the
    artifact is on this host and is hashed locally.
    """
    allow = _allowlist(engine)
    use_ssh = engine.settings.executor == "ssh"
    for p in evidence_paths:
        if use_ssh:
            ev = await register_remote(
                engine.executor, p, allow, engine.settings.default_timeout_s
            )
        else:
            ev = register_local(p, allow)
        state.evidence.append(ev)
        engine.ledger.add_evidence(state.run_id, ev)
    if not state.evidence:
        raise RuntimeError("no evidence registered")


async def triage(engine, state: RunState) -> None:
    """Establish ground truth before reasoning.

    Runs cheap, deterministic Sleuth Kit orientation tools (mmls, then fsstat on
    the primary data partition) against a disk image, parses the output with the
    ported parsers, and records facts in state.triage_facts. Every tool run is
    best effort: a missing fixture or a parse miss is logged and skipped, never
    raised, so triage degrades without aborting the run.
    """
    disk = next((ev for ev in state.evidence if ev.type == "disk_image"), None)
    if disk is None:
        log.info("triage_no_disk_image")
        return

    ev_map = _evidence_map(state)
    allow = _allowlist(engine)
    facts: dict = {"evidence": [ev.path for ev in state.evidence]}

    # mmls: partition layout.
    offset: int | None = None
    try:
        cmd = assemble_command(
            _metadata(),
            ToolParams(tool="mmls", params={"image": disk.evidence_id}),
            ev_map,
            allow,
        )
        res = await _execute(
            engine,
            "mmls",
            cmd,
            _tool_timeout("mmls", engine.settings.default_timeout_s),
        )
        if res.status == "ok":
            parsed = TSKParser().parse(res.stdout, tool="mmls")
            if parsed.success and parsed.data.partitions:
                facts["partitions"] = [
                    {
                        "start": p.start_sector,
                        "length": p.length,
                        "description": p.description,
                    }
                    for p in parsed.data.partitions
                ]
                ntfs = next(
                    (
                        p
                        for p in parsed.data.partitions
                        if "NTFS" in p.description.upper()
                    ),
                    None,
                )
                offset = ntfs.start_sector if ntfs else None
                if offset is not None:
                    facts["partition_offset"] = offset
    except Exception as e:  # noqa: BLE001 - triage is best effort
        log.warning("triage_mmls_failed", error=str(e))

    # fsstat: filesystem details on the primary data partition.
    if offset is not None:
        try:
            cmd = assemble_command(
                _metadata(),
                ToolParams(
                    tool="fsstat",
                    params={"image": disk.evidence_id, "offset": str(offset)},
                ),
                ev_map,
                allow,
            )
            res = await _execute(
                engine,
                "fsstat",
                cmd,
                _tool_timeout("fsstat", engine.settings.default_timeout_s),
            )
            if res.status == "ok":
                parsed = TSKParser().parse(res.stdout, tool="fsstat")
                if parsed.success and parsed.data.filesystem:
                    facts["filesystem"] = parsed.data.filesystem.fs_type
        except Exception as e:  # noqa: BLE001 - triage is best effort
            log.warning("triage_fsstat_failed", error=str(e))

    state.triage_facts = facts
    log.info("triage_complete", facts_keys=list(facts.keys()))


async def hypothesize(engine, state: RunState) -> None:
    """Generate 1-3 falsifiable, MITRE-mapped hypotheses, once per run.

    Subsequent loop iterations are no-ops: the engine calls this each turn, but
    hypotheses are generated only when none exist yet, which keeps the loop
    bounded (generate once, then test until none remain open).
    """
    if state.hypotheses:
        return

    llm = _get_llm(engine)
    facts = state.triage_facts or {}
    system = (
        "You are the lead DFIR analyst. From the incident description and the "
        "triage facts, form 1 to 3 falsifiable hypotheses about what happened. "
        "Each hypothesis must be testable with a single forensic tool, must name "
        "the MITRE ATT&CK technique IDs it implies, and must state what evidence "
        "would falsify it. Do not speculate beyond the incident and the facts."
    )
    user = (
        f"Incident: {state.incident}\n"
        f"Goal: {state.goal}\n"
        f"Triage facts: {facts}\n\n"
        "Return 1 to 3 hypotheses."
    )

    result = await llm.chat_structured(
        [{"role": "system", "content": system}, {"role": "user", "content": user}],
        _HypothesisSet,
    )

    for item in result.hypotheses[:3]:
        h = Hypothesis(
            hypothesis_id=str(uuid.uuid4()),
            statement=item.statement,
            mitre=item.mitre,
            prior=item.prior,
            posterior=item.prior,
            status="open",
            falsification=item.falsification,
        )
        state.hypotheses.append(h)
        engine.ledger.add_hypothesis(state.run_id, h)

    log.info("hypothesize_complete", count=len(state.hypotheses))


async def test_next_hypothesis(engine, state: RunState) -> bool:
    """Test the highest-value open hypothesis and return whether to continue.

    Selects a hypothesis, asks the model for typed ToolParams (never a command),
    assembles and executes the command, analyzes the output into grounded
    findings, persists only grounded findings, and resolves the hypothesis. The
    selected hypothesis always leaves the open set this turn, which guarantees
    the loop terminates once every hypothesis is resolved.
    """
    open_h = [h for h in state.hypotheses if h.status == "open"]
    if not open_h:
        return False

    pick = max(open_h, key=lambda h: h.posterior)
    llm = _get_llm(engine)
    tokens_before = _llm_tokens(llm)

    system = (
        "You are a DFIR analyst selecting ONE forensic tool to test a hypothesis. "
        "Choose a tool from the catalog and fill its typed slots. Reference "
        "evidence only by its evidence_id. You do not write commands; you return "
        "structured parameters and the system assembles the command safely.\n"
        "Selection rules:\n"
        "- Choose a tool whose required evidence type is actually available "
        "(for example, only run a memory tool when a memory image is present, "
        "only run a disk tool when a disk image is present).\n"
        "- Prefer a tool that directly reveals the indicator the hypothesis is "
        "about (a running process, a file, a string) in a single step."
    )
    user = (
        f"Hypothesis: {pick.statement}\n"
        f"Falsification: {pick.falsification}\n\n"
        f"Available tools:\n{_tools_catalog()}\n\n"
        f"Available evidence:\n{_evidence_listing(state)}\n\n"
        "Select the single most informative tool and its parameters."
    )

    try:
        params = await llm.chat_structured(
            [{"role": "system", "content": system}, {"role": "user", "content": user}],
            ToolParams,
        )
    except Exception as e:  # noqa: BLE001 - a failed selection resolves the hypothesis
        log.warning("tool_selection_failed", error=str(e))
        _resolve(engine, state, pick, confirmed=False)
        return _has_open(state)

    try:
        command = assemble_command(
            _metadata(), params, _evidence_map(state), _allowlist(engine)
        )
    except CommandBuildError as e:
        log.warning("command_build_failed", tool=params.tool, error=str(e))
        _resolve(engine, state, pick, confirmed=False)
        return _has_open(state)

    res = await _execute(
        engine,
        params.tool,
        command,
        _tool_timeout(params.tool, engine.settings.default_timeout_s),
    )
    pick.tested_by.append(res.execution_id)

    findings = await analyzer.analyze(llm, res)
    if engine.settings.critique_enabled:
        findings = [
            await verify.critique(llm, f, verify.cited_span_text(res.stdout, f))
            for f in findings
        ]
    grounded = [f for f in findings if verify.keep_for_report(f)]
    # Dedup against findings already recorded this run. Two hypotheses that pick
    # the same tool on the same evidence yield the same finding; we keep one row.
    seen = {_finding_signature(f) for f in state.findings}
    for f in grounded:
        sig = _finding_signature(f)
        if sig in seen:
            continue
        seen.add(sig)
        state.findings.append(f)
        engine.ledger.add_finding(state.run_id, f)

    # Attribute this iteration's LLM token cost (selection + analysis + critique)
    # to the execution it produced, for the per-call execution-log accounting.
    spent = _llm_tokens(llm) - tokens_before
    if spent > 0:
        engine.ledger.update_execution_tokens(res.execution_id, spent)

    _resolve(engine, state, pick, confirmed=bool(grounded))
    log.info(
        "hypothesis_tested",
        hypothesis=pick.hypothesis_id,
        tool=params.tool,
        grounded_findings=len(grounded),
        status=pick.status,
    )
    return _has_open(state)


def _finding_signature(f) -> tuple:
    """Semantic identity of a finding, independent of which execution produced it.

    Two findings with the same description, severity, and indicators are the same
    observation even when separate hypotheses surfaced them from separate runs of
    the same tool.
    """
    indicators = tuple(sorted((k, tuple(sorted(v))) for k, v in f.indicators.items()))
    return (f.description.strip().lower(), f.severity.value, indicators)


def _resolve(engine, state: RunState, h: Hypothesis, confirmed: bool) -> None:
    """Move a hypothesis out of the open set and persist the update."""
    if confirmed:
        h.status = "confirmed"
        h.posterior = min(0.99, h.posterior + 0.4)
    else:
        h.status = "inconclusive"
        h.posterior = max(0.01, h.posterior - 0.2)
    engine.ledger.add_hypothesis(state.run_id, h)


def _has_open(state: RunState) -> bool:
    return any(h.status == "open" for h in state.hypotheses)


async def summarize(engine, findings) -> str:
    """Generate the constrained executive summary for the verified findings."""
    from find_evil.analysis.summary import summarize as _summarize

    return await _summarize(_get_llm(engine), findings)


def decide_stop_reason(state: RunState) -> str:
    open_h = [h for h in state.hypotheses if h.status == "open"]
    if not state.hypotheses:
        return "no hypotheses generated"
    if not open_h:
        return "all hypotheses resolved"
    return "no further leads"


async def _execute(engine, tool: str, command: str, timeout_s: int):
    """Run a command, persist stdout under the workspace, write the execution to
    the ledger with the stdout path, and return the ExecResult.

    The executor protocol always returns an ExecResult (timeouts and transport
    errors become ExecResult(status=...)), so this never raises for tool failure.
    """
    res = await engine.executor.run(tool, command, timeout_s)
    run_id = getattr(engine, "_current_run_id", "unknown")

    workspace = Path(engine.settings.workspace_dir) / run_id
    stdout_path = ""
    try:
        workspace.mkdir(parents=True, exist_ok=True)
        out_file = workspace / f"{tool}-{res.execution_id}.txt"
        out_file.write_text(res.stdout)
        stdout_path = str(out_file)
    except OSError as e:
        log.warning("stdout_persist_failed", tool=tool, error=str(e))

    engine.ledger.add_execution(run_id, res, stdout_path=stdout_path)
    return res


def build_result(state: RunState, duration_s: float) -> InvestigationResult:
    """Assemble the final result from state. Pure function; always succeeds."""
    iocs: dict[str, list[str]] = {}
    for f in state.findings:
        for k, vals in f.indicators.items():
            iocs.setdefault(k, [])
            for v in vals:
                if v not in iocs[k]:
                    iocs[k].append(v)
    report_findings = [f for f in state.findings if verify.keep_for_report(f)]
    return InvestigationResult(
        run_id=state.run_id,
        incident=state.incident,
        goal=state.goal,
        evidence=state.evidence,
        hypotheses=state.hypotheses,
        findings=report_findings,
        iocs=iocs,
        stop_reason=state.stop_reason or "complete",
        duration_s=duration_s,
    )
