# CLAUDE.md — Operating contract for the Find Evil Agent

This is an autonomous DFIR agent for the SANS SIFT Workstation (Find Evil!
hackathon, deadline June 15 2026). The agent is implemented and validated end to
end against a live SIFT VM; the rules below still govern all further work. Read
the ADRs in `docs/adr/` before changing any architectural decision.

## Mission in one line
Given an incident description and evidence, autonomously investigate using SIFT
tools and produce a report in which every finding is traceable to the exact
command that produced it.

## The two invariants. Never violate these.

1. COMPLETION GUARANTEE. A run always terminates in a report. `engine/machine.py`
   is structured so the report phase runs on every exit path, including failure
   and budget exhaustion. Returning zero findings is a SUCCESS state, not a
   failure. Do not add an early return or an uncaught raise that bypasses the
   report. `tests/test_engine_completion.py` enforces this.

2. PROVENANCE GROUNDING. A `Finding` cannot be constructed without `provenance`
   (an execution_id plus an evidence_span). Every finding in the report must
   trace to a real execution via the ledger join. Run every finding through
   `analysis/verify.membership_check` before it is kept. Findings whose claimed
   indicators do not appear in the cited output are dropped. Do not relax the
   required `provenance` field.

## Hard rules (each prevents a documented failure mode)

- The LLM NEVER writes a command string. It returns typed `ToolParams`; code
  assembles the command in `tools/command.assemble_command` from a template.
  Do not add any path that executes free-text model output.
- The executor protocol always returns an `ExecResult`. Transport errors,
  timeouts, and non-zero exits become `ExecResult(status=...)`, never an
  exception that escapes `run()`. The engine relies on this to keep going.
- The structured LLM path retries on BOTH validation failures AND transport
  failures (timeout, connection, HTTP 5xx) with backoff. A single Ollama
  timeout must not end an investigation.
- One engine, one result type, one report path. The CLI and any future MCP
  interface are thin adapters that call the engine and render the result. No
  investigation logic or bespoke report building inside an interface.
- No fabricated output. If something cannot be produced, record it honestly.
  Never return a fake "report generated" message or mock case data.

## Architecture map
- `engine/machine.py`    state machine + completion guarantee (rail; small edits only)
- `engine/phases.py`     triage, hypothesize, test_next_hypothesis, _execute
- `engine/schemas.py`    contracts (rail; do not weaken)
- `tools/command.py`     template command assembly (rail)
- `tools/executor.py`    mock and SSH executors
- `tools/metadata.yaml`  tool catalog in template form; extend as needed
- `tools/parsers/`       Volatility, TSK, timeline, grep, strings parsers
- `analysis/analyzer.py` grounded extraction and the adversarial guardrail
- `analysis/verify.py`   membership check + critique pass
- `evidence/register.py` local and VM-side evidence hashing
- `ledger/store.py`      SQLite audit spine (rail)
- `llm/`                 Ollama, OpenAI, Anthropic providers with transport retry
- `report/`              deterministic assembly from the ledger, PDF export
- `interfaces/`          core entrypoint, CLI, MCP (thin)

## Conventions
- Python 3.11+, async throughout, Pydantic v2, type hints everywhere.
- Prose and docstrings in the writing style used here: no contractions, no em
  dashes, direct statements. This matches the maintainer's standards.
- Run `make test` after every change. Keep all tests green. Add a test with
  every new behavior.
- Structured logging via structlog. Log every phase outcome.

## How to run
- Tests: `make test`
- Mock run (no SIFT needed): `make run-mock`
- Live run against the SIFT VM: set `.env` from `.env.example`, then `make run-live`

## Current status
Complete and green. All milestones (M0 through M6) are implemented: phase logic,
the three LLM providers with transport retry, the analyzer with the adversarial
guardrail, the SSH executor, the trust layer (critique plus constrained
summary), the execution log, the MCP interface, and PDF export. The full test
suite passes and the agent has produced grounded reports from a live SIFT
Workstation. Further work must keep the suite green and honor the invariants and
hard rules above.
