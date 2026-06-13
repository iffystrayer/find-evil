# ADR 0001: Explicit state machine, not a graph framework

## Status
Accepted.

## Context
The previous build used LangGraph for the iterative workflow. It produced three
recurring failures: checkpoint serialization warnings from storing Pydantic
objects in a dict channel, an unconditional human-approval interrupt that made
the autonomous mode stop after one iteration, and silent termination when a node
raised. The control flow was hard to inspect.

## Decision
Use a plain explicit async state machine in `engine/machine.py`. The phases are
ordinary functions. The loop and the budget are visible in one place. The report
phase runs in a `finally` block so it executes on every exit path.

## Consequences
The completion guarantee is enforceable and testable. Resume across processes is
not provided; for this scope a run is a single process. If durable cross-process
resume becomes a requirement, reintroduce a checkpointer behind the engine
without changing the phase contracts.
