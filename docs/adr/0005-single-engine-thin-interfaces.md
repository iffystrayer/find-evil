# ADR 0005: One engine, thin interfaces

## Status
Accepted.

## Context
The previous build had four interfaces (CLI, REST, MCP, Gradio) that each rebuilt
the stack and handled results differently. Reports diverged by interface, and two
interfaces produced no real report at all.

## Decision
A single `InvestigationEngine` owns the run and returns one `InvestigationResult`.
One reporter renders it. Interfaces are thin adapters. The CLI is primary; an MCP
wrapper is optional and must call the same engine.

## Consequences
Identical reports across interfaces are structural. New interfaces are cheap and
cannot drift. Effort concentrates on the engine, which is what the rubric rewards.
