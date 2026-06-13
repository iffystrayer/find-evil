# ADR 0002: Template command assembly, model fills typed slots

## Status
Accepted.

## Context
The previous build asked the model to return a full command string. The model
returned prose with the command embedded, the whole blob was treated as the
command, and the validator blocked it. Every run produced zero executions.

## Decision
Tools declare a command template with typed slots in `tools/metadata.yaml`. The
model returns a `ToolParams` object (typed slots only) through the structured
path. Code assembles the command with `shlex.quote` and a validator backstop.

## Consequences
Model narration can never become an executable command. Commands are safe by
construction and auditable. New tools are added by writing a template, not code.
