# ADR 0003: Findings require provenance

## Status
Accepted.

## Context
The reports could not be trusted because findings were narrative and ungrounded.
The hackathon requires that any finding trace to the tool execution that produced
it, and weights hallucination management heavily.

## Decision
`Finding.provenance` is a required field (execution_id + evidence_span). A
deterministic membership check confirms claimed indicators appear in the cited
output. Only SUPPORTED or WEAK findings reach the report body. The report joins
findings to executions in the ledger.

## Consequences
Hallucinated findings are structurally excluded. The audit trail is a database
join, not a promise. The model cannot author substantive claims; it extracts
from evidence and the system verifies.
