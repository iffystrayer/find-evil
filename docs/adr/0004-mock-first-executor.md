# ADR 0004: Mock-first executor behind a protocol

## Status
Accepted.

## Context
The previous build could not be developed or tested without a live SIFT VM, so
the loop was never validated in isolation, and a single environment problem
ended every run.

## Decision
The engine depends on an `Executor` protocol. `MockExecutor` replays captured
tool outputs from `fixtures/sample_case`. `SSHExecutor` runs on the SIFT VM.
Build and test the whole loop on mock, then swap the executor for live runs.

## Consequences
The loop is provably correct before the VM is involved. Live bring-up becomes a
transport swap rather than a debugging session. Captured outputs double as the
regression corpus.
