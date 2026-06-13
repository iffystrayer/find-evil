# Accuracy Report

Self-assessment of findings accuracy, as required by the FIND EVIL! submission
rules. The rules state that honesty is valued over perfection. This document
describes the accuracy controls that are structural to the system, then
records measured results from testing. Sections marked TODO must be completed
from real run data before submission. Do not estimate or reconstruct numbers
from memory.

## 1. Structural accuracy controls

These controls are enforced in code and covered by the test suite:

1. **Provenance is mandatory.** A `Finding` cannot be constructed without an
   execution id and an evidence span (`engine/schemas.py`). A finding that
   cites nothing cannot exist.
2. **Membership verification.** `analysis/verify.membership_check` confirms
   that every claimed indicator literally appears in the cited output span.
   Findings that fail are not kept (`tests/test_provenance.py`).
3. **Critique pass.** Each grounded finding receives one LLM review and is
   labeled supported, weak, or contradicted. Contradicted findings are
   dropped; only supported and weak findings reach the report body
   (`tests/test_trust_layer.py`).
4. **Constrained summary.** The executive summary is generated from verified
   findings only and is rejected if it introduces any IOC absent from them
   (`analysis/summary.py`). The summary cannot invent indicators.
5. **Untrusted output handling.** Tool stdout is treated as data. An
   adversarial guardrail surfaces instruction-like content in output as a
   suspicious artifact instead of obeying it (`tests/test_guardrail.py`).
6. **Honest failure.** Transport errors, timeouts, and empty results are
   recorded as results. Zero findings is a success state. The system never
   fabricates a report or mock case data.

## 2. Hallucination handling observed in testing

> TODO: record real examples from your runs. For each, state what the model
> proposed, which control caught it, and what appeared in the report instead.

| # | What the model produced | Control that caught it | Outcome |
| --- | --- | --- | --- |
| 1 | `TODO` | `TODO (membership check / critique / summary gate)` | `TODO (dropped / demoted to weak / flagged)` |

## 3. Measured results

> TODO: complete from live runs against the documented evidence dataset
> (see `docs/EVIDENCE-DATASET.md`).

- Runs evaluated: `TODO`
- Grounded findings reported: `TODO`
- True positives (confirmed against ground truth or manual review): `TODO`
- False positives: `TODO`
- Missed artifacts (known indicators the agent did not surface): `TODO`
- Hallucinated claims that reached a report: `TODO (target: zero; if any,
  describe and explain)`
- Findings dropped by the membership check: `TODO`
- Findings demoted or dropped by the critique pass: `TODO`

## 4. Known limitations

- The tool catalog (`tools/metadata.yaml`) covers a focused set of SIFT
  tools. Depth was chosen over breadth, consistent with the judging guidance
  that depth on fewer data types beats shallow coverage of many.
- The membership check verifies that indicators appear in cited output. It
  does not verify analytic interpretation; the critique pass addresses
  interpretation but is itself an LLM judgment.
- Small local models frequently fail to produce valid structured output. A
  capable model is required for reliable hypothesize and tool selection.
- `TODO: add limitations observed during your live testing.`
