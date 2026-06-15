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

| # | What the model produced | Control that caught it | Outcome |
| --- | --- | --- | --- |
| 1 | _CritiqueVerdict schema failures (3 attempts) - gemma4:31b-cloud could not produce valid JSON | Retry with backoff (all 3 attempts failed) | Critique pass did NOT execute; findings rested on membership check alone |
| 2 | _Extraction schema failures (3 attempts) - "unexpected character" when parsing vol_pslist output | Retry with backoff (all 3 attempts failed) | No findings extracted from vol_pslist despite successful tool execution |
| 3 | False positive findings: OfficeIntegrator.ps1 and RegisterInboxTemplates.ps1 flagged as suspicious | None (membership check passed - files exist in output) | Findings reported but are probable false positives (benign Microsoft components) |

**Note on Finding #3:** The two findings are likely false positives. OfficeIntegrator.ps1 is a standard Microsoft Application Virtualization (AppV) component, and RegisterInboxTemplates.ps1 is a standard User Experience Virtualization (UEV) component. On a normal Windows system these are benign. The agent correctly identified their presence but did not correctly assess their maliciousness. The hypothesis "Persistence via scheduled task or registry: CONFIRMED, posterior 0.99" is not supported by this evidence.

## 3. Measured results

**ROCBA Live Run (dca34a92-2824-45fc-89fb-65668684d551):**

- Runs evaluated: 4 total runs (3 failed/inconclusive, 1 degraded with findings)
- Grounded findings reported: 2 (both INFO severity)
- True positives (confirmed against ground truth or manual review): 0 (both findings are probable false positives)
- False positives: 2 (OfficeIntegrator.ps1, RegisterInboxTemplates.ps1 - benign Microsoft components)
- Missed artifacts (known indicators the agent did not surface): Unknown (no ground truth available)
- Hallucinated claims that reached a report: 0 (all findings passed membership check)
- Findings dropped by the membership check: 0 (both findings passed membership verification)
- Findings demoted or dropped by the critique pass: 0 (critique pass did NOT execute due to schema validation failures)

**Tool Execution Results:**

| Tool | Status | Exit Code | Duration | Notes |
|------|--------|-----------|----------|-------|
| mmls | error | 1 | 0.08s | E01 image has no partition table; mmls cannot process it |
| fls | ok | 0 | 70.10s | Successfully enumerated filesystem; produced 2 findings (probable FPs) |
| vol_pslist | ok | 0 | 5.12s | Successfully executed but extraction failed |

## 4. Autonomous vs. manual corrections

**Manual corrections (between runs, not autonomous):**
- Evidence path correction: Initial runs failed because `/mnt/ewf/ewf1` could not be accessed. Fixed by editing metadata.yaml to use E01 path directly.
- Volatility path correction: Original template used `vol` but actual path is `/home/sansforensics/.local/bin/vol`. Fixed by editing metadata.yaml.
- Tool parameter correction: `fls` template simplified to remove `-o {offset}` by editing metadata.yaml.

**Autonomous retries (agent behavior during run):**
- Retry with backoff on _CritiqueVerdict schema: 3 attempts, all failed
- Retry with backoff on _Extraction schema: 3 attempts, all failed
- Transport retries: None observed during this run

**Criterion 1 (autonomous self-correction) assessment:** The genuine autonomous behavior (retry with backoff) actually failed. The agent did not successfully correct itself mid-run. The corrections listed in the original "self-correction events" were manual configuration edits between runs, not autonomous agent behavior.

## 5. Evidence integrity

- Evidence hashes recorded in `docs/sample-run/evidence-hashes.txt`
- Disk image SHA256: f2eb856d6fb48e3928e6b6d388b2f116a57b735137354a7eaddca951d81b5c67
- Memory SHA256: eb33bdf63730858a65a90fcf68d2190c17fb13a1f2945370d5493a27ed44765d
- Hash verification: Not performed against published values (no ground truth available)

## 6. Known limitations

- The tool catalog (`tools/metadata.yaml`) covers a focused set of SIFT
  tools. Depth was chosen over breadth, consistent with the judging guidance
  that depth on fewer data types beats shallow coverage of many.
- The membership check verifies that indicators appear in cited output. It
  does not verify analytic interpretation or assess maliciousness. A file can
  exist and be benign.
- The critique pass is itself an LLM judgment. When schema validation fails,
  the entire control is bypassed.
- Small local models frequently fail to produce valid structured output.
  The gemma4:31b-cloud model had difficulty with _CritiqueVerdict and
  _Extraction schemas during the ROCBA run.
- **mmls incompatibility:** The E01 image appears to be a filesystem image without a partition table, causing mmls to fail. fls works directly on such images.
- **Volatility on hibernation files:** The memory capture is a Windows hibernation file (hiberfil.sys), which Volatility 3 can process but some plugins may have limited functionality.
- **Finding extraction from vol_pslist:** Despite successful tool execution, the structured extraction failed to parse process listings into findings.
- **False positive assessment:** The agent lacks domain knowledge to distinguish between suspicious and benign Windows components (AppV, UEV scripts).

## 7. What we would fix next

Given more time, the following fixes would be prioritized:

1. **Add a benign Windows components knowledge base** to reduce false positives from standard Microsoft components (AppV, UEV, default scripts).

2. **Improve schema robustness** for _CritiqueVerdict and _Extraction to handle edge cases that cause gemma4:31b-cloud to fail.

3. **Add a second-stage filter** that assesses finding context beyond mere membership (e.g., checking file paths against known benign locations).

4. **Enable mmls fallback** for filesystem images without partition tables (currently assumes partition table exists).

5. **Improve vol_pslist extraction** to handle large output volumes and malformed process names.
