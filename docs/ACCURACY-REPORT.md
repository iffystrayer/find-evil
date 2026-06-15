# Accuracy Report

Self-assessment of findings accuracy for the ROCBA investigation run.

## 1. Structural accuracy controls

These controls are enforced in code and covered by the test suite:

1. **Provenance is mandatory.** A `Finding` cannot be constructed without an execution id and an evidence span.
2. **Membership verification.** Confirms every claimed indicator literally appears in the cited output span.
3. **Critique pass.** Each grounded finding receives one LLM review and is labeled supported, weak, or contradicted.
4. **Constrained summary.** Executive summary generated from verified findings only.
5. **Untrusted output handling.** Tool stdout is treated as data; instruction-like content is surfaced as suspicious artifacts.
6. **Honest failure.** Transport errors, timeouts, and empty results are recorded as results.

## 2. Hallucination handling observed in testing

| # | What the model produced | Control that caught it | Outcome |
| --- | --- | --- | --- |
| 1 | None observed | N/A | All structured outputs succeeded on first attempt |

## 3. Measured results

**ROCBA Live Run (65a50b65-4316-46d6-b2eb-350e5b95f8eb):**

- **Date:** 2026-06-15
- **Model:** deepseek-v4-pro:cloud
- **Duration:** 244.3 seconds
- **LLM usage:** 348,557 tokens across 9 calls

**Findings:**
- Grounded findings reported: 2
  - 1 HIGH: Suspicious process `pacjsworker.ex` (confidence 0.70)
  - 1 INFO: User account pictures (confidence 1.00)
- True positives: Unknown (no ground truth available)
- False positives: Unknown (manual review required)
- Hallucinated claims: 0 (all findings passed membership check)
- Findings dropped by membership check: 0
- Findings demoted by critique: 0 (critique executed successfully)

**Tool Results:**
| Tool | Status | Duration | Tokens | Notes |
|------|--------|----------|--------|-------|
| mmls | error | 0.15s | 0 | No partition table on E01 |
| vol_pslist | ok | 5.29s | 270,305 | 1 HIGH finding |
| fls | ok | 72.44s | 73,728 | 1 INFO finding |

**Hypotheses:**
- RDP with credential compromise: CONFIRMED (posterior 0.90)
- Phishing with malware: CONFIRMED (posterior 0.90)
- Physical USB access: INCONCLUSIVE (posterior 0.30)

## 4. Known limitations

- **mmls incompatibility:** The E01 image appears to be a filesystem image without a partition table.
- **Membership vs. truth:** The membership check verifies that indicators appear in output but does not verify maliciousness.
- **No ground truth:** Without a known answer key, true positive/false positive rates cannot be definitively established.

## 5. What `pacjsworker.ex` might be

The process name `pacjsworker.ex` is suspicious and warrants investigation:
- The `.ex` extension is truncated (normally `.exe`)
- Parent is svchost.exe (service host), atypical for user-mode processes
- Two instances spawned simultaneously at 2020-11-14 05:00:20 UTC
- Does not correspond to known legitimate Windows applications

**Possible explanations:**
1. Obfuscated malware with truncated extension
2. Legitimate PAC (Proxy Auto Config) JavaScript worker with unusual naming
3. Evidence-packed artifact from the investigation scenario

**Further investigation recommended:**
- Strings analysis on the memory capture for this process
- Network connection analysis for these PIDs
- MFT timeline analysis for files created around 2020-11-14 05:00:20 UTC

## 6. Evidence integrity

All evidence hashes recorded in `docs/sample-run/evidence-hashes.txt`:
- Disk SHA256: f2eb856d6fb48e3928e6b6d388b2f116a57b735137354a7eaddca951d81b5c67
- Memory SHA256: eb33bdf63730858a65a90fcf68d2190c17fb13a1f2945370d5493a27ed44765d
