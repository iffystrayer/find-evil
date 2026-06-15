# ROCBA Sample Run Artifacts

Complete investigation artifacts from the ROCBA (Fred Rocba Case) forensic analysis.

## Contents

- `report.md` - Full investigation report with findings and execution log
- `report.pdf` - PDF export of the report
- `execution-log.md` - Detailed execution log with tool commands and timestamps
- `evidence-hashes.txt` - SHA256 hashes and sizes of all evidence artifacts

## Investigation Summary

**Run ID:** 65a50b65-4316-46d6-b2eb-350e5b95f8eb
**Status:** completed
**Duration:** 244.3 seconds
**Model:** deepseek-v4-pro:cloud

### Findings

| Severity | Finding | Confidence | Source |
|----------|---------|------------|--------|
| HIGH | Suspicious process `pacjsworker.ex` from svchost.exe | 0.70 | vol_pslist |
| INFO | Multiple user accounts present | 1.00 | fls |

### Key IOC

- **Process:** pacjsworker.ex, svchost.exe
- **PIDs:** 24348, 27704, 2800
- **Timestamp:** 2020-11-14 05:00:20 UTC
- **Users:** Administrator, defaultuser0, defaultuser100000, defaultuser100001, fredr, guest, srl-h

## Evidence

- **Disk:** `/cases/starter/rocba-cdrive.e01` (23GB, EnCase E01)
- **Memory:** `/cases/rocba/Rocba-Memory/Rocba-Memory.raw` (18GB, hibernation file)

## Hypotheses Confirmed

1. **RDP with credential compromise** (posterior 0.90)
2. **Phishing with malware attachment** (posterior 0.90)

## Reproduction

See `../EVIDENCE-DATASET.md` for environment details and reproduction steps.
