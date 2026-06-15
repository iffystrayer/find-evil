# ROCBA Sample Run Artifacts

This directory contains the complete artifacts from the ROCBA (Fred Rocba Case) investigation run against real SIFT Workstation evidence.

## Contents

- `report.md` - Full investigation report with findings, hypotheses, and execution log
- `report.pdf` - PDF export of the report
- `execution-log.md` - Detailed execution log with timestamps, tool commands, and results
- `evidence-hashes.txt` - SHA256 hashes and sizes of all evidence artifacts

## Investigation Summary

**Run ID:** dca34a92-2824-45fc-89fb-65668684d551
**Status:** degraded (2 grounded findings, vol_pslist extraction failed)
**Duration:** 382.1 seconds

**Findings:** 2 INFO-level findings (OfficeIntegrator.ps1, RegisterInboxTemplates.ps1)
- Note: These are probable false positives (benign Microsoft AppV/UEV components)
- See `../ACCURACY-REPORT.md` for detailed analysis

**Evidence:**
- rocba-cdrive.e01 (23GB EnCase disk image)
- Rocba-Memory.raw (18GB Windows hibernation file)
- ROCBA-BACKGROUND.pptx (39MB briefing)

## Reproduction

See `../EVIDENCE-DATASET.md` for environment details and reproduction steps.
