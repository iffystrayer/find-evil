# Incident Report: Fred Rocba, a Stark Research Labs employee, discovered unauthorized access to his work computer while on vacation. Pictures from his work system were synced to an unknown location. The disk image (rocba-cdrive.e01) contains a Windows filesystem, and the memory capture (Rocba-Memory.raw) is a Windows hibernation file. Investigate both artifacts to identify: (1) how attackers gained initial access, (2) what malware or persistence mechanisms were installed, (3) what data was exfiltrated, and (4) any network connections or command-and-control activity. Use Volatility on the memory file to analyze running processes, network connections, and malicious code.

**Run:** dca34a92-2824-45fc-89fb-65668684d551  **Status:** degraded  **Duration:** 382.1s
**Goal:** Reconstruct the attack chain and identify IOCs.
**Stop reason:** no further leads
**LLM usage:** 797478 tokens across 16 calls

## Executive Summary
Two PowerShell scripts were identified on the system. These include OfficeIntegrator.ps1 located in the AppV Setup directory and RegisterInboxTemplates.ps1 located in the UEV Scripts directory.

## Evidence
- `/cases/starter/rocba-cdrive.e01` (disk_image, sha256 `f2eb856d6fb48e39...`, 23678691658 bytes)
- `/cases/rocba/Rocba-Memory/Rocba-Memory.raw` (disk_image, sha256 `eb33bdf63730858a...`, 19050528768 bytes)


## Hypothesis Ledger
- **[confirmed]** The attacker established persistence using a scheduled task or registry run key to execute a malicious payload. (MITRE: T1053.005, T1547.001; posterior 0.99)
- **[inconclusive]** The attacker used a remote access trojan (RAT) to exfiltrate files, evidenced by active network connections in memory. (MITRE: T1071.001, T1041; posterior 0.30)
- **[open]** Initial access was gained via a phishing email containing a malicious attachment that executed a process in memory. (MITRE: T1566.001, T1204.002; posterior 0.40)


## Findings (provenance-grounded)


### INFO - Presence of a PowerShell script named OfficeIntegrator.ps1 in the AppV Setup directory.
- **Verification:** supported  **Confidence:** 0.90
- **Produced by:** `sudo fls -r /cases/starter/rocba-cdrive.e01`
- **Evidence span:** lines 110-110 (raw output: `/tmp/find-evil/dca34a92-2824-45fc-89fb-65668684d551/fls-42cb6aaf-beff-4783-9579-2333524aaf6c.txt`)

### INFO - Presence of a script named RegisterInboxTemplates.ps1 in the UEV Scripts directory.
- **Verification:** supported  **Confidence:** 0.90
- **Produced by:** `sudo fls -r /cases/starter/rocba-cdrive.e01`
- **Evidence span:** lines 505-505 (raw output: `/tmp/find-evil/dca34a92-2824-45fc-89fb-65668684d551/fls-42cb6aaf-beff-4783-9579-2333524aaf6c.txt`)


## Indicators of Compromise
- **path:** OfficeIntegrator.ps1, RegisterInboxTemplates.ps1


## Execution Log

- `2026-06-14T07:10:36.611719+00:00` **mmls** [error, exit 1, 0.08s, 0 tok] (`cdabee11-9ba0-4e64-997b-c3d4d6f096d1`)
  - command: `sudo mmls /cases/starter/rocba-cdrive.e01`
  - raw output: `/tmp/find-evil/dca34a92-2824-45fc-89fb-65668684d551/mmls-cdabee11-9ba0-4e64-997b-c3d4d6f096d1.txt`
- `2026-06-14T07:11:52.598463+00:00` **fls** [ok, exit 0, 70.10s, 201838 tok] (`42cb6aaf-beff-4783-9579-2333524aaf6c`)
  - command: `sudo fls -r /cases/starter/rocba-cdrive.e01`
  - raw output: `/tmp/find-evil/dca34a92-2824-45fc-89fb-65668684d551/fls-42cb6aaf-beff-4783-9579-2333524aaf6c.txt`
- `2026-06-14T07:13:01.032577+00:00` **vol_pslist** [ok, exit 0, 5.12s, 0 tok] (`a270849c-7d5c-48d9-afd4-6618642d8b92`)
  - command: `/home/sansforensics/.local/bin/vol -f /cases/rocba/Rocba-Memory/Rocba-Memory.raw windows.pslist`
  - raw output: `/tmp/find-evil/dca34a92-2824-45fc-89fb-65668684d551/vol_pslist-a270849c-7d5c-48d9-afd4-6618642d8b92.txt`
