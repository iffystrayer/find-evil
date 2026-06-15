# Incident Report: Fred Rocba, a Stark Research Labs employee, is a victim of a break-in and intellectual property theft. While Fred was on vacation, pictures from his work system were synced to an unknown location. The disk image (rocba-cdrive.e01) contains a Windows filesystem, and the memory capture (Rocba-Memory.raw) is a Windows hibernation file. Investigate both artifacts to identify: (1) how attackers gained initial access, (2) what malware or persistence mechanisms were installed, (3) what data was exfiltrated, and (4) any network connections or command-and-control activity. Analyze running processes, network connections, filesystem for suspicious files, and any signs of unauthorized access.

**Run:** 65a50b65-4316-46d6-b2eb-350e5b95f8eb  **Status:** completed  **Duration:** 244.3s
**Goal:** Reconstruct the attack chain and identify IOCs.
**Stop reason:** all hypotheses resolved
**LLM usage:** 348557 tokens across 9 calls

## Executive Summary
At 2020-11-14 05:00:20 UTC, two instances of an unrecognized process named `pacjsworker.ex` were spawned from the service host `svchost.exe` (PID 2800). The process name does not correspond to any known legitimate application, and its parent is atypical for user-mode processes. This activity is suspicious and warrants immediate investigation.

## Evidence
- `/cases/starter/rocba-cdrive.e01` (disk_image, sha256 `f2eb856d6fb48e39...`, 23678691658 bytes)
- `/cases/rocba/Rocba-Memory/Rocba-Memory.raw` (disk_image, sha256 `eb33bdf63730858a...`, 19050528768 bytes)


## Hypothesis Ledger
- **[confirmed]** The attacker gained initial access via Remote Desktop Protocol (RDP) using compromised credentials, then exfiltrated pictures over the RDP connection or a separate channel. (MITRE: T1078, T1021.001, T1041; posterior 0.90)
- **[confirmed]** The attacker delivered malware via a phishing email with a malicious attachment, which the user executed, leading to exfiltration of pictures to a cloud storage service. (MITRE: T1566.001, T1204.002, T1567.002; posterior 0.90)
- **[inconclusive]** The attacker physically accessed the machine while Fred was on vacation and used a USB device to copy pictures directly. (MITRE: T1091, T1052.001; posterior 0.30)


## Findings (provenance-grounded)


### HIGH - Suspicious process 'pacjsworker.ex' spawned from svchost.exe (PID 2800). Two instances observed with PIDs 24348 and 27704, both created at 2020-11-14 05:00:20 UTC. The process name does not correspond to any known legitimate Windows or common third-party application, and its parent is a service host process, which is atypical for user-mode worker processes.
- **Verification:** supported  **Confidence:** 0.70
- **Produced by:** `/home/sansforensics/.local/bin/vol -f /cases/rocba/Rocba-Memory/Rocba-Memory.raw windows.pslist`
- **Evidence span:** lines 54, 1214-1215 (raw output: `/tmp/find-evil/65a50b65-4316-46d6-b2eb-350e5b95f8eb/vol_pslist-7242d640-d902-48ee-8d15-e24d7f3acf80.txt`)

### INFO - User account pictures indicate the presence of several user accounts on the system.
- **Verification:** supported  **Confidence:** 1.00
- **Produced by:** `sudo fls -r /cases/starter/rocba-cdrive.e01`
- **Evidence span:** lines 581-596 (raw output: `/tmp/find-evil/65a50b65-4316-46d6-b2eb-350e5b95f8eb/fls-e96b9696-5447-41ee-83de-fb5a55dfac73.txt`)


## Indicators of Compromise
- **process:** pacjsworker.ex, svchost.exe
- **pid:** 24348, 27704, 2800
- **username:** Administrator, defaultuser0, defaultuser100000, defaultuser100001, fredr, guest, srl-h


## Execution Log

- `2026-06-15T21:45:08.501202+00:00` **mmls** [error, exit 1, 0.15s, 0 tok] (`00bc98a1-218f-4e13-999c-7af1f3a860df`)
  - command: `sudo mmls /cases/starter/rocba-cdrive.e01`
  - raw output: `/tmp/find-evil/65a50b65-4316-46d6-b2eb-350e5b95f8eb/mmls-00bc98a1-218f-4e13-999c-7af1f3a860df.txt`
- `2026-06-15T21:45:38.258283+00:00` **vol_pslist** [ok, exit 0, 5.29s, 270305 tok] (`7242d640-d902-48ee-8d15-e24d7f3acf80`)
  - command: `/home/sansforensics/.local/bin/vol -f /cases/rocba/Rocba-Memory/Rocba-Memory.raw windows.pslist`
  - raw output: `/tmp/find-evil/65a50b65-4316-46d6-b2eb-350e5b95f8eb/vol_pslist-7242d640-d902-48ee-8d15-e24d7f3acf80.txt`
- `2026-06-15T21:47:43.192399+00:00` **fls** [ok, exit 0, 72.44s, 73728 tok] (`e96b9696-5447-41ee-83de-fb5a55dfac73`)
  - command: `sudo fls -r /cases/starter/rocba-cdrive.e01`
  - raw output: `/tmp/find-evil/65a50b65-4316-46d6-b2eb-350e5b95f8eb/fls-e96b9696-5447-41ee-83de-fb5a55dfac73.txt`
