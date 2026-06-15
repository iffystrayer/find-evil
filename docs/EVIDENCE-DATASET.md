# Evidence Dataset Documentation

## 1. Captured fixtures (mock executor)

**Location.** `fixtures/sample_case/`

**Contents.**

| File | Role |
| --- | --- |
| `disk.img` | placeholder disk artifact |
| `memory.mem` | placeholder memory artifact |
| `mmls.txt` | partition table output |
| `vol_pslist.txt` | Volatility process listing |
| `strings.txt` | strings output |

## 2. Live SIFT Workstation runs (ssh executor)

**Environment.**

- SIFT Workstation version: Ubuntu Noble (24.04), SIFT scripts loaded
- Deployment: local VM on a LAN, accessed over SSH
- LLM provider and model: Ollama, deepseek-v4-pro:cloud

**Case data.**

| Item | Value |
| --- | --- |
| Dataset name | ROCBA (Fred Rocba Case) |
| Source | SANS SIFT Workstation hackathon starter evidence |
| Artifact types | EnCase E01 disk image, Windows hibernation file |

**Evidence Details:**

| Artifact | SHA256 | Size |
|----------|--------|------|
| rocba-cdrive.e01 | f2eb856d6fb48e3928e6b6d388b2f116a57b735137354a7eaddca951d81b5c67 | 23.6 GB |
| Rocba-Memory.raw | eb33bdf63730858a65a90fcf68d2190c17fb13a1f2945370d5493a27ed44765d | 19.0 GB |

**What the agent found.**

| Run | Incident prompt | Grounded findings | Stop reason | Report |
| --- | --- | --- | --- | --- |
| 65a50b65 | Fred Rocba break-in and IP theft | 2 (1 HIGH: pacjsworker.ex, 1 INFO: user accounts) | all hypotheses resolved | `docs/sample-run/report.md` |

**Key Finding:**
> **HIGH:** Suspicious process `pacjsworker.ex` spawned from svchost.exe (PID 2800)
> - PIDs 24348, 27704 created at 2020-11-14 05:00:20 UTC
> - Process name doesn't match known legitimate Windows applications

## 3. Reproduction for judges

**Environment Configuration:**

```bash
# .env settings
LLM_PROVIDER=ollama
LLM_MODEL=deepseek-v4-pro:cloud
OLLAMA_BASE_URL=http://<OLLAMA_HOST>:11434
EXECUTOR=ssh
SIFT_HOST=<SIFT_VM_IP>
SIFT_USER=sansforensics
SIFT_SSH_KEY_PATH=~/.ssh/sift_vm_key
EVIDENCE_ALLOWLIST=/cases/rocba/,/cases/starter/
```

**Tool metadata notes:**
- `vol_pslist` uses full path: `/home/sansforensics/.local/bin/vol`
- `fls` uses simplified template (no `-o {offset}` for filesystem images)
- TSK tools use `sudo` prefix
