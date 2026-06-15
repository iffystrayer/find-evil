# Evidence Dataset Documentation

This document records what the agent was tested against, where the data came
from, and what the agent found. The hackathon submission requires it; judges
use it to reproduce and evaluate the runs.

## 1. Captured fixtures (mock executor)

**Location.** `fixtures/sample_case/`

**Source.** Tool outputs captured from real executions on a SANS SIFT
Workstation VM during live bring-up, plus synthetic placeholder artifacts
(`disk.img`, `memory.mem`) used only for evidence registration. None of the
fixture content contains real-world case data, personal information, or live
credentials. All indicators in the fixtures (file names, IP addresses,
mutexes, paths) are synthetic.

**Contents.**

| File | Role |
| --- | --- |
| `disk.img` | placeholder disk artifact for registration and triage |
| `memory.mem` | placeholder memory artifact for registration |
| `mmls.txt` | captured `mmls` partition table output (triage replay) |
| `vol_pslist.txt` | captured Volatility process listing (analysis replay) |
| `strings.txt` | captured `strings` output containing planted indicators |

**Purpose.** `make run-mock` replays these outputs through the full loop with
zero SIFT access. The fixtures double as the regression corpus for the test
suite. The mock executor replaces the tools, not the model: hypothesize and
tool selection still call a live LLM.

## 2. Live SIFT Workstation runs (ssh executor)

**Environment.**

- SIFT Workstation version: Ubuntu Noble (24.04), SIFT scripts loaded
- Deployment: local VM on a LAN ([SIFT_VM_IP]), accessed over SSH with host key verification
- LLM provider and model: Ollama at http://[OLLAMA_HOST]:11434, gemma4:31b-cloud

**Case data.**

| Item | Value |
| --- | --- |
| Dataset name | ROCBA (Fred Rocba Case) |
| Source | SANS SIFT Workstation hackathon starter evidence |
| Artifact types | EnCase E01 disk image, Windows hibernation file (memory), PowerPoint briefing |
| Sizes and sha256 | See `docs/sample-run/evidence-hashes.txt` |

**Evidence Details:**

| Artifact | Path | SHA256 | Size |
|----------|------|--------|------|
| rocba-cdrive.e01 | /cases/starter/rocba-cdrive.e01 | f2eb856d6fb48e3928e6b6d388b2f116a57b735137354a7eaddca951d81b5c67 | 23.6 GB |
| Rocba-Memory.raw | /cases/rocba/Rocba-Memory/Rocba-Memory.raw | eb33bdf63730858a65a90fcf68d2190c17fb13a1f2945370d5493a27ed44765d | 19.0 GB |
| ROCBA-BACKGROUND.pptx | /cases/starter/ROCBA-BACKGROUND.pptx | 44a12c54d13243397803e6e44112fa7bc365ed7f9bcb48e6769d7e91d8980834 | 39 MB |

**What the agent found.**

| Run | Incident prompt | Grounded findings | Stop reason | Report |
| --- | --- | --- | --- | --- |
| 1 | Fred Rocba break-in and IP theft investigation | 2 (INFO: OfficeIntegrator.ps1, RegisterInboxTemplates.ps1) | no further leads | `docs/sample-run/report.md` |

**Full Report:** `docs/sample-run/report.md`
**Execution Log:** `docs/sample-run/execution-log.md`

## 3. Reproduction for judges

1. Mock path (no SIFT required): follow the README section "Running on
   captured fixtures". This validates the full loop, the grounding pipeline,
   and the report.
2. Live path: follow the README section "Running live against the SIFT VM"
   using the ROCBA evidence from `/cases/starter/` on the SIFT VM.

**Key Configuration for Reproduction:**

```bash
# .env settings
LLM_PROVIDER=ollama
LLM_MODEL=gemma4:31b-cloud
OLLAMA_BASE_URL=http://[OLLAMA_HOST]:11434
EXECUTOR=ssh
SIFT_HOST=[SIFT_VM_IP]
SIFT_USER=sansforensics
SIFT_SSH_KEY_PATH=~/.ssh/sift_vm_key
EVIDENCE_ALLOWLIST=/cases/rocba/,/cases/starter/
```

**Note:** The tool metadata (`src/find_evil/tools/metadata.yaml`) was updated during testing:
- `vol_pslist` template changed from `vol` to `/home/sansforensics/.local/bin/vol`
- `fls` template simplified to remove `-o {offset}` (not needed for filesystem images)
- Added `sudo` prefix to TSK tools (`mmls`, `fsstat`, `fls`)
