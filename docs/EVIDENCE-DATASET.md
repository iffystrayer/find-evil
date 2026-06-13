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

> TODO before submission: complete every field in this section from your
> actual live runs. Do not estimate. Pull values from the run ledger
> (`find_evil_runs.db`) and the generated reports.

**Environment.**

- SIFT Workstation version: `TODO`
- Deployment: local VM on a LAN, accessed over SSH with host key verification
- LLM provider and model: `TODO (for example: Ollama, model tag)`

**Case data.**

| Item | Value |
| --- | --- |
| Dataset name | `TODO (for example: hackathon starter case)` |
| Source | `TODO (for example: Protocol SIFT Slack starter evidence)` |
| Artifact types | `TODO (disk image, memory capture, logs)` |
| Sizes and sha256 | `TODO (copy from the report Evidence section)` |

**What the agent found.**

| Run | Incident prompt | Grounded findings | Stop reason | Report |
| --- | --- | --- | --- | --- |
| 1 | `TODO` | `TODO` | `TODO` | `TODO (path or link)` |

Attach or link at least one full report produced from live evidence, and the
corresponding execution log, so any finding can be traced to the tool
execution that produced it.

## 3. Reproduction for judges

1. Mock path (no SIFT required): follow the README section "Running on
   captured fixtures". This validates the full loop, the grounding pipeline,
   and the report.
2. Live path: follow the README section "Running live against the SIFT VM"
   using the starter evidence from the Protocol SIFT resources, mounted under
   an allowlisted path on the VM.
