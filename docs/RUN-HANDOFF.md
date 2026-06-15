# Claude Code Handoff — ROCBA live run and submission artifacts

You are operating inside the `find-evil` repository. Your job is to take the
ROCBA standard forensic case from downloaded files through a clean live run and
produce the submission artifacts. Read `CLAUDE.md` and `docs/adr/` first. Honor
the two invariants. Do not weaken any rail. Run `make test` after any code
change and keep it green. Do not modify findings or fabricate any output; if a
step cannot be completed, record it honestly and stop for me.

## Operating context

- Host A: the machine running Claude Code and the `find-evil` CLI. Reaches both
  the SIFT VM (SSH) and an Ollama endpoint.
- SIFT VM: Linux SANS SIFT Workstation on the LAN. Holds the evidence and runs
  the forensic tools. Keep it off any production network segment.
- The agent runs in `EXECUTOR=ssh` mode. It hashes and reads evidence on the
  VM, never locally.

## Safety rails (non-negotiable)

1. Mount the disk image READ ONLY. Never mount read-write.
2. Never copy an executable out of the mounted image and run it.
3. Snapshot the VM before mounting (I will confirm this is done).
4. Do all evidence handling on the VM, not on Host A.
5. The VM needs network only to its Ollama host and to accept SSH from Host A.
   It does not need broad internet egress during analysis.

## Inputs I will provide

- The three ROCBA files downloaded to a directory on Host A or already copied
  to the VM: `rocba-cdrive.e01`, `Rocba-Memory.zip`, `ROCBA-BACKGROUND.pptx`.
- The SIFT VM host, user, and SSH key path.
- The Ollama base URL and a capable model tag.
- The incident description text (I will extract it from the briefing pptx).

Ask me for any of these that are not present before proceeding. Do not guess
hosts, keys, or model names.

## Phase 0 — Verify the environment

1. Confirm `make test` is green and `make lint` is clean on the current tree.
2. Confirm Host A can SSH to the VM and can reach the Ollama endpoint.
3. Read `src/find_evil/tools/metadata.yaml` and the TSK and Volatility parsers
   in `src/find_evil/tools/parsers/`. Determine the exact form each tool
   expects for its evidence path slot: a raw image path, the `.E01` directly,
   or a mounted filesystem path. This decides what to pass in Phase 3. Report
   what you find before mounting; do not assume.

## Phase 1 — Place and verify evidence on the VM

All commands run on the VM via SSH unless stated.

1. Ensure a case directory exists and has at least 50 GB free:
   `mkdir -p /cases/rocba && df -h /cases`.
2. Get the three files onto the VM under `/cases/rocba/`. If they are on
   Host A, transfer with `scp`. If I give direct URLs, `wget` them on the VM.
3. Record sha256 of each file and save to
   `docs/sample-run/evidence-hashes.txt`:
   `sha256sum /cases/rocba/rocba-cdrive.e01 /cases/rocba/Rocba-Memory.zip`.
   If the briefing publishes hashes, compare and report any mismatch.
4. Extract the memory capture in place:
   `cd /cases/rocba && unzip Rocba-Memory.zip`. If it is password protected,
   try `infected`, then ask me if that fails. Note the extracted memory file
   name (likely `.raw`, `.mem`, or `.vmem`).

## Phase 2 — Mount the disk image read only

1. `sudo ewfmount /cases/rocba/rocba-cdrive.e01 /mnt/ewf/` produces the raw
   image at `/mnt/ewf/ewf1`.
2. `sudo mmls /mnt/ewf/ewf1` to find the partition table. Identify the Windows
   filesystem partition and its start sector.
3. If Phase 0 determined the tools want a mounted filesystem, mount read only
   at the byte offset (start sector times sector size, usually 512):
   `sudo mount -o ro,loop,offset=<bytes>,noatime /mnt/ewf/ewf1 /mnt/case_disk`.
   If the tools operate on the raw image or the `.E01` directly, skip the
   filesystem mount and use `/mnt/ewf/ewf1` or the `.E01` path as Phase 0
   indicated.
4. Confirm read-only: the mount options must include `ro`. Report the final
   evidence paths you will pass to the agent.

## Phase 3 — Configure and validate

1. On Host A, write `.env` from `.env.example` with the real values:
   `LLM_PROVIDER=ollama`, `LLM_MODEL=<model>`, `OLLAMA_BASE_URL=<url>`,
   `EXECUTOR=ssh`, the SIFT host/user/key, `SIFT_STRICT_HOST_KEY=true`,
   `EVIDENCE_ALLOWLIST=/cases/rocba/,/mnt/case_disk/,/mnt/ewf/` (include
   whichever prefixes cover the paths from Phase 2), and a `DB_PATH` such as
   `./rocba_run.db`. Never commit `.env`.
2. Validation gate: run `make run-mock` once and confirm it completes and
   writes a grounded report. This proves the loop and the model endpoint work
   before spending a long live run. Do not proceed if the mock run fails.

## Phase 4 — Live run

1. Run the investigation, writing artifacts into `docs/sample-run/`:
   ```
   find-evil "<incident description I provide>" \
     --evidence <disk path from Phase 2> \
     --evidence /cases/rocba/<memory file> \
     --out docs/sample-run/report.md \
     --pdf docs/sample-run/report.pdf
   ```
2. Watch the structured logs. A timeout or transport error that becomes a
   recorded result and lets the loop continue is expected and good; keep it.
3. Confirm the run reached a real terminal state and the report contains
   findings with commands and cited spans, an execution log, and a summary.
   Zero findings is a valid honest result; do not pad it.
4. If no self-correction event appears (a membership-check drop, a critique
   demotion, or a retried transport failure), run a second incident prompt to
   try to surface one, since the demo and accuracy report need a real example.
   Record which run contains it.

## Phase 5 — Extract artifacts for the documents

1. Read `src/find_evil/ledger/store.py` to learn the real table and column
   names. Do not assume the schema.
2. Export the execution log and the finding-to-execution join into
   `docs/sample-run/execution-log.md` so any finding traces to its execution.
3. From the report Evidence section and the ledger, collect: artifact sha256
   and sizes, grounded findings count, stop reason, findings dropped by the
   membership check, findings demoted or dropped by critique, and any
   hallucinated claim that reached a report (target zero).
4. Fill `docs/EVIDENCE-DATASET.md` and `docs/ACCURACY-REPORT.md` with these
   real values only. Leave any value you cannot measure marked TODO and tell
   me; do not estimate. For ground truth, use the briefing pptx and any
   published case answer key I provide.

## Phase 6 — Redact and commit

1. Scan `docs/sample-run/` for environment specifics you should not publish:
   internal hostnames, full user home paths, the VM IP. Redact location only,
   never finding substance.
2. Confirm `.env` is gitignored and no secrets are staged.
3. Commit in honest, separate steps:
   - `docs: add ROCBA sample run report and execution log`
   - `docs: complete evidence and accuracy documentation from ROCBA run`
4. Report a short summary: stop reason, findings count, the self-correction
   example captured, and any TODO that still needs me.

## Teardown

After artifacts are committed, unmount cleanly:
`sudo umount /mnt/case_disk` (if mounted) then `sudo umount /mnt/ewf`. Leave the
evidence files in place in case I need to rerun.
