# Find Evil Agent

An autonomous DFIR agent for the SANS SIFT Workstation. Given an incident
description and evidence, it investigates with real SIFT tools and produces a
report in which every finding is traceable to the exact command that produced
it.

It is built to two invariants:

1. **Completion guarantee.** A run always terminates in a report, including on
   failure and budget exhaustion. Returning zero findings is a success state.
2. **Provenance grounding.** A finding cannot exist without provenance (an
   execution id plus an evidence span). Every finding is checked against the
   cited output before it is kept, and the report is assembled from the audit
   ledger, so each claim links to a verifiable command.

## How it works

```
incident + evidence
      |
      v
 register evidence  ->  hash + classify (locally for mock, on the VM for ssh)
      |
      v
 triage             ->  mmls / fsstat to establish ground truth
      |
      v
 hypothesize        ->  1-3 falsifiable, MITRE-mapped hypotheses (LLM, structured)
      |
      v
 test hypothesis    ->  LLM returns typed ToolParams (never a command string)
      |                 code assembles the command from a template
      |                 executor runs it -> stdout
      |                 analyzer extracts grounded findings (membership check)
      |                 critique demotes or drops weak / contradicted findings
      v
 report             ->  findings with provenance, execution log, constrained
                        executive summary, IOCs (Markdown, optional PDF)
```

The LLM never writes a command. It returns typed parameters and code assembles
the command from a tool template, which removes the class of failures where
model prose reaches the shell. Tool output is treated as untrusted data; the
analyzer flags instruction-like content in output as a suspicious artifact
rather than acting on it.

## Install

```
pip install -e ".[dev]"
make test            # the full suite, green
```

The OpenAI and Anthropic SDKs are optional. Install them only if you use those
providers. The MCP interface needs the `mcp` extra: `pip install -e ".[mcp]"`.

## Running on captured fixtures (no SIFT VM)

`make run-mock` runs the whole loop against the mock executor, which replays
captured tool output from `fixtures/sample_case/`. No SIFT access is required.

The mock executor replaces the tools, not the model: hypothesize and tool
selection still call an LLM. Point it at a reachable Ollama with a capable
model first, for example:

```
LLM_MODEL=gpt-oss:120b-cloud OLLAMA_BASE_URL=http://your-ollama:11434 make run-mock
```

A small local model often fails to produce valid structured output; prefer a
capable model. The provider retries transport timeouts and rate limits with
backoff, so a single slow response does not end the investigation.

## Running live against the SIFT VM

Copy the template and fill in your host:

```
cp .env.example .env
```

Key settings (see `.env.example` for the full list):

```
LLM_PROVIDER=ollama
LLM_MODEL=gpt-oss:120b-cloud
OLLAMA_BASE_URL=http://your-ollama:11434

EXECUTOR=ssh
SIFT_HOST=192.168.1.50
SIFT_USER=sansforensics
SIFT_SSH_KEY_PATH=/home/you/.ssh/id_ed25519   # key auth is preferred
# SIFT_PASSWORD=...                            # password auth fallback
SIFT_STRICT_HOST_KEY=true                      # known-hosts verification

EVIDENCE_ALLOWLIST=/mnt/evidence/,/cases/      # paths AS SEEN ON THE VM
```

Then run, passing one or more evidence paths as seen on the VM:

```
find-evil "suspected web shell on a Linux server" \
  --evidence /cases/demo/web_uploads/img-cache.php \
  --evidence /cases/demo/payload.bin \
  --out report.md --pdf report.pdf
```

In ssh mode the agent never reads evidence locally. It hashes each artifact on
the VM (`sha256sum`) for registration and runs every tool over SSH. Transport
errors and timeouts become recorded results, never crashes, so the loop keeps
going and still produces a report.

## Interfaces

Both interfaces are thin adapters over one engine and one report path. They
produce identical reports for the same input.

- **CLI:** `find-evil "<incident>" --evidence <path> [--goal ...] [--supervised] [--out report.md] [--pdf report.pdf]`
- **MCP:** `find-evil-mcp` starts an MCP server exposing one `investigate` tool
  that returns the same Markdown report. Requires the `mcp` extra.

## What the report contains

- **Evidence:** each artifact with its sha256 and size.
- **Hypothesis ledger:** each hypothesis, its MITRE techniques, status, and
  posterior.
- **Findings:** every finding shows its verification level, the command that
  produced it, and the cited output span. Only grounded findings appear.
- **Execution log:** every tool execution in order, with timestamp, status,
  duration, per-call token usage, and the path to the raw output.
- **Executive summary:** generated from the verified findings only and rejected
  if it introduces any IOC absent from the findings, so the summary invents
  nothing.
- **Indicators of compromise:** collected from the grounded findings.

## Configuration reference

Settings load from the environment or `.env`. The notable ones:

| Setting | Meaning |
| --- | --- |
| `LLM_PROVIDER` | `ollama`, `openai`, or `anthropic` |
| `LLM_MODEL` | model name or tag on the provider |
| `OLLAMA_BASE_URL` | Ollama endpoint |
| `EXECUTOR` | `mock` or `ssh` |
| `SIFT_HOST` / `SIFT_USER` | the SIFT VM and account |
| `SIFT_SSH_KEY_PATH` / `SIFT_PASSWORD` | auth; key preferred |
| `SIFT_STRICT_HOST_KEY` | known-hosts verification on or off |
| `EVIDENCE_ALLOWLIST` | permitted evidence path prefixes on the VM |
| `CRITIQUE_ENABLED` | run the LLM critique pass on findings |
| `MAX_STEPS` / `MAX_WALL_SECONDS` / `MAX_TOKENS` | run budget |
| `DB_PATH` | SQLite ledger path |

## Architecture map

- `engine/machine.py`   state machine and completion guarantee
- `engine/phases.py`    triage, hypothesize, test, execute
- `engine/schemas.py`   shared contracts
- `tools/command.py`    template command assembly
- `tools/executor.py`   mock and SSH executors
- `tools/parsers/`      Volatility, TSK, timeline, grep, strings parsers
- `analysis/analyzer.py`   grounded extraction and the adversarial guardrail
- `analysis/verify.py`     membership check and critique pass
- `analysis/summary.py`    constrained executive summary
- `analysis/mitre.py`      MITRE ATT&CK mapping
- `evidence/register.py`   local and VM-side evidence hashing
- `ledger/store.py`     SQLite audit spine
- `llm/`                Ollama, OpenAI, Anthropic providers with retry
- `report/`             deterministic report assembly and PDF export
- `interfaces/`         core entrypoint, CLI, MCP

## For judges (FIND EVIL! hackathon)

The fastest verification path requires no SIFT Workstation:

```
pip install -e ".[dev]"
make test        # full suite
LLM_MODEL=<capable-model> OLLAMA_BASE_URL=http://<host>:11434 make run-mock
```

`run-mock` exercises the entire loop (triage, hypothesize, test, verify,
critique, report) against captured fixtures and writes `mock_report.md`. Every
finding in the report shows the command that produced it and the cited output
span. For a live run against the SIFT Workstation, follow "Running live
against the SIFT VM" above using the starter evidence mounted under an
allowlisted path.

Submission documents: architecture in `docs/ARCHITECTURE.md` and
`docs/architecture-diagram.svg`, evidence dataset documentation in
`docs/EVIDENCE-DATASET.md`, accuracy self-assessment in
`docs/ACCURACY-REPORT.md`.

### Self-correction

The agent detects and resolves its own errors without human intervention:

- Structured-output validation failures and transport failures (timeouts,
  connection errors, HTTP 5xx) trigger automatic retries with backoff.
- Findings whose claimed indicators do not appear in the cited output are
  dropped by a deterministic membership check before they can enter a report.
- A critique pass demotes weak findings and drops contradicted ones.
- An executive summary that introduces an indicator absent from the verified
  findings is rejected and regenerated under constraint.
- Tool timeouts and failures become recorded results; the investigation
  continues and still terminates in a complete report.

### Novel contribution

All engine, trust-layer, executor, and interface code in this repository is
new work created during the hackathon period. The design responds to a
documented prior failure mode in agentic DFIR tooling: confident narrative
reports that could not be traced to evidence. The contribution is an
architecture in which hallucinated findings are structurally excluded rather
than discouraged by prompting: findings cannot be constructed without
provenance, claims are verified by membership against cited output, commands
are assembled from templates so model prose can never reach the shell, and
the report is a deterministic join over an audit ledger. The decision record
is in `docs/adr/`.

## License

MIT. See `LICENSE`.

## Further reading

`CLAUDE.md` is the operating contract and conventions. Architecture decisions
are in `docs/adr/`. The architecture overview and diagram are in
`docs/ARCHITECTURE.md`. The submission checklist is in `docs/SUBMISSION.md`.
