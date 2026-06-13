# Submission Guide — FIND EVIL! Hackathon

Deadline: June 15, 2026, 11:45 PM EDT. Submit at https://findevil.devpost.com.

## A. Pre-submission checklist

Repository:

- [ ] Repository is public on GitHub.
- [ ] MIT license file present at the repository root and detected by GitHub
      (visible in the About section). The `LICENSE` file in this repository
      satisfies this once pushed.
- [ ] README contains setup instructions and judge run instructions. Done.
- [ ] Architecture diagram present (`docs/architecture-diagram.svg` and
      `docs/ARCHITECTURE.md`). Upload the SVG (or a PNG export) to the
      Devpost form as well.
- [ ] `docs/EVIDENCE-DATASET.md` completed with real live-run data. All TODO
      fields filled.
- [ ] `docs/ACCURACY-REPORT.md` completed with real measured results. All
      TODO fields filled.
- [ ] At least one real report and its execution log committed (for example
      under `docs/sample-run/`), so judges can trace findings to executions.
- [ ] `make test` green and `make lint` clean on a fresh clone.
- [ ] No secrets in the repository: `.env` is gitignored; `.env.example`
      contains placeholders only; no real hosts, keys, or credentials.
- [ ] Git history contains no commits with sensitive data. If the repository
      is being published for the first time, initialize a fresh history.

Demo video:

- [ ] Under five minutes.
- [ ] Screencast of live terminal execution with audio narration. No slides.
- [ ] Shows the agent working against real evidence on the SIFT Workstation.
- [ ] Shows at least one self-correction sequence. Good candidates in this
      system: a structured-output validation failure followed by an automatic
      retry that succeeds; a finding dropped by the membership check or
      demoted by the critique pass; a tool timeout recorded as a result while
      the investigation continues to a complete report.
- [ ] Shows the audit trail: open the report and trace one finding to the
      exact command and output span that produced it.
- [ ] No third-party trademarks or copyrighted music.
- [ ] Uploaded to YouTube or Vimeo and set to public.

## B. Step-by-step submission process

1. **Publish the repository.** Create a public GitHub repository and push
   this codebase with the `LICENSE` file at the root. Confirm GitHub shows
   "MIT license" in the About section.
2. **Complete the data documents.** Run the agent live against the starter
   evidence, then fill every TODO in `docs/EVIDENCE-DATASET.md` and
   `docs/ACCURACY-REPORT.md` from the ledger and the generated reports.
3. **Commit a sample run.** Add one real report (Markdown and PDF) and the
   structured execution log to `docs/sample-run/`. Redact any host names or
   internal paths if your environment differs from the documented one.
4. **Record the demo video.** Follow the checklist above. Upload and copy the
   public link.
5. **Export the diagram.** Devpost image fields prefer PNG. Export
   `docs/architecture-diagram.svg` to PNG (any browser: open the SVG, screenshot
   or print to image, or use `rsvg-convert -o diagram.png diagram.svg`).
6. **Register on Devpost.** Log in at findevil.devpost.com and click Join
   Hackathon if not already registered.
7. **Enter the submission.** Open "Enter a Submission" and complete every
   field:
   - Project name and short tagline.
   - Text description: features and functionality. Cover the two invariants
     (completion guarantee, provenance grounding), the three required
     demonstrations (self-correction, accuracy validation, analytical
     reasoning), and the novel contribution.
   - Repository URL.
   - Demo video URL.
   - Architecture diagram image.
   - Try-it-out instructions for judges: point to the README "For judges"
     section; the mock path requires only Python 3.11, a reachable LLM
     endpoint, and `make run-mock`.
8. **Verify before the deadline.** Open the submission preview, click every
   link from a logged-out browser session, and confirm the repository, video,
   and images are publicly visible.
9. **Submit.** Submissions lock at the end of the submission period. Draft
   early; you can edit drafts until June 15, 2026, 11:45 PM EDT.

## C. Mapping to the judging criteria

| Criterion | Where this project answers it |
| --- | --- |
| Autonomous execution quality | State machine with budget guard; transport retry; failures become results and the run continues to a report |
| IR accuracy | Provenance-required findings; membership check; critique pass; constrained summary |
| Breadth and depth | Disk and memory analysis via Volatility, TSK, timeline, grep, strings; depth-first tool catalog |
| Constraint implementation | Architectural guardrails: template command assembly, allowlists, validator backstop, injection guardrail; all tested in the suite |
| Audit trail quality | SQLite ledger joins findings to executions; report renders command and cited span for every finding |
| Usability and documentation | README quickstart, mock path with no SIFT required, ADRs, architecture document |
