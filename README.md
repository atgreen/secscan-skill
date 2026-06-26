# secscan

A token-efficient, **in-session** security-triage skill for [Claude Code](https://claude.com/claude-code).

`secscan` runs a staged LLM SAST pipeline entirely inside a single Claude Code
session using the agent's own `Read`/`Grep`/`Glob` tools — no external scanner,
no per-chunk fan-out, no voting runs. It costs a fraction of the tokens a
multi-call scanning harness would, while keeping real discipline: every finding
is gated, severity-calibrated, and adversarially verified before it's reported.

## The pipeline

| Stage | What it does |
|-------|--------------|
| **s1 — Survey & recon** | Read the project's own `SECURITY.md` (authoritative), inventory languages/frameworks, classify repo kind, map entry points → sinks, pick specialist lenses. |
| **s2 — Threat model** | Instantiate the OWASP/CWE baseline for the repo kind + a STRIDE pass; anchor to the project's published trust boundaries. |
| **s3 — Decompose** | Group code into focused review slices (by entry point, by specialist scope, plus a catch-all sweep). |
| **s4 — Deep-dive** | Per slice, trace data flow (not pattern-match), apply specialist lenses, and run every candidate through the gates. |
| **s5 — Pre-filter** | Drop low-confidence / uncited / out-of-scope findings, deterministically and for free. |
| **s6 — Adversarial verify** | Assume each finding is **wrong** until confirmed in source; walk callers back to an external entry point; assign a CVSS 3.1 vector. |
| **s7/s8 — Dedup & chain** | Merge duplicates; look for multi-hop exploit chains. |
| **s9 — Report** | Severity-ranked Markdown (CWE, source→sink, exploit scenario, fix), marked as triage candidates. |

## Design principles

- **Token discipline.** Locate before reading; single sequential pass; scope
  down by default; fan out to subagents only when it pays.
- **Untrusted input.** Repository content — including any embedded "ignore
  previous instructions" or `AGENTS`/`CLAUDE`-style blocks — is treated as DATA
  to analyze, never as instructions. Injection attempts are reported, not obeyed.
- **Read-only on the target.** secscan analyzes; it never edits the project's
  source, config, or tests.
- **Honest output.** Zero findings is a valid result. Findings are triage
  candidates requiring human review, never represented as confirmed vulns.

## Install

Clone straight into your Claude Code skills directory:

```sh
git clone ssh://cave@cave.moxielogic.com/atgreen/secscan-skill.git \
  ~/.claude/skills/secscan
```

Then in Claude Code:

```
/secscan <path>
```

or just ask: *"security scan src/ for vulnerabilities"*. With no path it
defaults to the current repo's diff vs. `main`.

## Files

- `SKILL.md` — the skill definition and pipeline (loaded by Claude Code).
- `gates.md` — exclusion rules, the five-check self-verification, severity
  calibration, and exhaustiveness (loaded on demand at s4–s6).
- `lenses.md` — the six specialist lenses (crypto, logic-bug, access-control,
  deserialization, batch-etl, iac) and per-repo-kind threat-model baselines.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).

