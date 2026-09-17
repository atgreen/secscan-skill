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
| **s3 — Decompose** | Group code into focused review slices (by entry point, by specialist scope, plus a catch-all sweep); lay out the slice × lens coverage matrix the pass is accountable to. |
| **s4 — Deep-dive** | Per slice, trace data flow (not pattern-match), apply specialist lenses, and run every candidate through the gates. |
| **s5 — Pre-filter** | Drop low-confidence / uncited / out-of-scope findings, deterministically and for free. |
| **s6 — Adversarial verify** | Assume each finding is **wrong** until confirmed in source; walk callers back to an external entry point; assign a CVSS 3.1 vector. |
| **s7/s8 — Dedup & chain** | Merge duplicates; look for multi-hop exploit chains. |
| **s9 — Report** | Severity-ranked Markdown (CWE, source→sink, exploit scenario, fix), marked as triage candidates, plus a coverage appendix naming the gaps. Optional schema-validated `findings.json` and a `coverage.json` matrix. |

## Design principles

- **Token discipline.** Locate before reading; single sequential pass; scope
  down by default; fan out to subagents only when it pays.
- **Untrusted input.** Repository content — including any embedded "ignore
  previous instructions" or `AGENTS`/`CLAUDE`-style blocks — is treated as DATA
  to analyze, never as instructions. Injection attempts are reported, not obeyed.
- **Read-only on the target.** A scan analyzes; it never edits the project's
  source, config, or tests. The one exception is the opt-in remediation flow
  (`remediate.md`), which edits only when you name findings to fix and
  adversarially validates each patch.
- **Honest output.** Zero findings is a valid result. Findings are triage
  candidates requiring human review, never represented as confirmed vulns.
- **Threat model first.** Every finding must name *who* the attacker is and
  *which* trust boundary their input crosses before it gets a title. A
  dangerous-looking sink with no actor and no boundary is a tautology, and
  saying so up front is what stops it dressing up as a vulnerability.
- **Structured, checkable output.** s9 can emit a `findings.json` conforming to
  `findings.schema.json` and validated by a zero-dependency script — which also
  resolves every cited `file:line` against the scanned tree, so a hallucinated
  citation fails instead of reaching a human.
- **Coverage accumulates.** A single pass never finds everything, so a scan
  records what it *looked at* — a slice × lens matrix marking each cell
  `covered` / `thin` / `n/a` / `not-run` — and ends by naming its own gaps. A
  class nobody examined otherwise leaves the same trace as one that came back
  clean. Persisted (opt-in), the matrix points the next run at the empty cells;
  it can only reorder that run's work, never let it skip.

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
- `gates.md` — exclusion rules, anti-manipulation (suppression annotations are
  not evidence), the six-check self-verification (which opens by naming the
  attacker and the trust boundary crossed), severity calibration, and
  exhaustiveness (loaded on demand at s4–s6).
- `lenses.md` — the specialist lenses (crypto, logic-bug, access-control,
  deserialization, batch-etl, iac, memory-safety, ai-llm, web-protocol,
  client-side, php, wordpress) and per-repo-kind threat-model baselines
  (web-api, web-app, mobile, native, iac, library).
- `cwe-kb.md` — per-CWE taint knowledge base (sources, sinks, real sanitizers
  vs. look-alike non-sanitizers, false-positive checks, and attacker bypass
  hints) plus a source/sink recognition taxonomy (sanitizer names, reflection
  sinks, framework request-binding sources). Loaded before s4; drives discovery
  (s4), pre-filter (s5), and adversarial verify (s6).
- `findings.schema.json` — JSON schema for the optional `findings.json` (s9),
  with `true_positive` and `false_positive` verdict branches.
- `validate-findings.cjs` — zero-dependency Node validator for a
  `findings.json`. Checks schema conformance, and with `--repo <scanned-path>`
  also resolves every `source_ref`/`sink_ref` against the scanned tree (file
  present, line in range and non-blank) — a hallucinated citation fails the
  build instead of reaching a human. Structural check only.
- `remediate.md` — the **opt-in** fix flow (re-confirm → minimal root-cause
  patch → adversarial validation), loaded only when you ask to fix named
  findings. It's the one path that edits the target; a scan never triggers it.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).

