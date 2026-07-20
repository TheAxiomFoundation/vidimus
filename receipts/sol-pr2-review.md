# Sol review of PR #2 (append gate) — APPROVE

Reviewer: gpt-5.6-sol via `codex exec`, 2026-07-20, equivalence-audit framing. Verdict: **APPROVE**.

## Port diff (695 lines) — behavior-preserving

Candidate paths remain isolated in `_set_root`; production anchors come from `trusted_code_root` (append_gate.py:774), not the candidate tree. Surface separation (GATE_SURFACE/DATA_SURFACE), append-only enforcement, exact-byte append, assertionVersion/supersedes/duplicate-source_record_id logic, and binding-pair validation all retain their order and error paths. Only change is parameterization into AppendGateSpec (composing ChainSpec).

## Harness non-vacuous

Runs the SHA-authenticated unmodified upstream gate CLI with `--base-ref` as oracle. Acceptance requires both exit 0 AND full message equality; refusal requires both exit 1 AND full normalized equality before the branch marker. Valid append accepts both; all 12 mutations reject both.

## Base-tree binding is REAL (the key claim from PR #1's deferral)

Sol ran the sabotage experiment as instructed:
- Before: 17 passed.
- `materialize_base_tree` (release_chain.py:1340) replaced by a no-op: **4 failed, 13 passed**. `test_clean_valid_append_verdicts_match` caught it directly — upstream accepted while the port refused with "base release chain is invalid: release chain is absent; genesis is required". Three mutation cases also failed equivalence.
- Reverted; 17 passed again, worktree clean.

So verify_base_release_chain + materialize_base_tree — the surface explicitly deferred from PR #1 — are now genuinely bound.

Full suite: **53 passed**.

## Non-blocking follow-ups

1. **Low, inherited (NOT a regression) → report upstream, not fix here.** Binding-pair validation uses truthiness (append_gate.py:394), so `targetContentHash: ""` without a projection, or `sourceBindingProjection: {}` without a hash, is accepted. Sol reproduced both with a real row + recomputed assertion ID. **Upstream check_thesis_facts_append.py behaves identically**, so the port is faithful; fixing it in vidimus would break byte-equivalence. This is a Ledger-side hardening item to report to that surface's owner.
2. **Optional hardening (most valuable missing test).** The fixture's candidate anchors and trusted-code-root anchors are identical, so a test cannot currently distinguish "anchors read from trusted root" from "from candidate." Sol proved the gap by inverting anchor lookup to `candidate.root` — all 17 still passed. A test that commits invalid candidate anchor bytes into the base while keeping pristine anchors under trusted_code_root would bind the CODE_ROOT-vs-ROOT anchor-source distinction. Tracked as follow-up hardening.

## Provenance

Built by Sol across three interrupted relaunches (process restarts + watchdog timeouts; Sol wrote correct files then died before reporting — harvested by running pytest, the oracle). Reviewed by a fresh Sol pass (this receipt). Merge held per the no-Opus-trust-path-merge rule; Sol cross-family approval is the trust anchor.
