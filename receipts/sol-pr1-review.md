# Sol cross-review of PR #1 — receipts

Reviewer: gpt-5.6-sol (ultra reasoning) via `codex exec`, 2026-07-20. Trust-path cross-family review required by ops/witnessed/SPEC.md before merge.

## Classifier note

The first review pass was refused by ChatGPT's cybersecurity content classifier (the RSA/RFC 3161 verification code plus adversarial "attack this" framing). This is a known Sol failure mode on cyber content, not a signal about the code. A second pass with the task framed for what it primarily is — a mechanical-refactoring equivalence review — completed and is reproduced below. (Concurrently, this session's own main loop was downgraded to Opus by the Anthropic-side classifier on the same content; both families' safety classifiers trip on custody/crypto verification code, a standing friction for this project's trust-path reviews.)

One process artifact: the running review observed the working tree change under it (the main session added three mutations mid-pass) and reverted them believing they were its own edits; it then reviewed the committed PR tree, which is the correct target. The verdict below is against the pushed PR state (18 tests).

## Verdict: REQUEST CHANGES

No production-code divergence. The port is clean; the changes requested are coverage gaps in the equivalence gate.

### Diff audit (42 hunks)

For the supplied `LEDGER_SPEC`, no hunk changes control flow, removes or weakens validation, reorders checks, or alters an existing verifier error path. Literal changes beyond the six claimed classes, all benign: shebang removed; module docstring/provenance edited; the canonical import relocated (helper files byte-identical); schema-validator docstring generalized; `verify_release_chain()` drops its default `root` and requires the caller to pass one (an API change, behavior unchanged once called — `ROOT` did not become a ChainSpec field).

### Requested changes (coverage gaps)

1. **Base-ref / immutability surface entirely unbound.** Baseline always runs `--full`; the port only calls `verify_release_chain`. So `release_root_relative`, file-mode checking, base-tree materialization, and `verify_base_release_chain`/`verify_release_history_immutable` are never exercised — a wrong path or mode implementation would pass every current test.
2. **Local oracle not authenticated.** `VIDIMUS_LEDGER_TREE` and `.extraction/ledger-0798427` are accepted after only `is_dir()`; only the clone fallback checks out `LEDGER_PIN`. A stale/altered local baseline could be used. (Sol manually confirmed the current script SHA-256 `7f73e692…` matches the receipt, but the suite must enforce it.)
3. **`symlink_manifest` misses its branch.** It leaves a `.real` file in the closed manifest dir, so both verifiers reject the unknown file before reaching the non-regular-entry check.
4. **"Identical output" slightly overstated** — output is stripped; clean-case ignores baseline stderr; corruption cases ignore baseline stdout; incidental port stdout is not captured.

### Missing distinct mutation classes (Sol's table)

| Corruption | Unreached branch |
|---|---|
| Copy a complete quartet under a duplicate index | duplicate sequence index |
| Remove/rename a complete middle quartet | non-contiguous indices |
| Rename a quartet to an incorrect digest stem | filename/content-hash mismatch |
| Change `releaseIndex`, recanonicalize, update digest stem | payload index vs filename |
| Change previous pointer, recanonicalize, update digest stem | chain-link mismatch (reached before signature per Sol — verify ordering) |
| Symlink in manifests whose target is outside the directory | non-regular directory entry |
| Add an orphan `.producer.sig` | orphan producer-signature branch |
| Truncate a producer signature to 63 bytes | signature-length validation |
| Change an existing release file's executable bit vs a Git base | file-mode immutability check |

### Confirmed sound

Clean test genuinely binds (requires both exit codes zero before matching the success message). The other 13 mutations reach meaningful refusal paths. `flip_covered_ledger_prefix` at byte 12,277 (line 8) is covered by genesis (143 lines through byte 237,251) and reaches the release-0 historical-prefix hash branch. OpenSSL id normalization is narrow and sound (masks only the 8–16 hex queue id before `:error:`, preserving codes/routines/files/lines/order). `uv run pytest -q`: 18 passed.

## Adjudication (pending — main loop downgraded)

The reviewer is separate from the implementer: harness hardening is delegated to a fresh Fable subagent (defensive-audit framing, model verified via claude-model), then Sol re-reviews the result. Convergence check: Sol's first three missing cases match the three mutations the main session had independently built before Sol reverted them.
