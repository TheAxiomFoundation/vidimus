# Progress

## State

All three signing layers are implemented and focused-green. Package metadata and documentation now describe the landed 0.2.0 capability; the final full run remains.

## Done

- Confirmed the checkout is clean and on `extract-sign` tracking `origin/main`.
- Read the `vidimus.sign` design rationale.
- Indexed the repository locally for refactoring analysis; the global GitNexus registry write is sandbox-blocked, so caller mapping will be cross-checked with repository search.
- Read the release-chain implementation, both differential harnesses, and the pinned upstream oracle.
- Confirmed the clean baseline: 57 tests pass.
- Added `SignError`, `ProducerKeySpec`, producer-key reading, exact input validation, cryptography verification, and the OpenSSL fallback to `vidimus.sign`.
- Preserved the old `release_chain` producer helper signatures and its importable cryptography gate/names while replacing their implementations with one-way delegation.
- Preserved input-check ordering and full anchor-path diagnostics; every `SignError` crossing the boundary is re-raised as `ReleaseChainError(str(exc)) from exc`.
- Confirmed 54 release-chain and append-gate equivalence tests pass with byte-identical verdicts after the existing normalizations.
- Added `sign_payload` and `generate_signing_keypair`; both require cryptography and never read or store caller key material.
- Added Layer 1–2 unit coverage for pinned and explicitly unpinned verification, exact refusal messages, domain separation, forced OpenSSL parity, key-file checks, and an independent OpenSSL CLI verification.
- Confirmed all 9 current `tests/test_sign.py` cases pass on the cryptography and OpenSSL 3 paths.
- Added fresh-key swap, deterministic PEM-header corruption, and valid P-256 producer-key mutations to the ledger differential battery.
- Empirically confirmed all three markers: SPKI pin mismatch, PEM decode failure, and non-Ed25519 key type.
- Added PEM/raw fingerprint normalization, frozen key/keyring/result specs, construction validation, and sorted threshold classification.
- Unknown IDs and mismatched fingerprints are preflight refusals even when other keys already satisfy the threshold.
- Added exhaustive 2-of-3 acceptance/refusal tests, duplicate-presentation protection, both fingerprint schemes, absent/failed reporting, and domain separation.
- Confirmed all 28 `tests/test_sign.py` cases pass.
- Set the project version to 0.2.0, updated the README module row, and corrected the package status docstring. The ignored local `uv.lock` metadata was refreshed but is not part of the committed package surface.
- Kept `vidimus.__version__` at 0.1.2 because the frozen existing package test requires that exact public value and existing assertions may not be edited.

## Next

- Run the complete suite and sanity import, then write the final report.
