# Progress

## State

Layer 1 now exists in `src/vidimus/sign.py` as a standalone copy of the producer-signature primitives. Release-chain delegation is the next step; the existing implementation remains intact until that boundary is verified.

## Done

- Confirmed the checkout is clean and on `extract-sign` tracking `origin/main`.
- Read the `vidimus.sign` design rationale.
- Indexed the repository locally for refactoring analysis; the global GitNexus registry write is sandbox-blocked, so caller mapping will be cross-checked with repository search.
- Read the release-chain implementation, both differential harnesses, and the pinned upstream oracle.
- Confirmed the clean baseline: 57 tests pass.
- Added `SignError`, `ProducerKeySpec`, producer-key reading, exact input validation, cryptography verification, and the OpenSSL fallback to `vidimus.sign`.

## Next

- Delegate the frozen `release_chain` producer-verification surface to `vidimus.sign`, preserving old helper signatures and exception types.
- Re-run the differential suites before adding sign-side capability.
