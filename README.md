# receipt

Verifiable custody of agent-produced records.

## Status

Shipped so far: the release-chain verifier, the append gate, ECMAScript-compatible canonical JSON, and standalone Ed25519 signing with consumer-pinned threshold keyrings. The machinery arrives by extraction from three production systems that each built it independently (pre-registered forecast records, an observation-ledger release chain, a signed statute corpus), behind a byte-equivalence gate: the extracted verifier must reproduce the source verifier's verdict, pass and fail alike, on the live production chain at a pinned commit before any system consumes the package. That gate has held end to end — the observation ledger consumes the package in production, with the differential harnesses re-proving equivalence on every package change.

## What it provides (shipped rows) and what is still arriving

- `receipt.chain` — append-only hash-chained manifests over record sets: enumerated genesis, content-addressed links, immutable-prefix verification
- `receipt.tsa` — RFC 3161 timestamps from independent authorities, two per record, with per-witness honest degradation (an unavailable witness is recorded with a reason, never silently skipped)
- `receipt.sign` — Ed25519 producer signatures verified against fingerprints pinned in the consumer's own committed code (shipped: ported ledger primitives, sign-side helpers, N-of-M keyrings with legacy verification generations — retired keys verify immutable history only; rotation by reviewed spec change)
- `receipt.attest` — CI push attestation with self-anchoring enforcement epochs and a completeness sweep over every record-touching commit
- `receipt.ratchet` — shrink-only exception registries recomputed from live state; an excused failure that starts passing is an error until removed
- `receipt.chronology` — record-vs-event ordering tiers: does witnessed time prove the record existed *ante quem* — before the event it predicts or observes?
- `receipt verify` — the outside auditor's command: a clone, commodity tools, one offline fail-closed verdict

## Design principle

Trust anchors live in the consumer's committed code, never in runtime configuration a producer could swap. The package ships machinery; consumers pin roots.

## The name

A receipt is the record you keep so anyone can check it later. Software already uses the word in exactly this sense: an app-store receipt is a signed proof validated offline, without trusting the store that issued it. This package writes receipts for agent-produced records; `receipt verify` is what happens when someone asks to see them.

Releases through 0.1.2 shipped as `vidimus`; those remain on PyPI under the old name.

## License

Apache-2.0.
