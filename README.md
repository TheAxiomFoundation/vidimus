# vidimus

Verifiable custody of agent-produced records.

*vidimus* (Latin, "we have seen"): the medieval certificate by which an authority attests it has inspected a record and recites it verbatim. Scandinavian law still stamps certified true copies with the word — *vidimerad kopia*, *vidimeret kopi*.

## Status

Pre-release extraction target — nothing here verifies anything yet. The machinery arrives by extraction from three production systems that each built it independently (pre-registered forecast records, an observation-ledger release chain, a signed statute corpus), behind a byte-equivalence gate: the extracted verifier must reproduce the source verifier's verdict, pass and fail alike, on the live production chain at a pinned commit before any system consumes the package.

## What it will provide

- `vidimus.chain` — append-only hash-chained manifests over record sets: enumerated genesis, content-addressed links, immutable-prefix verification
- `vidimus.tsa` — RFC 3161 timestamps from independent authorities, two per record, with per-witness honest degradation (an unavailable witness is recorded with a reason, never silently skipped)
- `vidimus.sign` — Ed25519 producer signatures verified against SPKI fingerprints pinned in the consumer's own committed code; N-of-M thresholds; rotation as an explicit recorded event
- `vidimus.attest` — CI push attestation with self-anchoring enforcement epochs and a completeness sweep over every record-touching commit
- `vidimus.ratchet` — shrink-only exception registries recomputed from live state; an excused failure that starts passing is an error until removed
- `vidimus.chronology` — record-vs-event ordering tiers: does witnessed time prove the record existed *ante quem* — before the event it predicts or observes?
- `vidimus verify` — the outside auditor's command: a clone, commodity tools, one offline fail-closed verdict

## Design principle

Trust anchors live in the consumer's committed code, never in runtime configuration a producer could swap. The package ships machinery; consumers pin roots.

## The name

"Control" descends from the counter-roll (*contre-rôle*): the independent duplicate record kept so the roll could be audited. This package is the counter-roll for agent-produced records.

## License

Apache-2.0.
