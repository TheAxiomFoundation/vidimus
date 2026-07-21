"""Verifiable custody of agent-produced records.

Shipped: the append-only release-chain verifier (vidimus.release_chain),
ECMAScript-compatible canonical JSON (vidimus.canonical), the append-only gate
(vidimus.append_gate), and standalone Ed25519 signing plus consumer-pinned
threshold keyrings (vidimus.sign). The ledger machinery was extracted from
PolicyEngine/ledger at commit 0798427850 behind differential harnesses that run
the unmodified upstream as an oracle and prove byte-identical verdicts. Trust
anchors are supplied by the consumer's committed code via ChainSpec,
AppendGateSpec, ProducerKeySpec, or KeyringSpec; the package ships no defaults.

Pending extraction: standalone dual-witness TSA orchestration, push attestation
with offline bundles, waiver ratchet, chronology tiers, and the spanning
verification CLI.
"""

__version__ = "0.1.2"
