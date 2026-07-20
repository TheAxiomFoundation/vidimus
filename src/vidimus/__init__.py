"""Verifiable custody of agent-produced records.

Shipped: the append-only release-chain verifier (vidimus.release_chain),
ECMAScript-compatible canonical JSON (vidimus.canonical), and the append-only
gate (vidimus.append_gate) — extracted from PolicyEngine/ledger at commit
0798427850 behind differential harnesses that run the unmodified upstream as
an oracle and prove byte-identical verdicts. Trust anchors are supplied by the
consumer's committed code via ChainSpec / AppendGateSpec; the package ships no
defaults.

Pending extraction: standalone dual-witness TSA orchestration, N-of-M producer
signing, push attestation with offline bundles, waiver ratchet, chronology
tiers, and the spanning verification CLI.
"""

__version__ = "0.1.2"
