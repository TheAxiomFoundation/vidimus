"""Verifiable custody of agent-produced records.

Shipped: the append-only release-chain verifier (receipt.release_chain),
ECMAScript-compatible canonical JSON (receipt.canonical), the append-only gate
(receipt.append_gate), standalone Ed25519 signing plus consumer-pinned threshold
keyrings (receipt.sign), RFC 3161 dual-witness verification (receipt.tsa), and
workflow-provenance verification (receipt.attest). The ledger machinery was
extracted from PolicyEngine/ledger at commit 0798427850, and the TSA and
attestation machinery from MaxGhenis/brier at commit 4b9e7be22de, behind
differential harnesses that run the unmodified upstream as an oracle and prove
byte-identical verdicts. Trust anchors are supplied by the consumer's committed
code via ChainSpec, AppendGateSpec, ProducerKeySpec, KeyringSpec, TsaSpec, or
AttestSpec; the package ships no defaults.

Pending extraction: waiver ratchet, chronology tiers, and the spanning
verification CLI.
"""

__version__ = "0.4.0"
