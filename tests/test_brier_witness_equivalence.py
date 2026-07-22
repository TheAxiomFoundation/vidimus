"""Differential harness for brier's RFC 3161 witness verifier.

Baseline = ``MaxGhenis/brier``'s unmodified
``scripts/verify_record_chain.py`` at commit
``4b9e7be22debc8349e76b8bdfe5a0fe18ed31a3f``.  Candidate = a thin
harness-local chain walk composed with :mod:`receipt.tsa` and
:mod:`receipt.sign`.  The brier values below are the consumer-committed spec;
the package contains none of them.

Comparison contract, stated exactly:

- exit status must match (0 accept, 1 refuse);
- on refusal, the baseline CLI's stderr must equal the candidate exception
  message byte for byte after two stated normalizations, and baseline stdout
  must be empty: surrounding whitespace is stripped from both captured
  messages, and OpenSSL 3's volatile 8--16 hexadecimal error-queue identifier
  before ``:error:`` is masked at the start of embedded error lines;
- on acceptance, the baseline stdout summary must equal the summary composed
  from the candidate return value byte for byte, and baseline stderr is empty;
- the package port is a silent library: stdout and stderr remain empty around
  candidate calls (asserted with ``capfd``); subprocesses capture their own
  streams.

The clean tree has 53 snapshots, 52 available witnesses, and 91 real tokens.
It also has armed producer signing: the final snapshot's production signature
is verified here through :mod:`receipt.sign`, not through copied oracle code.
Every mutation returns an empirically observed refusal marker, and the battery
is ordered by the verifier's check order.

Deliberately outside the mutation contract:

- witness objects are open-world in the oracle; an unknown top-level field is
  accepted, so there is no refusal branch to bind;
- the v1 unavailable genesis witness accepts token-looking fields; the fatal
  token-evidence rule is specifically the v2 per-anchor outcome contract;
- a true ``genTime``-after-wall-clock mutation is no longer reachable through
  the CLI because every pinned signed token is now in the past and the CLI has
  no ``--now`` input.  Editing only the declared time reaches the later claim
  mismatch, not signed-time skew.  ``tests/test_tsa.py`` pins both time-helper
  refusal messages directly;
- the tree has no cryptographically valid token from a different signer.  The
  reachable identity mutation binds the declared signer-certificate mismatch
  after successful crypto, not the deeper unpinned-signer branch;
- rehashing corrupted tokens reaches OpenSSL diagnostics containing random
  temporary paths, outside the stated normalization.  Flip/truncation cases
  intentionally retain the committed hash and bind the deterministic token
  hash refusal; clean agreement exercises all valid OpenSSL paths.

The authenticated tree resolves from ``RECEIPT_BRIER_TREE``, then the local
``.extraction/`` materialization, then a fresh public clone at the pin.  The
entry script and both imports it executes are SHA-authenticated in every path.
Mutation trees hardlink the large records surface and replace changed inodes;
they never write through a link into the read-only oracle tree.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest

from receipt.canonical import canonical_bytes
from receipt.sign import SignError, spki_sha256, verify_signature_bytes
from receipt.tsa import (
    TrustBundleSpec,
    TsaError,
    TsaIdentitySpec,
    TsaSpec,
    WitnessEvidence,
    activate_trust_bundles,
    bootstrap_trust_bundles,
    load_json,
    logical_path,
    physical_path,
    sha256_file,
    trust_bundle_updates,
    verify_witness,
)

BRIER_PIN = "4b9e7be22debc8349e76b8bdfe5a0fe18ed31a3f"
BRIER_REPO_URL = "https://github.com/MaxGhenis/brier.git"

BASELINE_AUTHENTICATED_FILES = {
    "scripts/verify_record_chain.py": (
        "8c61843042706d4e5ad0c417a759237141d3f04c8580b5adcdf8a7b873cc5d74"
    ),
    "scripts/canonical_json.py": (
        "562bf267b7686bce8cb71f3c13f34825c21cd4ef0aba1c0c46aff16962a6cadd"
    ),
    "scripts/producer_signing_pins.py": (
        "a9e3b4daabe85b2ecb6b040f458791155165be4b72406e43cc64d7ee641b7fc7"
    ),
}

# Consumer-committed transcription of the authenticated brier verifier and
# its byte-pinned trust bundles.  Anchor skew is explicit here; the package has
# no 300-second fallback or other repository trust default.
BRIER_TSA_SPEC = TsaSpec(
    trust_bundles=(
        TrustBundleSpec(
            bundle_id="tsa-anchors-v1",
            path="records/trust/tsa-anchors-v1.json",
            sha256=(
                "737bc9a149726f375edaebcd39b34116d90a5d29e9a043bcb0437998928e5791"
            ),
            size=1049,
            canonical_json_sha256=(
                "9930588eb27ba631446416cf0d2bdac80785e73cf1d32e1d2ed70b0bb49f3d39"
            ),
        ),
        TrustBundleSpec(
            bundle_id="tsa-anchors-v2",
            path="records/trust/tsa-anchors-v2.json",
            sha256=(
                "b8ece84adcc354f413f10f1b3999ac99679196b9391d76a9967369047b7d7716"
            ),
            size=1916,
            canonical_json_sha256=(
                "036737fdd779f5add77b79262d9967e4bac450ff3ab7132eb929dbf893a4c396"
            ),
        ),
    ),
    tsa_identities=(
        TsaIdentitySpec(
            bundle_id="tsa-anchors-v1",
            anchor_id="freetsa-root-2016",
            root_spki_sha256=(
                "52c54ba340885605314daa1857c8763b94087d05c636092938d4e2d1818e99b5"
            ),
            signer_spki_sha256=frozenset(
                {
                    "fa02bd555e3e483d62b4e70be6218692068d2b0b0a7525db58dcbf2901cdb072"
                }
            ),
            max_future_seconds=0,
            max_token_lead_seconds=300,
        ),
        TsaIdentitySpec(
            bundle_id="tsa-anchors-v2",
            anchor_id="freetsa-root-2016",
            root_spki_sha256=(
                "52c54ba340885605314daa1857c8763b94087d05c636092938d4e2d1818e99b5"
            ),
            signer_spki_sha256=frozenset(
                {
                    "fa02bd555e3e483d62b4e70be6218692068d2b0b0a7525db58dcbf2901cdb072"
                }
            ),
            max_future_seconds=0,
            max_token_lead_seconds=300,
        ),
        TsaIdentitySpec(
            bundle_id="tsa-anchors-v2",
            anchor_id="digicert-trusted-root-g4",
            root_spki_sha256=(
                "59df317bfa9f4f0ab7ca514d7772296aa2c765b87664d08b96e57399e364729c"
            ),
            signer_spki_sha256=frozenset(
                {
                    "7abda95ed7301ac94bded350babc319903d0b4f16c4e7e39346dba5f9e992b72"
                }
            ),
            max_future_seconds=0,
            max_token_lead_seconds=300,
        ),
    ),
    legacy_witness_bundle_id="tsa-anchors-v1",
)

SNAPSHOT_RE = re.compile(r"digest-[A-Za-z0-9][A-Za-z0-9._-]*\.json$")
SIGNATURE_DOMAIN = b"thesis-record-snapshot/v1\0"
SIGNATURE_SUFFIX = ".producer.sig"
PUBLIC_KEY_RELPATH = "records/trust/producer-ed25519.pem"
PRODUCER_SPKI_SHA256 = (
    "b96f4556ebe77bf97a1b7421a131ff49bec68b450bb92591cdf4b135c8d21e30"
)
ACTIVATION_SNAPSHOT = "records/2026-07-21/digest-29850168611-1.json"

GENESIS = pathlib.Path("2026-07-09/digest-f4f3-genesis.json")
PRE_TRANSITION = pathlib.Path("2026-07-10/digest-29109573200-1.json")
TRANSITION = pathlib.Path("2026-07-10/digest-29110005611-1.json")
POST_TRANSITION = pathlib.Path("2026-07-10/digest-29110188998-1.json")
V1_BUNDLE = pathlib.Path("trust/tsa-anchors-v1.json")
V2_BUNDLE = pathlib.Path("trust/tsa-anchors-v2.json")


@dataclass(frozen=True)
class CandidateVerification:
    ordered: tuple[pathlib.Path, ...]
    witnesses: dict[pathlib.Path, WitnessEvidence]
    active_trust_bundles: dict[str, dict[str, Any]]
    pending_trust_bundle_updates: tuple[dict[str, Any], ...]


def _authenticated_baseline_tree(tree: pathlib.Path) -> pathlib.Path:
    """Authenticate the entry point and every Python source it executes."""

    for relative, expected in BASELINE_AUTHENTICATED_FILES.items():
        path = tree / relative
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected:
            raise RuntimeError(
                "baseline oracle is not the pinned verifier: "
                f"{path} has SHA-256 {digest}, expected {expected} "
                "(receipts/brier-pin-source-hashes.txt). A stale or altered "
                "baseline must not silently vouch for the port."
            )
    return tree


@pytest.fixture(scope="session")
def brier_tree(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    override = os.environ.get("RECEIPT_BRIER_TREE")
    if override:
        tree = pathlib.Path(override)
        if not tree.is_dir():
            raise RuntimeError(f"RECEIPT_BRIER_TREE is not a directory: {tree}")
        return _authenticated_baseline_tree(tree)
    local = (
        pathlib.Path(__file__).resolve().parents[1]
        / ".extraction"
        / f"brier-{BRIER_PIN[:7]}"
    )
    if local.is_dir():
        return _authenticated_baseline_tree(local)
    clone = tmp_path_factory.mktemp("brier-pin") / "brier"
    subprocess.run(
        ["git", "clone", "--quiet", BRIER_REPO_URL, str(clone)],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(clone), "checkout", "--quiet", BRIER_PIN],
        check=True,
    )
    return _authenticated_baseline_tree(clone)


def run_baseline(
    tree: pathlib.Path, records: pathlib.Path
) -> tuple[int, str, str]:
    completed = subprocess.run(
        [
            sys.executable,
            str(tree / "scripts" / "verify_record_chain.py"),
            str(records),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def snapshot_paths(records: pathlib.Path) -> list[pathlib.Path]:
    return sorted(
        path
        for path in records.glob("????-??-??/digest-*.json")
        if SNAPSHOT_RE.fullmatch(path.name)
        and not path.name.endswith(".witness.json")
    )


def _ordered_chain(records: pathlib.Path) -> tuple[list[pathlib.Path], dict[pathlib.Path, dict[str, Any]]]:
    genesis = load_json(records / "CHAIN_GENESIS.json")
    snapshots = snapshot_paths(records)
    first_logical = genesis.get("firstSnapshot")
    if not isinstance(first_logical, str) or not first_logical:
        raise TsaError("genesis firstSnapshot must name one snapshot")
    first = physical_path(records, first_logical)
    if first not in snapshots:
        raise TsaError(f"genesis snapshot is missing or malformed: {first_logical}")
    snapshot_set = set(snapshots)
    successors: dict[pathlib.Path, list[pathlib.Path]] = {
        path: [] for path in snapshots
    }
    payloads: dict[pathlib.Path, dict[str, Any]] = {}
    for path in snapshots:
        payload = load_json(path)
        payloads[path] = payload
        chain = payload.get("chain")
        if path == first:
            if chain is not None:
                raise TsaError(f"genesis snapshot must not have a chain block: {path}")
            continue
        if not isinstance(chain, dict):
            raise TsaError(f"missing chain block after genesis: {path}")
        previous_logical = chain.get("prevDigestPath")
        if not isinstance(previous_logical, str):
            raise TsaError(f"missing chain.prevDigestPath in {path}")
        previous = physical_path(records, previous_logical)
        if previous not in snapshot_set:
            raise TsaError(f"missing predecessor for {path}: {previous_logical}")
        expected_sha = sha256_file(previous)
        if chain.get("prevDigestSha256") != expected_sha:
            raise TsaError(
                f"predecessor hash mismatch in {path}: expected {expected_sha}, "
                f"got {chain.get('prevDigestSha256')}"
            )
        successors[previous].append(path)
    ordered = [first]
    visited = {first}
    cursor = first
    while successors[cursor]:
        children = successors[cursor]
        if len(children) != 1:
            raise TsaError(
                f"fork after {logical_path(records, cursor)}: "
                + ", ".join(logical_path(records, child) for child in children)
            )
        cursor = children[0]
        if cursor in visited:
            raise TsaError(f"cycle at {logical_path(records, cursor)}")
        visited.add(cursor)
        ordered.append(cursor)
    if visited != snapshot_set:
        raise TsaError(
            "orphaned snapshot(s) not reachable from genesis: "
            + ", ".join(
                logical_path(records, path)
                for path in sorted(snapshot_set - visited)
            )
        )
    return ordered, payloads


def _verify_production_signature(
    records: pathlib.Path, ordered: list[pathlib.Path]
) -> None:
    """Harness-local composition of the authenticated producer-signing pins."""

    activation = physical_path(records, ACTIVATION_SNAPSHOT)
    if activation not in ordered:
        raise TsaError(
            "producer signing activation snapshot is absent from the reachable "
            f"chain: {ACTIVATION_SNAPSHOT}"
        )
    activation_index = ordered.index(activation)
    discovered = sorted(records.rglob(f"*{SIGNATURE_SUFFIX}"))
    discovered_set = set(discovered)
    for snapshot in ordered[: activation_index + 1]:
        signature = snapshot.with_suffix(SIGNATURE_SUFFIX)
        if signature in discovered_set:
            raise TsaError(
                "producer signature is forbidden at or before activation: "
                f"{logical_path(records, signature)}"
            )
    signed_snapshots = ordered[activation_index + 1 :]
    expected = {snapshot.with_suffix(SIGNATURE_SUFFIX) for snapshot in signed_snapshots}
    orphaned = sorted(discovered_set - expected)
    if orphaned:
        raise TsaError(
            "orphan producer signature is not a post-activation snapshot sibling: "
            f"{logical_path(records, orphaned[0])}"
        )
    public_key = physical_path(records, PUBLIC_KEY_RELPATH)
    public_key_pem = public_key.read_bytes()
    computed_spki = spki_sha256(public_key_pem)
    if computed_spki != PRODUCER_SPKI_SHA256:
        raise TsaError(
            "producer public-key SPKI is not code-pinned for "
            f"{PUBLIC_KEY_RELPATH}: {computed_spki}"
        )
    for snapshot in signed_snapshots:
        signature = snapshot.with_suffix(SIGNATURE_SUFFIX)
        signature_logical = logical_path(records, signature)
        verify_signature_bytes(
            SIGNATURE_DOMAIN + snapshot.read_bytes(),
            signature.read_bytes(),
            public_key_pem,
            public_key_filename=PUBLIC_KEY_RELPATH,
            spki_sha256=PRODUCER_SPKI_SHA256,
            label=signature_logical,
        )


def verify_candidate(records: pathlib.Path) -> CandidateVerification:
    records = records.resolve()
    ordered, payloads = _ordered_chain(records)
    _verify_production_signature(records, ordered)
    genesis = load_json(records / "CHAIN_GENESIS.json")
    active = bootstrap_trust_bundles(
        records,
        genesis,
        spec=BRIER_TSA_SPEC,
        required=True,
    )
    pending: list[dict[str, Any]] = []
    witnesses: dict[pathlib.Path, WitnessEvidence] = {}
    for path in ordered:
        current_updates = trust_bundle_updates(
            records, payloads[path], spec=BRIER_TSA_SPEC
        )
        evidence = verify_witness(
            path,
            spec=BRIER_TSA_SPEC,
            records=records,
            trusted_bundles=active,
            transition_bundle_updates=[*pending, *current_updates],
        )
        witnesses[path] = evidence
        pending.extend(current_updates)
        if evidence.status == "available":
            activate_trust_bundles(active, pending)
            pending.clear()
    return CandidateVerification(
        ordered=tuple(ordered),
        witnesses=witnesses,
        active_trust_bundles={
            path: dict(reference) for path, reference in active.items()
        },
        pending_trust_bundle_updates=tuple(dict(value) for value in pending),
    )


def _candidate_summary(
    records: pathlib.Path, verification: CandidateVerification
) -> str:
    available = [
        (path, evidence)
        for path, evidence in verification.witnesses.items()
        if evidence.status == "available"
    ]
    lines: list[str] = []
    for path, evidence in available:
        anchors = ",".join(token.anchor_id for token in evidence.tokens)
        policies = ",".join(token.policy_oid for token in evidence.tokens)
        lines.append(
            "witness OK: "
            f"{logical_path(records.resolve(), path)} genTime={evidence.gen_time} "
            f"policies={policies} anchors={anchors}"
        )
    active_bundle_ids = sorted(
        str(reference["bundleId"])
        for reference in verification.active_trust_bundles.values()
    )
    pending_bundle_ids = sorted(
        str(reference["bundleId"])
        for reference in verification.pending_trust_bundle_updates
    )
    lines.append(
        f"chain OK: {len(verification.ordered)} snapshot(s), "
        f"availableWitnesses={len(available)}, "
        f"activeTrustBundles={active_bundle_ids}, "
        f"pendingTrustBundles={pending_bundle_ids}, "
        f"head={verification.ordered[-1]}"
    )
    return "\n".join(lines)


def run_candidate(records: pathlib.Path) -> tuple[int, str]:
    try:
        verification = verify_candidate(records)
    except (OSError, SignError, TsaError) as exc:
        return 1, f"CHAIN BROKEN: {exc}"
    return 0, _candidate_summary(records, verification)


def _normalize_openssl_ids(message: str) -> str:
    return re.sub(
        r"(?m)^[0-9A-Fa-f]{8,16}(?=:error:)",
        "<openssl-err-id>",
        message.strip(),
    )


def _assert_candidate_silent(capfd: pytest.CaptureFixture[str]) -> None:
    captured = capfd.readouterr()
    assert (captured.out, captured.err) == ("", ""), (
        "the port must not write to stdout/stderr; captured "
        f"out={captured.out!r} err={captured.err!r}"
    )


def _link_or_copy(source: str, destination: str) -> str:
    try:
        os.link(source, destination)
        return destination
    except OSError:
        return shutil.copy2(source, destination)


def mutable_records_copy(
    tree: pathlib.Path, destination: pathlib.Path
) -> pathlib.Path:
    records = destination / "records"
    shutil.copytree(tree / "records", records, copy_function=_link_or_copy)
    return records


def _replace_bytes(path: pathlib.Path, payload: bytes) -> None:
    """Replace a hardlinked destination inode without touching the oracle."""

    replacement = path.with_name(f".{path.name}.mutation")
    replacement.write_bytes(payload)
    os.replace(replacement, path)


def _replace_json(path: pathlib.Path, payload: dict[str, Any]) -> None:
    _replace_bytes(path, canonical_bytes(payload) + b"\n")


def _flip_byte(path: pathlib.Path) -> None:
    payload = bytearray(path.read_bytes())
    payload[len(payload) // 2] ^= 0x01
    _replace_bytes(path, bytes(payload))


def _truncate(path: pathlib.Path) -> None:
    _replace_bytes(path, path.read_bytes()[:-1])


def _snapshot(records: pathlib.Path, relative: pathlib.Path) -> pathlib.Path:
    return records / relative


def _witness(records: pathlib.Path, relative: pathlib.Path) -> pathlib.Path:
    return _snapshot(records, relative).with_suffix(".witness.json")


def _mutate_witness(
    records: pathlib.Path,
    relative: pathlib.Path,
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    path = _witness(records, relative)
    payload = json.loads(path.read_text())
    mutation(payload)
    _replace_json(path, payload)


def flip_v1_bundle(records: pathlib.Path) -> str:
    _flip_byte(records / V1_BUNDLE)
    return "TSA trust bundle commitment mismatch for records/trust/tsa-anchors-v1.json"


def delete_genesis_witness(records: pathlib.Path) -> str:
    _witness(records, GENESIS).unlink()
    return "missing explicit witness marker for "


def drop_required_digest(records: pathlib.Path) -> str:
    _mutate_witness(records, GENESIS, lambda payload: payload.pop("digestSha256"))
    return "witness digest mismatch for "


def flip_v2_bundle(records: pathlib.Path) -> str:
    _flip_byte(records / V2_BUNDLE)
    return "TSA trust bundle commitment mismatch for records/trust/tsa-anchors-v2.json"


def pending_bundle_used_as_active(records: pathlib.Path) -> str:
    def mutate(payload: dict[str, Any]) -> None:
        v2 = BRIER_TSA_SPEC.bundle_reference("records/trust/tsa-anchors-v2.json")
        assert v2 is not None
        payload["trustBundleId"] = v2["bundleId"]
        payload["trustBundlePath"] = v2["path"]
        payload["trustBundleSha256"] = v2["sha256"]

    _mutate_witness(records, TRANSITION, mutate)
    return "multi-token witness does not use the newest active TSA trust bundle"


def wrong_type_anchor_outcomes(records: pathlib.Path) -> str:
    _mutate_witness(
        records,
        TRANSITION,
        lambda payload: payload.__setitem__("anchorOutcomes", {}),
    )
    return "multi-token witness anchorOutcomes must be a list"


def token_evidence_inside_unavailable(records: pathlib.Path) -> str:
    def mutate(payload: dict[str, Any]) -> None:
        outcome = payload["anchorOutcomes"][0]
        outcome["status"] = "unavailable"
        outcome["reason"] = "differential mutation"

    _mutate_witness(records, TRANSITION, mutate)
    return (
        "TSA anchor freetsa-root-2016 unavailable outcome contains token evidence: "
        "['tokenPath', 'tokenSha256', 'tsaGenTime', "
        "'tsaImprintAlgorithmOid', 'tsaPolicyOid', "
        "'tsaSignerCertificateSha256', 'tsaSignerSpkiSha256']"
    )


def _transition_token_path(records: pathlib.Path, supplemental: bool) -> pathlib.Path:
    payload = json.loads(_witness(records, TRANSITION).read_text())
    outcome = (
        payload["supplementalOutcomes"][0]
        if supplemental
        else payload["anchorOutcomes"][0]
    )
    return physical_path(records, outcome["tokenPath"])


def flip_freetsa_token(records: pathlib.Path) -> str:
    _flip_byte(_transition_token_path(records, supplemental=False))
    return "witness token hash mismatch for "


def truncate_freetsa_token(records: pathlib.Path) -> str:
    _truncate(_transition_token_path(records, supplemental=False))
    return "witness token hash mismatch for "


def flip_digicert_token(records: pathlib.Path) -> str:
    _flip_byte(_transition_token_path(records, supplemental=True))
    return "witness token hash mismatch for "


def truncate_digicert_token(records: pathlib.Path) -> str:
    _truncate(_transition_token_path(records, supplemental=True))
    return "witness token hash mismatch for "


def contradict_record_creation_claim(records: pathlib.Path) -> str:
    earlier = json.loads(_witness(records, PRE_TRANSITION).read_text())

    def mutate(payload: dict[str, Any]) -> None:
        outcome = payload["anchorOutcomes"][0]
        outcome["tokenPath"] = earlier["tokenPath"]
        outcome["tokenSha256"] = earlier["tokenSha256"]

    _mutate_witness(records, TRANSITION, mutate)
    return (
        "RFC 3161 genTime 2026-07-10T17:03:56Z impossibly precedes "
        "recordedAt=2026-07-10T17:10:11Z"
    )


def signer_certificate_identity_mismatch(records: pathlib.Path) -> str:
    def mutate(payload: dict[str, Any]) -> None:
        payload["anchorOutcomes"][0]["tsaSignerCertificateSha256"] = "0" * 64

    _mutate_witness(records, TRANSITION, mutate)
    return (
        "witness tsaSignerCertificateSha256 mismatch for "
    )


def supplemental_outside_transition(records: pathlib.Path) -> str:
    transition = json.loads(_witness(records, TRANSITION).read_text())

    def mutate(payload: dict[str, Any]) -> None:
        payload["supplementalOutcomes"] = transition["supplementalOutcomes"]

    _mutate_witness(records, POST_TRANSITION, mutate)
    return (
        "supplemental TSA outcome is not introduced by a pending trust transition: "
        "('records/trust/tsa-anchors-v2.json', 'digicert-trusted-root-g4')"
    )


MUTATIONS: tuple[tuple[str, Callable[[pathlib.Path], str]], ...] = (
    ("flip_v1_bundle", flip_v1_bundle),
    ("delete_genesis_witness", delete_genesis_witness),
    ("drop_required_digest", drop_required_digest),
    ("flip_v2_bundle", flip_v2_bundle),
    ("pending_bundle_used_as_active", pending_bundle_used_as_active),
    ("wrong_type_anchor_outcomes", wrong_type_anchor_outcomes),
    ("token_evidence_inside_unavailable", token_evidence_inside_unavailable),
    ("flip_freetsa_token", flip_freetsa_token),
    ("truncate_freetsa_token", truncate_freetsa_token),
    ("flip_digicert_token", flip_digicert_token),
    ("truncate_digicert_token", truncate_digicert_token),
    ("contradict_record_creation_claim", contradict_record_creation_claim),
    ("signer_certificate_identity_mismatch", signer_certificate_identity_mismatch),
    ("supplemental_outside_transition", supplemental_outside_transition),
)


def test_clean_tree_verdicts_match(
    brier_tree: pathlib.Path, capfd: pytest.CaptureFixture[str]
) -> None:
    records = brier_tree / "records"
    baseline_code, baseline_out, baseline_err = run_baseline(brier_tree, records)
    assert baseline_code == 0, f"baseline failed on the pinned tree: {baseline_err}"
    assert baseline_err == ""
    capfd.readouterr()
    # This call verifies the final snapshot's real production Ed25519 signature
    # through receipt.sign as well as all production witness tokens through tsa.
    candidate_code, candidate_message = run_candidate(records)
    _assert_candidate_silent(capfd)
    assert candidate_code == 0, candidate_message
    assert candidate_message == baseline_out
    assert "chain OK: 53 snapshot(s), availableWitnesses=52" in candidate_message


@pytest.mark.parametrize(
    "dependency",
    ("scripts/canonical_json.py", "scripts/producer_signing_pins.py"),
)
def test_swapped_runtime_import_fails_authentication(
    brier_tree: pathlib.Path,
    tmp_path: pathlib.Path,
    dependency: str,
) -> None:
    fake = tmp_path / "tree"
    (fake / "scripts").mkdir(parents=True)
    for relative in BASELINE_AUTHENTICATED_FILES:
        shutil.copyfile(brier_tree / relative, fake / relative)
    path = fake / dependency
    path.write_bytes(path.read_bytes() + b"\n# tampered\n")
    with pytest.raises(RuntimeError, match=re.escape(path.name)):
        _authenticated_baseline_tree(fake)


@pytest.mark.parametrize(
    ("name", "mutation"),
    MUTATIONS,
    ids=[name for name, _mutation in MUTATIONS],
)
def test_witness_mutation_refused_identically(
    brier_tree: pathlib.Path,
    tmp_path: pathlib.Path,
    capfd: pytest.CaptureFixture[str],
    name: str,
    mutation: Callable[[pathlib.Path], str],
) -> None:
    records = mutable_records_copy(brier_tree, tmp_path)
    marker = mutation(records)
    baseline_code, baseline_out, baseline_err = run_baseline(brier_tree, records)
    capfd.readouterr()
    candidate_code, candidate_message = run_candidate(records)
    _assert_candidate_silent(capfd)

    assert baseline_code == 1, f"baseline ACCEPTED mutation {name}"
    assert baseline_out == "", (
        f"baseline printed to stdout while refusing {name}: {baseline_out!r}"
    )
    assert candidate_code == 1, f"candidate ACCEPTED mutation {name}"
    normalized_baseline = _normalize_openssl_ids(baseline_err)
    normalized_candidate = _normalize_openssl_ids(candidate_message)
    assert normalized_candidate == normalized_baseline, (
        f"divergent refusal for {name}:\n"
        f"  baseline: {baseline_err}\n"
        f"  candidate: {candidate_message}"
    )
    assert marker in normalized_candidate, (
        f"mutation {name} no longer binds its observed branch:\n"
        f"  expected: {marker}\n"
        f"  refusal: {candidate_message}"
    )
