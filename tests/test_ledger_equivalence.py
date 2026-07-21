"""Differential harness: the port must reproduce the ledger verifier exactly.

Baseline = PolicyEngine/ledger scripts/verify_release_chain.py, unmodified, at
the pinned commit. Candidate = receipt.release_chain with LEDGER_SPEC (the
consumer pin, committed here). Equivalence is judged on the live chain, on a
mutation battery, and on the --base-ref immutability surface: for every
mutation both verifiers must refuse, and their refusals must match byte for
byte after the two normalizations stated in the comparison contract below
(whitespace stripping of the baseline CLI streams, and OpenSSL error-queue-id
masking).

Comparison contract, stated exactly:

- exit status must match (0 accept, 1 refuse);
- on refusal, the baseline CLI's stderr must equal the port's exception
  message byte for byte after two normalizations, and the baseline must print
  nothing to stdout: (a) surrounding whitespace is stripped from the baseline's
  captured streams (the CLI's trailing newline; applied to both sides equally,
  so it cannot mask a message divergence, only a purely whitespace-only diff);
  (b) OpenSSL 3's per-process error-queue id — an 8–16 hex prefix before
  ``:error:`` that necessarily differs between processes — is masked at the
  start of embedded error lines. Error codes, routines, files, and line
  numbers still compare exactly;
- on acceptance, the baseline CLI's stdout summary must equal the summary
  composed from the port's return value byte for byte, and the baseline must
  print nothing to stderr;
- the port is a library: it must write nothing to stdout or stderr itself
  (asserted via capfd; its subprocesses capture their own output), so its
  entire observable behavior is the returned value or raised exception.

Every mutation function returns the branch marker it binds: a substring of
the refusal message, captured from observed runs of the unmodified baseline.
The harness asserts the marker is present, so a mutation that silently starts
dying at a different (earlier) check fails loudly instead of degrading into
a duplicate of another test.

The pinned tree resolves from RECEIPT_LEDGER_TREE, then the local extraction
workspace, then a fresh clone of the public repo at the pin (CI path). In
every case the baseline oracle script is authenticated against its recorded
SHA-256 before it is trusted (receipts/ledger-pin-source-hashes.txt).
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
from collections.abc import Callable

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from receipt.canonical import canonical_bytes
from receipt.release_chain import (
    AnchorSpec,
    ChainSpec,
    ReleaseChainError,
    _format_time,
    verify_release_chain,
    verify_release_history_immutable,
)
from receipt.sign import generate_signing_keypair

LEDGER_PIN = "9dafe8174f42a06c00817fe596d5a8e686cb17b7"
LEDGER_REPO_URL = "https://github.com/PolicyEngine/ledger.git"
LEDGER_BRANCH = "codex/thesis-ledger-facts"

# SHA-256 of scripts/verify_release_chain.py at LEDGER_PIN, transcribed from
# receipts/ledger-pin-source-hashes.txt. The baseline is only an oracle if it
# is exactly these bytes; a stale or edited local tree must fail loudly here
# rather than silently vouch for the port.
BASELINE_SCRIPT_SHA256 = (
    "7f73e6921ca40e41e556c8e37a634e2780e7e8eeb3ab203ecdb9b7bd4b15a844"
)
# The baseline verifier imports scripts/canonical_json.py at runtime, so the
# oracle is only trustworthy if that dependency is pinned too: a semantically
# altered canonical serializer with the exact verifier bytes would otherwise
# pass authentication and vouch for the port (Sol re-review P1).
BASELINE_CANONICAL_SHA256 = (
    "562bf267b7686bce8cb71f3c13f34825c21cd4ef0aba1c0c46aff16962a6cadd"
)
BASELINE_AUTHENTICATED_FILES = {
    "scripts/verify_release_chain.py": BASELINE_SCRIPT_SHA256,
    "scripts/canonical_json.py": BASELINE_CANONICAL_SHA256,
}

# The consumer pin: every value below is committed verifier configuration,
# transcribed from scripts/verify_release_chain.py at LEDGER_PIN. Anchor
# insertion order (freetsa, digicert) is part of the pin — error messages
# join anchor names in this order.
LEDGER_SPEC = ChainSpec(
    manifest_relative=pathlib.PurePosixPath("releases/manifests"),
    state_relative=pathlib.PurePosixPath("ledger/official_observations.jsonl"),
    prefix_relative=pathlib.PurePosixPath("ledger/immutable_prefix.json"),
    anchor_relative=pathlib.PurePosixPath("releases/anchors"),
    release_root_relative=pathlib.PurePosixPath("releases"),
    schema_version="thesis_ledger_release_v1",
    producer_public_key_filename="producer-ed25519.pub",
    producer_spki_sha256=(
        "4a90eff40455ce0d853d4bab1608efbdae1efaf8c06054ead6e396c5b0c4846e"
    ),
    anchors={
        "freetsa": AnchorSpec(
            filename="freetsa-root-2016.pem",
            pem_sha256=(
                "2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438"
            ),
            policy_oid="1.2.3.4.1",
            signer_certificate_sha256=(
                "32e841a95cc1164101ffde41298ef2fc75c1c4372ef095e88a6bbd47dfb191fc"
            ),
            signer_spki_sha256=(
                "fa02bd555e3e483d62b4e70be6218692068d2b0b0a7525db58dcbf2901cdb072"
            ),
        ),
        "digicert": AnchorSpec(
            filename="digicert-trusted-root-g4.pem",
            pem_sha256=(
                "ce7d6b44f5d510391be98c8d76b18709400a30cd87659bfebe1c6f97ff5181ee"
            ),
            policy_oid="2.16.840.1.114412.7.1",
            signer_certificate_sha256=(
                "4aa03fa22cd75c84c55c938f828e676b9caecab33fe36d269aa334f146110a33"
            ),
            signer_spki_sha256=(
                "7abda95ed7301ac94bded350babc319903d0b4f16c4e7e39346dba5f9e992b72"
            ),
        ),
    },
)

# Every release is a quartet of sibling files sharing one stem.
RELEASE_FILE_SUFFIXES = (".json", ".producer.sig", ".freetsa.tsr", ".digicert.tsr")

# Pinned chain stems (3 releases). Mutations name them explicitly so a re-cut
# chain invalidates the battery loudly instead of drifting.
GENESIS_STEM = "0000-307cedbc91de43be"
RELEASE_1_STEM = "0001-916626696d034b80"
RELEASE_2_STEM = "0002-a69272175b73c83b"


def _authenticated_baseline_tree(tree: pathlib.Path) -> pathlib.Path:
    """Refuse to treat ``tree`` as the oracle unless the verifier AND every
    source file it executes are byte-pinned (receipts/ledger-pin-source-hashes.txt).
    Authenticating only the entry script would let a swapped canonical_json.py
    silently change the oracle's behavior."""

    for relative, expected in BASELINE_AUTHENTICATED_FILES.items():
        path = tree / relative
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected:
            raise RuntimeError(
                "baseline oracle is not the pinned verifier: "
                f"{path} has SHA-256 {digest}, expected {expected} "
                "(receipts/ledger-pin-source-hashes.txt). A stale or altered "
                "baseline must not silently vouch for the port."
            )
    return tree


@pytest.fixture(scope="session")
def pinned_tree(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    override = os.environ.get("RECEIPT_LEDGER_TREE")
    if override:
        tree = pathlib.Path(override)
        if not tree.is_dir():
            raise RuntimeError(f"RECEIPT_LEDGER_TREE is not a directory: {tree}")
        return _authenticated_baseline_tree(tree)
    local = (
        pathlib.Path(__file__).resolve().parents[1]
        / ".extraction"
        / f"ledger-{LEDGER_PIN[:7]}"
    )
    if local.is_dir():
        return _authenticated_baseline_tree(local)
    clone = tmp_path_factory.mktemp("ledger-pin") / "ledger"
    subprocess.run(
        ["git", "clone", "--quiet", "--branch", LEDGER_BRANCH, "--single-branch",
         LEDGER_REPO_URL, str(clone)],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(clone), "checkout", "--quiet", LEDGER_PIN],
        check=True,
    )
    # The pin commit already fixes the bytes; authenticate anyway so all three
    # resolution paths share one trust check.
    return _authenticated_baseline_tree(clone)


def run_baseline(tree: pathlib.Path, root: pathlib.Path) -> tuple[int, str, str]:
    """Run the unmodified pinned verifier script against ``root`` (--full)."""

    completed = subprocess.run(
        [
            sys.executable,
            str(tree / "scripts" / "verify_release_chain.py"),
            "--full",
            "--root",
            str(root),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def run_baseline_base_ref(
    tree: pathlib.Path, root: pathlib.Path, base_ref: str
) -> tuple[int, str, str]:
    """Run the unmodified pinned verifier script with --base-ref."""

    completed = subprocess.run(
        [
            sys.executable,
            str(tree / "scripts" / "verify_release_chain.py"),
            "--base-ref",
            base_ref,
            "--root",
            str(root),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def run_port(root: pathlib.Path) -> tuple[int, str]:
    """Run the extracted verifier; mirror the baseline's (exit, message) shape."""

    try:
        verification = verify_release_chain(
            root.resolve(),
            spec=LEDGER_SPEC,
            require_chain=True,
            verify_state=True,
        )
    except (OSError, ReleaseChainError) as exc:
        return 1, f"release chain verification failed: {exc}"
    head = verification.releases[-1]
    receipt_summary = ", ".join(
        f"{tsa}={_format_time(value)}"
        for tsa, value in sorted(head.receipt_times.items())
    )
    return 0, (
        f"release chain OK: {len(verification.releases)} releases, "
        f"HEAD={head.path.name}, {receipt_summary}"
    )


def run_port_base_ref(root: pathlib.Path, base_ref: str) -> tuple[int, str]:
    """Mirror the baseline CLI's --base-ref composition exactly.

    The baseline main() runs verify_release_history_immutable first, then
    verify_release_chain with require_chain=True, verify_state=True, and
    production pins enforced (no anchor override).
    """

    try:
        verify_release_history_immutable(root.resolve(), base_ref, spec=LEDGER_SPEC)
        verification = verify_release_chain(
            root.resolve(),
            spec=LEDGER_SPEC,
            require_chain=True,
            verify_state=True,
            enforce_production_pins=True,
        )
    except (OSError, ReleaseChainError) as exc:
        return 1, f"release chain verification failed: {exc}"
    head = verification.releases[-1]
    receipt_summary = ", ".join(
        f"{tsa}={_format_time(value)}"
        for tsa, value in sorted(head.receipt_times.items())
    )
    return 0, (
        f"release chain OK: {len(verification.releases)} releases, "
        f"HEAD={head.path.name}, {receipt_summary}"
    )


def _normalize_openssl_ids(message: str) -> str:
    """Mask OpenSSL 3's per-process error-queue id at the start of error lines."""

    import re

    return re.sub(r"(?m)^[0-9A-Fa-f]{8,16}(?=:error:)", "<openssl-err-id>", message)


def _assert_port_silent(capfd: pytest.CaptureFixture[str]) -> None:
    """The port is a library; it owns no stdout/stderr (see module docstring)."""

    captured = capfd.readouterr()
    assert (captured.out, captured.err) == ("", ""), (
        "the port must not write to stdout/stderr; captured "
        f"out={captured.out!r} err={captured.err!r}"
    )


def mutable_copy(tree: pathlib.Path, destination: pathlib.Path) -> pathlib.Path:
    """Copy only the custody surface; the baseline script runs via --root."""

    root = destination / "root"
    for relative in ("releases", "ledger"):
        shutil.copytree(tree / relative, root / relative)
    return root


def flip_byte(path: pathlib.Path, offset_fraction: float = 0.5) -> None:
    data = bytearray(path.read_bytes())
    index = int(len(data) * offset_fraction)
    data[index] ^= 0x01
    path.write_bytes(bytes(data))


def manifest_paths(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted((root / "releases" / "manifests").glob("*.json"))


def sibling(root: pathlib.Path, stem: str, suffix: str) -> pathlib.Path:
    return root / "releases" / "manifests" / f"{stem}{suffix}"


def rename_release_quartet(root: pathlib.Path, old_stem: str, new_stem: str) -> None:
    for suffix in RELEASE_FILE_SUFFIXES:
        sibling(root, old_stem, suffix).rename(sibling(root, new_stem, suffix))


def copy_release_quartet(root: pathlib.Path, old_stem: str, new_stem: str) -> None:
    for suffix in RELEASE_FILE_SUFFIXES:
        shutil.copyfile(
            sibling(root, old_stem, suffix), sibling(root, new_stem, suffix)
        )


def recanonicalize_and_rename(
    root: pathlib.Path, path: pathlib.Path, payload: dict
) -> None:
    """Write ``payload`` back as canonical JSON + LF; rename its quartet to the
    fresh digest stem, keeping the filename's existing four-digit index."""

    raw = canonical_bytes(payload) + b"\n"
    path.write_bytes(raw)
    index_prefix = path.stem.split("-")[0]
    new_stem = f"{index_prefix}-{hashlib.sha256(raw).hexdigest()[:16]}"
    rename_release_quartet(root, path.stem, new_stem)


def test_clean_chain_verdicts_match(
    pinned_tree: pathlib.Path, capfd: pytest.CaptureFixture[str]
) -> None:
    baseline_code, baseline_out, baseline_err = run_baseline(
        pinned_tree, pinned_tree
    )
    assert baseline_code == 0, f"baseline failed on the pinned tree: {baseline_err}"
    assert baseline_err == "", "baseline must print nothing to stderr on acceptance"
    capfd.readouterr()  # isolate the port's own emissions from anything prior
    port_code, port_message = run_port(pinned_tree)
    _assert_port_silent(capfd)
    assert port_code == 0, port_message
    assert port_message == baseline_out


def test_swapped_canonical_dependency_fails_authentication(
    pinned_tree: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """A tree with the exact verifier but an altered canonical_json.py must be
    rejected as an oracle — the verifier imports and executes it, so pinning
    only the entry script would let a swapped serializer vouch for the port
    (Sol re-review P1 regression)."""

    fake = tmp_path / "tree"
    (fake / "scripts").mkdir(parents=True)
    for relative in BASELINE_AUTHENTICATED_FILES:
        shutil.copyfile(pinned_tree / relative, fake / relative)
    # Semantically alter the imported serializer (any byte change breaks the pin).
    canonical = fake / "scripts" / "canonical_json.py"
    canonical.write_bytes(canonical.read_bytes() + b"\n# tampered\n")

    with pytest.raises(RuntimeError, match=r"canonical_json\.py"):
        _authenticated_baseline_tree(fake)


# --- full-chain mutation battery -------------------------------------------
#
# Each mutation corrupts a fresh copy of the pinned tree and returns the
# branch marker it binds (a substring of the observed refusal). The battery is
# ordered roughly by the verifier's own check order: directory enumeration,
# chain structure, producer signature, receipts, anchors, state history.
#
# Empirical check-order note for the two manifest-editing mutations below
# (payload_index_vs_filename, prev_pointer_mismatch): in the pinned verifier
# the per-manifest chain-structure checks — filename contiguity, payload
# releaseIndex vs filename index, filename digest vs content hash, and
# previousManifestSha256 linkage — all run BEFORE verify_producer_signature.
# Editing manifest bytes necessarily breaks the producer signature (it signs
# exact bytes and we do not hold the private key), but verification aborts at
# the structure branch first, so both verifiers refuse there identically and
# the signature is never consulted for the edited release. The asserted
# markers pin this ordering: if signature verification ever moved ahead of
# the structure checks, these two tests would fail loudly.


def flip_last_manifest_byte(root: pathlib.Path) -> str:
    """Binds: closed-world manifest schema (byte flips die at schema/canonical
    validation — the motivation for the structure-level mutations below)."""

    flip_byte(sibling(root, RELEASE_2_STEM, ".json"))
    return "producer keys are not closed-world"


def flip_genesis_manifest_byte(root: pathlib.Path) -> str:
    """Binds: closed-world manifest schema, genesis release."""

    flip_byte(sibling(root, GENESIS_STEM, ".json"))
    return "state keys are not closed-world"


def flip_producer_signature(root: pathlib.Path) -> str:
    """Binds: Ed25519 producer-signature verification failure."""

    flip_byte(sibling(root, RELEASE_1_STEM, ".producer.sig"))
    return (
        "producer Ed25519 signature verification failed for "
        f"{RELEASE_1_STEM}.producer.sig"
    )


def truncate_producer_signature(root: pathlib.Path) -> str:
    """Binds: the exact 64-byte raw-signature length check."""

    signature = sibling(root, RELEASE_1_STEM, ".producer.sig")
    signature.write_bytes(signature.read_bytes()[:63])
    return (
        f"producer signature for {RELEASE_1_STEM}.producer.sig "
        "must be exactly 64 raw bytes; found=63"
    )


def swap_producer_public_key(root: pathlib.Path) -> str:
    """Binds the SPKI pin check: PEM decoding and the Ed25519 type check
    succeed first, then the fresh key's SPKI is rejected before signature
    verification."""

    _, public_key_pem = generate_signing_keypair()
    path = root / "releases" / "anchors" / "producer-ed25519.pub"
    path.write_bytes(public_key_pem)
    return "producer public-key SPKI is not code-pinned: "


def corrupt_producer_public_key_pem(root: pathlib.Path) -> str:
    """Binds PEM decoding. Flipping the first PEM-armor byte guarantees an
    undecodable header; corrupting the base64 body could still produce a valid
    different Ed25519 key and bind the later SPKI-pin branch instead."""

    path = root / "releases" / "anchors" / "producer-ed25519.pub"
    flip_byte(path, offset_fraction=0.0)
    return "cannot decode producer Ed25519 public key: "


def non_ed25519_producer_public_key(root: pathlib.Path) -> str:
    """Binds the key-type check: valid P-256 SPKI decoding succeeds, and the
    non-Ed25519 check fires before SPKI pinning or signature verification."""

    public_key_pem = (
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    path = root / "releases" / "anchors" / "producer-ed25519.pub"
    path.write_bytes(public_key_pem)
    return "producer public key is not Ed25519: "


def delete_producer_signature(root: pathlib.Path) -> str:
    """Binds: missing-producer-signature check during enumeration."""

    sibling(root, RELEASE_1_STEM, ".producer.sig").unlink()
    return (
        f"manifest {RELEASE_1_STEM}.json is missing its producer signature "
        f"{RELEASE_1_STEM}.producer.sig"
    )


def orphan_producer_signature(root: pathlib.Path) -> str:
    """Binds: orphan-producer-signature check (signature with no manifest)."""

    shutil.copyfile(
        sibling(root, RELEASE_1_STEM, ".producer.sig"),
        sibling(root, "9999-deadbeefdeadbeef", ".producer.sig"),
    )
    return "orphan producer signatures for manifest stems: ['9999-deadbeefdeadbeef']"


def flip_freetsa_receipt(root: pathlib.Path) -> str:
    """Binds: RFC 3161 receipt ASN.1 inspection failure."""

    flip_byte(sibling(root, RELEASE_1_STEM, ".freetsa.tsr"))
    return "cannot inspect RFC 3161 receipt "


def flip_digicert_receipt(root: pathlib.Path) -> str:
    """Binds: RFC 3161 cryptographic verification failure."""

    flip_byte(sibling(root, RELEASE_1_STEM, ".digicert.tsr"))
    return f"RFC 3161 verification failed for {RELEASE_1_STEM}.digicert.tsr"


def delete_one_receipt(root: pathlib.Path) -> str:
    """Binds: the exactly-one-receipt-per-anchor completeness check."""

    sibling(root, RELEASE_1_STEM, ".freetsa.tsr").unlink()
    return (
        f"manifest {RELEASE_1_STEM}.json must have exactly freetsa and "
        "digicert receipts; found=['digicert']"
    )


def orphan_receipt(root: pathlib.Path) -> str:
    """Binds: orphan-receipt check (receipt with no manifest)."""

    shutil.copyfile(
        sibling(root, RELEASE_1_STEM, ".freetsa.tsr"),
        sibling(root, "9999-deadbeefdeadbeef", ".freetsa.tsr"),
    )
    return "orphan release receipts for manifest stems: ['9999-deadbeefdeadbeef']"


def unknown_file_in_manifest_dir(root: pathlib.Path) -> str:
    """Binds: closed-directory unknown-file check."""

    (root / "releases" / "manifests" / "junk.txt").write_text("tamper\n")
    return "unknown file in closed release manifest directory: junk.txt"


def symlink_manifest(root: pathlib.Path) -> tuple[str, str]:
    """Binds the closed-directory surface via a rename-and-symlink swap: the
    renamed ``.real`` target and the ``.json`` symlink are both anomalous, so
    which check fires first depends on directory-iteration order, which is
    filesystem-dependent (macOS/APFS reached the unknown-file branch; Linux/ext4
    reaches the non-regular-entry branch — CI caught the narrowing to one
    marker). Either marker is correct; the branch that fires is not fixed. This
    tuple cannot mask a baseline/port divergence: full normalized-message
    equality is asserted BEFORE the marker, and it passed on both platforms
    (baseline and port always agree on which branch fires for a given FS).
    external_symlink_manifest binds the non-regular-entry branch
    deterministically, so coverage does not depend on this platform accident."""

    target = manifest_paths(root)[-1]
    target.rename(target.with_suffix(".real"))
    target.symlink_to(target.with_suffix(".real").name)
    return (
        f"unknown file in closed release manifest directory: {RELEASE_2_STEM}.real",
        "release manifest directory contains a non-regular entry",
    )


def external_symlink_manifest(root: pathlib.Path) -> str:
    """Binds: the non-regular-entry check, deterministically — the symlink
    points outside the manifests directory, so it is the only anomalous entry
    (unlike symlink_manifest, which also leaves a renamed target inside)."""

    manifest = sibling(root, RELEASE_1_STEM, ".json")
    manifest.unlink()
    manifest.symlink_to(root / "ledger" / "official_observations.jsonl")
    return "release manifest directory contains a non-regular entry"


def duplicate_release_index(root: pathlib.Path) -> str:
    """Binds: duplicate-release-index check (two stems carrying index 0001).

    The marker omits the two filenames: their order in the message follows
    directory iteration order, which baseline and port share but the pin does
    not fix."""

    copy_release_quartet(
        root, RELEASE_2_STEM, f"0001-{RELEASE_2_STEM.split('-')[1]}"
    )
    return "duplicate release index 1: "


def noncontiguous_release_index(root: pathlib.Path) -> str:
    """Binds: the contiguous-from-zero index check."""

    rename_release_quartet(
        root, RELEASE_2_STEM, f"0003-{RELEASE_2_STEM.split('-')[1]}"
    )
    return "release indices are not contiguous from 0: expected 0002, found 0003"


def filename_digest_mismatch(root: pathlib.Path) -> str:
    """Binds: the filename-digest-vs-content-hash check."""

    rename_release_quartet(root, RELEASE_1_STEM, "0001-0000000000000000")
    return (
        "manifest filename hash does not match exact file bytes: "
        "0001-0000000000000000.json"
    )


def payload_index_vs_filename(root: pathlib.Path) -> str:
    """Binds: payload releaseIndex vs filename index (see check-order note
    above: fires before producer-signature verification)."""

    path = manifest_paths(root)[1]
    payload = json.loads(path.read_text())
    payload["releaseIndex"] = 2
    recanonicalize_and_rename(root, path, payload)
    return "manifest releaseIndex 2 does not match filename index 1"


def payload_index_two_to_one(root: pathlib.Path) -> str:
    """Binds: payload releaseIndex vs filename in the REVERSE direction.

    payload_index_vs_filename edits release 1 (1->2, i.e. payload > filename);
    this edits release 2 (2->1, payload < filename). A `>`-for-`!=` bug at the
    index check would refuse the first and silently fall through to signature
    verification on this one, so the pair pins the exact comparator (Sol
    re-review residual gap)."""

    path = manifest_paths(root)[2]
    payload = json.loads(path.read_text())
    payload["releaseIndex"] = 1
    recanonicalize_and_rename(root, path, payload)
    return "manifest releaseIndex 1 does not match filename index 2"


def prev_pointer_mismatch(root: pathlib.Path) -> str:
    """Binds: previousManifestSha256 chain linkage (see check-order note
    above: fires before producer-signature verification)."""

    path = manifest_paths(root)[1]
    payload = json.loads(path.read_text())
    payload["previousManifestSha256"] = "0" * 64
    recanonicalize_and_rename(root, path, payload)
    return (
        "release 1 previousManifestSha256 does not match the previous "
        "manifest file bytes"
    )


def flip_covered_ledger_prefix(root: pathlib.Path) -> str:
    """Binds: historical state.jsonlSha256 prefix verification."""

    flip_byte(root / "ledger" / "official_observations.jsonl", offset_fraction=0.05)
    return (
        "release 0 state.jsonlSha256 does not match the exact historical "
        "JSONL prefix"
    )


def append_uncovered_ledger_row(root: pathlib.Path) -> str:
    """Binds: HEAD lineCount vs working-tree line count."""

    ledger = root / "ledger" / "official_observations.jsonl"
    ledger.write_bytes(ledger.read_bytes() + b'{"tampered": true}\n')
    return "HEAD release lineCount 147 does not match working-tree line count 148"


def flip_immutable_prefix(root: pathlib.Path) -> str:
    """Binds: immutablePrefixSha256 vs ledger/immutable_prefix.json."""

    flip_byte(root / "ledger" / "immutable_prefix.json")
    return "release 0 immutablePrefixSha256 does not match ledger/immutable_prefix.json"


def flip_freetsa_anchor_pem(root: pathlib.Path) -> str:
    """Binds: code-pinned TSA anchor bytes."""

    flip_byte(root / "releases" / "anchors" / "freetsa-root-2016.pem")
    return "production TSA anchor bytes are not code-pinned for freetsa: "


MUTATIONS: dict[str, Callable[[pathlib.Path], str | tuple[str, ...]]] = {
    "flip_last_manifest_byte": flip_last_manifest_byte,
    "flip_genesis_manifest_byte": flip_genesis_manifest_byte,
    "flip_producer_signature": flip_producer_signature,
    "truncate_producer_signature": truncate_producer_signature,
    "swap_producer_public_key": swap_producer_public_key,
    "corrupt_producer_public_key_pem": corrupt_producer_public_key_pem,
    "non_ed25519_producer_public_key": non_ed25519_producer_public_key,
    "delete_producer_signature": delete_producer_signature,
    "orphan_producer_signature": orphan_producer_signature,
    "flip_freetsa_receipt": flip_freetsa_receipt,
    "flip_digicert_receipt": flip_digicert_receipt,
    "delete_one_receipt": delete_one_receipt,
    "orphan_receipt": orphan_receipt,
    "unknown_file_in_manifest_dir": unknown_file_in_manifest_dir,
    "symlink_manifest": symlink_manifest,
    "external_symlink_manifest": external_symlink_manifest,
    "duplicate_release_index": duplicate_release_index,
    "noncontiguous_release_index": noncontiguous_release_index,
    "filename_digest_mismatch": filename_digest_mismatch,
    "payload_index_vs_filename": payload_index_vs_filename,
    "payload_index_two_to_one": payload_index_two_to_one,
    "prev_pointer_mismatch": prev_pointer_mismatch,
    "flip_covered_ledger_prefix": flip_covered_ledger_prefix,
    "append_uncovered_ledger_row": append_uncovered_ledger_row,
    "flip_immutable_prefix": flip_immutable_prefix,
    "flip_freetsa_anchor_pem": flip_freetsa_anchor_pem,
}


@pytest.mark.parametrize("mutation", sorted(MUTATIONS))
def test_mutation_refused_identically(
    pinned_tree: pathlib.Path,
    tmp_path: pathlib.Path,
    capfd: pytest.CaptureFixture[str],
    mutation: str,
) -> None:
    root = mutable_copy(pinned_tree, tmp_path)
    binds = MUTATIONS[mutation](root)
    markers = (binds,) if isinstance(binds, str) else binds

    baseline_code, baseline_out, baseline_err = run_baseline(pinned_tree, root)
    capfd.readouterr()  # isolate the port's own emissions from anything prior
    port_code, port_message = run_port(root)
    _assert_port_silent(capfd)

    assert baseline_code == 1, (
        f"baseline ACCEPTED mutation {mutation}: fail-closed property broken"
    )
    assert baseline_out == "", (
        f"baseline printed to stdout while refusing {mutation}: {baseline_out!r}"
    )
    assert port_code == 1, (
        f"port ACCEPTED mutation {mutation}: fail-closed property broken"
    )
    # The baseline prints exactly one message to stderr; it may span lines
    # (openssl ASN.1 diagnostics are embedded verbatim). Compare in full,
    # after normalizing the one volatile token: OpenSSL 3 prefixes each
    # error line with a per-process error-queue id (e.g. 40374933CF7F0000),
    # which necessarily differs between the baseline subprocess and this
    # process. Error codes, routines, files, and line numbers still compare
    # byte for byte.
    normalized_port = _normalize_openssl_ids(port_message)
    assert normalized_port == _normalize_openssl_ids(baseline_err), (
        f"divergent refusal for {mutation}:\n"
        f"  baseline: {baseline_err}\n"
        f"  port:     {port_message}"
    )
    assert any(marker in normalized_port for marker in markers), (
        f"mutation {mutation} no longer binds its declared branch:\n"
        f"  expected one of: {markers}\n"
        f"  refusal: {port_message}"
    )


# --- base-ref immutability surface -----------------------------------------
#
# The baseline's --base-ref mode (verify_release_history_immutable followed by
# a full chain re-verification) needs a git repo whose base commit holds the
# clean custody surface. Each case builds its own repo from a fresh copy,
# commits it with an isolated git config, then tampers with the working tree
# (or the ref) and returns (base_ref, branch marker).
#
# Deliberately out of scope for THIS PR (Sol re-review P1, scoped not deferred):
# verify_base_release_chain and materialize_base_tree are unbound here because
# verify_release_chain.py's own CLI never invokes them — its main() runs only
# verify_release_history_immutable plus verify_release_chain, so the
# byte-equivalence contract (unmodified script CLI vs port) has no baseline
# surface for them in this module. Their real caller is the append gate,
# check_thesis_facts_append.py, whose CLI DOES invoke verify_base_release_chain
# (base-tree materialization + trusted-base verification). They get their
# differential coverage when that gate is extracted in the next PR, where the
# baseline CLI exercises them directly. Binding them earlier would require a
# second oracle mode (import the pinned script as a module) that this harness
# deliberately does not adopt.

BASE_MANIFEST_RELATIVE = f"releases/manifests/{RELEASE_1_STEM}.json"
BASE_RECEIPT_RELATIVE = f"releases/manifests/{RELEASE_1_STEM}.freetsa.tsr"


def _git(root: pathlib.Path, *arguments: str) -> str:
    """Run git for fixture setup with the ambient config isolated away."""

    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
        }
    )
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    return completed.stdout.strip()


def commit_custody_surface(root: pathlib.Path) -> str:
    """git-init ``root`` and commit the copied custody surface; return the sha."""

    _git(root, "init", "--quiet")
    _git(root, "config", "user.email", "harness@example.invalid")
    _git(root, "config", "user.name", "Differential Harness")
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", "pinned custody surface")
    return _git(root, "rev-parse", "HEAD")


def base_mode_change(root: pathlib.Path) -> tuple[str, str]:
    """Binds: executable-bit change on an existing release file vs base."""

    base = commit_custody_surface(root)
    (root / BASE_MANIFEST_RELATIVE).chmod(0o755)
    return base, (
        "existing release file mode changed relative to "
        f"{base}: {BASE_MANIFEST_RELATIVE} (100644 -> 100755)"
    )


def base_byte_change(root: pathlib.Path) -> tuple[str, str]:
    """Binds: byte change to an existing release file vs base (fires in the
    immutability pass, before chain re-verification would see the bytes)."""

    base = commit_custody_surface(root)
    flip_byte(root / BASE_MANIFEST_RELATIVE)
    return base, (
        f"existing release file bytes changed relative to {base}: "
        f"{BASE_MANIFEST_RELATIVE}"
    )


def base_file_deleted(root: pathlib.Path) -> tuple[str, str]:
    """Binds: deletion of an existing release file vs base."""

    base = commit_custody_surface(root)
    (root / BASE_RECEIPT_RELATIVE).unlink()
    return base, (
        f"existing release file was deleted relative to {base}: "
        f"{BASE_RECEIPT_RELATIVE}"
    )


def base_worktree_symlink(root: pathlib.Path) -> tuple[str, str]:
    """Binds: symlink rejection while enumerating the working releases tree."""

    base = commit_custody_surface(root)
    manifest = root / BASE_MANIFEST_RELATIVE
    manifest.unlink()
    manifest.symlink_to(root / "ledger" / "official_observations.jsonl")
    return base, f"release path is a symlink: {BASE_MANIFEST_RELATIVE}"


def base_unresolvable_ref(root: pathlib.Path) -> tuple[str, str]:
    """Binds: base-ref resolution failure."""

    commit_custody_surface(root)
    return "no-such-ref", "cannot resolve base ref 'no-such-ref' to a commit: "


def base_not_ancestor(root: pathlib.Path) -> tuple[str, str]:
    """Binds: the ancestry requirement on the resolved base commit (a rootless
    commit object over the same tree is resolvable but not an ancestor)."""

    base = commit_custody_surface(root)
    tree = _git(root, "rev-parse", f"{base}^{{tree}}")
    disconnected = _git(root, "commit-tree", tree, "-m", "disconnected")
    return disconnected, f"base commit {disconnected} is not an ancestor of HEAD"


def base_committed_noncanonical_mode(root: pathlib.Path) -> tuple[str, str]:
    """Binds: rejection of non-regular git modes recorded in the base tree
    (a committed symlink, mode 120000). The working-tree copy is replaced by
    a regular file so enumeration survives long enough to reach the mode
    check."""

    note = root / "releases" / "zz-note"
    note.symlink_to(root / "ledger" / "official_observations.jsonl")
    base = commit_custody_surface(root)
    note.unlink()
    note.write_text("regular now\n")
    return base, (
        "base release entry has non-regular git mode 120000: releases/zz-note"
    )


BASE_REF_MUTATIONS: dict[str, Callable[[pathlib.Path], tuple[str, str]]] = {
    "base_mode_change": base_mode_change,
    "base_byte_change": base_byte_change,
    "base_file_deleted": base_file_deleted,
    "base_worktree_symlink": base_worktree_symlink,
    "base_unresolvable_ref": base_unresolvable_ref,
    "base_not_ancestor": base_not_ancestor,
    "base_committed_noncanonical_mode": base_committed_noncanonical_mode,
}


def test_base_ref_clean_pass_verdicts_match(
    pinned_tree: pathlib.Path,
    tmp_path: pathlib.Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    root = mutable_copy(pinned_tree, tmp_path)
    base = commit_custody_surface(root)
    baseline_code, baseline_out, baseline_err = run_baseline_base_ref(
        pinned_tree, root, base
    )
    assert baseline_code == 0, (
        f"baseline --base-ref failed on the clean surface: {baseline_err}"
    )
    assert baseline_err == "", "baseline must print nothing to stderr on acceptance"
    capfd.readouterr()  # isolate the port's own emissions from anything prior
    port_code, port_message = run_port_base_ref(root, base)
    _assert_port_silent(capfd)
    assert port_code == 0, port_message
    assert port_message == baseline_out


@pytest.mark.parametrize("mutation", sorted(BASE_REF_MUTATIONS))
def test_base_ref_mutation_refused_identically(
    pinned_tree: pathlib.Path,
    tmp_path: pathlib.Path,
    capfd: pytest.CaptureFixture[str],
    mutation: str,
) -> None:
    root = mutable_copy(pinned_tree, tmp_path)
    base_ref, marker = BASE_REF_MUTATIONS[mutation](root)

    baseline_code, baseline_out, baseline_err = run_baseline_base_ref(
        pinned_tree, root, base_ref
    )
    capfd.readouterr()  # isolate the port's own emissions from anything prior
    port_code, port_message = run_port_base_ref(root, base_ref)
    _assert_port_silent(capfd)

    assert baseline_code == 1, (
        f"baseline ACCEPTED base-ref mutation {mutation}: "
        "fail-closed property broken"
    )
    assert baseline_out == "", (
        f"baseline printed to stdout while refusing {mutation}: {baseline_out!r}"
    )
    assert port_code == 1, (
        f"port ACCEPTED base-ref mutation {mutation}: fail-closed property broken"
    )
    normalized_port = _normalize_openssl_ids(port_message)
    assert normalized_port == _normalize_openssl_ids(baseline_err), (
        f"divergent refusal for {mutation}:\n"
        f"  baseline: {baseline_err}\n"
        f"  port:     {port_message}"
    )
    assert marker in normalized_port, (
        f"base-ref mutation {mutation} no longer binds its declared branch:\n"
        f"  expected: {marker}\n"
        f"  refusal: {port_message}"
    )
