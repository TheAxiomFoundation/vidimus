"""Differential harness: the port must reproduce the ledger verifier exactly.

Baseline = PolicyEngine/ledger scripts/verify_release_chain.py, unmodified, at
the pinned commit. Candidate = vidimus.release_chain with LEDGER_SPEC (the
consumer pin, committed here). Equivalence is judged on the live chain and on
a mutation battery: for every mutation both verifiers must refuse, and their
error messages must match byte for byte.

The pinned tree resolves from VIDIMUS_LEDGER_TREE, then the local extraction
workspace, then a fresh clone of the public repo at the pin (CI path).
"""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys

import pytest

from vidimus.release_chain import (
    AnchorSpec,
    ChainSpec,
    ReleaseChainError,
    _format_time,
    verify_release_chain,
)

LEDGER_PIN = "07984278503b8e06c48c539327f6f1d01c035510"
LEDGER_REPO_URL = "https://github.com/PolicyEngine/ledger.git"
LEDGER_BRANCH = "codex/thesis-ledger-facts"

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


@pytest.fixture(scope="session")
def pinned_tree(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    override = os.environ.get("VIDIMUS_LEDGER_TREE")
    if override:
        tree = pathlib.Path(override)
        if not tree.is_dir():
            raise RuntimeError(f"VIDIMUS_LEDGER_TREE is not a directory: {tree}")
        return tree
    local = (
        pathlib.Path(__file__).resolve().parents[1]
        / ".extraction"
        / f"ledger-{LEDGER_PIN[:7]}"
    )
    if local.is_dir():
        return local
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
    return clone


def run_baseline(tree: pathlib.Path, root: pathlib.Path) -> tuple[int, str, str]:
    """Run the unmodified pinned verifier script against ``root``."""

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


def test_clean_chain_verdicts_match(pinned_tree: pathlib.Path) -> None:
    baseline_code, baseline_out, baseline_err = run_baseline(
        pinned_tree, pinned_tree
    )
    assert baseline_code == 0, f"baseline failed on the pinned tree: {baseline_err}"
    port_code, port_message = run_port(pinned_tree)
    assert port_code == 0, port_message
    assert port_message == baseline_out


MUTATIONS = {
    "flip_last_manifest_byte": lambda root: flip_byte(manifest_paths(root)[-1]),
    "flip_genesis_manifest_byte": lambda root: flip_byte(manifest_paths(root)[0]),
    "flip_producer_signature": lambda root: flip_byte(
        manifest_paths(root)[1].with_suffix("").with_name(
            manifest_paths(root)[1].stem + ".producer.sig"
        )
    ),
    "flip_freetsa_receipt": lambda root: flip_byte(
        manifest_paths(root)[1].with_name(manifest_paths(root)[1].stem + ".freetsa.tsr")
    ),
    "flip_digicert_receipt": lambda root: flip_byte(
        manifest_paths(root)[1].with_name(
            manifest_paths(root)[1].stem + ".digicert.tsr"
        )
    ),
    "flip_covered_ledger_prefix": lambda root: flip_byte(
        root / "ledger" / "official_observations.jsonl", offset_fraction=0.05
    ),
    "append_uncovered_ledger_row": lambda root: (
        root / "ledger" / "official_observations.jsonl"
    ).write_bytes(
        (root / "ledger" / "official_observations.jsonl").read_bytes()
        + b'{"tampered": true}\n'
    ),
    "flip_immutable_prefix": lambda root: flip_byte(
        root / "ledger" / "immutable_prefix.json"
    ),
    "flip_freetsa_anchor_pem": lambda root: flip_byte(
        root / "releases" / "anchors" / "freetsa-root-2016.pem"
    ),
    "delete_one_receipt": lambda root: manifest_paths(root)[1]
    .with_name(manifest_paths(root)[1].stem + ".freetsa.tsr")
    .unlink(),
    "delete_producer_signature": lambda root: manifest_paths(root)[1]
    .with_name(manifest_paths(root)[1].stem + ".producer.sig")
    .unlink(),
    "unknown_file_in_manifest_dir": lambda root: (
        root / "releases" / "manifests" / "junk.txt"
    ).write_text("tamper\n"),
    "orphan_receipt": lambda root: shutil.copyfile(
        manifest_paths(root)[1].with_name(
            manifest_paths(root)[1].stem + ".freetsa.tsr"
        ),
        root / "releases" / "manifests" / "9999-deadbeefdeadbeef.freetsa.tsr",
    ),
    "symlink_manifest": lambda root: (
        lambda target: (
            target.rename(target.with_suffix(".real")),
            target.symlink_to(target.with_suffix(".real").name),
        )
    )(manifest_paths(root)[-1]),
}


@pytest.mark.parametrize("mutation", sorted(MUTATIONS))
def test_mutation_refused_identically(
    pinned_tree: pathlib.Path, tmp_path: pathlib.Path, mutation: str
) -> None:
    root = mutable_copy(pinned_tree, tmp_path)
    MUTATIONS[mutation](root)

    baseline_code, _baseline_out, baseline_err = run_baseline(pinned_tree, root)
    port_code, port_message = run_port(root)

    assert baseline_code == 1, (
        f"baseline ACCEPTED mutation {mutation}: fail-closed property broken"
    )
    assert port_code == 1, (
        f"port ACCEPTED mutation {mutation}: fail-closed property broken"
    )
    # The baseline prints exactly one message to stderr; it may span lines
    # (openssl ASN.1 diagnostics are embedded verbatim). Compare in full.
    assert port_message == baseline_err, (
        f"divergent refusal for {mutation}:\n"
        f"  baseline: {baseline_err}\n"
        f"  port:     {port_message}"
    )
