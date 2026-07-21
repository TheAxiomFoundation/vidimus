"""Differential harness: the extracted append gate must match its oracle.

Baseline = PolicyEngine/ledger scripts/check_thesis_facts_append.py, run
unmodified at the pinned commit. Candidate = receipt.append_gate with the
consumer-pinned ``APPEND_GATE_SPEC`` below, which composes the same
``LEDGER_SPEC`` used by the release-chain differential harness.

The git fixture replays a real, already-witnessed transition from the pinned
tree. Its base commit contains releases 0 and 1 plus the first 145 ledger rows;
the candidate restores the exact pinned release-2 quartet and rows 146-147.
That gives the oracle and port a cryptographically valid append without
re-cutting or re-signing a release.

Comparison contract, matching tests/test_ledger_equivalence.py:

- exit status must match (0 accept, 1 refuse);
- on refusal, the baseline CLI's stderr must equal the port exception rendered
  with the CLI prefix byte for byte after two normalizations: surrounding
  whitespace is stripped from both captured messages, and OpenSSL 3's volatile
  per-process error-queue id is masked; the baseline must emit no stdout;
- on acceptance, the baseline's stripped stdout must equal the port's returned
  summary byte for byte, and the baseline must emit no stderr;
- the port is a library and must write nothing to stdout or stderr.

Each mutation returns a marker for the exact refusal branch it is intended to
bind. Full message equality is asserted before that marker, so a mutation that
starts failing earlier cannot silently masquerade as equivalent coverage.
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

import pytest

from test_ledger_equivalence import LEDGER_SPEC
from receipt.append_gate import (
    AppendError,
    AppendGateSpec,
    expected_assertion_version_id,
    verify_append_gate,
)
from receipt.canonical import canonical_bytes

LEDGER_PIN = "9dafe8174f42a06c00817fe596d5a8e686cb17b7"
LEDGER_REPO_URL = "https://github.com/PolicyEngine/ledger.git"
LEDGER_BRANCH = "codex/thesis-ledger-facts"

BASELINE_AUTHENTICATED_FILES = {
    "scripts/check_thesis_facts_append.py": (
        "46727ab22186b8f150fc7dbee8222cee729a6ddb4ba8e8cbe4a3dda702cbc427"
    ),
    "scripts/verify_release_chain.py": (
        "7f73e6921ca40e41e556c8e37a634e2780e7e8eeb3ab203ecdb9b7bd4b15a844"
    ),
    "scripts/canonical_json.py": (
        "562bf267b7686bce8cb71f3c13f34825c21cd4ef0aba1c0c46aff16962a6cadd"
    ),
}

APPEND_GATE_SPEC = AppendGateSpec(
    chain=LEDGER_SPEC,
    prefix_schema_version="thesis_facts_immutable_prefix_v1",
    release_manifest_prefix="releases/manifests/",
    genesis_support_files=frozenset(
        {
            "releases/README.md",
            *(
                f"releases/anchors/{anchor.filename}"
                for anchor in LEDGER_SPEC.anchors.values()
            ),
            (f"releases/anchors/{LEDGER_SPEC.producer_public_key_filename}"),
        }
    ),
    gate_surface=frozenset(
        {
            "scripts/check_thesis_facts_append.py",
            "scripts/verify_release_chain.py",
            "scripts/canonical_json.py",
            "scripts/cut_release_manifest.py",
            ".github/workflows/thesis-facts-append.yml",
            "releases/anchors/**",
        }
    ),
    data_surface=frozenset(
        {
            "ledger/**",
            "releases/manifests/**",
        }
    ),
    assertion_content_keys=(
        "source_record_id",
        "value",
        "observed_at",
        "period",
        "geography",
        "entity",
        "aggregation",
        "filters",
        "domain",
    ),
)

BASE_LINE_COUNT = 145
CANDIDATE_LINE_COUNT = 147
NEW_RELEASE_STEM = "0002-a69272175b73c83b"
BASE_RELEASE_STEM = "0001-916626696d034b80"
RELEASE_FILE_SUFFIXES = (
    ".json",
    ".producer.sig",
    ".freetsa.tsr",
    ".digicert.tsr",
)


def _authenticated_baseline_tree(tree: pathlib.Path) -> pathlib.Path:
    """Authenticate every source file executed by the subprocess oracle."""

    for relative, expected in BASELINE_AUTHENTICATED_FILES.items():
        path = tree / relative
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected:
            raise RuntimeError(
                "baseline oracle is not the pinned append gate: "
                f"{path} has SHA-256 {digest}, expected {expected}; "
                "a stale or altered baseline must not vouch for the port"
            )
    return tree


@pytest.fixture(scope="session")
def append_pinned_tree(
    tmp_path_factory: pytest.TempPathFactory,
) -> pathlib.Path:
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
    clone = tmp_path_factory.mktemp("append-ledger-pin") / "ledger"
    subprocess.run(
        [
            "git",
            "clone",
            "--quiet",
            "--branch",
            LEDGER_BRANCH,
            "--single-branch",
            LEDGER_REPO_URL,
            str(clone),
        ],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(clone), "checkout", "--quiet", LEDGER_PIN],
        check=True,
    )
    return _authenticated_baseline_tree(clone)


def run_baseline(
    tree: pathlib.Path,
    root: pathlib.Path,
    base_ref: str,
) -> tuple[int, str, str]:
    """Run the authenticated, unmodified upstream gate as a subprocess."""

    completed = subprocess.run(
        [
            sys.executable,
            str(tree / "scripts" / "check_thesis_facts_append.py"),
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


def run_port(
    tree: pathlib.Path,
    root: pathlib.Path,
    base_ref: str,
) -> tuple[int, str]:
    """Render the silent library entrypoint in the baseline CLI's shape."""

    try:
        summary = verify_append_gate(
            root.resolve(),
            spec=APPEND_GATE_SPEC,
            base_ref=base_ref,
            trusted_code_root=tree.resolve(),
        )
    except AppendError as exc:
        return 1, f"thesis-facts append check failed: {exc}"
    return 0, summary


def _normalize_openssl_ids(message: str) -> str:
    """Mask OpenSSL 3's per-process error-queue id on embedded error lines."""

    return re.sub(
        r"(?m)^[0-9A-Fa-f]{8,16}(?=:error:)",
        "<openssl-err-id>",
        message.strip(),
    )


def _assert_port_silent(capfd: pytest.CaptureFixture[str]) -> None:
    captured = capfd.readouterr()
    assert (captured.out, captured.err) == ("", ""), (
        "the port must not write to stdout/stderr; captured "
        f"out={captured.out!r} err={captured.err!r}"
    )


def _git(root: pathlib.Path, *arguments: str) -> str:
    """Run fixture git commands with ambient user configuration isolated."""

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


def commit_tree(root: pathlib.Path, message: str) -> str:
    _git(root, "init", "--quiet")
    _git(root, "config", "user.email", "harness@example.invalid")
    _git(root, "config", "user.name", "Differential Harness")
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", message)
    return _git(root, "rev-parse", "HEAD")


def release_file(root: pathlib.Path, stem: str, suffix: str) -> pathlib.Path:
    return root / "releases" / "manifests" / f"{stem}{suffix}"


def replay_release_two(
    tree: pathlib.Path,
    destination: pathlib.Path,
    *,
    mutate_base: Callable[[pathlib.Path], None] | None = None,
) -> tuple[pathlib.Path, str]:
    """Construct base release 1, then restore the authentic release-2 append."""

    root = destination / "root"
    for relative in ("ledger", "releases"):
        shutil.copytree(tree / relative, root / relative)

    ledger = root / LEDGER_SPEC.state_relative
    full_ledger = ledger.read_bytes()
    rows = full_ledger.splitlines(keepends=True)
    assert len(rows) == CANDIDATE_LINE_COUNT
    assert all(row.endswith(b"\n") for row in rows)
    ledger.write_bytes(b"".join(rows[:BASE_LINE_COUNT]))
    for suffix in RELEASE_FILE_SUFFIXES:
        release_file(root, NEW_RELEASE_STEM, suffix).unlink()
    if mutate_base is not None:
        mutate_base(root)

    base = commit_tree(root, "release 1 base")

    ledger.write_bytes(full_ledger)
    for suffix in RELEASE_FILE_SUFFIXES:
        shutil.copyfile(
            release_file(tree, NEW_RELEASE_STEM, suffix),
            release_file(root, NEW_RELEASE_STEM, suffix),
        )
    return root, base


def gate_only_candidate(
    tree: pathlib.Path,
    destination: pathlib.Path,
) -> tuple[pathlib.Path, str]:
    """Commit the full pinned data tree, then add one gate-only file."""

    root = destination / "root"
    for relative in ("ledger", "releases"):
        shutil.copytree(tree / relative, root / relative)
    base = commit_tree(root, "full pinned tree")
    script = root / "scripts" / "check_thesis_facts_append.py"
    script.parent.mkdir(parents=True)
    script.write_text("# gate-only fixture\n", encoding="utf-8")
    return root, base


def _replace_jsonl_row(
    root: pathlib.Path,
    number: int,
    mutate: Callable[[dict], None],
) -> None:
    ledger = root / LEDGER_SPEC.state_relative
    rows = ledger.read_bytes().splitlines(keepends=True)
    row = json.loads(rows[number - 1])
    mutate(row)
    rows[number - 1] = (
        json.dumps(
            row,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    ledger.write_bytes(b"".join(rows))


def _prepend_space_to_row(root: pathlib.Path, number: int) -> None:
    ledger = root / LEDGER_SPEC.state_relative
    rows = ledger.read_bytes().splitlines(keepends=True)
    rows[number - 1] = b" " + rows[number - 1]
    ledger.write_bytes(b"".join(rows))


def _flip_middle_byte(path: pathlib.Path) -> None:
    payload = bytearray(path.read_bytes())
    payload[len(payload) // 2] ^= 0x01
    path.write_bytes(bytes(payload))


def _assert_accepts_identically(
    tree: pathlib.Path,
    root: pathlib.Path,
    base_ref: str,
    capfd: pytest.CaptureFixture[str],
) -> str:
    baseline_code, baseline_out, baseline_err = run_baseline(
        tree,
        root,
        base_ref,
    )
    capfd.readouterr()
    port_code, port_message = run_port(tree, root, base_ref)
    _assert_port_silent(capfd)

    assert baseline_code == 0, baseline_err
    assert baseline_err == "", "baseline must print no stderr on acceptance"
    assert port_code == 0, port_message
    assert port_message.strip() == baseline_out
    return port_message


def _assert_refuses_identically(
    tree: pathlib.Path,
    root: pathlib.Path,
    base_ref: str,
    marker: str,
    mutation: str,
    capfd: pytest.CaptureFixture[str],
) -> str:
    baseline_code, baseline_out, baseline_err = run_baseline(
        tree,
        root,
        base_ref,
    )
    capfd.readouterr()
    port_code, port_message = run_port(tree, root, base_ref)
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
    normalized_baseline = _normalize_openssl_ids(baseline_err)
    normalized_port = _normalize_openssl_ids(port_message)
    assert normalized_port == normalized_baseline, (
        f"divergent refusal for {mutation}:\n"
        f"  baseline: {baseline_err}\n"
        f"  port:     {port_message}"
    )
    assert marker in normalized_port, (
        f"mutation {mutation} no longer binds its declared branch:\n"
        f"  expected: {marker}\n"
        f"  refusal: {port_message}"
    )
    return port_message


def test_clean_valid_append_verdicts_match(
    append_pinned_tree: pathlib.Path,
    tmp_path: pathlib.Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    root, base = replay_release_two(append_pinned_tree, tmp_path)
    message = _assert_accepts_identically(
        append_pinned_tree,
        root,
        base,
        capfd,
    )
    assert message == (
        "thesis-facts append check OK: 147 rows, immutable prefix 128, "
        "+2 appended vs base, release 2"
    )


def test_candidate_base_anchor_bytes_do_not_replace_trusted_anchors(
    append_pinned_tree: pathlib.Path,
    tmp_path: pathlib.Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    anchor_relative = (
        LEDGER_SPEC.anchor_relative
        / LEDGER_SPEC.anchors["freetsa"].filename
    )

    def poison_candidate_base(root: pathlib.Path) -> None:
        _flip_middle_byte(root / anchor_relative)

    root, base = replay_release_two(
        append_pinned_tree,
        tmp_path,
        mutate_base=poison_candidate_base,
    )
    assert (root / anchor_relative).read_bytes() != (
        append_pinned_tree / anchor_relative
    ).read_bytes()

    message = _assert_accepts_identically(
        append_pinned_tree,
        root,
        base,
        capfd,
    )
    marker = (
        "thesis-facts append check OK: 147 rows, immutable prefix 128, "
        "+2 appended vs base, release 2"
    )
    assert message == marker


def test_gate_only_acceptance_verdicts_match(
    append_pinned_tree: pathlib.Path,
    tmp_path: pathlib.Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    root, base = gate_only_candidate(append_pinned_tree, tmp_path)
    message = _assert_accepts_identically(
        append_pinned_tree,
        root,
        base,
        capfd,
    )
    assert message == (
        "thesis-facts append check OK: gate-only proposal; DATA_SURFACE "
        "unchanged; GATE_SURFACE changes="
        "['scripts/check_thesis_facts_append.py']"
    )


@pytest.mark.parametrize("relative", sorted(BASELINE_AUTHENTICATED_FILES))
def test_each_oracle_source_is_authenticated(
    append_pinned_tree: pathlib.Path,
    tmp_path: pathlib.Path,
    relative: str,
) -> None:
    fake = tmp_path / "tree"
    for source in BASELINE_AUTHENTICATED_FILES:
        destination = fake / source
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(append_pinned_tree / source, destination)
    target = fake / relative
    target.write_bytes(target.read_bytes() + b"\n# altered\n")

    with pytest.raises(RuntimeError, match=re.escape(relative)):
        _authenticated_baseline_tree(fake)


# --- requested refusal branches ------------------------------------------


def frozen_prefix_rewrite(root: pathlib.Path, _base: str) -> str:
    _prepend_space_to_row(root, 1)
    return (
        "immutable prefix line 1 "
        "(bls.ces.total_nonfarm_payroll_change.may_2026.first_print) "
        "was rewritten"
    )


def historical_non_append(root: pathlib.Path, _base: str) -> str:
    _prepend_space_to_row(root, 129)
    return (
        "change rewrites existing line 129 "
        "(statcan.cpi.all_items_annual_rate.canada.may_2026.first_print); "
        "the ledger is append-only — supersede instead"
    )


def prefix_manifest_changed(root: pathlib.Path, base: str) -> str:
    prefix_path = root / LEDGER_SPEC.prefix_relative
    prefix = json.loads(prefix_path.read_text(encoding="utf-8"))
    ledger_rows = (
        (root / LEDGER_SPEC.state_relative).read_bytes().splitlines(keepends=True)
    )
    new_count = int(prefix["prefixLineCount"]) - 1
    prefix["prefixLineCount"] = new_count
    prefix["lineSha256s"] = prefix["lineSha256s"][:new_count]
    prefix["prefixSha256"] = hashlib.sha256(
        b"".join(ledger_rows[:new_count])
    ).hexdigest()
    prefix_path.write_text(
        json.dumps(prefix, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return f"immutable prefix manifest prefixLineCount changed vs base {base}"


def missing_assertion_version(root: pathlib.Path, _base: str) -> str:
    _replace_jsonl_row(root, 146, lambda row: row.pop("assertionVersion"))
    return (
        "appended line 146 "
        "(bls.cpi.u.headline_mom.june_2026.first_print) "
        "lacks assertionVersion"
    )


def duplicate_without_supersedes(root: pathlib.Path, _base: str) -> str:
    ledger = root / LEDGER_SPEC.state_relative
    rows = ledger.read_bytes().splitlines()
    previous_id = json.loads(rows[144])["source_record_id"]

    def mutate(row: dict) -> None:
        row["source_record_id"] = previous_id
        row["assertionVersion"]["supersedes"] = None
        row["assertionVersion"]["id"] = expected_assertion_version_id(
            row,
            APPEND_GATE_SPEC,
        )

    _replace_jsonl_row(root, 146, mutate)
    return (
        f"line 146 duplicates {previous_id} (line 145) without superseding "
        "an assertion version — corrections must be explicit"
    )


def invalid_target_content_hash(root: pathlib.Path, _base: str) -> str:
    def mutate(row: dict) -> None:
        row["targetContentHash"] = "not-a-sha256"
        row["sourceBindingProjection"] = {
            "responseSha256": row["responseArchive"]["sha256"],
            "unit": row["measure"]["unit"],
        }

    _replace_jsonl_row(root, 146, mutate)
    return (
        "appended line 146 "
        "(bls.cpi.u.headline_mom.june_2026.first_print) "
        "targetContentHash is not a SHA-256 hex digest"
    )


def empty_source_binding_projection(root: pathlib.Path, _base: str) -> str:
    def mutate(row: dict) -> None:
        row["targetContentHash"] = "0" * 64
        row["sourceBindingProjection"] = {}

    _replace_jsonl_row(root, 146, mutate)
    return (
        "appended line 146 "
        "(bls.cpi.u.headline_mom.june_2026.first_print) "
        "sourceBindingProjection must be a non-empty object"
    )


def non_dict_source_binding_projection(root: pathlib.Path, _base: str) -> str:
    def mutate(row: dict) -> None:
        row["targetContentHash"] = "0" * 64
        row["sourceBindingProjection"] = "not-an-object"

    _replace_jsonl_row(root, 146, mutate)
    return (
        "appended line 146 "
        "(bls.cpi.u.headline_mom.june_2026.first_print) "
        "sourceBindingProjection must be a non-empty object"
    )


def binding_presence_xor_empty_hash_only(root: pathlib.Path, _base: str) -> str:
    def mutate(row: dict) -> None:
        row["targetContentHash"] = ""
        row.pop("sourceBindingProjection", None)

    _replace_jsonl_row(
        root,
        146,
        mutate,
    )
    return (
        "appended line 146 "
        "(bls.cpi.u.headline_mom.june_2026.first_print) must carry "
        "targetContentHash and sourceBindingProjection together"
    )


def projection_without_target_hash(root: pathlib.Path, _base: str) -> str:
    def mutate(row: dict) -> None:
        row["sourceBindingProjection"] = {
            "responseSha256": row["responseArchive"]["sha256"],
            "unit": row["measure"]["unit"],
        }

    _replace_jsonl_row(
        root,
        146,
        mutate,
    )
    return (
        "appended line 146 "
        "(bls.cpi.u.headline_mom.june_2026.first_print) must carry "
        "targetContentHash and sourceBindingProjection together"
    )


def base_release_file_changed(root: pathlib.Path, base: str) -> str:
    relative = f"releases/manifests/{BASE_RELEASE_STEM}.json"
    _flip_middle_byte(root / relative)
    return f"existing release file bytes changed relative to {base}: {relative}"


def missing_new_release_manifest(root: pathlib.Path, _base: str) -> str:
    release_file(root, NEW_RELEASE_STEM, ".json").unlink()
    return "release proposal must add exactly one manifest for index 2; found []"


def altered_new_release_manifest(root: pathlib.Path, _base: str) -> str:
    manifest = release_file(root, NEW_RELEASE_STEM, ".json")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["append"]["appendedRowCount"] += 1
    manifest.write_bytes(canonical_bytes(payload) + b"\n")
    return (
        "manifest filename hash does not match exact file bytes: "
        f"{NEW_RELEASE_STEM}.json"
    )


def release_only_proposal(root: pathlib.Path, _base: str) -> str:
    ledger = root / LEDGER_SPEC.state_relative
    rows = ledger.read_bytes().splitlines(keepends=True)
    ledger.write_bytes(b"".join(rows[:BASE_LINE_COUNT]))
    return (
        "release-only proposal is forbidden after genesis; a next release "
        "must witness an actual ledger byte append"
    )


def mixed_data_and_gate(root: pathlib.Path, _base: str) -> str:
    script = root / "scripts" / "check_thesis_facts_append.py"
    script.parent.mkdir(parents=True)
    script.write_text("# mixed-surface fixture\n", encoding="utf-8")
    return "mixed data/gate proposal is forbidden"


MUTATIONS: dict[str, Callable[[pathlib.Path, str], str]] = {
    "altered_new_release_manifest": altered_new_release_manifest,
    "base_release_file_changed": base_release_file_changed,
    "binding_presence_xor_empty_hash_only": binding_presence_xor_empty_hash_only,
    "duplicate_without_supersedes": duplicate_without_supersedes,
    "empty_source_binding_projection": empty_source_binding_projection,
    "frozen_prefix_rewrite": frozen_prefix_rewrite,
    "historical_non_append": historical_non_append,
    "invalid_target_content_hash": invalid_target_content_hash,
    "missing_assertion_version": missing_assertion_version,
    "missing_new_release_manifest": missing_new_release_manifest,
    "mixed_data_and_gate": mixed_data_and_gate,
    "non_dict_source_binding_projection": non_dict_source_binding_projection,
    "prefix_manifest_changed": prefix_manifest_changed,
    "projection_without_target_hash": projection_without_target_hash,
    "release_only_proposal": release_only_proposal,
}


@pytest.mark.parametrize("mutation", sorted(MUTATIONS))
def test_mutation_refused_identically(
    append_pinned_tree: pathlib.Path,
    tmp_path: pathlib.Path,
    capfd: pytest.CaptureFixture[str],
    mutation: str,
) -> None:
    root, base = replay_release_two(append_pinned_tree, tmp_path)
    marker = MUTATIONS[mutation](root, base)
    _assert_refuses_identically(
        append_pinned_tree,
        root,
        base,
        marker,
        mutation,
        capfd,
    )
