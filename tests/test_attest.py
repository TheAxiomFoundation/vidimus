"""Focused unit coverage for the spec-parameterized attestation helpers.

The oracle-level command and git-history comparisons live in the dedicated
attestation differential.  These tests pin pure behavior, spec validation,
captured subprocess boundaries, and every refusal emitted directly by the
library.
"""

from __future__ import annotations

import inspect
import json
import pathlib
import re
import subprocess
from dataclasses import FrozenInstanceError

import pytest

import receipt.attest as attest_module
from receipt.attest import (
    AttestSpec,
    ProvenanceError,
    attestation_subject,
    cert_identity_pattern,
    commit_age_seconds,
    commit_in_scope,
    enforcement_epoch,
    extract_certificate_identities,
    records_commits,
    repository_slug,
    subject_bytes,
    subject_name,
    verify_commit,
)


COMMIT = "a" * 40
WORKFLOW = ".github/workflows/record-forecasts.yml"
SECOND_WORKFLOW = ".github/workflows/roll-docket.yml"


def _spec(**changes: object) -> AttestSpec:
    values: dict[str, object] = {
        "repository": "MaxGhenis/brier",
        "allowed_workflows": frozenset({WORKFLOW, SECOND_WORKFLOW}),
        "allowed_ref": "refs/heads/main",
        "protected_prefix": "records/",
        "checker_path": pathlib.PurePosixPath(
            "scripts/verify_records_attestations.py"
        ),
    }
    values.update(changes)
    return AttestSpec(**values)  # type: ignore[arg-type]


def test_attestation_subject_is_exact_canonical_payload() -> None:
    expected = (
        b'{"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        b'"repository":"MaxGhenis/brier",'
        b'"schemaVersion":"thesis_records_push_subject_v1"}\n'
    )
    assert attestation_subject("MaxGhenis/brier", COMMIT) == expected
    assert subject_bytes("MaxGhenis/brier", COMMIT) == expected
    assert subject_name(COMMIT) == f"records-push-{COMMIT}.json"


@pytest.mark.parametrize(
    ("repository", "commit", "message"),
    [
        (
            "MaxGhenis/brier",
            "abc123",
            "subject requires a full 40-hex commit sha: 'abc123'",
        ),
        (
            "not a slug",
            COMMIT,
            "invalid repository slug: 'not a slug'",
        ),
    ],
)
def test_attestation_subject_refusals_are_verbatim(
    repository: str,
    commit: str,
    message: str,
) -> None:
    with pytest.raises(ValueError) as caught:
        attestation_subject(repository, commit)
    assert str(caught.value) == message


def test_attest_spec_is_required_frozen_and_deeply_immutable() -> None:
    for field in (
        "repository",
        "allowed_workflows",
        "allowed_ref",
        "protected_prefix",
        "checker_path",
    ):
        assert (
            inspect.signature(AttestSpec).parameters[field].default
            is inspect.Parameter.empty
        )

    workflows = {WORKFLOW}
    spec = _spec(allowed_workflows=workflows, checker_path="scripts/check.py")
    workflows.add(".github/workflows/foreign.yml")
    assert spec.allowed_workflows == frozenset({WORKFLOW})
    assert spec.checker_path == pathlib.PurePosixPath("scripts/check.py")
    with pytest.raises(FrozenInstanceError):
        spec.repository = "Other/repo"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        (
            {"repository": "no-slash"},
            "invalid repository slug: 'no-slash'",
        ),
        (
            {"allowed_workflows": frozenset()},
            "allowed_workflows must be a non-empty collection of workflow paths",
        ),
        (
            {"allowed_workflows": WORKFLOW},
            "allowed_workflows must be a non-empty collection of workflow paths",
        ),
        (
            {"allowed_workflows": frozenset({"workflows/publish.yml"})},
            "invalid allowed workflow path: 'workflows/publish.yml'",
        ),
        (
            {"allowed_workflows": frozenset({".github/workflows/../evil.yml"})},
            "invalid allowed workflow path: '.github/workflows/../evil.yml'",
        ),
        (
            {"allowed_ref": "main"},
            "invalid allowed ref: 'main'",
        ),
        (
            {"allowed_ref": "refs/heads/main@evil"},
            "invalid allowed ref: 'refs/heads/main@evil'",
        ),
        (
            {"protected_prefix": "../records/"},
            "invalid protected prefix: '../records/'",
        ),
        (
            {"checker_path": pathlib.PurePosixPath("/scripts/check.py")},
            "invalid checker path: PurePosixPath('/scripts/check.py')",
        ),
        (
            {"checker_path": "scripts/"},
            "invalid checker path: 'scripts/'",
        ),
    ],
)
def test_attest_spec_validation_refusals(
    changes: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError) as caught:
        _spec(**changes)
    assert str(caught.value) == message


def test_cert_identity_pattern_is_exact_and_anchored() -> None:
    spec = _spec()
    pattern_text = cert_identity_pattern(spec)
    assert pattern_text == (
        r"^https://github\.com/MaxGhenis/brier/"
        r"(\.github/workflows/record\-forecasts\.yml|"
        r"\.github/workflows/roll\-docket\.yml)@refs/heads/main$"
    )
    pattern = re.compile(pattern_text)
    assert pattern.fullmatch(
        "https://github.com/MaxGhenis/brier/"
        ".github/workflows/record-forecasts.yml@refs/heads/main"
    )
    for identity in (
        "https://github.com/Other/repo/"
        ".github/workflows/record-forecasts.yml@refs/heads/main",
        "https://github.com/MaxGhenis/brier/"
        ".github/workflows/foreign.yml@refs/heads/main",
        "https://github.com/MaxGhenis/brier/"
        ".github/workflows/record-forecasts.yml@refs/heads/feature",
        "https://github.com/MaxGhenis/brier/"
        ".github/workflows/record-forecasts.yml@refs/heads/main.evil",
    ):
        assert pattern.fullmatch(identity) is None


def test_certificate_identity_extraction_uses_certificate_fields_only() -> None:
    first = (
        "https://github.com/MaxGhenis/brier/.github/workflows/"
        "record-forecasts.yml@refs/heads/main"
    )
    second = (
        "https://github.com/MaxGhenis/brier/.github/workflows/"
        "roll-docket.yml@refs/heads/main"
    )
    payload = [
        {
            "verificationResult": {
                "signature": {
                    "certificate": {
                        "buildSignerURI": first,
                        "other": f"prefix {second} suffix",
                        "ignored": 7,
                    }
                },
                "statement": {
                    "certificate": (
                        "github.com/Evil/fork/.github/workflows/"
                        "evil.yml@refs/heads/main"
                    )
                },
            }
        },
        None,
        {"verificationResult": "wrong type"},
    ]
    assert extract_certificate_identities(payload) == {
        first.removeprefix("https://"),
        second.removeprefix("https://"),
    }


def test_enforcement_epoch_command_and_refusals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = pathlib.Path("/repo")
    spec = _spec()
    seen: list[tuple[object, ...]] = []
    outputs = iter(["", f"{'b' * 40}\n{'c' * 40}", "d" * 40])

    def fake_git_output(path: pathlib.Path, *args: str) -> str:
        seen.append((path, *args))
        return next(outputs)

    monkeypatch.setattr(attest_module, "git_output", fake_git_output)
    with pytest.raises(ProvenanceError) as caught:
        enforcement_epoch(root, spec=spec)
    assert str(caught.value) == (
        "enforcement epoch must be exactly one introducing commit for "
        "scripts/verify_records_attestations.py; found 0"
    )
    with pytest.raises(ProvenanceError) as caught:
        enforcement_epoch(root, spec=spec)
    assert str(caught.value).endswith("; found 2")
    assert enforcement_epoch(root, spec=spec) == "d" * 40
    assert seen[0] == (
        root,
        "log",
        "--full-history",
        "--diff-filter=A",
        "--format=%H",
        "--",
        "scripts/verify_records_attestations.py",
    )


def test_records_commits_uses_full_history_and_consumer_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = pathlib.Path("/repo")
    seen: list[tuple[object, ...]] = []
    outputs = iter([f"{'b' * 40}\n{'c' * 40}", ""])

    def fake_git_output(path: pathlib.Path, *args: str) -> str:
        seen.append((path, *args))
        return next(outputs)

    monkeypatch.setattr(attest_module, "git_output", fake_git_output)
    assert records_commits(root, "A..B", spec=_spec()) == ["b" * 40, "c" * 40]
    assert records_commits(root, "B..C", spec=_spec()) == []
    assert seen[0] == (
        root,
        "log",
        "--full-history",
        "--format=%H",
        "A..B",
        "--",
        "records/",
    )


def test_commit_age_and_repository_slug_parsers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = pathlib.Path("/repo")
    outputs = iter(
        [
            "100",
            "200",
            "git@github.com:MaxGhenis/brier.git",
            "https://example.com/MaxGhenis/brier.git",
        ]
    )
    monkeypatch.setattr(
        attest_module,
        "git_output",
        lambda _root, *args: next(outputs),
    )
    assert commit_age_seconds(root, COMMIT, now=150.9) == 50
    assert commit_age_seconds(root, COMMIT, now=150) == 0
    assert repository_slug(root) == "MaxGhenis/brier"
    with pytest.raises(ProvenanceError) as caught:
        repository_slug(root)
    assert str(caught.value) == (
        "cannot derive repository slug from "
        "'https://example.com/MaxGhenis/brier.git'"
    )


@pytest.mark.parametrize(
    ("returncode", "expected"),
    [(0, False), (1, True)],
)
def test_commit_scope_branch_outcomes(
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    expected: bool,
) -> None:
    root = pathlib.Path("/repo")
    seen: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        seen.append((args, kwargs))
        return subprocess.CompletedProcess(args, returncode, b"", b"")

    monkeypatch.setattr(attest_module.subprocess, "run", fake_run)
    assert commit_in_scope(root, "b" * 40, "c" * 40) is expected
    assert seen == [
        (
            [
                "git",
                "merge-base",
                "--is-ancestor",
                "b" * 40,
                "c" * 40,
            ],
            {"cwd": root, "capture_output": True, "check": False},
        )
    ]


def test_commit_scope_merge_base_error_is_verbatim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed = subprocess.CompletedProcess(
        ["git"], 128, stdout=b"", stderr=b"fatal: bad object\n"
    )
    monkeypatch.setattr(
        attest_module.subprocess,
        "run",
        lambda *args, **kwargs: completed,
    )
    with pytest.raises(ProvenanceError) as caught:
        commit_in_scope(pathlib.Path("/repo"), "b" * 40, "c" * 40)
    assert str(caught.value) == (
        f"merge-base --is-ancestor failed for {'b' * 40}: fatal: bad object"
    )


def _verification_payload(workflow: str = WORKFLOW) -> dict[str, object]:
    return {
        "verificationResult": {
            "signature": {
                "certificate": {
                    "buildSignerURI": (
                        "https://github.com/MaxGhenis/brier/"
                        f"{workflow}@refs/heads/main"
                    )
                }
            }
        }
    }


def test_verify_commit_constructs_exact_gh_command_and_is_silent(
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    root = pathlib.Path("/repo")
    spec = _spec()
    seen: list[tuple[list[str], dict[str, object], bytes]] = []

    monkeypatch.setattr(
        attest_module,
        "commit_age_seconds",
        lambda _root, _commit: 10**9,
    )

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        seen.append((args, kwargs, pathlib.Path(args[3]).read_bytes()))
        return subprocess.CompletedProcess(
            args,
            0,
            stdout=json.dumps(_verification_payload()),
            stderr="",
        )

    monkeypatch.setattr(attest_module.subprocess, "run", fake_run)
    identity = verify_commit(root, COMMIT, spec=spec)
    assert identity == (
        "github.com/MaxGhenis/brier/.github/workflows/"
        "record-forecasts.yml@refs/heads/main"
    )
    assert len(seen) == 1
    args, kwargs, payload = seen[0]
    assert pathlib.Path(args[3]).name == subject_name(COMMIT)
    assert args[:3] == ["gh", "attestation", "verify"]
    assert args[4:] == [
        "--repo",
        "MaxGhenis/brier",
        "--cert-identity-regex",
        cert_identity_pattern(spec),
        "--format",
        "json",
    ]
    assert kwargs == {"capture_output": True, "text": True, "check": False}
    assert payload == attestation_subject("MaxGhenis/brier", COMMIT)
    assert capfd.readouterr() == ("", "")


def test_verify_commit_retries_fresh_commit_then_accepts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        attest_module,
        "commit_age_seconds",
        lambda _root, _commit: 1,
    )
    outcomes = iter(
        [
            subprocess.CompletedProcess(
                ["gh"], 1, stdout="", stderr="not indexed yet"
            ),
            subprocess.CompletedProcess(
                ["gh"],
                0,
                stdout=json.dumps(_verification_payload(SECOND_WORKFLOW)),
                stderr="",
            ),
        ]
    )
    calls: list[list[str]] = []

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        calls.append(args)
        return next(outcomes)

    monkeypatch.setattr(attest_module.subprocess, "run", fake_run)
    delays: list[float] = []
    identity = verify_commit(
        pathlib.Path("/repo"),
        COMMIT,
        spec=_spec(),
        sleep=delays.append,
    )
    assert len(calls) == 2
    assert delays == [20]
    assert "roll-docket.yml@refs/heads/main" in identity


def test_verify_commit_exhausts_retries_and_uses_last_diagnostic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        attest_module,
        "commit_age_seconds",
        lambda _root, _commit: 1,
    )
    calls = 0

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess:
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(
            args,
            1,
            stdout="stdout fallback",
            stderr=f"attempt {calls}\nlast detail {calls}\n",
        )

    monkeypatch.setattr(attest_module.subprocess, "run", fake_run)
    delays: list[float] = []
    with pytest.raises(ProvenanceError) as caught:
        verify_commit(
            pathlib.Path("/repo"),
            COMMIT,
            spec=_spec(),
            sleep=delays.append,
        )
    assert calls == 6
    assert delays == [20] * 5
    assert str(caught.value) == (
        f"{COMMIT}: no valid attestation for its records push subject "
        "(last detail 6)"
    )


def test_verify_commit_old_failure_and_unparseable_success_messages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        attest_module,
        "commit_age_seconds",
        lambda _root, _commit: 10**9,
    )
    outcomes = iter(
        [
            subprocess.CompletedProcess(["gh"], 1, stdout="", stderr=""),
            subprocess.CompletedProcess(["gh"], 0, stdout="not json", stderr=""),
        ]
    )
    monkeypatch.setattr(
        attest_module.subprocess,
        "run",
        lambda *args, **kwargs: next(outcomes),
    )
    with pytest.raises(ProvenanceError) as caught:
        verify_commit(pathlib.Path("/repo"), COMMIT, spec=_spec())
    assert str(caught.value) == (
        f"{COMMIT}: no valid attestation for its records push subject (no detail)"
    )
    assert verify_commit(pathlib.Path("/repo"), COMMIT, spec=_spec()) == "<verified>"
