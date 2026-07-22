"""Verify workflow provenance for commits touching a protected tree.

This module is a spec-parameterized port of brier's pinned
``verify_records_attestations.py`` and ``attest_subject.py``.  It contains no
repository policy: the repository, workflow identities, ref, protected path,
and self-anchoring checker path all arrive in a frozen :class:`AttestSpec`
committed by the consumer.

Git and ``gh attestation verify`` remain subprocess boundaries.  Every
subprocess stream is captured, so these helpers are silent library calls; the
caller decides how to render accepted and refused outcomes.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from receipt.canonical import canonical_bytes


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SUBJECT_SCHEMA = "thesis_records_push_subject_v1"
SIGNER_RE = re.compile(
    r"github\.com/(?P<repo>[^/]+/[^/]+)/(?P<workflow>\.github/workflows/[^@]+)"
    r"@(?P<ref>refs/\S+)"
)

# Protocol mechanics retained from the pinned verifier.  These values do not
# identify a trusted repository, signer, or ref; all such policy is in
# AttestSpec.
FRESH_COMMIT_GRACE_SECONDS = 15 * 60
VERIFY_RETRIES = 6
VERIFY_RETRY_DELAY_SECONDS = 20


class ProvenanceError(RuntimeError):
    """A protected-tree commit failed provenance verification."""


def _repository_slug(repository: object) -> str:
    if not isinstance(repository, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository
    ):
        raise ValueError(f"invalid repository slug: {repository!r}")
    return repository


def _relative_posix_path(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if "\\" in value or "\x00" in value or "\n" in value or "\r" in value:
        return None
    path = pathlib.PurePosixPath(value)
    parts = value[:-1].split("/") if value.endswith("/") else value.split("/")
    if path.is_absolute() or any(part in {"", ".", ".."} for part in parts):
        return None
    return value


@dataclass(frozen=True)
class AttestSpec:
    """Consumer-committed workflow-provenance policy.

    Every field is required.  ``allowed_workflows`` is normalized to a
    ``frozenset`` so the frozen spec does not retain a mutable policy object.
    """

    repository: str
    allowed_workflows: frozenset[str]
    allowed_ref: str
    protected_prefix: str
    checker_path: pathlib.PurePosixPath

    def __post_init__(self) -> None:
        _repository_slug(self.repository)

        workflows_value: object = self.allowed_workflows
        if isinstance(workflows_value, (str, bytes)) or not isinstance(
            workflows_value, Iterable
        ):
            raise ValueError(
                "allowed_workflows must be a non-empty collection of workflow paths"
            )
        try:
            workflows = frozenset(workflows_value)
        except TypeError as exc:
            raise ValueError(
                "allowed_workflows must be a non-empty collection of workflow paths"
            ) from exc
        if not workflows:
            raise ValueError(
                "allowed_workflows must be a non-empty collection of workflow paths"
            )
        for workflow in sorted(workflows, key=repr):
            if (
                _relative_posix_path(workflow) is None
                or not isinstance(workflow, str)
                or not workflow.startswith(".github/workflows/")
                or workflow == ".github/workflows/"
                or "@" in workflow
            ):
                raise ValueError(f"invalid allowed workflow path: {workflow!r}")
        object.__setattr__(self, "allowed_workflows", workflows)

        if (
            not isinstance(self.allowed_ref, str)
            or not self.allowed_ref.startswith("refs/")
            or self.allowed_ref == "refs/"
            or "@" in self.allowed_ref
            or re.search(r"\s", self.allowed_ref)
        ):
            raise ValueError(f"invalid allowed ref: {self.allowed_ref!r}")

        if _relative_posix_path(self.protected_prefix) is None:
            raise ValueError(f"invalid protected prefix: {self.protected_prefix!r}")

        checker_value: object = self.checker_path
        if isinstance(checker_value, pathlib.PurePosixPath):
            checker_text = checker_value.as_posix()
        elif isinstance(checker_value, str):
            checker_text = checker_value
        else:
            checker_text = ""
        if _relative_posix_path(checker_text) is None:
            raise ValueError(f"invalid checker path: {checker_value!r}")
        if checker_text.endswith("/"):
            raise ValueError(f"invalid checker path: {checker_value!r}")
        object.__setattr__(self, "checker_path", pathlib.PurePosixPath(checker_text))


def attestation_subject(repository: str, commit: str) -> bytes:
    """Return the canonical records-push subject, including its final newline."""

    if not COMMIT_RE.fullmatch(commit):
        raise ValueError(f"subject requires a full 40-hex commit sha: {commit!r}")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError(f"invalid repository slug: {repository!r}")
    return (
        canonical_bytes(
            {
                "schemaVersion": SUBJECT_SCHEMA,
                "repository": repository,
                "commit": commit,
            }
        )
        + b"\n"
    )


# Keep the pinned producer's helper name available at the same public joint.
subject_bytes = attestation_subject


def subject_name(commit: str) -> str:
    return f"records-push-{commit}.json"


def git_output(root: pathlib.Path, *args: str) -> str:
    """Run a captured git query in ``root`` and return stripped text."""

    return subprocess.check_output(
        ["git", *args], cwd=root, text=True, stderr=subprocess.PIPE
    ).strip()


def enforcement_epoch(root: pathlib.Path, *, spec: AttestSpec) -> str:
    commits = git_output(
        root,
        "log",
        "--full-history",
        "--diff-filter=A",
        "--format=%H",
        "--",
        spec.checker_path.as_posix(),
    ).splitlines()
    if len(commits) != 1:
        raise ProvenanceError(
            "enforcement epoch must be exactly one introducing commit for "
            f"{spec.checker_path.as_posix()}; found {len(commits)}"
        )
    return commits[0]


def records_commits(
    root: pathlib.Path,
    rev_range: str,
    *,
    spec: AttestSpec,
) -> list[str]:
    """Enumerate protected-tree commits without simplifying merge history."""

    # --full-history: path simplification may otherwise drop a protected-tree
    # commit that arrived on a side branch.
    output = git_output(
        root,
        "log",
        "--full-history",
        "--format=%H",
        rev_range,
        "--",
        spec.protected_prefix,
    )
    return output.splitlines() if output else []


def commit_age_seconds(
    root: pathlib.Path,
    commit: str,
    *,
    now: float | None = None,
) -> int:
    committed = int(git_output(root, "show", "-s", "--format=%ct", commit))
    current = time.time() if now is None else now
    return max(0, int(current) - committed)


def repository_slug(root: pathlib.Path) -> str:
    """Derive the GitHub ``owner/name`` slug using the pinned parser."""

    url = git_output(root, "remote", "get-url", "origin")
    match = re.search(r"github\.com[:/]+([^/]+/[^/.]+)", url)
    if not match:
        raise ProvenanceError(f"cannot derive repository slug from {url!r}")
    return match.group(1)


def extract_certificate_identities(payload: object) -> set[str]:
    """Return signer URIs from verificationResult.signature.certificate only."""

    identities: set[str] = set()
    results = payload if isinstance(payload, list) else [payload]
    for result in results:
        if not isinstance(result, dict):
            continue
        certificate = (
            (result.get("verificationResult") or {})
            .get("signature", {})
            .get("certificate", {})
            if isinstance(result.get("verificationResult"), dict)
            else {}
        )
        if not isinstance(certificate, dict):
            continue
        for value in certificate.values():
            if isinstance(value, str):
                for match in SIGNER_RE.finditer(value):
                    identities.add(match.group(0))
    return identities


def cert_identity_pattern(spec: AttestSpec) -> str:
    """Return the exact signer-identity regex that ``gh`` must enforce."""

    workflows = "|".join(
        re.escape(workflow) for workflow in sorted(spec.allowed_workflows)
    )
    return (
        f"^https://github\\.com/{re.escape(spec.repository)}/"
        f"({workflows})@{re.escape(spec.allowed_ref)}$"
    )


def verify_commit(
    root: pathlib.Path,
    commit: str,
    *,
    spec: AttestSpec,
    now: float | None = None,
    sleep: Callable[[float], None] | None = None,
) -> str:
    """Verify one commit's attestation; return the accepted signer identity."""

    payload = attestation_subject(spec.repository, commit)
    with tempfile.TemporaryDirectory() as tmp:
        subject_path = pathlib.Path(tmp) / subject_name(commit)
        subject_path.write_bytes(payload)
        age = (
            commit_age_seconds(root, commit)
            if now is None
            else commit_age_seconds(root, commit, now=now)
        )
        attempts = VERIFY_RETRIES if age < FRESH_COMMIT_GRACE_SECONDS else 1
        last_error = ""
        for attempt in range(1, attempts + 1):
            completed = subprocess.run(
                [
                    "gh",
                    "attestation",
                    "verify",
                    str(subject_path),
                    "--repo",
                    spec.repository,
                    "--cert-identity-regex",
                    cert_identity_pattern(spec),
                    "--format",
                    "json",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if completed.returncode == 0:
                # gh already enforced the certificate identity; parse it back
                # out of the certificate fields for the log line only.
                try:
                    parsed = json.loads(completed.stdout)
                except json.JSONDecodeError:
                    parsed = None
                identities = extract_certificate_identities(parsed)
                return sorted(identities)[0] if identities else "<verified>"
            last_error = (completed.stderr or completed.stdout).strip()
            if attempt < attempts:
                (time.sleep if sleep is None else sleep)(
                    VERIFY_RETRY_DELAY_SECONDS
                )
        raise ProvenanceError(
            f"{commit}: no valid attestation for its records push subject "
            f"({last_error.splitlines()[-1] if last_error else 'no detail'})"
        )


def commit_in_scope(root: pathlib.Path, commit: str, epoch: str) -> bool:
    """Exempt only commits proven ancestors of the enforcement epoch."""

    probe = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, epoch],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if probe.returncode == 0:
        return False
    if probe.returncode == 1:
        return True
    raise ProvenanceError(
        f"merge-base --is-ancestor failed for {commit}: "
        f"{probe.stderr.decode(errors='replace').strip()}"
    )
