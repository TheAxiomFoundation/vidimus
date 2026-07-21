"""Offline verification for an append-only witnessed release chain.

The verifier treats manifest, signature, and receipt bytes as an append-only
journal. It does not trust manifest provenance or timestamps supplied by the
producer: each manifest is canonical and content-addressed, every state and
append digest is recomputed from the current append-only JSONL, every manifest
has a valid signature from the pinned producer key, and both RFC 3161 receipts
are verified against separate, committed trust anchors.

Extracted nearly verbatim from PolicyEngine/ledger scripts/verify_release_chain.py
at commit 07984278503b8e06c48c539327f6f1d01c035510 (branch
codex/thesis-ledger-facts); see receipts/ledger-pin-source-hashes.txt. The only
intended change is parameterization: every repo-specific constant moved into
ChainSpec, supplied by the consumer's committed code. Behavior is gated by the
differential harness in tests/test_ledger_equivalence.py.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from receipt import sign as _sign
from receipt.canonical import canonical_bytes

# One availability gate for the whole package: producer-signature verification
# lives in receipt.sign, and this module's only remaining cryptography use is
# choosing between sign's cryptography and OpenSSL 3 CLI paths.
from receipt.sign import CRYPTOGRAPHY_AVAILABLE, SignError, _openssl_environment

MAX_RELEASE_INDEX = 9_999
DEFAULT_CLOCK_SKEW_SECONDS = 300
MAX_FUTURE_SECONDS = 300
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
MANIFEST_RE = re.compile(r"(?P<index>[0-9]{4})-(?P<digest>[0-9a-f]{16})\.json\Z")
PRODUCER_SIGNATURE_RE = re.compile(
    r"(?P<stem>[0-9]{4}-[0-9a-f]{16})\.producer\.sig\Z"
)
PRODUCER_SIGNATURE_BYTES = _sign.PRODUCER_SIGNATURE_BYTES
STRICT_UTC_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:"
    r"[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z\Z"
)
TIME_STAMP_RE = re.compile(
    r"(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>[0-9]{1,2})\s+"
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):"
    r"(?P<second>[0-9]{2})(?P<fraction>\.[0-9]+)?\s+"
    r"(?P<year>[0-9]{4})\s+GMT\Z"
)


@dataclass(frozen=True)
class AnchorSpec:
    filename: str
    pem_sha256: str
    policy_oid: str
    signer_certificate_sha256: str
    signer_spki_sha256: str


@dataclass(frozen=True)
class ChainSpec:
    """Repo-specific custody constants, pinned in the consumer's committed code.

    The package ships machinery only. Every trust anchor — manifest layout,
    schema name, producer SPKI fingerprint, TSA anchor identities — arrives
    from the consumer's own committed code, never from package defaults, so a
    producer can never swap a pin at runtime.
    """

    manifest_relative: pathlib.PurePosixPath
    state_relative: pathlib.PurePosixPath
    prefix_relative: pathlib.PurePosixPath
    anchor_relative: pathlib.PurePosixPath
    release_root_relative: pathlib.PurePosixPath
    schema_version: str
    producer_public_key_filename: str
    producer_spki_sha256: str
    anchors: Mapping[str, AnchorSpec]

    @property
    def state_path(self) -> str:
        return self.state_relative.as_posix()


def _receipt_re(spec: ChainSpec) -> re.Pattern[str]:
    tsa_alternation = "|".join(re.escape(tsa) for tsa in sorted(spec.anchors))
    return re.compile(
        r"(?P<stem>[0-9]{4}-[0-9a-f]{16})"
        rf"\.(?P<tsa>{tsa_alternation})\.tsr\Z"
    )


class ReleaseChainError(ValueError):
    """The release journal is malformed, inconsistent, or untrusted."""


@dataclass(frozen=True)
class GitEntry:
    mode: str
    object_type: str
    object_id: str
    path: str


@dataclass(frozen=True)
class ReleaseRecord:
    path: pathlib.Path
    raw: bytes
    sha256: str
    manifest: dict[str, Any]
    receipt_paths: dict[str, pathlib.Path]
    receipt_times: dict[str, datetime]
    producer_signature_path: pathlib.Path

    @property
    def release_index(self) -> int:
        return int(self.manifest["releaseIndex"])


@dataclass(frozen=True)
class ChainVerification:
    releases: tuple[ReleaseRecord, ...]

    @property
    def head(self) -> ReleaseRecord | None:
        return self.releases[-1] if self.releases else None


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _fail_json_constant(value: str) -> None:
    raise ReleaseChainError(f"manifest contains non-JSON number {value!r}")


def _object_without_duplicates(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseChainError(f"manifest has duplicate key {key!r}")
        result[key] = value
    return result


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ReleaseChainError(f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise ReleaseChainError(
            f"{label} keys are not closed-world: missing={missing}, unknown={unknown}"
        )
    return value


def _strict_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int:
        raise ReleaseChainError(f"{label} must be an integer, not a boolean")
    if value < minimum:
        raise ReleaseChainError(f"{label} must be >= {minimum}")
    return value


def _strict_string(value: Any, label: str, *, nonempty: bool = True) -> str:
    if type(value) is not str or (nonempty and not value):
        suffix = " and non-empty" if nonempty else ""
        raise ReleaseChainError(f"{label} must be a string{suffix}")
    return value


def _sha256(value: Any, label: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise ReleaseChainError(
            f"{label} must be exactly 64 lowercase hexadecimal characters"
        )
    return value


def parse_created_at(value: Any, label: str = "createdAtUtc") -> datetime:
    text = _strict_string(value, label)
    if STRICT_UTC_RE.fullmatch(text) is None:
        raise ReleaseChainError(f"{label} must be a strict UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise ReleaseChainError(f"{label} is not a real UTC time: {text!r}") from exc
    return parsed.astimezone(timezone.utc)


def validate_manifest_schema(manifest: Any, spec: ChainSpec) -> dict[str, Any]:
    """Validate the closed-world release-manifest schema named by ``spec``."""

    payload = _exact_keys(
        manifest,
        {
            "schemaVersion",
            "releaseIndex",
            "previousManifestSha256",
            "state",
            "append",
            "createdAtUtc",
            "producer",
        },
        "manifest",
    )
    if payload["schemaVersion"] != spec.schema_version:
        raise ReleaseChainError(
            f"unsupported manifest schema {payload['schemaVersion']!r}"
        )
    index = _strict_int(payload["releaseIndex"], "releaseIndex")
    if index > MAX_RELEASE_INDEX:
        raise ReleaseChainError(
            f"releaseIndex {index} exceeds the four-digit filename limit"
        )

    previous = payload["previousManifestSha256"]
    if index == 0:
        if previous is not None:
            raise ReleaseChainError("genesis previousManifestSha256 must be null")
    else:
        _sha256(previous, "previousManifestSha256")

    state = _exact_keys(
        payload["state"],
        {
            "path",
            "jsonlSha256",
            "lineCount",
            "immutablePrefixSha256",
        },
        "state",
    )
    if state["path"] != spec.state_path:
        raise ReleaseChainError(f"state.path must be exactly {spec.state_path!r}")
    _sha256(state["jsonlSha256"], "state.jsonlSha256")
    _strict_int(state["lineCount"], "state.lineCount")
    _sha256(
        state["immutablePrefixSha256"],
        "state.immutablePrefixSha256",
    )

    append = payload["append"]
    if index == 0:
        if append is not None:
            raise ReleaseChainError("genesis append must be null")
    else:
        append_block = _exact_keys(
            append,
            {
                "previousLineCount",
                "appendedRowCount",
                "appendedBytesSha256",
            },
            "append",
        )
        _strict_int(
            append_block["previousLineCount"],
            "append.previousLineCount",
        )
        _strict_int(
            append_block["appendedRowCount"],
            "append.appendedRowCount",
            minimum=1,
        )
        _sha256(
            append_block["appendedBytesSha256"],
            "append.appendedBytesSha256",
        )

    parse_created_at(payload["createdAtUtc"])
    producer = _exact_keys(payload["producer"], {"repo", "branch"}, "producer")
    _strict_string(producer["repo"], "producer.repo")
    _strict_string(producer["branch"], "producer.branch")
    return payload


def load_manifest(
    path: pathlib.Path, spec: ChainSpec
) -> tuple[dict[str, Any], bytes, str]:
    if path.is_symlink() or not path.is_file():
        raise ReleaseChainError(f"manifest is not a regular file: {path}")
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseChainError(f"manifest is not UTF-8: {path}") from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_fail_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise ReleaseChainError(f"manifest is not valid JSON: {path}: {exc}") from exc
    payload = validate_manifest_schema(parsed, spec)
    expected = canonical_bytes(payload) + b"\n"
    if raw != expected:
        raise ReleaseChainError(
            f"manifest bytes are not canonical JSON plus one newline: {path}"
        )
    return payload, raw, sha256_bytes(raw)


def manifest_filename(index: int, raw: bytes) -> str:
    _strict_int(index, "releaseIndex")
    if index > MAX_RELEASE_INDEX:
        raise ReleaseChainError(
            f"releaseIndex {index} exceeds the four-digit filename limit"
        )
    return f"{index:04d}-{sha256_bytes(raw)[:16]}.json"


def receipt_paths_for_manifest(
    path: pathlib.Path, spec: ChainSpec
) -> dict[str, pathlib.Path]:
    stem = path.stem
    return {tsa: path.with_name(f"{stem}.{tsa}.tsr") for tsa in spec.anchors}


def producer_signature_path_for_manifest(path: pathlib.Path) -> pathlib.Path:
    return path.with_name(f"{path.stem}.producer.sig")


def _enumerate_manifest_files(
    root: pathlib.Path, spec: ChainSpec
) -> list[tuple[pathlib.Path, dict[str, pathlib.Path], pathlib.Path]]:
    directory = root / spec.manifest_relative
    if not directory.exists():
        return []
    if directory.is_symlink() or not directory.is_dir():
        raise ReleaseChainError(
            f"release manifest path is not a regular directory: {directory}"
        )

    receipt_re = _receipt_re(spec)
    manifests: dict[str, pathlib.Path] = {}
    receipts: dict[str, dict[str, pathlib.Path]] = {}
    producer_signatures: dict[str, pathlib.Path] = {}
    for entry in directory.iterdir():
        if entry.is_symlink() or not entry.is_file():
            raise ReleaseChainError(
                f"release manifest directory contains a non-regular entry: {entry}"
            )
        manifest_match = MANIFEST_RE.fullmatch(entry.name)
        if manifest_match is not None:
            manifests[entry.stem] = entry
            continue
        receipt_match = receipt_re.fullmatch(entry.name)
        if receipt_match is not None:
            stem = receipt_match.group("stem")
            tsa = receipt_match.group("tsa")
            receipts.setdefault(stem, {})[tsa] = entry
            continue
        signature_match = PRODUCER_SIGNATURE_RE.fullmatch(entry.name)
        if signature_match is not None:
            producer_signatures[signature_match.group("stem")] = entry
            continue
        raise ReleaseChainError(
            f"unknown file in closed release manifest directory: {entry.name}"
        )

    orphan_receipts = sorted(set(receipts) - set(manifests))
    if orphan_receipts:
        raise ReleaseChainError(
            f"orphan release receipts for manifest stems: {orphan_receipts}"
        )
    orphan_signatures = sorted(set(producer_signatures) - set(manifests))
    if orphan_signatures:
        raise ReleaseChainError(
            "orphan producer signatures for manifest stems: "
            f"{orphan_signatures}"
        )
    result: list[
        tuple[pathlib.Path, dict[str, pathlib.Path], pathlib.Path]
    ] = []
    seen_indices: dict[int, str] = {}
    for stem, path in manifests.items():
        match = MANIFEST_RE.fullmatch(path.name)
        assert match is not None
        index = int(match.group("index"))
        if index in seen_indices:
            raise ReleaseChainError(
                f"duplicate release index {index}: {seen_indices[index]}, {path.name}"
            )
        seen_indices[index] = path.name
        actual_receipts = receipts.get(stem, {})
        if set(actual_receipts) != set(spec.anchors):
            raise ReleaseChainError(
                f"manifest {path.name} must have exactly "
                f"{' and '.join(spec.anchors)} "
                f"receipts; found={sorted(actual_receipts)}"
            )
        producer_signature = producer_signatures.get(stem)
        if producer_signature is None:
            raise ReleaseChainError(
                f"manifest {path.name} is missing its producer signature "
                f"{stem}.producer.sig"
            )
        result.append((path, actual_receipts, producer_signature))
    return sorted(
        result,
        key=lambda item: int(MANIFEST_RE.fullmatch(item[0].name).group("index")),
    )


def _command_error(completed: subprocess.CompletedProcess[str]) -> str:
    details = (completed.stderr or completed.stdout).strip()
    return details[-1000:] if details else "no OpenSSL diagnostic"


def _parse_receipt_text(output: str, receipt: pathlib.Path) -> tuple[datetime, str]:
    status_lines = [
        line.strip() for line in output.splitlines() if line.startswith("Status:")
    ]
    if status_lines != ["Status: Granted."]:
        raise ReleaseChainError(
            f"RFC 3161 receipt is not granted for {receipt}: {status_lines}"
        )
    hash_lines = [
        line.split(":", 1)[1].strip()
        for line in output.splitlines()
        if line.startswith("Hash Algorithm:")
    ]
    if hash_lines != ["sha256"]:
        raise ReleaseChainError(
            f"RFC 3161 receipt does not use SHA-256 for {receipt}: {hash_lines}"
        )
    policy_lines = [
        line.split(":", 1)[1].strip()
        for line in output.splitlines()
        if line.startswith("Policy OID:")
    ]
    if len(policy_lines) != 1:
        raise ReleaseChainError(
            f"RFC 3161 receipt has no unique policy OID for {receipt}"
        )
    time_lines = [
        line.split(":", 1)[1].strip()
        for line in output.splitlines()
        if line.startswith("Time stamp:")
    ]
    if len(time_lines) != 1:
        raise ReleaseChainError(f"RFC 3161 receipt has no unique genTime for {receipt}")
    match = TIME_STAMP_RE.fullmatch(time_lines[0])
    if match is None:
        raise ReleaseChainError(
            f"unsupported RFC 3161 genTime for {receipt}: {time_lines[0]!r}"
        )
    timestamp = (
        f"{match.group('month')} {match.group('day')} "
        f"{match.group('hour')}:{match.group('minute')}:"
        f"{match.group('second')} {match.group('year')} GMT"
    )
    try:
        parsed = datetime.strptime(timestamp, "%b %d %H:%M:%S %Y GMT").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ReleaseChainError(
            f"invalid RFC 3161 genTime for {receipt}: {timestamp!r}"
        ) from exc
    fraction = match.group("fraction")
    if fraction:
        parsed = parsed.replace(microsecond=int((fraction[1:] + "000000")[:6]))
    return parsed, policy_lines[0]


def _openssl_binary(
    arguments: list[str],
    *,
    environment: dict[str, str],
    label: str,
) -> bytes:
    try:
        completed = subprocess.run(
            ["openssl", *arguments],
            check=False,
            capture_output=True,
            env=environment,
        )
    except FileNotFoundError as exc:
        raise ReleaseChainError(
            "openssl is required for RFC 3161 verification"
        ) from exc
    if completed.returncode != 0:
        diagnostic = (completed.stderr or completed.stdout).decode(
            "utf-8", errors="replace"
        )
        raise ReleaseChainError(
            f"OpenSSL {label} failed (exit {completed.returncode}): "
            f"{diagnostic.strip()[-1000:]}"
        )
    return completed.stdout


def _producer_openssl_binary(
    arguments: list[str],
    *,
    environment: dict[str, str],
    label: str,
) -> bytes:
    try:
        return _sign._producer_openssl_binary(
            arguments,
            environment=environment,
            label=label,
        )
    except SignError as exc:
        raise ReleaseChainError(str(exc)) from exc


def _verify_producer_signature_with_openssl(
    manifest: bytes,
    signature: bytes,
    public_key_pem: bytes,
    *,
    spec: ChainSpec,
    enforce_production_pin: bool,
    label: str,
) -> None:
    try:
        _sign._verify_producer_signature_with_openssl(
            manifest,
            signature,
            public_key_pem,
            public_key_filename=spec.producer_public_key_filename,
            temporary_public_key_filename=spec.producer_public_key_filename,
            spki_sha256=(
                spec.producer_spki_sha256 if enforce_production_pin else None
            ),
            label=label,
        )
    except SignError as exc:
        raise ReleaseChainError(str(exc)) from exc


def verify_producer_signature_bytes(
    manifest: bytes,
    signature: bytes,
    *,
    spec: ChainSpec,
    anchor_dir: pathlib.Path,
    enforce_production_pin: bool,
    label: str,
) -> None:
    """Verify one raw Ed25519 signature over exact manifest bytes."""

    key_spec = _sign.ProducerKeySpec(
        public_key_filename=spec.producer_public_key_filename,
        spki_sha256=spec.producer_spki_sha256,
    )
    public_key_path = anchor_dir / key_spec.public_key_filename
    try:
        # Preserve the upstream branch order: bad payload/signature inputs
        # refuse before a missing producer-key path is inspected.
        _sign._validate_signature_inputs(manifest, signature, label)
        public_key_pem = _sign.read_producer_public_key(anchor_dir, key_spec)
        if not CRYPTOGRAPHY_AVAILABLE:
            _sign._verify_producer_signature_with_openssl(
                manifest,
                signature,
                public_key_pem,
                public_key_filename=str(public_key_path),
                temporary_public_key_filename=key_spec.public_key_filename,
                spki_sha256=(
                    key_spec.spki_sha256 if enforce_production_pin else None
                ),
                label=label,
            )
            return
        _sign.verify_signature_bytes(
            manifest,
            signature,
            public_key_pem,
            public_key_filename=str(public_key_path),
            spki_sha256=(key_spec.spki_sha256 if enforce_production_pin else None),
            label=label,
        )
    except SignError as exc:
        raise ReleaseChainError(str(exc)) from exc


def verify_producer_signature(
    manifest: bytes,
    signature_path: pathlib.Path,
    *,
    spec: ChainSpec,
    anchor_dir: pathlib.Path,
    enforce_production_pin: bool,
) -> None:
    if signature_path.is_symlink() or not signature_path.is_file():
        raise ReleaseChainError(
            f"missing or non-regular producer signature: {signature_path}"
        )
    verify_producer_signature_bytes(
        manifest,
        signature_path.read_bytes(),
        spec=spec,
        anchor_dir=anchor_dir,
        enforce_production_pin=enforce_production_pin,
        label=signature_path.name,
    )


def _verify_production_signer(
    receipt: pathlib.Path,
    anchor: pathlib.Path,
    anchor_spec: AnchorSpec,
    gen_time: datetime,
    temporary: pathlib.Path,
    environment: dict[str, str],
) -> None:
    token = temporary / "token.der"
    signer = temporary / "signer.pem"
    content = temporary / "tst-info.der"
    _openssl_binary(
        [
            "ts",
            "-reply",
            "-config",
            "/dev/null",
            "-in",
            str(receipt),
            "-token_out",
            "-out",
            str(token),
        ],
        environment=environment,
        label=f"token extraction for {receipt.name}",
    )
    _openssl_binary(
        [
            "cms",
            "-verify",
            "-inform",
            "DER",
            "-in",
            str(token),
            "-CAfile",
            str(anchor),
            "-no-CApath",
            "-no-CAstore",
            "-purpose",
            "timestampsign",
            "-attime",
            str(int(gen_time.timestamp())),
            "-signer",
            str(signer),
            "-out",
            str(content),
        ],
        environment=environment,
        label=f"signer extraction for {receipt.name}",
    )
    certificate_der = _openssl_binary(
        ["x509", "-in", str(signer), "-outform", "DER"],
        environment=environment,
        label=f"signer certificate decoding for {receipt.name}",
    )
    public_key_pem = _openssl_binary(
        ["x509", "-in", str(signer), "-pubkey", "-noout"],
        environment=environment,
        label=f"signer public-key extraction for {receipt.name}",
    )
    public_key = temporary / "signer-public-key.pem"
    public_key.write_bytes(public_key_pem)
    public_key_der = _openssl_binary(
        ["pkey", "-pubin", "-in", str(public_key), "-outform", "DER"],
        environment=environment,
        label=f"signer SPKI decoding for {receipt.name}",
    )
    certificate_sha256 = sha256_bytes(certificate_der)
    spki_sha256 = sha256_bytes(public_key_der)
    if certificate_sha256 != anchor_spec.signer_certificate_sha256:
        raise ReleaseChainError(
            f"RFC 3161 signer certificate is not pinned for {receipt.name}: "
            f"{certificate_sha256}"
        )
    if spki_sha256 != anchor_spec.signer_spki_sha256:
        raise ReleaseChainError(
            f"RFC 3161 signer SPKI is not pinned for {receipt.name}: {spki_sha256}"
        )


def verify_receipt(
    manifest_digest: str,
    receipt: pathlib.Path,
    tsa: str,
    *,
    spec: ChainSpec,
    anchor_dir: pathlib.Path,
    enforce_production_pins: bool,
    now: datetime | None = None,
) -> datetime:
    """Cryptographically verify one receipt and return its signed genTime."""

    if tsa not in spec.anchors:
        raise ReleaseChainError(f"unknown TSA receipt kind {tsa!r}")
    _sha256(manifest_digest, "manifest digest")
    if receipt.is_symlink() or not receipt.is_file():
        raise ReleaseChainError(f"missing or non-regular RFC 3161 receipt: {receipt}")
    anchor_spec = spec.anchors[tsa]
    anchor = anchor_dir / anchor_spec.filename
    if anchor.is_symlink() or not anchor.is_file():
        raise ReleaseChainError(f"missing or non-regular TSA anchor: {anchor}")
    if enforce_production_pins:
        anchor_digest = sha256_bytes(anchor.read_bytes())
        if anchor_digest != anchor_spec.pem_sha256:
            raise ReleaseChainError(
                f"production TSA anchor bytes are not code-pinned for {tsa}: "
                f"{anchor_digest}"
            )

    with tempfile.TemporaryDirectory(prefix="thesis-release-tsa-") as name:
        temporary = pathlib.Path(name)
        empty_ca_dir = temporary / "empty-ca"
        empty_ca_dir.mkdir()
        environment = _openssl_environment(empty_ca_dir)
        try:
            text_result = subprocess.run(
                [
                    "openssl",
                    "ts",
                    "-reply",
                    "-config",
                    "/dev/null",
                    "-in",
                    str(receipt),
                    "-text",
                ],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )
        except FileNotFoundError as exc:
            raise ReleaseChainError(
                "openssl is required for RFC 3161 verification"
            ) from exc
        if text_result.returncode != 0:
            raise ReleaseChainError(
                f"cannot inspect RFC 3161 receipt {receipt} "
                f"(exit {text_result.returncode}): {_command_error(text_result)}"
            )
        gen_time, policy_oid = _parse_receipt_text(text_result.stdout, receipt)
        if enforce_production_pins and policy_oid != anchor_spec.policy_oid:
            raise ReleaseChainError(
                f"RFC 3161 policy is not pinned for {tsa}: {policy_oid!r}"
            )
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if gen_time > current + timedelta(seconds=MAX_FUTURE_SECONDS):
            raise ReleaseChainError(
                f"RFC 3161 genTime {gen_time.isoformat()} for {receipt.name} "
                f"postdates verifier time {current.isoformat()}"
            )

        verify_result = subprocess.run(
            [
                "openssl",
                "ts",
                "-verify",
                "-config",
                "/dev/null",
                "-digest",
                manifest_digest,
                "-in",
                str(receipt),
                "-CAfile",
                str(anchor),
                "-CApath",
                str(empty_ca_dir),
                "-attime",
                str(int(gen_time.timestamp())),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        if verify_result.returncode != 0:
            raise ReleaseChainError(
                f"RFC 3161 verification failed for {receipt.name} "
                f"(exit {verify_result.returncode}): "
                f"{_command_error(verify_result)}"
            )
        if enforce_production_pins:
            _verify_production_signer(
                receipt,
                anchor,
                anchor_spec,
                gen_time,
                temporary,
                environment,
            )
    return gen_time


def verify_release_receipts(
    manifest: dict[str, Any],
    manifest_digest: str,
    receipt_paths: dict[str, pathlib.Path],
    *,
    spec: ChainSpec,
    anchor_dir: pathlib.Path,
    enforce_production_pins: bool,
    clock_skew_seconds: int,
    previous_times: dict[str, datetime] | None = None,
    now: datetime | None = None,
) -> dict[str, datetime]:
    """Verify both receipts and their chronology for one manifest."""

    if set(receipt_paths) != set(spec.anchors):
        raise ReleaseChainError(
            f"release must have exactly {' and '.join(spec.anchors)} receipt paths"
        )
    receipt_times = {
        tsa: verify_receipt(
            manifest_digest,
            receipt_path,
            tsa,
            spec=spec,
            anchor_dir=anchor_dir,
            enforce_production_pins=enforce_production_pins,
            now=now,
        )
        for tsa, receipt_path in receipt_paths.items()
    }
    created_at = parse_created_at(manifest["createdAtUtc"])
    earliest_allowed = created_at - timedelta(seconds=clock_skew_seconds)
    release_index = manifest["releaseIndex"]
    for tsa, gen_time in receipt_times.items():
        if gen_time < earliest_allowed:
            raise ReleaseChainError(
                f"release {release_index} {tsa} genTime "
                f"{gen_time.isoformat()} impossibly precedes createdAtUtc "
                f"{created_at.isoformat()}"
            )
    if previous_times is not None:
        lower_bound = max(previous_times.values()) - timedelta(
            seconds=clock_skew_seconds
        )
        current_earliest = min(receipt_times.values())
        if current_earliest < lower_bound:
            raise ReleaseChainError(
                f"release {release_index} receipt chronology regresses: "
                f"earliest current genTime {current_earliest.isoformat()} "
                f"precedes latest prior genTime "
                f"{max(previous_times.values()).isoformat()} beyond "
                f"{clock_skew_seconds}s skew"
            )
    return receipt_times


def jsonl_line_offsets(payload: bytes, label: str) -> list[int]:
    """Return exact byte offsets after each non-empty LF-terminated row."""

    try:
        payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseChainError(f"{label} is not UTF-8") from exc
    if not payload.endswith(b"\n"):
        raise ReleaseChainError(
            f"{label} must end with exactly one LF after its final JSONL row"
        )
    rows = payload.split(b"\n")
    if rows[-1] != b"":
        raise AssertionError("split invariant")
    rows = rows[:-1]
    offsets = [0]
    position = 0
    for number, row in enumerate(rows, start=1):
        if not row.strip():
            raise ReleaseChainError(f"{label} row {number} is blank")
        if row.endswith(b"\r"):
            raise ReleaseChainError(f"{label} row {number} uses CRLF, not exact LF")
        position += len(row) + 1
        offsets.append(position)
    return offsets


def _regular_file_bytes(root: pathlib.Path, relative: pathlib.PurePosixPath) -> bytes:
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise ReleaseChainError(
            f"required state file is missing or non-regular: {path}"
        )
    return path.read_bytes()


def _verify_state_history(
    records: list[ReleaseRecord],
    root: pathlib.Path,
    *,
    spec: ChainSpec,
    require_head_current: bool,
) -> None:
    ledger = _regular_file_bytes(root, spec.state_relative)
    prefix = _regular_file_bytes(root, spec.prefix_relative)
    offsets = jsonl_line_offsets(ledger, spec.state_path)
    total_lines = len(offsets) - 1
    prefix_digest = sha256_bytes(prefix)

    previous_line_count: int | None = None
    for record in records:
        state = record.manifest["state"]
        line_count = int(state["lineCount"])
        if line_count > total_lines:
            raise ReleaseChainError(
                f"release {record.release_index} lineCount {line_count} exceeds "
                f"working-tree line count {total_lines}"
            )
        historical_bytes = ledger[: offsets[line_count]]
        historical_digest = sha256_bytes(historical_bytes)
        if historical_digest != state["jsonlSha256"]:
            raise ReleaseChainError(
                f"release {record.release_index} state.jsonlSha256 does not "
                "match the exact historical JSONL prefix"
            )
        if state["immutablePrefixSha256"] != prefix_digest:
            raise ReleaseChainError(
                f"release {record.release_index} immutablePrefixSha256 does "
                "not match ledger/immutable_prefix.json"
            )

        if previous_line_count is not None:
            append = record.manifest["append"]
            assert isinstance(append, dict)
            if line_count <= previous_line_count:
                raise ReleaseChainError(
                    f"release {record.release_index} lineCount must strictly increase"
                )
            if append["previousLineCount"] != previous_line_count:
                raise ReleaseChainError(
                    f"release {record.release_index} append.previousLineCount "
                    "does not match the previous manifest"
                )
            row_delta = line_count - previous_line_count
            if append["appendedRowCount"] != row_delta:
                raise ReleaseChainError(
                    f"release {record.release_index} appendedRowCount "
                    f"{append['appendedRowCount']} does not match line delta "
                    f"{row_delta}"
                )
            suffix = ledger[offsets[previous_line_count] : offsets[line_count]]
            suffix_digest = sha256_bytes(suffix)
            if append["appendedBytesSha256"] != suffix_digest:
                raise ReleaseChainError(
                    f"release {record.release_index} appendedBytesSha256 does "
                    "not match the exact byte suffix"
                )
        previous_line_count = line_count

    if require_head_current:
        head = records[-1]
        if head.manifest["state"]["lineCount"] != total_lines:
            raise ReleaseChainError(
                f"HEAD release lineCount {head.manifest['state']['lineCount']} "
                f"does not match working-tree line count {total_lines}"
            )
        if head.manifest["state"]["jsonlSha256"] != sha256_bytes(ledger):
            raise ReleaseChainError(
                "HEAD release state.jsonlSha256 does not match working-tree bytes"
            )


def verify_release_chain(
    root: pathlib.Path,
    *,
    spec: ChainSpec,
    anchor_dir: pathlib.Path | None = None,
    require_chain: bool = True,
    verify_state: bool = True,
    allow_pending_append: bool = False,
    enforce_production_pins: bool | None = None,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    now: datetime | None = None,
) -> ChainVerification:
    """Verify all manifests, signatures, receipts, links, and state bytes."""

    root = root.resolve()
    default_anchor_dir = root / spec.anchor_relative
    selected_anchors = (anchor_dir or default_anchor_dir).resolve()
    if enforce_production_pins is None:
        enforce_production_pins = selected_anchors == default_anchor_dir
    if type(clock_skew_seconds) is not int or clock_skew_seconds < 0:
        raise ReleaseChainError("clock_skew_seconds must be a non-negative integer")

    enumerated = _enumerate_manifest_files(root, spec)
    if not enumerated:
        if require_chain:
            raise ReleaseChainError("release chain is absent; genesis is required")
        return ChainVerification(())

    records: list[ReleaseRecord] = []
    previous_hash: str | None = None
    previous_times: dict[str, datetime] | None = None
    verification_now = now or datetime.now(timezone.utc)
    for expected_index, (path, receipt_paths, producer_signature_path) in enumerate(
        enumerated
    ):
        manifest, raw, digest = load_manifest(path, spec)
        filename_match = MANIFEST_RE.fullmatch(path.name)
        assert filename_match is not None
        filename_index = int(filename_match.group("index"))
        if filename_index != expected_index:
            raise ReleaseChainError(
                f"release indices are not contiguous from 0: expected "
                f"{expected_index:04d}, found {filename_index:04d}"
            )
        if manifest["releaseIndex"] != expected_index:
            raise ReleaseChainError(
                f"manifest releaseIndex {manifest['releaseIndex']} does not "
                f"match filename index {expected_index}"
            )
        if filename_match.group("digest") != digest[:16]:
            raise ReleaseChainError(
                f"manifest filename hash does not match exact file bytes: {path.name}"
            )
        if manifest["previousManifestSha256"] != previous_hash:
            raise ReleaseChainError(
                f"release {expected_index} previousManifestSha256 does not "
                "match the previous manifest file bytes"
            )
        verify_producer_signature(
            raw,
            producer_signature_path,
            spec=spec,
            anchor_dir=selected_anchors,
            enforce_production_pin=enforce_production_pins,
        )
        if records:
            previous_line_count = records[-1].manifest["state"]["lineCount"]
            line_count = manifest["state"]["lineCount"]
            append = manifest["append"]
            assert isinstance(append, dict)
            if line_count <= previous_line_count:
                raise ReleaseChainError(
                    f"release {expected_index} lineCount must strictly increase"
                )
            if append["previousLineCount"] != previous_line_count:
                raise ReleaseChainError(
                    f"release {expected_index} append.previousLineCount does "
                    "not match the previous manifest"
                )
            row_delta = line_count - previous_line_count
            if append["appendedRowCount"] != row_delta:
                raise ReleaseChainError(
                    f"release {expected_index} appendedRowCount "
                    f"{append['appendedRowCount']} does not match line delta "
                    f"{row_delta}"
                )

        receipt_times = verify_release_receipts(
            manifest,
            digest,
            receipt_paths,
            spec=spec,
            anchor_dir=selected_anchors,
            enforce_production_pins=enforce_production_pins,
            clock_skew_seconds=clock_skew_seconds,
            previous_times=previous_times,
            now=verification_now,
        )

        records.append(
            ReleaseRecord(
                path=path,
                raw=raw,
                sha256=digest,
                manifest=manifest,
                receipt_paths=receipt_paths,
                receipt_times=receipt_times,
                producer_signature_path=producer_signature_path,
            )
        )
        previous_hash = digest
        previous_times = receipt_times

    if type(allow_pending_append) is not bool:
        raise ReleaseChainError("allow_pending_append must be a boolean")
    if allow_pending_append and not verify_state:
        raise ReleaseChainError(
            "allow_pending_append requires historical state verification"
        )
    if verify_state:
        _verify_state_history(
            records,
            root,
            spec=spec,
            require_head_current=not allow_pending_append,
        )
    return ChainVerification(tuple(records))


def _git_run(
    root: pathlib.Path,
    arguments: list[str],
    *,
    text: bool = False,
) -> subprocess.CompletedProcess[Any]:
    try:
        return subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=False,
            capture_output=True,
            text=text,
        )
    except FileNotFoundError as exc:
        raise ReleaseChainError("git is required for --base-ref verification") from exc


def resolve_base_commit(root: pathlib.Path, base_ref: str) -> str:
    completed = _git_run(
        root,
        ["rev-parse", "--verify", "--end-of-options", f"{base_ref}^{{commit}}"],
        text=True,
    )
    if completed.returncode != 0:
        raise ReleaseChainError(
            f"cannot resolve base ref {base_ref!r} to a commit: "
            f"{completed.stderr.strip()}"
        )
    commit = completed.stdout.strip()
    ancestor = _git_run(root, ["merge-base", "--is-ancestor", commit, "HEAD"])
    if ancestor.returncode != 0:
        raise ReleaseChainError(f"base commit {commit} is not an ancestor of HEAD")
    return commit


def git_tree_entries(
    root: pathlib.Path, commit: str, pathspec: str
) -> dict[str, GitEntry]:
    completed = _git_run(
        root,
        ["ls-tree", "-r", "-z", "--full-tree", commit, "--", pathspec],
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ReleaseChainError(
            f"cannot enumerate {pathspec} at base {commit}: {diagnostic}"
        )
    entries: dict[str, GitEntry] = {}
    for record in completed.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ReleaseChainError(
                f"cannot parse git tree entry under {pathspec}"
            ) from exc
        if path in entries:
            raise ReleaseChainError(f"duplicate git tree entry for {path}")
        entries[path] = GitEntry(mode, object_type, object_id, path)
    return entries


def git_blob_bytes(root: pathlib.Path, entry: GitEntry) -> bytes:
    if entry.object_type != "blob":
        raise ReleaseChainError(
            f"base release entry is not a blob: {entry.path} ({entry.object_type})"
        )
    completed = _git_run(root, ["cat-file", "blob", entry.object_id])
    if completed.returncode != 0:
        diagnostic = completed.stderr.decode("utf-8", errors="replace").strip()
        raise ReleaseChainError(f"cannot read base blob for {entry.path}: {diagnostic}")
    return completed.stdout


def git_file_entry(root: pathlib.Path, commit: str, path: str) -> GitEntry:
    entries = git_tree_entries(root, commit, path)
    entry = entries.get(path)
    if entry is None:
        raise ReleaseChainError(f"required file {path} is absent at base {commit}")
    return entry


def _working_release_files(
    root: pathlib.Path, spec: ChainSpec
) -> dict[str, pathlib.Path]:
    release_root = root / spec.release_root_relative
    if not release_root.exists():
        return {}
    if release_root.is_symlink() or not release_root.is_dir():
        raise ReleaseChainError("releases must be a real directory, not a symlink")
    files: dict[str, pathlib.Path] = {}
    for path in release_root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ReleaseChainError(f"release path is a symlink: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ReleaseChainError(f"release path is not regular: {relative}")
        files[relative] = path
    return files


def verify_release_history_immutable(
    root: pathlib.Path, base_ref: str, spec: ChainSpec
) -> tuple[str, set[str], dict[str, GitEntry]]:
    """Compare every base ``releases/`` file byte and mode to the candidate."""

    root = root.resolve()
    commit = resolve_base_commit(root, base_ref)
    base_entries = git_tree_entries(root, commit, str(spec.release_root_relative))
    current_files = _working_release_files(root, spec)
    for relative, entry in base_entries.items():
        if entry.mode not in {"100644", "100755"}:
            raise ReleaseChainError(
                f"base release entry has non-regular git mode {entry.mode}: {relative}"
            )
        current = current_files.get(relative)
        if current is None:
            raise ReleaseChainError(
                f"existing release file was deleted relative to {commit}: {relative}"
            )
        candidate_mode = "100755" if current.stat().st_mode & 0o111 else "100644"
        if candidate_mode != entry.mode:
            raise ReleaseChainError(
                f"existing release file mode changed relative to {commit}: "
                f"{relative} ({entry.mode} -> {candidate_mode})"
            )
        if current.read_bytes() != git_blob_bytes(root, entry):
            raise ReleaseChainError(
                f"existing release file bytes changed relative to {commit}: {relative}"
            )
    return commit, set(current_files) - set(base_entries), base_entries


def materialize_base_tree(
    root: pathlib.Path,
    commit: str,
    destination: pathlib.Path,
    release_entries: dict[str, GitEntry],
    spec: ChainSpec,
) -> None:
    entries = dict(release_entries)
    for relative in (
        spec.state_relative.as_posix(),
        spec.prefix_relative.as_posix(),
    ):
        entries[relative] = git_file_entry(root, commit, relative)
    for relative, entry in entries.items():
        if entry.mode not in {"100644", "100755"}:
            raise ReleaseChainError(
                f"base tree entry has non-regular mode {entry.mode}: {relative}"
            )
        output = destination / pathlib.PurePosixPath(relative)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(git_blob_bytes(root, entry))


def verify_base_release_chain(
    root: pathlib.Path,
    commit: str,
    release_entries: dict[str, GitEntry],
    *,
    spec: ChainSpec,
    anchor_dir: pathlib.Path | None = None,
    enforce_production_pins: bool = True,
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
) -> ChainVerification:
    with tempfile.TemporaryDirectory(prefix="thesis-release-base-") as name:
        base_root = pathlib.Path(name)
        materialize_base_tree(root, commit, base_root, release_entries, spec)
        base_anchor_dir = anchor_dir or (base_root / spec.anchor_relative)
        return verify_release_chain(
            base_root,
            spec=spec,
            anchor_dir=base_anchor_dir,
            require_chain=True,
            verify_state=True,
            enforce_production_pins=enforce_production_pins,
            clock_skew_seconds=clock_skew_seconds,
        )


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
