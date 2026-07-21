"""Ed25519 verification, signing, and consumer-pinned threshold keyrings.

The verification primitives are ported from the witnessed release-chain
verifier and retain its literal producer-oriented refusal messages. Signing
keys are always supplied by the caller; this package neither stores key
material nor reads trust configuration from the environment.

Keyrings follow loud rotation: the keyring is an object committed in consumer
code, and rotation is a reviewed replacement of that object that moves the
retired key into ``legacy_keys``. Legacy keys can vouch only where the caller
explicitly verifies immutable pre-rotation history (``allow_legacy=True``, or
``verify_any_generation`` for envelopes whose key identifier does not name the
signing generation); they are refused loudly for new material, malformed key
material is always fatal, and only a clean signature mismatch under a
validated key falls through to an older generation. There are no time-based
transition windows. Keys outside the committed keyring are refused, and
unknown fingerprints are surfaced verbatim in refusals.
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass

try:
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
        load_pem_private_key,
        load_pem_public_key,
    )
except ImportError:  # Bare pre-sync CI falls back to the OpenSSL 3 CLI below.
    CRYPTOGRAPHY_AVAILABLE = False
else:
    CRYPTOGRAPHY_AVAILABLE = True


PRODUCER_SIGNATURE_BYTES = 64


class SignError(ValueError):
    """A signature, key, fingerprint, or keyring is malformed or untrusted."""


@dataclass(frozen=True)
class ProducerKeySpec:
    public_key_filename: str
    spki_sha256: str


def _openssl_environment(empty_ca_dir: pathlib.Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "LC_ALL": "C",
            "OPENSSL_CONF": "/dev/null",
            "SSL_CERT_DIR": str(empty_ca_dir),
            "SSL_CERT_FILE": "/dev/null",
        }
    )
    return environment


def _producer_openssl_binary(
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
        raise SignError(
            "producer signature verification requires cryptography or OpenSSL 3"
        ) from exc
    if completed.returncode != 0:
        diagnostic = (completed.stderr or completed.stdout).decode(
            "utf-8", errors="replace"
        )
        raise SignError(
            f"OpenSSL producer {label} failed (exit {completed.returncode}): "
            f"{diagnostic.strip()[-1000:]}"
        )
    return completed.stdout


def _validate_signature_inputs(payload: bytes, signature: bytes, label: str) -> None:
    """Retain the upstream verifier's exact input checks and branch order."""

    if type(payload) is not bytes:
        raise SignError("producer-signed manifest payload must be bytes")
    if type(signature) is not bytes or len(signature) != PRODUCER_SIGNATURE_BYTES:
        actual = len(signature) if isinstance(signature, bytes) else "non-bytes"
        raise SignError(
            f"producer signature for {label} must be exactly "
            f"{PRODUCER_SIGNATURE_BYTES} raw bytes; found={actual}"
        )


def _verify_producer_signature_with_openssl(
    payload: bytes,
    signature: bytes,
    public_key_pem: bytes,
    *,
    public_key_filename: str,
    temporary_public_key_filename: str | None = None,
    spki_sha256: str | None,
    label: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="thesis-release-producer-") as name:
        temporary = pathlib.Path(name)
        empty_ca_dir = temporary / "empty-ca"
        empty_ca_dir.mkdir()
        environment = _openssl_environment(empty_ca_dir)
        manifest_path = temporary / "manifest.json"
        signature_path = temporary / "producer.sig"
        # Release-chain diagnostics carry the full anchor path. The upstream
        # temporary file nevertheless uses only the configured filename.
        temporary_key_name = (
            temporary_public_key_filename
            if temporary_public_key_filename is not None
            else pathlib.Path(public_key_filename).name
        )
        public_key_path = temporary / temporary_key_name
        manifest_path.write_bytes(payload)
        signature_path.write_bytes(signature)
        public_key_path.write_bytes(public_key_pem)

        spki_der = _producer_openssl_binary(
            [
                "pkey",
                "-pubin",
                "-in",
                str(public_key_path),
                "-outform",
                "DER",
            ],
            environment=environment,
            label=f"public-key decoding for {label}",
        )
        if spki_sha256 is not None:
            computed_spki_sha256 = hashlib.sha256(spki_der).hexdigest()
            if computed_spki_sha256 != spki_sha256:
                raise SignError(
                    "producer public-key SPKI is not code-pinned: "
                    f"{computed_spki_sha256}"
                )

        try:
            _producer_openssl_binary(
                [
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(public_key_path),
                    "-rawin",
                    "-in",
                    str(manifest_path),
                    "-sigfile",
                    str(signature_path),
                ],
                environment=environment,
                label=f"Ed25519 signature verification for {label}",
            )
        except SignError as exc:
            raise SignError(
                f"producer Ed25519 signature verification failed for {label}"
            ) from exc


def read_producer_public_key(
    anchor_dir: pathlib.Path, spec: ProducerKeySpec
) -> bytes:
    """Read the configured producer key after the upstream regular-file checks."""

    public_key_path = anchor_dir / spec.public_key_filename
    if public_key_path.is_symlink() or not public_key_path.is_file():
        raise SignError(
            f"missing or non-regular producer public key: {public_key_path}"
        )
    return public_key_path.read_bytes()


def verify_signature_bytes(
    payload: bytes,
    signature: bytes,
    public_key_pem: bytes,
    *,
    public_key_filename: str,
    spki_sha256: str | None,
    label: str,
) -> None:
    """Verify one raw Ed25519 signature over exact caller-supplied bytes."""

    _validate_signature_inputs(payload, signature, label)
    if type(public_key_pem) is not bytes:
        raise SignError(
            f"cannot decode producer Ed25519 public key: {public_key_filename}"
        )

    if not CRYPTOGRAPHY_AVAILABLE:
        _verify_producer_signature_with_openssl(
            payload,
            signature,
            public_key_pem,
            public_key_filename=public_key_filename,
            spki_sha256=spki_sha256,
            label=label,
        )
        return

    try:
        public_key = load_pem_public_key(public_key_pem)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise SignError(
            f"cannot decode producer Ed25519 public key: {public_key_filename}"
        ) from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise SignError(
            f"producer public key is not Ed25519: {public_key_filename}"
        )
    spki_der = public_key.public_bytes(
        Encoding.DER,
        PublicFormat.SubjectPublicKeyInfo,
    )
    if spki_sha256 is not None:
        computed_spki_sha256 = hashlib.sha256(spki_der).hexdigest()
        if computed_spki_sha256 != spki_sha256:
            raise SignError(
                "producer public-key SPKI is not code-pinned: "
                f"{computed_spki_sha256}"
            )
    try:
        public_key.verify(signature, payload)
    except InvalidSignature as exc:
        raise SignError(
            f"producer Ed25519 signature verification failed for {label}"
        ) from exc


def sign_payload(
    private_key_pem: bytes,
    payload: bytes,
    *,
    domain: bytes,
) -> bytes:
    """Return a raw Ed25519 signature over ``domain + payload``.

    ``domain`` is required so every signing call names its role explicitly;
    a consumer that signs exact bytes with no domain states ``domain=b""``
    deliberately rather than by omission.
    """

    if type(private_key_pem) is not bytes:
        raise SignError("Ed25519 private key PEM must be bytes")
    if type(payload) is not bytes:
        raise SignError("signature payload must be bytes")
    if type(domain) is not bytes:
        raise SignError("signature domain must be bytes")
    if not CRYPTOGRAPHY_AVAILABLE:
        raise SignError("Ed25519 signing requires cryptography")
    try:
        private_key = load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise SignError("cannot decode Ed25519 private key") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise SignError("private key is not Ed25519")
    return private_key.sign(domain + payload)


def generate_signing_keypair() -> tuple[bytes, bytes]:
    """Ceremony/test helper; the package never stores or reads key material."""

    if not CRYPTOGRAPHY_AVAILABLE:
        raise SignError("Ed25519 key generation requires cryptography")
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        Encoding.PEM,
        PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _load_ed25519_public_key(public_key: bytes) -> Ed25519PublicKey:
    if type(public_key) is not bytes:
        raise SignError("Ed25519 public key must be bytes")
    if not CRYPTOGRAPHY_AVAILABLE:
        raise SignError("Ed25519 public-key normalization requires cryptography")
    if len(public_key) == 32:
        try:
            return Ed25519PublicKey.from_public_bytes(public_key)
        except ValueError as exc:
            raise SignError("cannot decode Ed25519 public key") from exc
    try:
        loaded = load_pem_public_key(public_key)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise SignError("cannot decode Ed25519 public key") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise SignError("public key is not Ed25519")
    return loaded


def spki_sha256(public_key: bytes) -> str:
    """Return SHA-256 of a PEM or raw Ed25519 key's DER SPKI encoding."""

    normalized = _load_ed25519_public_key(public_key)
    spki_der = normalized.public_bytes(
        Encoding.DER,
        PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).hexdigest()


def raw_public_key_sha256(public_key: bytes) -> str:
    """Return SHA-256 of a PEM or raw Ed25519 key's 32-byte encoding."""

    normalized = _load_ed25519_public_key(public_key)
    raw = normalized.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class KeySpec:
    key_id: str
    fingerprint: str
    scheme: str

    def __post_init__(self) -> None:
        if self.scheme not in ("spki-sha256", "raw-sha256"):
            raise SignError(f"unsupported key fingerprint scheme: {self.scheme!r}")


@dataclass(frozen=True)
class KeyringSpec:
    """Current trust generation plus retired verification-only generations.

    ``keys`` are the current generation: they sign and verify new material,
    and ``threshold`` is defined over them. ``legacy_keys`` are retired keys
    kept only so immutable pre-rotation history stays verifiable; they never
    satisfy anything unless the caller explicitly allows them.
    """

    keys: tuple[KeySpec, ...]
    threshold: int
    legacy_keys: tuple[KeySpec, ...] = ()

    def __post_init__(self) -> None:
        if not self.keys:
            raise SignError("keyring must contain at least one key")
        if self.threshold < 1:
            raise SignError(
                f"keyring threshold must be at least 1; found={self.threshold}"
            )
        if self.threshold > len(self.keys):
            raise SignError(
                f"keyring threshold {self.threshold} exceeds key count "
                f"{len(self.keys)}"
            )
        seen_key_ids: set[str] = set()
        seen_fingerprints: set[str] = set()
        for key in (*self.keys, *self.legacy_keys):
            if key.key_id in seen_key_ids:
                raise SignError(f"duplicate key_id in keyring: {key.key_id!r}")
            if key.fingerprint in seen_fingerprints:
                raise SignError(
                    f"duplicate fingerprint in keyring: {key.fingerprint!r}"
                )
            seen_key_ids.add(key.key_id)
            seen_fingerprints.add(key.fingerprint)


@dataclass(frozen=True)
class ThresholdVerification:
    satisfied: tuple[str, ...]
    failed: tuple[str, ...]
    absent: tuple[str, ...]
    legacy_satisfied: tuple[str, ...] = ()


def _key_fingerprint(public_key: Ed25519PublicKey, scheme: str) -> str:
    if scheme == "spki-sha256":
        encoded = public_key.public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        )
    else:
        encoded = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return hashlib.sha256(encoded).hexdigest()


def _normalize_pinned_public_keys(
    public_keys: Mapping[str, bytes],
    specs: Mapping[str, KeySpec],
) -> dict[str, Ed25519PublicKey]:
    """Fingerprint-check every supplied key and refuse duplicate material.

    Malformed or mispinned key material is always fatal here — it is never
    skipped in favor of a key that happens to verify (the failure mode a
    production rotation review caught: a bad key silently ignored because a
    sibling key vouched).
    """

    normalized_public_keys: dict[str, Ed25519PublicKey] = {}
    seen_material: dict[bytes, str] = {}
    for key_id in sorted(set(public_keys)):
        key_spec = specs[key_id]
        normalized = _load_ed25519_public_key(public_keys[key_id])
        computed = _key_fingerprint(normalized, key_spec.scheme)
        if computed != key_spec.fingerprint:
            raise SignError(
                f"public key fingerprint mismatch for {key_id!r} "
                f"({key_spec.scheme}): expected={key_spec.fingerprint}, "
                f"computed={computed}"
            )
        raw = normalized.public_bytes(Encoding.Raw, PublicFormat.Raw)
        if raw in seen_material:
            first, second = sorted((seen_material[raw], key_id))
            raise SignError(
                f"duplicate key material presented for {first!r} and {second!r}"
            )
        seen_material[raw] = key_id
        normalized_public_keys[key_id] = normalized
    return normalized_public_keys


def verify_threshold(
    payload: bytes,
    signatures: Mapping[str, bytes],
    public_keys: Mapping[str, bytes],
    keyring: KeyringSpec,
    *,
    domain: bytes,
    label: str,
    allow_legacy: bool,
) -> ThresholdVerification:
    """Verify a closed-world threshold over ``domain + payload``.

    ``allow_legacy`` is required at every call site: verification of new
    material says ``False`` and refuses any keyring-legacy key loudly;
    verification of immutable pre-rotation history says ``True`` and legacy
    keys count toward the threshold (reported in ``legacy_satisfied``).
    """

    if type(payload) is not bytes:
        raise SignError("signature payload must be bytes")
    if type(domain) is not bytes:
        raise SignError("signature domain must be bytes")
    if type(allow_legacy) is not bool:
        raise SignError("allow_legacy must be a bool")

    legacy_ids = {key.key_id for key in keyring.legacy_keys}
    specs = {
        key.key_id: key for key in (*keyring.keys, *keyring.legacy_keys)
    }
    unknown_key_ids = sorted((set(signatures) | set(public_keys)) - set(specs))
    if unknown_key_ids:
        raise SignError(f"unknown key_id: {unknown_key_ids[0]!r}")
    if not allow_legacy:
        presented_legacy = sorted(
            (set(signatures) | set(public_keys)) & legacy_ids
        )
        if presented_legacy:
            raise SignError(
                f"legacy key_id refused for new material: {presented_legacy[0]!r}"
            )

    normalized_public_keys = _normalize_pinned_public_keys(public_keys, specs)

    eligible = (
        (*keyring.keys, *keyring.legacy_keys) if allow_legacy else keyring.keys
    )
    message = domain + payload
    satisfied: list[str] = []
    failed: list[str] = []
    absent: list[str] = []
    legacy_satisfied: list[str] = []
    for key_spec in eligible:
        key_id = key_spec.key_id
        if key_id not in signatures or key_id not in normalized_public_keys:
            absent.append(key_id)
            continue
        signature = signatures[key_id]
        if type(signature) is not bytes or len(signature) != PRODUCER_SIGNATURE_BYTES:
            failed.append(key_id)
            continue
        try:
            normalized_public_keys[key_id].verify(signature, message)
        except InvalidSignature:
            failed.append(key_id)
        else:
            satisfied.append(key_id)
            if key_id in legacy_ids:
                legacy_satisfied.append(key_id)

    verification = ThresholdVerification(
        satisfied=tuple(sorted(satisfied)),
        failed=tuple(sorted(failed)),
        absent=tuple(sorted(absent)),
        legacy_satisfied=tuple(sorted(legacy_satisfied)),
    )
    if len(verification.satisfied) < keyring.threshold:
        raise SignError(
            f"signature threshold not satisfied for {label}: "
            f"threshold={keyring.threshold}; "
            f"satisfied={verification.satisfied}; "
            f"failed={verification.failed}; absent={verification.absent}"
        )
    return verification


def verify_any_generation(
    payload: bytes,
    signature: bytes,
    public_keys: Mapping[str, bytes],
    keyring: KeyringSpec,
    *,
    domain: bytes,
    label: str,
) -> str:
    """Verify one signature against the current generation, then each legacy.

    For single-signature envelopes whose key identifier does not name the
    signing generation (the artifact is immutable history; the keyring has
    rotated under it). Current keys are tried first in declaration order,
    then legacy keys in declaration order. Key material is required for every
    keyring key and is fingerprint-checked up front; malformed input of any
    kind is immediately fatal, and only a clean signature mismatch under a
    validated key falls through to the next generation. Returns the key_id
    that vouched, so consumers log which generation verified the artifact.
    """

    if keyring.threshold != 1:
        raise SignError(
            "verify_any_generation requires a threshold-1 keyring; "
            f"found={keyring.threshold}"
        )
    if type(payload) is not bytes:
        raise SignError("signature payload must be bytes")
    if type(domain) is not bytes:
        raise SignError("signature domain must be bytes")
    if type(signature) is not bytes or len(signature) != PRODUCER_SIGNATURE_BYTES:
        actual = len(signature) if isinstance(signature, bytes) else "non-bytes"
        raise SignError(
            f"signature for {label} must be exactly "
            f"{PRODUCER_SIGNATURE_BYTES} raw bytes; found={actual}"
        )

    ordered = (*keyring.keys, *keyring.legacy_keys)
    specs = {key.key_id: key for key in ordered}
    unknown_key_ids = sorted(set(public_keys) - set(specs))
    if unknown_key_ids:
        raise SignError(f"unknown key_id: {unknown_key_ids[0]!r}")
    missing = sorted(set(specs) - set(public_keys))
    if missing:
        raise SignError(
            "verify_any_generation requires key material for every keyring "
            f"key; missing={missing}"
        )

    normalized_public_keys = _normalize_pinned_public_keys(public_keys, specs)

    message = domain + payload
    for key_spec in ordered:
        try:
            normalized_public_keys[key_spec.key_id].verify(signature, message)
        except InvalidSignature:
            continue
        return key_spec.key_id
    raise SignError(
        f"signature does not verify under any keyring generation for {label}: "
        f"tried={[key.key_id for key in ordered]}"
    )
