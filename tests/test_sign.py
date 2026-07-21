"""Tests for the standalone signing layers.

Layer 1 is differential-gated through the release-chain harness. Layers 2–3
are additive capability with no upstream CLI oracle, so they are covered by
unit, property, and round-trip tests only.
"""

from __future__ import annotations

import hashlib
import inspect
import itertools
import pathlib
import shutil
import subprocess
from collections.abc import Callable, Iterator, Mapping
from dataclasses import FrozenInstanceError

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import receipt.sign as sign_module
from receipt.sign import (
    KeyringSpec,
    KeySpec,
    ProducerKeySpec,
    SignError,
    ThresholdVerification,
    generate_signing_keypair,
    raw_public_key_sha256,
    read_producer_public_key,
    sign_payload,
    spki_sha256,
    verify_any_generation,
    verify_signature_bytes,
    verify_threshold,
)


def _spki_pin(public_key_pem: bytes) -> str:
    public_key = serialization.load_pem_public_key(public_key_pem)
    assert isinstance(public_key, Ed25519PublicKey)
    spki_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki_der).hexdigest()


def _verify(
    payload: bytes,
    signature: bytes,
    public_key_pem: bytes,
    *,
    pin: str | None,
    label: str = "artifact.sig",
) -> None:
    verify_signature_bytes(
        payload,
        signature,
        public_key_pem,
        public_key_filename="producer-ed25519.pub",
        spki_sha256=pin,
        label=label,
    )


def _outcome(callable_: Callable[[], None]) -> tuple[str, str]:
    try:
        callable_()
    except SignError as exc:
        return "refused", str(exc)
    return "accepted", ""


def test_sign_round_trip_pinned_and_explicitly_unpinned() -> None:
    private_key_pem, public_key_pem = generate_signing_keypair()
    payload = b"exact payload bytes\n"
    signature = sign_payload(private_key_pem, payload, domain=b"")

    assert type(signature) is bytes
    assert len(signature) == 64
    _verify(payload, signature, public_key_pem, pin=_spki_pin(public_key_pem))
    _verify(payload, signature, public_key_pem, pin=None)

    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
    )
    public_key = serialization.load_pem_public_key(public_key_pem)
    assert isinstance(private_key, Ed25519PrivateKey)
    assert isinstance(public_key, Ed25519PublicKey)
    assert private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    ) == public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def test_sign_payload_domain_is_part_of_the_verified_message() -> None:
    private_key_pem, public_key_pem = generate_signing_keypair()
    payload = b"payload"
    domain = b"consumer/v1\0"
    signature = sign_payload(private_key_pem, payload, domain=domain)

    _verify(domain + payload, signature, public_key_pem, pin=None)
    with pytest.raises(SignError) as caught:
        _verify(payload, signature, public_key_pem, pin=None)
    assert str(caught.value) == (
        "producer Ed25519 signature verification failed for artifact.sig"
    )


def test_verify_refusal_messages_retain_ported_shapes() -> None:
    private_key_pem, public_key_pem = generate_signing_keypair()
    _, wrong_public_key_pem = generate_signing_keypair()
    payload = b"payload"
    signature = sign_payload(private_key_pem, payload, domain=b"")

    with pytest.raises(SignError) as caught:
        _verify(payload, signature, wrong_public_key_pem, pin=None)
    assert str(caught.value) == (
        "producer Ed25519 signature verification failed for artifact.sig"
    )

    with pytest.raises(SignError) as caught:
        _verify(b"wrong payload", signature, public_key_pem, pin=None)
    assert str(caught.value) == (
        "producer Ed25519 signature verification failed for artifact.sig"
    )

    with pytest.raises(SignError) as caught:
        _verify(payload, signature[:-1], public_key_pem, pin=None)
    assert str(caught.value) == (
        "producer signature for artifact.sig must be exactly 64 raw bytes; "
        "found=63"
    )

    with pytest.raises(SignError) as caught:
        verify_signature_bytes(
            bytearray(payload),  # type: ignore[arg-type]
            signature,
            public_key_pem,
            public_key_filename="producer-ed25519.pub",
            spki_sha256=None,
            label="artifact.sig",
        )
    assert str(caught.value) == "producer-signed manifest payload must be bytes"

    with pytest.raises(SignError) as caught:
        verify_signature_bytes(
            payload,
            bytearray(signature),  # type: ignore[arg-type]
            public_key_pem,
            public_key_filename="producer-ed25519.pub",
            spki_sha256=None,
            label="artifact.sig",
        )
    assert str(caught.value) == (
        "producer signature for artifact.sig must be exactly 64 raw bytes; "
        "found=non-bytes"
    )

    with pytest.raises(SignError) as caught:
        verify_signature_bytes(
            payload,
            signature,
            "not-bytes",  # type: ignore[arg-type]
            public_key_filename="producer-ed25519.pub",
            spki_sha256=None,
            label="artifact.sig",
        )
    assert str(caught.value) == (
        "cannot decode producer Ed25519 public key: producer-ed25519.pub"
    )


def test_verify_pin_decode_and_key_type_refusals() -> None:
    private_key_pem, public_key_pem = generate_signing_keypair()
    _, wrong_public_key_pem = generate_signing_keypair()
    payload = b"payload"
    signature = sign_payload(private_key_pem, payload, domain=b"")

    computed_wrong_pin = _spki_pin(wrong_public_key_pem)
    with pytest.raises(SignError) as caught:
        _verify(
            payload,
            signature,
            wrong_public_key_pem,
            pin=_spki_pin(public_key_pem),
        )
    assert str(caught.value) == (
        f"producer public-key SPKI is not code-pinned: {computed_wrong_pin}"
    )

    with pytest.raises(SignError) as caught:
        _verify(payload, signature, b"not a PEM key", pin=None)
    assert str(caught.value) == (
        "cannot decode producer Ed25519 public key: producer-ed25519.pub"
    )

    ec_public_pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(SignError) as caught:
        _verify(payload, signature, ec_public_pem, pin=None)
    assert str(caught.value) == (
        "producer public key is not Ed25519: producer-ed25519.pub"
    )


def test_unpinned_mode_is_required_and_has_no_default() -> None:
    parameter = inspect.signature(verify_signature_bytes).parameters["spki_sha256"]
    assert parameter.default is inspect.Parameter.empty

    private_key_pem, public_key_pem = generate_signing_keypair()
    signature = sign_payload(private_key_pem, b"payload", domain=b"")
    with pytest.raises(TypeError, match="spki_sha256"):
        verify_signature_bytes(  # type: ignore[call-arg]
            b"payload",
            signature,
            public_key_pem,
            public_key_filename="producer-ed25519.pub",
            label="artifact.sig",
        )


def test_read_producer_public_key_regular_file_and_refusals(
    tmp_path: pathlib.Path,
) -> None:
    spec = ProducerKeySpec("producer-ed25519.pub", "0" * 64)
    path = tmp_path / spec.public_key_filename

    with pytest.raises(SignError) as caught:
        read_producer_public_key(tmp_path, spec)
    assert str(caught.value) == (
        f"missing or non-regular producer public key: {path}"
    )

    path.write_bytes(b"key bytes")
    assert read_producer_public_key(tmp_path, spec) == b"key bytes"

    path.unlink()
    target = tmp_path / "target.pub"
    target.write_bytes(b"key bytes")
    path.symlink_to(target)
    with pytest.raises(SignError) as caught:
        read_producer_public_key(tmp_path, spec)
    assert str(caught.value) == (
        f"missing or non-regular producer public key: {path}"
    )


def test_sign_payload_input_and_key_refusals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key_pem, _ = generate_signing_keypair()

    with pytest.raises(SignError, match="^Ed25519 private key PEM must be bytes$"):
        sign_payload(bytearray(private_key_pem), b"payload", domain=b"")  # type: ignore[arg-type]
    with pytest.raises(SignError, match="^signature payload must be bytes$"):
        sign_payload(private_key_pem, bytearray(b"payload"), domain=b"")  # type: ignore[arg-type]
    with pytest.raises(SignError, match="^signature domain must be bytes$"):
        sign_payload(private_key_pem, b"payload", domain=bytearray())  # type: ignore[arg-type]
    with pytest.raises(SignError, match="^cannot decode Ed25519 private key$"):
        sign_payload(b"not a private key", b"payload", domain=b"")

    ec_private_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with pytest.raises(SignError, match="^private key is not Ed25519$"):
        sign_payload(ec_private_pem, b"payload", domain=b"")

    monkeypatch.setattr(sign_module, "CRYPTOGRAPHY_AVAILABLE", False)
    with pytest.raises(SignError, match="^Ed25519 signing requires cryptography$"):
        sign_payload(private_key_pem, b"payload", domain=b"")
    with pytest.raises(
        SignError,
        match="^Ed25519 key generation requires cryptography$",
    ):
        generate_signing_keypair()


def test_forced_openssl_path_matches_stable_crypto_outcomes(
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")

    private_key_pem, public_key_pem = generate_signing_keypair()
    _, wrong_public_key_pem = generate_signing_keypair()
    payload = b"payload"
    signature = sign_payload(private_key_pem, payload, domain=b"")
    pin = _spki_pin(public_key_pem)

    cases = {
        "pinned": lambda: _verify(payload, signature, public_key_pem, pin=pin),
        "unpinned": lambda: _verify(payload, signature, public_key_pem, pin=None),
        "wrong_payload": lambda: _verify(
            b"wrong", signature, public_key_pem, pin=None
        ),
        "wrong_key": lambda: _verify(
            payload, signature, wrong_public_key_pem, pin=None
        ),
        "truncated": lambda: _verify(
            payload, signature[:-1], public_key_pem, pin=None
        ),
        "nonbytes_payload": lambda: verify_signature_bytes(
            bytearray(payload),  # type: ignore[arg-type]
            signature,
            public_key_pem,
            public_key_filename="producer-ed25519.pub",
            spki_sha256=None,
            label="artifact.sig",
        ),
        "nonbytes_signature": lambda: verify_signature_bytes(
            payload,
            bytearray(signature),  # type: ignore[arg-type]
            public_key_pem,
            public_key_filename="producer-ed25519.pub",
            spki_sha256=None,
            label="artifact.sig",
        ),
        "pin_mismatch": lambda: _verify(
            payload,
            signature,
            wrong_public_key_pem,
            pin=pin,
        ),
    }
    cryptography_outcomes = {name: _outcome(call) for name, call in cases.items()}

    monkeypatch.setattr(sign_module, "CRYPTOGRAPHY_AVAILABLE", False)
    openssl_outcomes = {name: _outcome(call) for name, call in cases.items()}
    assert openssl_outcomes == cryptography_outcomes

    with pytest.raises(SignError) as caught:
        _verify(payload, signature, b"not a PEM key", pin=None)
    assert str(caught.value).startswith(
        "OpenSSL producer public-key decoding for artifact.sig failed (exit "
    )
    captured = capfd.readouterr()
    assert (captured.out, captured.err) == ("", "")


def test_sign_payload_cross_checks_with_openssl_cli(
    tmp_path: pathlib.Path,
) -> None:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is not installed")

    private_key_pem, public_key_pem = generate_signing_keypair()
    payload = b"independent OpenSSL cross-check\n"
    signature = sign_payload(private_key_pem, payload, domain=b"")
    public_key_path = tmp_path / "public.pem"
    payload_path = tmp_path / "payload.bin"
    signature_path = tmp_path / "signature.bin"
    public_key_path.write_bytes(public_key_pem)
    payload_path.write_bytes(payload)
    signature_path.write_bytes(signature)

    completed = subprocess.run(
        [
            openssl,
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(public_key_path),
            "-rawin",
            "-in",
            str(payload_path),
            "-sigfile",
            str(signature_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        diagnostic = (completed.stderr or completed.stdout).strip()
        if (
            "not supported" in diagnostic.lower()
            or "unsupported" in diagnostic.lower()
        ):
            pytest.skip(f"openssl lacks Ed25519 pkeyutl support: {diagnostic}")
        pytest.fail(f"openssl rejected the generated signature: {diagnostic}")


def _raw_public_key(public_key_pem: bytes) -> bytes:
    public_key = serialization.load_pem_public_key(public_key_pem)
    assert isinstance(public_key, Ed25519PublicKey)
    return public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _three_keyring() -> tuple[
    dict[str, tuple[bytes, bytes]],
    KeyringSpec,
]:
    material = {
        key_id: generate_signing_keypair()
        for key_id in ("key-a", "key-b", "key-c")
    }
    # Deliberately non-lexical: result tuples must still be sorted.
    keyring = KeyringSpec(
        keys=tuple(
            KeySpec(key_id, spki_sha256(material[key_id][1]), "spki-sha256")
            for key_id in ("key-c", "key-a", "key-b")
        ),
        threshold=2,
    )
    return material, keyring


def _present_subset(
    material: Mapping[str, tuple[bytes, bytes]],
    subset: tuple[str, ...],
    *,
    payload: bytes,
    domain: bytes,
) -> tuple[dict[str, bytes], dict[str, bytes]]:
    signatures = {
        key_id: sign_payload(material[key_id][0], payload, domain=domain)
        for key_id in reversed(subset)
    }
    public_keys = {key_id: material[key_id][1] for key_id in subset}
    return signatures, public_keys


def test_fingerprint_helpers_normalize_pem_and_raw() -> None:
    _, public_key_pem = generate_signing_keypair()
    raw = _raw_public_key(public_key_pem)
    public_key = serialization.load_pem_public_key(public_key_pem)
    assert isinstance(public_key, Ed25519PublicKey)
    spki_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    expected_spki = hashlib.sha256(spki_der).hexdigest()
    expected_raw = hashlib.sha256(raw).hexdigest()
    assert spki_sha256(public_key_pem) == expected_spki
    assert spki_sha256(raw) == expected_spki
    assert raw_public_key_sha256(public_key_pem) == expected_raw
    assert raw_public_key_sha256(raw) == expected_raw


def test_fingerprint_helper_refusals() -> None:
    with pytest.raises(SignError, match="^Ed25519 public key must be bytes$"):
        spki_sha256(bytearray(32))  # type: ignore[arg-type]
    with pytest.raises(SignError, match="^cannot decode Ed25519 public key$"):
        spki_sha256(b"not a public key")

    ec_public_pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(SignError, match="^public key is not Ed25519$"):
        raw_public_key_sha256(ec_public_pem)


def test_keyring_construction_refusals_and_frozen_specs() -> None:
    assert issubclass(SignError, ValueError)

    with pytest.raises(
        SignError,
        match="^unsupported key fingerprint scheme: 'sha256'$",
    ):
        KeySpec("root", "fingerprint", "sha256")

    with pytest.raises(SignError, match="^keyring must contain at least one key$"):
        KeyringSpec((), 1)

    key_a = KeySpec("key-a", "fingerprint-a", "spki-sha256")
    for threshold in (0, -1):
        with pytest.raises(SignError) as caught:
            KeyringSpec((key_a,), threshold)
        assert str(caught.value) == (
            f"keyring threshold must be at least 1; found={threshold}"
        )

    with pytest.raises(SignError) as caught:
        KeyringSpec((key_a,), 2)
    assert str(caught.value) == "keyring threshold 2 exceeds key count 1"

    duplicate_id = KeySpec("key-a", "fingerprint-b", "raw-sha256")
    with pytest.raises(SignError) as caught:
        KeyringSpec((key_a, duplicate_id), 1)
    assert str(caught.value) == "duplicate key_id in keyring: 'key-a'"

    duplicate_fingerprint = KeySpec(
        "key-b",
        "fingerprint-a",
        "raw-sha256",
    )
    with pytest.raises(SignError) as caught:
        KeyringSpec((key_a, duplicate_fingerprint), 1)
    assert str(caught.value) == (
        "duplicate fingerprint in keyring: 'fingerprint-a'"
    )

    keyring = KeyringSpec((key_a,), 1)
    verification = ThresholdVerification(("key-a",), (), ())
    producer = ProducerKeySpec("producer.pub", "fingerprint")
    for instance, attribute, replacement in (
        (key_a, "key_id", "changed"),
        (keyring, "threshold", 2),
        (verification, "satisfied", ()),
        (producer, "public_key_filename", "changed.pub"),
    ):
        with pytest.raises(FrozenInstanceError):
            setattr(instance, attribute, replacement)


THRESHOLD_KEY_IDS = ("key-a", "key-b", "key-c")
ACCEPTING_SUBSETS = tuple(
    subset
    for size in (2, 3)
    for subset in itertools.combinations(THRESHOLD_KEY_IDS, size)
)


@pytest.mark.parametrize("subset", ACCEPTING_SUBSETS)
def test_two_of_three_accepts_every_satisfying_subset(
    subset: tuple[str, ...],
) -> None:
    material, keyring = _three_keyring()
    payload = b"threshold payload"
    domain = b"threshold/v1\0"
    signatures, public_keys = _present_subset(
        material,
        subset,
        payload=payload,
        domain=domain,
    )

    verification = verify_threshold(
        payload,
        signatures,
        public_keys,
        keyring,
        domain=domain,
        label="record",
        allow_legacy=False,
    )
    assert verification == ThresholdVerification(
        satisfied=tuple(sorted(subset)),
        failed=(),
        absent=tuple(sorted(set(THRESHOLD_KEY_IDS) - set(subset))),
    )


@pytest.mark.parametrize("key_id", THRESHOLD_KEY_IDS)
def test_two_of_three_refuses_every_one_key_subset(key_id: str) -> None:
    material, keyring = _three_keyring()
    payload = b"threshold payload"
    domain = b"threshold/v1\0"
    signatures, public_keys = _present_subset(
        material,
        (key_id,),
        payload=payload,
        domain=domain,
    )

    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            signatures,
            public_keys,
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    message = str(caught.value)
    assert "threshold=2" in message
    assert f"satisfied={(key_id,)!r}" in message
    assert "failed=()" in message
    absent = tuple(sorted(set(THRESHOLD_KEY_IDS) - {key_id}))
    assert f"absent={absent!r}" in message


class _DuplicatePresentation(Mapping[str, bytes]):
    def __init__(self, key_id: str, value: bytes) -> None:
        self.key_id = key_id
        self.value = value

    def __getitem__(self, key: str) -> bytes:
        if key != self.key_id:
            raise KeyError(key)
        return self.value

    def __iter__(self) -> Iterator[str]:
        yield self.key_id
        yield self.key_id

    def __len__(self) -> int:
        return 2


def test_duplicate_presentation_counts_one_key_once() -> None:
    material, keyring = _three_keyring()
    payload = b"threshold payload"
    domain = b"threshold/v1\0"
    key_id = "key-a"
    signature = sign_payload(material[key_id][0], payload, domain=domain)

    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            _DuplicatePresentation(key_id, signature),
            _DuplicatePresentation(key_id, material[key_id][1]),
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    message = str(caught.value)
    assert "satisfied=('key-a',)" in message
    assert "absent=('key-b', 'key-c')" in message


@pytest.mark.parametrize("unknown_mapping", ("signatures", "public_keys"))
def test_unknown_key_id_refuses_even_when_threshold_is_met(
    unknown_mapping: str,
) -> None:
    material, keyring = _three_keyring()
    payload = b"threshold payload"
    domain = b"threshold/v1\0"
    signatures, public_keys = _present_subset(
        material,
        ("key-a", "key-b"),
        payload=payload,
        domain=domain,
    )
    if unknown_mapping == "signatures":
        signatures["unknown-root"] = b"0" * 64
    else:
        public_keys["unknown-root"] = material["key-c"][1]

    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            signatures,
            public_keys,
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    assert str(caught.value) == "unknown key_id: 'unknown-root'"


def test_fingerprint_mismatch_refuses_with_computed_value_after_threshold_met() -> None:
    material, keyring = _three_keyring()
    payload = b"threshold payload"
    domain = b"threshold/v1\0"
    signatures, public_keys = _present_subset(
        material,
        ("key-a", "key-b"),
        payload=payload,
        domain=domain,
    )
    public_keys["key-c"] = material["key-a"][1]
    computed = spki_sha256(material["key-a"][1])

    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            signatures,
            public_keys,
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    message = str(caught.value)
    assert "public key fingerprint mismatch for 'key-c' (spki-sha256)" in message
    assert f"computed={computed}" in message


def test_spki_and_raw_fingerprint_keyrings_verify_the_same_key() -> None:
    private_key_pem, public_key_pem = generate_signing_keypair()
    raw_public_key = _raw_public_key(public_key_pem)
    payload = b"threshold payload"
    domain = b"threshold/v1\0"
    signature = sign_payload(private_key_pem, payload, domain=domain)

    cases = (
        (
            "spki-sha256",
            spki_sha256(public_key_pem),
            public_key_pem,
        ),
        (
            "raw-sha256",
            raw_public_key_sha256(public_key_pem),
            raw_public_key,
        ),
    )
    for scheme, fingerprint, supplied_key in cases:
        keyring = KeyringSpec(
            (KeySpec("root", fingerprint, scheme),),
            threshold=1,
        )
        verification = verify_threshold(
            payload,
            {"root": signature},
            {"root": supplied_key},
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
        assert verification == ThresholdVerification(("root",), (), ())


def test_threshold_reports_failed_and_absent_keys() -> None:
    material, keyring = _three_keyring()
    payload = b"threshold payload"
    domain = b"threshold/v1\0"
    signatures, public_keys = _present_subset(
        material,
        ("key-a", "key-b"),
        payload=payload,
        domain=domain,
    )
    signatures["key-c"] = b"0" * 64
    public_keys["key-c"] = material["key-c"][1]
    verification = verify_threshold(
        payload,
        signatures,
        public_keys,
        keyring,
        domain=domain,
        label="record",
        allow_legacy=False,
    )
    assert verification == ThresholdVerification(
        ("key-a", "key-b"),
        ("key-c",),
        (),
    )

    signatures = {
        "key-a": sign_payload(material["key-a"][0], payload, domain=domain),
        "key-b": b"0" * 64,
    }
    public_keys = {
        "key-a": material["key-a"][1],
        "key-b": material["key-b"][1],
    }
    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            signatures,
            public_keys,
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    message = str(caught.value)
    assert "satisfied=('key-a',)" in message
    assert "failed=('key-b',)" in message
    assert "absent=('key-c',)" in message


def test_signature_or_public_key_alone_counts_as_absent() -> None:
    material, keyring = _three_keyring()
    payload = b"threshold payload"
    domain = b"threshold/v1\0"
    signature = sign_payload(material["key-a"][0], payload, domain=domain)

    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            {"key-a": signature},
            {"key-b": material["key-b"][1]},
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    message = str(caught.value)
    assert "satisfied=()" in message
    assert "failed=()" in message
    assert "absent=('key-a', 'key-b', 'key-c')" in message


def test_threshold_domain_separation() -> None:
    private_key_pem, public_key_pem = generate_signing_keypair()
    payload = b"threshold payload"
    domain_a = b"consumer/a\0"
    domain_b = b"consumer/b\0"
    signature = sign_payload(private_key_pem, payload, domain=domain_a)
    keyring = KeyringSpec(
        (KeySpec("root", spki_sha256(public_key_pem), "spki-sha256"),),
        threshold=1,
    )

    assert verify_threshold(
        payload,
        {"root": signature},
        {"root": public_key_pem},
        keyring,
        domain=domain_a,
        label="record",
        allow_legacy=False,
    ) == ThresholdVerification(("root",), (), ())

    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            {"root": signature},
            {"root": public_key_pem},
            keyring,
            domain=domain_b,
            label="record",
            allow_legacy=False,
        )
    message = str(caught.value)
    assert "satisfied=()" in message
    assert "failed=('root',)" in message
    assert "absent=()" in message


def test_threshold_requires_exact_bytes_and_explicit_domain() -> None:
    _, public_key_pem = generate_signing_keypair()
    keyring = KeyringSpec(
        (KeySpec("root", spki_sha256(public_key_pem), "spki-sha256"),),
        threshold=1,
    )
    parameter = inspect.signature(verify_threshold).parameters["domain"]
    assert parameter.default is inspect.Parameter.empty

    with pytest.raises(SignError, match="^signature payload must be bytes$"):
        verify_threshold(
            bytearray(),  # type: ignore[arg-type]
            {},
            {},
            keyring,
            domain=b"",
            label="record",
            allow_legacy=False,
        )
    with pytest.raises(SignError, match="^signature domain must be bytes$"):
        verify_threshold(
            b"",
            {},
            {},
            keyring,
            domain=bytearray(),  # type: ignore[arg-type]
            label="record",
            allow_legacy=False,
        )
    with pytest.raises(TypeError, match="domain"):
        verify_threshold(  # type: ignore[call-arg]
            b"",
            {},
            {},
            keyring,
            label="record",
            allow_legacy=False,
        )


# --- key generations (0.3.0): legacy verification sets + required domains ---
#
# Modeled on the semantics a production rotation incident fixed upstream:
# current keys sign and verify new material; retired keys verify immutable
# pre-rotation history only, explicitly; malformed key material is always
# fatal; only a clean signature mismatch under a validated key falls through
# to an older generation.


def test_sign_payload_requires_explicit_domain() -> None:
    parameter = inspect.signature(sign_payload).parameters["domain"]
    assert parameter.default is inspect.Parameter.empty

    private_key_pem, _ = generate_signing_keypair()
    with pytest.raises(TypeError, match="domain"):
        sign_payload(private_key_pem, b"payload")  # type: ignore[call-arg]


def test_verify_threshold_requires_explicit_allow_legacy() -> None:
    parameter = inspect.signature(verify_threshold).parameters["allow_legacy"]
    assert parameter.default is inspect.Parameter.empty

    _, public_key_pem = generate_signing_keypair()
    keyring = KeyringSpec(
        (KeySpec("root", spki_sha256(public_key_pem), "spki-sha256"),),
        threshold=1,
    )
    with pytest.raises(TypeError, match="allow_legacy"):
        verify_threshold(  # type: ignore[call-arg]
            b"",
            {},
            {},
            keyring,
            domain=b"",
            label="record",
        )
    with pytest.raises(SignError, match="^allow_legacy must be a bool$"):
        verify_threshold(
            b"",
            {},
            {},
            keyring,
            domain=b"",
            label="record",
            allow_legacy=1,  # type: ignore[arg-type]
        )


def _rotated_keyring() -> tuple[
    dict[str, tuple[bytes, bytes]],
    KeyringSpec,
]:
    """One current key ("new-root") over one retired key ("old-root")."""

    material = {
        "new-root": generate_signing_keypair(),
        "old-root": generate_signing_keypair(),
    }
    keyring = KeyringSpec(
        keys=(
            KeySpec("new-root", spki_sha256(material["new-root"][1]), "spki-sha256"),
        ),
        threshold=1,
        legacy_keys=(
            KeySpec("old-root", spki_sha256(material["old-root"][1]), "spki-sha256"),
        ),
    )
    return material, keyring


def test_keyring_legacy_construction_refusals() -> None:
    current = KeySpec("root", "fp-current", "spki-sha256")

    with pytest.raises(SignError) as caught:
        KeyringSpec(
            (current,),
            1,
            legacy_keys=(KeySpec("root", "fp-old", "spki-sha256"),),
        )
    assert str(caught.value) == "duplicate key_id in keyring: 'root'"

    with pytest.raises(SignError) as caught:
        KeyringSpec(
            (current,),
            1,
            legacy_keys=(KeySpec("old", "fp-current", "raw-sha256"),),
        )
    assert str(caught.value) == "duplicate fingerprint in keyring: 'fp-current'"

    with pytest.raises(SignError) as caught:
        KeyringSpec(
            (current,),
            1,
            legacy_keys=(
                KeySpec("old-a", "fp-old", "spki-sha256"),
                KeySpec("old-b", "fp-old", "spki-sha256"),
            ),
        )
    assert str(caught.value) == "duplicate fingerprint in keyring: 'fp-old'"

    # Threshold is defined over current keys alone; legacy keys never raise it.
    with pytest.raises(SignError) as caught:
        KeyringSpec(
            (current,),
            2,
            legacy_keys=(KeySpec("old", "fp-old", "spki-sha256"),),
        )
    assert str(caught.value) == "keyring threshold 2 exceeds key count 1"


def test_legacy_key_refused_for_new_material() -> None:
    material, keyring = _rotated_keyring()
    payload = b"new material"
    domain = b"consumer/v1\0"
    signature = sign_payload(material["old-root"][0], payload, domain=domain)

    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            {"old-root": signature},
            {"old-root": material["old-root"][1]},
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    assert str(caught.value) == "legacy key_id refused for new material: 'old-root'"

    # Supplying only the legacy PUBLIC KEY (no signature) refuses identically:
    # a legacy key has no business anywhere near new-material verification.
    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            {},
            {"old-root": material["old-root"][1]},
            keyring,
            domain=domain,
            label="record",
            allow_legacy=False,
        )
    assert str(caught.value) == "legacy key_id refused for new material: 'old-root'"


def test_legacy_counts_for_history_and_is_reported() -> None:
    material, keyring = _rotated_keyring()
    payload = b"immutable pre-rotation artifact"
    domain = b"consumer/v1\0"
    signature = sign_payload(material["old-root"][0], payload, domain=domain)

    verification = verify_threshold(
        payload,
        {"old-root": signature},
        {"old-root": material["old-root"][1]},
        keyring,
        domain=domain,
        label="record",
        allow_legacy=True,
    )
    assert verification == ThresholdVerification(
        satisfied=("old-root",),
        failed=(),
        absent=("new-root",),
        legacy_satisfied=("old-root",),
    )

    # A current-key signature on history reports no legacy involvement.
    current_signature = sign_payload(material["new-root"][0], payload, domain=domain)
    verification = verify_threshold(
        payload,
        {"new-root": current_signature},
        {"new-root": material["new-root"][1]},
        keyring,
        domain=domain,
        label="record",
        allow_legacy=True,
    )
    assert verification == ThresholdVerification(
        satisfied=("new-root",),
        failed=(),
        absent=("old-root",),
        legacy_satisfied=(),
    )


def test_duplicate_key_material_refused() -> None:
    private_key_pem, public_key_pem = generate_signing_keypair()
    raw_public_key = _raw_public_key(public_key_pem)
    payload = b"payload"
    domain = b"consumer/v1\0"
    signature = sign_payload(private_key_pem, payload, domain=domain)
    # Same physical key pinned as current (spki scheme) AND legacy (raw
    # scheme): fingerprints differ, so construction passes — the material-level
    # duplicate must be caught when the keys are supplied.
    keyring = KeyringSpec(
        keys=(KeySpec("current", spki_sha256(public_key_pem), "spki-sha256"),),
        threshold=1,
        legacy_keys=(
            KeySpec("shadow", raw_public_key_sha256(public_key_pem), "raw-sha256"),
        ),
    )

    with pytest.raises(SignError) as caught:
        verify_threshold(
            payload,
            {"current": signature},
            {"current": public_key_pem, "shadow": raw_public_key},
            keyring,
            domain=domain,
            label="record",
            allow_legacy=True,
        )
    assert str(caught.value) == (
        "duplicate key material presented for 'current' and 'shadow'"
    )


def test_verify_any_generation_current_first_then_legacy() -> None:
    material, keyring = _rotated_keyring()
    payload = b"artifact"
    domain = b"consumer/v1\0"
    public_keys = {
        "new-root": material["new-root"][1],
        "old-root": material["old-root"][1],
    }

    current_signature = sign_payload(material["new-root"][0], payload, domain=domain)
    assert (
        verify_any_generation(
            payload,
            current_signature,
            public_keys,
            keyring,
            domain=domain,
            label="record",
        )
        == "new-root"
    )

    legacy_signature = sign_payload(material["old-root"][0], payload, domain=domain)
    assert (
        verify_any_generation(
            payload,
            legacy_signature,
            public_keys,
            keyring,
            domain=domain,
            label="record",
        )
        == "old-root"
    )

    # A signature by an unrelated key exhausts every generation; the refusal
    # lists the try order: current first, then legacy.
    stranger_private, _ = generate_signing_keypair()
    stranger_signature = sign_payload(stranger_private, payload, domain=domain)
    with pytest.raises(SignError) as caught:
        verify_any_generation(
            payload,
            stranger_signature,
            public_keys,
            keyring,
            domain=domain,
            label="record",
        )
    assert str(caught.value) == (
        "signature does not verify under any keyring generation for record: "
        "tried=['new-root', 'old-root']"
    )


def test_verify_any_generation_malformed_is_fatal() -> None:
    material, keyring = _rotated_keyring()
    payload = b"artifact"
    domain = b"consumer/v1\0"
    legacy_signature = sign_payload(material["old-root"][0], payload, domain=domain)
    public_keys = {
        "new-root": material["new-root"][1],
        "old-root": material["old-root"][1],
    }

    with pytest.raises(SignError) as caught:
        verify_any_generation(
            payload,
            legacy_signature[:-1],
            public_keys,
            keyring,
            domain=domain,
            label="record",
        )
    assert str(caught.value) == (
        "signature for record must be exactly 64 raw bytes; found=63"
    )

    # Mispinned CURRENT key while the LEGACY key would cleanly verify: fatal.
    # Bad key material is never skipped in favor of a key that vouches (the
    # regression a production rotation review caught).
    _, wrong_public_key = generate_signing_keypair()
    computed = spki_sha256(wrong_public_key)
    with pytest.raises(SignError) as caught:
        verify_any_generation(
            payload,
            legacy_signature,
            {"new-root": wrong_public_key, "old-root": material["old-root"][1]},
            keyring,
            domain=domain,
            label="record",
        )
    assert str(caught.value) == (
        "public key fingerprint mismatch for 'new-root' (spki-sha256): "
        f"expected={keyring.keys[0].fingerprint}, computed={computed}"
    )


def test_verify_any_generation_requires_material_and_threshold_one() -> None:
    material, keyring = _rotated_keyring()
    payload = b"artifact"
    domain = b"consumer/v1\0"
    signature = sign_payload(material["new-root"][0], payload, domain=domain)

    with pytest.raises(SignError) as caught:
        verify_any_generation(
            payload,
            signature,
            {"new-root": material["new-root"][1]},
            keyring,
            domain=domain,
            label="record",
        )
    assert str(caught.value) == (
        "verify_any_generation requires key material for every keyring key; "
        "missing=['old-root']"
    )

    with pytest.raises(SignError, match="^unknown key_id: 'stranger'$"):
        verify_any_generation(
            payload,
            signature,
            {
                "new-root": material["new-root"][1],
                "old-root": material["old-root"][1],
                "stranger": material["new-root"][1],
            },
            keyring,
            domain=domain,
            label="record",
        )

    wide = KeyringSpec(
        keys=(
            KeySpec("a", "fp-a", "spki-sha256"),
            KeySpec("b", "fp-b", "spki-sha256"),
        ),
        threshold=2,
    )
    with pytest.raises(
        SignError,
        match="^verify_any_generation requires a threshold-1 keyring; found=2$",
    ):
        verify_any_generation(
            payload,
            signature,
            {},
            wide,
            domain=domain,
            label="record",
        )


def test_rotation_round_trip_story() -> None:
    """The corpus-shaped lifecycle: sign, rotate, history stays verifiable."""

    domain = b"consumer/v1\0"
    first_private, first_public = generate_signing_keypair()
    artifact = b"released under the first key"
    artifact_signature = sign_payload(first_private, artifact, domain=domain)

    ring_v1 = KeyringSpec(
        (KeySpec("root-2026a", spki_sha256(first_public), "spki-sha256"),),
        threshold=1,
    )
    assert (
        verify_any_generation(
            artifact,
            artifact_signature,
            {"root-2026a": first_public},
            ring_v1,
            domain=domain,
            label="release",
        )
        == "root-2026a"
    )

    # Rotation: reviewed replacement moves the retired key into legacy_keys.
    second_private, second_public = generate_signing_keypair()
    ring_v2 = KeyringSpec(
        keys=(KeySpec("root-2026b", spki_sha256(second_public), "spki-sha256"),),
        threshold=1,
        legacy_keys=(
            KeySpec("root-2026a", spki_sha256(first_public), "spki-sha256"),
        ),
    )
    both_keys = {"root-2026a": first_public, "root-2026b": second_public}

    # Immutable history remains verifiable, attributed to the retired key.
    assert (
        verify_any_generation(
            artifact,
            artifact_signature,
            both_keys,
            ring_v2,
            domain=domain,
            label="release",
        )
        == "root-2026a"
    )

    # New material must come from the current key.
    fresh = b"released after rotation"
    with pytest.raises(SignError):
        verify_threshold(
            fresh,
            {"root-2026a": sign_payload(first_private, fresh, domain=domain)},
            {"root-2026a": first_public},
            ring_v2,
            domain=domain,
            label="release",
            allow_legacy=False,
        )
    fresh_signature = sign_payload(second_private, fresh, domain=domain)
    verification = verify_threshold(
        fresh,
        {"root-2026b": fresh_signature},
        {"root-2026b": second_public},
        ring_v2,
        domain=domain,
        label="release",
        allow_legacy=False,
    )
    assert verification.satisfied == ("root-2026b",)
    assert verification.legacy_satisfied == ()
