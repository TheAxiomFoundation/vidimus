"""Package-level invariants: honest status and verbatim provenance."""

import hashlib
import pathlib

import vidimus

# canonical.py is a byte-identical copy of the pinned source file; this hash
# is scripts/canonical_json.py at PolicyEngine/ledger commit 0798427850
# (receipts/ledger-pin-source-hashes.txt).
CANONICAL_SOURCE_SHA256 = (
    "562bf267b7686bce8cb71f3c13f34825c21cd4ef0aba1c0c46aff16962a6cadd"
)


def test_version() -> None:
    assert vidimus.__version__ == "0.1.2"


def test_docstring_names_landed_and_pending_extraction() -> None:
    # The package must not claim capability it does not have: the docstring
    # names exactly what has landed and what is still pending.
    assert "Pending extraction" in vidimus.__doc__
    assert "release-chain verifier" in vidimus.__doc__


def test_canonical_module_is_byte_identical_to_pinned_source() -> None:
    module_path = pathlib.Path(vidimus.__file__).parent / "canonical.py"
    digest = hashlib.sha256(module_path.read_bytes()).hexdigest()
    assert digest == CANONICAL_SOURCE_SHA256
