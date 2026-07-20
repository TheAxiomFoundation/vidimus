"""Scaffold smoke tests: the package imports and is honest about its state."""

import vidimus


def test_version() -> None:
    assert vidimus.__version__ == "0.0.1"


def test_docstring_declares_preverification_status() -> None:
    # The package must not claim capability it does not have; the docstring
    # carries the pre-release disclaimer until extraction lands.
    assert "Nothing in this version verifies anything" in vidimus.__doc__
