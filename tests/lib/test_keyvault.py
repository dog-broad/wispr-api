from __future__ import annotations

import pytest

from app.config import Settings
from app.lib.keyvault import KeyVault


def test_wrap_unwrap_roundtrip() -> None:
    vault = KeyVault.from_settings(Settings())
    key = b"\x02" * 32
    wrapped, iv, version = vault.wrap(key)
    assert version == 1
    assert wrapped != key  # actually encrypted
    assert vault.unwrap(wrapped, iv, version) == key


def test_unwrap_unknown_version_raises() -> None:
    vault = KeyVault.from_settings(Settings())
    wrapped, iv, _ = vault.wrap(b"\x03" * 32)
    with pytest.raises(KeyError):
        vault.unwrap(wrapped, iv, 99)


def test_wrap_uses_fresh_iv() -> None:
    vault = KeyVault.from_settings(Settings())
    key = b"\x04" * 32
    _, iv1, _ = vault.wrap(key)
    _, iv2, _ = vault.wrap(key)
    assert iv1 != iv2
