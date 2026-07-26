from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from functools import lru_cache

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import Settings, get_settings

logger = logging.getLogger(__name__)

_IV_BYTES = 12
# Deterministic across dev restarts so a share wrapped in one dev session
# unwraps in the next. Never used when a real key is configured.
_DEV_KEY = hashlib.sha256(b"wispr-dev-key-vault-master").digest()


def _load_keys(settings: Settings) -> dict[int, bytes]:
    configured = {1: settings.key_vault_master_v1, 2: settings.key_vault_master_v2}
    return {v: base64.b64decode(raw) for v, raw in configured.items() if raw}


class KeyVault:
    """Wraps/unwraps Mode 2 content keys with versioned master keys. Decrypt
    looks up the version recorded on the row, so a rotation can hold both the
    new and previous key during the dual-key window."""

    def __init__(self, keys: dict[int, bytes], current_version: int) -> None:
        self._keys = keys
        self._current = current_version

    @classmethod
    def from_settings(cls, settings: Settings) -> KeyVault:
        keys = _load_keys(settings)
        current = settings.key_vault_current_version
        if current not in keys:
            logger.warning("KEY_VAULT_MASTER_V%d not set - using insecure dev key", current)
            keys = {**keys, current: _DEV_KEY}
        return cls(keys, current)

    @property
    def current_version(self) -> int:
        return self._current

    def wrap(self, content_key: bytes) -> tuple[bytes, bytes, int]:
        """Encrypt a content key under the current master key. Returns
        (wrapped, iv, key_version)."""
        iv = secrets.token_bytes(_IV_BYTES)
        wrapped = AESGCM(self._keys[self._current]).encrypt(iv, content_key, None)
        return wrapped, iv, self._current

    def unwrap(self, wrapped: bytes, iv: bytes, version: int) -> bytes:
        key = self._keys.get(version)
        if key is None:
            raise KeyError(f"no key vault master for version {version}")
        return AESGCM(key).decrypt(iv, wrapped, None)


@lru_cache(maxsize=1)
def get_key_vault() -> KeyVault:
    return KeyVault.from_settings(get_settings())
