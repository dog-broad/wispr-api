from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# argon2id over the client-derived auth token. The token is already a
# 32-byte PBKDF2 output, so this is a fast verify at login and a defense in
# depth if the DB leaks. The optional server pepper is mixed in by prefixing
# it to the token before hashing (argon2-cffi's high-level API has no keyed
# "secret" parameter); a DB leak without the pepper can't be brute-forced.
_hasher = PasswordHasher()


def _peppered(auth_token: bytes, pepper: str | None) -> bytes:
    prefix = pepper.encode("utf-8") if pepper else b""
    return prefix + auth_token


def hash_auth_credential(auth_token: bytes, pepper: str | None) -> bytes:
    """Return the argon2id PHC string (encoded as bytes for the bytea column)."""
    return _hasher.hash(_peppered(auth_token, pepper)).encode("utf-8")


def verify_auth_credential(stored_hash: bytes, auth_token: bytes, pepper: str | None) -> bool:
    try:
        return _hasher.verify(stored_hash.decode("utf-8"), _peppered(auth_token, pepper))
    except (VerifyMismatchError, InvalidHashError):
        return False
