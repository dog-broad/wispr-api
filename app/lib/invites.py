from __future__ import annotations

import secrets

# 8-character invite codes from an unambiguous alphabet (no 0/O/1/I/L) so a
# code read off a screen or dictated aloud doesn't get mistyped. The column is
# String(8) with a unique constraint; callers retry on the (astronomically
# unlikely) collision.
_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
_CODE_LEN = 8


def generate_invite_code() -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(_CODE_LEN))
