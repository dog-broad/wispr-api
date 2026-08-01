from __future__ import annotations

import secrets
import string

# 62-char alphabet: digits + lowercase + uppercase, no ambiguous characters
# stripped because the IDs travel in the URL path, not in user-typed form.
_BASE62 = string.digits + string.ascii_lowercase + string.ascii_uppercase
_DEFAULT_LENGTH = 12


def new_snippet_id(length: int = _DEFAULT_LENGTH) -> str:
    """Cryptographically random base62 ID. Default length matches the
    snippets.id column width (12 chars) and gives 62^12 ≈ 3.2e21 possible
    values: collisions are not a practical concern at this scale, but
    the create path retries on the primary-key conflict anyway.
    """
    return "".join(secrets.choice(_BASE62) for _ in range(length))
