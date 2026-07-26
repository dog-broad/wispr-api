from __future__ import annotations

from app.lib.invites import generate_invite_code

_AMBIGUOUS = set("01OIL")


def test_code_is_eight_unambiguous_chars() -> None:
    code = generate_invite_code()
    assert len(code) == 8
    assert all(c.isalnum() and c.upper() == c for c in code)
    assert not (set(code) & _AMBIGUOUS)


def test_codes_are_distinct() -> None:
    codes = {generate_invite_code() for _ in range(200)}
    # 31^8 space — 200 draws should never collide in practice.
    assert len(codes) == 200
