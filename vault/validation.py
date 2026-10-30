"""Whitelist validation. Anything that doesn't match is rejected, never "cleaned"."""

from __future__ import annotations

import re

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
# File names are display names only; nothing on disk is ever named after them.
FILENAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}(\.[A-Za-z0-9]{1,10})?$")
GROUPS = frozenset({"doctors", "nurses", "admin", "reception"})
PASSWORD_MIN, PASSWORD_MAX = 12, 128
MAX_FILE_BYTES = 1_000_000


class ValidationError(ValueError):
    pass


def username(value) -> str:
    if not isinstance(value, str) or not USERNAME_RE.fullmatch(value):
        raise ValidationError("Invalid username: 3-32 letters, digits or underscore")
    return value


def filename(value) -> str:
    if not isinstance(value, str) or not FILENAME_RE.fullmatch(value):
        raise ValidationError("Invalid filename: letters, digits, '_', '-' and one extension")
    return value


def password(value, user: str) -> str:
    if not isinstance(value, str) or not PASSWORD_MIN <= len(value) <= PASSWORD_MAX:
        raise ValidationError(f"Password must be {PASSWORD_MIN}-{PASSWORD_MAX} characters")
    if user.lower() in value.lower():
        raise ValidationError("Password must not contain the username")
    return value


def group(value) -> str:
    if value not in GROUPS:
        raise ValidationError(f"Invalid group: must be one of {sorted(GROUPS)}")
    return value


def mode(value) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0o777:
        raise ValidationError("Invalid mode: octal 000-777")
    return value


def content(value) -> bytes:
    data = value.encode("utf-8") if isinstance(value, str) else value
    if not isinstance(data, bytes):
        raise ValidationError("Content must be text or bytes")
    if len(data) > MAX_FILE_BYTES:
        raise ValidationError(f"File too large (max {MAX_FILE_BYTES} bytes)")
    return data
