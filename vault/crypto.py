"""Encryption at rest and key handling.

Files are encrypted with AES-256-GCM. The associated data is the file's id
and version, so the authentication tag fails if someone:
  - edits the bytes on disk               (tampering)
  - copies another file's blob over it     (swap)
  - restores an older copy from a backup   (rollback)
"""

from __future__ import annotations

import base64
import os
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_BYTES = 12


class ConfigError(RuntimeError):
    pass


class IntegrityError(Exception):
    """Stored data failed its authenticity check."""


def load_master_key(env: str = "VAULT_MASTER_KEY") -> bytes:
    value = os.environ.get(env, "")
    if not value:
        raise ConfigError(f"{env} is not set. Generate one with: "
                        "python -c \"import secrets,base64; "
                        "print(base64.b64encode(secrets.token_bytes(32)).decode())\"")
    try:
        key = base64.b64decode(value, validate=True)
    except ValueError:
        raise ConfigError(f"{env} must be base64") from None
    if len(key) != 32:
        raise ConfigError(f"{env} must decode to exactly 32 bytes, got {len(key)}")
    return key


def new_master_key() -> bytes:
    return secrets.token_bytes(32)


def derive(master: bytes, purpose: str) -> bytes:
    """One key per purpose, so the audit key and the file key are never the same."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=purpose.encode()).derive(master)


class FileCipher:
    def __init__(self, key: bytes):
        self._aead = AESGCM(key)

    @staticmethod
    def _aad(file_id: str, version: int) -> bytes:
        return f"{file_id}:{version}".encode()

    def seal(self, file_id: str, version: int, plaintext: bytes) -> bytes:
        nonce = secrets.token_bytes(NONCE_BYTES)
        return nonce + self._aead.encrypt(nonce, plaintext, self._aad(file_id, version))

    def open(self, file_id: str, version: int, blob: bytes) -> bytes:
        try:
            return self._aead.decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:],
                                      self._aad(file_id, version))
        except Exception:
            raise IntegrityError("file failed its integrity check") from None
