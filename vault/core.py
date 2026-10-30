"""The vault: users, sessions, Unix-style permissions, encrypted storage, audit.

Order of checks for every file operation:
    token -> file name -> permission -> decrypt / encrypt -> audit
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import time
import uuid
from pathlib import Path

from . import validation as v
from .audit import AuditLog
from .crypto import FileCipher, IntegrityError, derive
from .validation import ValidationError

READ, WRITE = 4, 2
TOKEN_TTL = 30 * 60
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 300
GENERIC_LOGIN_ERROR = "Invalid username or password"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username        TEXT PRIMARY KEY,
    salt            TEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    user_group      TEXT,                 -- NULL until an admin assigns one
    is_admin        INTEGER NOT NULL DEFAULT 0,
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    REAL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL REFERENCES users(username),
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
    id         TEXT PRIMARY KEY,          -- random; this is the name on disk
    name       TEXT NOT NULL,
    name_key   TEXT NOT NULL UNIQUE,      -- casefolded, so Report.txt and report.txt clash
    owner      TEXT NOT NULL REFERENCES users(username),
    file_group TEXT,
    mode       INTEGER NOT NULL,
    version    INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS audit (
    seq     INTEGER PRIMARY KEY,
    ts      REAL NOT NULL,
    actor   TEXT NOT NULL,
    action  TEXT NOT NULL,
    target  TEXT NOT NULL,
    outcome TEXT NOT NULL,
    mac     TEXT NOT NULL
);
"""


class AuthenticationError(Exception):
    pass


class AccessDeniedError(PermissionError):
    pass


class NotFound(Exception):
    pass


def permission_string(mode: int) -> str:
    out = ""
    for shift in (6, 3, 0):
        bits = (mode >> shift) & 0o7
        out += ("r" if bits & 4 else "-") + ("w" if bits & 2 else "-") + ("x" if bits & 1 else "-")
    return out


class Vault:
    def __init__(self, base_dir, master_key: bytes, pbkdf2_iterations: int = 600_000,
                 clock=time.time):
        self.base = Path(base_dir).resolve()
        self.blobs = self.base / "blobs"
        self.blobs.mkdir(parents=True, exist_ok=True)
        self.iterations = pbkdf2_iterations          # OWASP 2023 figure for PBKDF2-HMAC-SHA256
        self.clock = clock
        self.db = sqlite3.connect(str(self.base / "vault.db"), isolation_level=None)
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.executescript(SCHEMA)
        self.cipher = FileCipher(derive(master_key, "file-encryption"))
        self.audit = AuditLog(self.db, derive(master_key, "audit-log"), clock)
        self._dummy_salt, self._dummy_hash = self._hash("timing-equaliser-1")

    def close(self):
        self.db.close()

    # --- passwords and sessions ----------------------------------------------

    def _hash(self, password: str, salt: bytes | None = None) -> tuple[str, str]:
        salt = salt or secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, self.iterations)
        return salt.hex(), digest.hex()

    def _check(self, password: str, salt_hex: str, hash_hex: str) -> bool:
        return hmac.compare_digest(self._hash(password, bytes.fromhex(salt_hex))[1], hash_hex)

    def _insert_user(self, username: str, password: str, group, is_admin: bool):
        v.username(username)
        v.password(password, username)
        salt, pw_hash = self._hash(password)
        try:
            self.db.execute("INSERT INTO users (username, salt, password_hash, user_group, is_admin) "
                            "VALUES (?, ?, ?, ?, ?)", (username, salt, pw_hash, group, int(is_admin)))
        except sqlite3.IntegrityError:
            raise ValidationError("Username not available") from None

    def bootstrap_admin(self, username: str, password: str) -> None:
        """Run once from the command line on the server. Not reachable through the API."""
        if self.db.execute("SELECT 1 FROM users WHERE is_admin = 1").fetchone():
            raise AccessDeniedError("An admin already exists")
        self._insert_user(username, password, "admin", True)
        self.audit.record(username, "bootstrap_admin", username, "ok")

    def register(self, username: str, password: str) -> None:
        """Self-service sign-up. The new account has no group, so only 'other' bits apply."""
        self._insert_user(username, password, None, False)
        self.audit.record(username, "register", username, "ok")

    def assign_group(self, admin_token: str, username: str, group: str) -> None:
        actor, _ = self.authenticate(admin_token)
        if not self._is_admin(actor):
            self.audit.record(actor, "assign_group", username, "denied")
            raise AccessDeniedError("Only an admin can assign groups")
        v.group(group)
        if not self.db.execute("UPDATE users SET user_group = ? WHERE username = ?",
                               (group, username)).rowcount:
            raise NotFound("No such user")
        self.audit.record(actor, "assign_group", f"{username}->{group}", "ok")

    def _is_admin(self, username: str) -> bool:
        row = self.db.execute("SELECT is_admin FROM users WHERE username = ?", (username,)).fetchone()
        return bool(row and row[0])

    def login(self, username: str, password: str) -> str:
        now = self.clock()
        try:
            v.username(username)
            row = self.db.execute("SELECT salt, password_hash, locked_until FROM users "
                                  "WHERE username = ?", (username,)).fetchone()
        except ValidationError:
            row = None
        if row is None:
            self._check(str(password), self._dummy_salt, self._dummy_hash)
            self.audit.record(str(username)[:40], "login", "-", "denied")
            raise AuthenticationError(GENERIC_LOGIN_ERROR)
        if row[2] and now < row[2]:
            self._check(str(password), self._dummy_salt, self._dummy_hash)
            self.audit.record(username, "login", "-", "locked")
            raise AuthenticationError(GENERIC_LOGIN_ERROR)
        if not isinstance(password, str) or not self._check(password, row[0], row[1]):
            self.db.execute("UPDATE users SET failed_logins = failed_logins + 1 WHERE username = ?",
                            (username,))
            fails = self.db.execute("SELECT failed_logins FROM users WHERE username = ?",
                                    (username,)).fetchone()[0]
            if fails >= MAX_FAILED_LOGINS:
                self.db.execute("UPDATE users SET locked_until = ?, failed_logins = 0 "
                                "WHERE username = ?", (now + LOCKOUT_SECONDS, username))
            self.audit.record(username, "login", "-", "denied")
            raise AuthenticationError(GENERIC_LOGIN_ERROR)

        self.db.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE username = ?",
                        (username,))
        token = secrets.token_urlsafe(32)
        self.db.execute("INSERT INTO sessions VALUES (?, ?, ?)",
                        (self._digest(token), username, now + TOKEN_TTL))
        self.audit.record(username, "login", "-", "ok")
        return token

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def authenticate(self, token) -> tuple[str, str | None]:
        if not isinstance(token, str) or not token:
            raise AuthenticationError("Invalid or expired token")
        row = self.db.execute(
            "SELECT s.username, u.user_group, s.expires_at FROM sessions s "
            "JOIN users u ON u.username = s.username WHERE s.token_hash = ?",
            (self._digest(token),)).fetchone()
        if row is None or row[2] <= self.clock():
            if row is not None:
                self.db.execute("DELETE FROM sessions WHERE token_hash = ?", (self._digest(token),))
            raise AuthenticationError("Invalid or expired token")
        return row[0], row[1]

    def logout(self, token: str) -> None:
        self.db.execute("DELETE FROM sessions WHERE token_hash = ?", (self._digest(str(token)),))

    # --- permissions ---------------------------------------------------------

    @staticmethod
    def allowed(user: str, group, meta: dict, needed: int) -> bool:
        mode = meta["mode"]
        if user == meta["owner"]:
            bits = (mode >> 6) & 0o7
        elif group is not None and group == meta["group"]:
            bits = (mode >> 3) & 0o7
        else:
            bits = mode & 0o7
        return bool(bits & needed)

    def _meta(self, name: str) -> dict:
        row = self.db.execute("SELECT id, name, owner, file_group, mode, version FROM files "
                              "WHERE name_key = ?", (v.filename(name).casefold(),)).fetchone()
        if row is None:
            raise NotFound(f"No file named {name}")
        return dict(zip(("id", "name", "owner", "group", "mode", "version"), row))

    def _blob(self, file_id: str) -> Path:
        # file_id is always a uuid4 hex we generated, never user input.
        return self.blobs / f"{file_id}.bin"

    def _require(self, actor, action, target, ok: bool, message: str):
        """Log and raise on denial. Successes are logged after the operation completes."""
        if not ok:
            self.audit.record(actor, action, target, "denied")
            raise AccessDeniedError(message)

    # --- file operations -----------------------------------------------------

    def create_file(self, token: str, name: str, content, mode: int = 0o640) -> None:
        user, group = self.authenticate(token)
        v.filename(name)
        v.mode(mode)
        data = v.content(content)
        file_id = uuid.uuid4().hex
        try:
            self.db.execute("INSERT INTO files (id, name, name_key, owner, file_group, mode) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            (file_id, name, name.casefold(), user, group, mode))
        except sqlite3.IntegrityError:
            self.audit.record(user, "create", name, "denied")
            raise ValidationError("A file with that name already exists") from None
        self._blob(file_id).write_bytes(self.cipher.seal(file_id, 1, data))
        self.audit.record(user, "create", name, "ok")

    def read_file(self, token: str, name: str) -> str:
        user, group = self.authenticate(token)
        meta = self._meta(name)
        self._require(user, "read", meta["name"], self.allowed(user, group, meta, READ),
                      f"{user} has no read permission on {meta['name']}")
        try:
            data = self.cipher.open(meta["id"], meta["version"], self._blob(meta["id"]).read_bytes())
        except (IntegrityError, FileNotFoundError):
            self.audit.record(user, "read", meta["name"], "integrity_failure")
            raise IntegrityError(f"{meta['name']} has been modified or replaced outside the vault")
        self.audit.record(user, "read", meta["name"], "ok")
        return data.decode("utf-8")

    def write_file(self, token: str, name: str, content) -> None:
        user, group = self.authenticate(token)
        meta = self._meta(name)
        self._require(user, "write", meta["name"], self.allowed(user, group, meta, WRITE),
                      f"{user} has no write permission on {meta['name']}")
        data = v.content(content)
        new_version = meta["version"] + 1
        tmp = self._blob(meta["id"]).with_suffix(".tmp")
        tmp.write_bytes(self.cipher.seal(meta["id"], new_version, data))
        tmp.replace(self._blob(meta["id"]))
        self.db.execute("UPDATE files SET version = ? WHERE id = ?", (new_version, meta["id"]))
        self.audit.record(user, "write", meta["name"], "ok")

    def chmod(self, token: str, name: str, mode: int) -> None:
        user, _ = self.authenticate(token)
        meta = self._meta(name)
        v.mode(mode)
        self._require(user, "chmod", meta["name"], user == meta["owner"],
                      "Only the owner can change permissions")
        self.db.execute("UPDATE files SET mode = ? WHERE id = ?", (mode, meta["id"]))
        self.audit.record(user, "chmod", meta["name"], f"ok {oct(mode)}")

    def delete_file(self, token: str, name: str) -> None:
        user, _ = self.authenticate(token)
        meta = self._meta(name)
        self._require(user, "delete", meta["name"], user == meta["owner"],
                      "Only the owner can delete a file")
        self.db.execute("DELETE FROM files WHERE id = ?", (meta["id"],))
        self._blob(meta["id"]).unlink(missing_ok=True)
        self.audit.record(user, "delete", meta["name"], "ok")

    def list_files(self, token: str) -> list[dict]:
        """Only files the caller can read. Names like patient_101.txt are themselves sensitive."""
        user, group = self.authenticate(token)
        out = []
        for fid, name, owner, fgroup, mode in self.db.execute(
                "SELECT id, name, owner, file_group, mode FROM files ORDER BY name_key"):
            meta = {"owner": owner, "group": fgroup, "mode": mode}
            if self.allowed(user, group, meta, READ):
                out.append({"name": name, "owner": owner, "group": fgroup,
                            "perms": permission_string(mode)})
        return out

    def access_history(self, admin_token: str, name: str) -> list[dict]:
        """Who touched this file, and whether they were allowed to."""
        actor, _ = self.authenticate(admin_token)
        if not self._is_admin(actor):
            raise AccessDeniedError("Only an admin can read the audit log")
        return self.audit.entries(target=name)
