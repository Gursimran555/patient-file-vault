"""Run the same attacks against version 1 (legacy/v1.py) and version 2 (vault/).

    python -m vault.attacks

Each attack gets a fresh, throwaway instance of each version.
"""

from __future__ import annotations

import shutil
import sqlite3
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

from legacy import v1

from .core import AccessDeniedError, AuthenticationError, NotFound, Vault
from .crypto import IntegrityError, new_master_key
from .validation import ValidationError

V2_ERRORS = (AccessDeniedError, AuthenticationError, NotFound, IntegrityError, ValidationError)
V1_ERRORS = (v1.AccessDeniedError, v1.AuthenticationError, v1.ValidationError, FileNotFoundError)
RECORD = "Patient 101: diagnosis - hypertension"


@contextmanager
def tempdir():
    d = Path(tempfile.mkdtemp())
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


@contextmanager
def old():
    """v1 with dr_smith (doctors) owning patient_101.txt, mode 640."""
    with tempdir() as d:
        fs = v1.SecureFileSystem(d)
        fs.register("dr_smith", "Doctor2026", "doctors")
        fs.register("nurse_amy", "Nurse2026", "nurses")
        smith = fs.login("dr_smith", "Doctor2026")
        fs.create_file(smith, "patient_101.txt", RECORD, 0o640)
        fs.create_file(smith, "patient_102.txt", "Patient 102: no known conditions", 0o640)
        try:
            yield fs, smith
        finally:
            fs.close()


@contextmanager
def new():
    """v2 with the same setup. Groups are assigned by an admin."""
    with tempdir() as d:
        vt = Vault(d, new_master_key())
        vt.bootstrap_admin("it_admin", "admin-passphrase-2026")
        admin = vt.login("it_admin", "admin-passphrase-2026")
        vt.register("dr_smith", "stethoscope-blue-41")
        vt.register("nurse_amy", "lantern-quiet-river-7")
        vt.assign_group(admin, "dr_smith", "doctors")
        vt.assign_group(admin, "nurse_amy", "nurses")
        smith = vt.login("dr_smith", "stethoscope-blue-41")
        vt.create_file(smith, "patient_101.txt", RECORD, 0o640)
        vt.create_file(smith, "patient_102.txt", "Patient 102: no known conditions", 0o640)
        try:
            yield vt, smith
        finally:
            vt.close()


def fails(fn, errors) -> bool:
    try:
        fn()
    except errors:
        return True
    return False


def case_insensitive_fs(path: Path) -> bool:
    probe = path / "CaseProbe.tmp"
    probe.write_text("x")
    try:
        return (path / "caseprobe.tmp").exists()
    finally:
        probe.unlink()


# --- attacks: each returns (v1 result, v2 result) ---------------------------

def self_assigned_group():
    with old() as (fs, _):
        fs.register("mallory", "Mallory2026", "doctors")
        m = fs.login("mallory", "Mallory2026")
        r1 = fs.read_file(m, "patient_101.txt") == RECORD
    with new() as (vt, _):
        vt.register("mallory", "nightshade-orchard-9")
        m = vt.login("mallory", "nightshade-orchard-9")
        r2 = not fails(lambda: vt.read_file(m, "patient_101.txt"), V2_ERRORS)
    return r1, r2, "sign up as a 'doctor', then read a patient file"


def case_variant_overwrite():
    with old() as (fs, smith):
        if not case_insensitive_fs(fs.storage_dir):
            r1 = None
        else:
            amy = fs.login("nurse_amy", "Nurse2026")
            fails(lambda: fs.create_file(amy, "PATIENT_101.TXT", "edited by nurse_amy", 0o666),
                  V1_ERRORS)
            r1 = fs.read_file(smith, "patient_101.txt") != RECORD
    with new() as (vt, smith):
        amy = vt.login("nurse_amy", "lantern-quiet-river-7")
        fails(lambda: vt.create_file(amy, "PATIENT_101.TXT", "edited by nurse_amy", 0o666),
              V2_ERRORS)
        r2 = vt.read_file(smith, "patient_101.txt") != RECORD
    return r1, r2, "user with no write access creates PATIENT_101.TXT"


def list_without_login():
    with old() as (fs, _):
        r1 = len(fs.list_files()) > 0
    with new() as (vt, _):
        r2 = not fails(lambda: vt.list_files(""), V2_ERRORS)
        vt.register("visitor", "paper-kite-harbor-3")
        outsider = vt.login("visitor", "paper-kite-harbor-3")
        r2 = r2 or len(vt.list_files(outsider)) > 0
    return r1, r2, "list patient file names without a session / without access"


def edit_on_disk():
    with old() as (fs, smith):
        (fs.storage_dir / "patient_101.txt").write_text("Patient 101: no known conditions")
        r1 = fs.read_file(smith, "patient_101.txt") != RECORD
    with new() as (vt, smith):
        blob = next(vt.blobs.glob("*.bin"))
        data = bytearray(blob.read_bytes())
        data[-1] ^= 0x01
        blob.write_bytes(bytes(data))
        r2 = not fails(lambda: [vt.read_file(smith, n) for n in ("patient_101.txt", "patient_102.txt")],
                       V2_ERRORS)
    return r1, r2, "change a record's bytes directly on disk"


def swap_records():
    with old() as (fs, smith):
        shutil.copy(fs.storage_dir / "patient_102.txt", fs.storage_dir / "patient_101.txt")
        r1 = fs.read_file(smith, "patient_101.txt") != RECORD
    with new() as (vt, smith):
        a, b = (vt._meta(n)["id"] for n in ("patient_101.txt", "patient_102.txt"))
        shutil.copy(vt._blob(b), vt._blob(a))
        r2 = not fails(lambda: vt.read_file(smith, "patient_101.txt"), V2_ERRORS)
    return r1, r2, "copy one patient's file over another's"


def rollback():
    with old() as (fs, smith):
        before = (fs.storage_dir / "patient_101.txt").read_bytes()
        fs.write_file(smith, "patient_101.txt", "Patient 101: allergy - penicillin")
        (fs.storage_dir / "patient_101.txt").write_bytes(before)
        r1 = "penicillin" not in fs.read_file(smith, "patient_101.txt")
    with new() as (vt, smith):
        blob = vt._blob(vt._meta("patient_101.txt")["id"])
        before = blob.read_bytes()
        vt.write_file(smith, "patient_101.txt", "Patient 101: allergy - penicillin")
        blob.write_bytes(before)
        r2 = not fails(lambda: vt.read_file(smith, "patient_101.txt"), V2_ERRORS)
    return r1, r2, "restore an older copy to hide a newly added allergy"


def stolen_disk():
    with old() as (fs, _):
        r1 = any(b"hypertension" in p.read_bytes() for p in fs.storage_dir.iterdir())
    with new() as (vt, _):
        r2 = any(b"hypertension" in p.read_bytes() for p in vt.base.rglob("*") if p.is_file())
    return r1, r2, "read records from a copied disk or backup"


def cover_tracks():
    with old() as (fs, _):
        r1 = True        # there is no access log to tamper with, so nothing to detect
    with new() as (vt, _):
        vt.register("mallory", "nightshade-orchard-9")
        mallory = vt.login("mallory", "nightshade-orchard-9")
        fails(lambda: vt.read_file(mallory, "patient_101.txt"), V2_ERRORS)
        db = sqlite3.connect(str(vt.base / "vault.db"))
        db.execute("UPDATE audit SET outcome = 'ok' WHERE actor = 'mallory' AND outcome = 'denied'")
        db.commit()
        db.close()
        r2 = vt.audit.verify()[0]
    return r1, r2, "rewrite the access log after a denied read"


def password_guessing():
    with old() as (fs, _):
        for i in range(20):
            fails(lambda: fs.login("dr_smith", f"guess{i}abc"), V1_ERRORS)
        r1 = not fails(lambda: fs.login("dr_smith", "Doctor2026"), V1_ERRORS)
    with new() as (vt, _):
        for i in range(20):
            fails(lambda: vt.login("dr_smith", f"guess-number-{i}"), V2_ERRORS)
        r2 = not fails(lambda: vt.login("dr_smith", "stethoscope-blue-41"), V2_ERRORS)
    return r1, r2, "20 wrong passwords, then the right one"


def path_traversal():
    names = ["../../etc/passwd", "..\\..\\windows\\win.ini", "/etc/passwd", "a/../../b.txt"]
    with old() as (fs, smith):
        r1 = not all(fails(lambda n=n: fs.read_file(smith, n), V1_ERRORS) for n in names)
    with new() as (vt, smith):
        r2 = not all(fails(lambda n=n: vt.read_file(smith, n), V2_ERRORS) for n in names)
    return r1, r2, "../ and absolute paths in the file name"


def sql_injection():
    payloads = ["' OR '1'='1", "dr_smith'--", "x'; DROP TABLE users;--"]
    with old() as (fs, _):
        r1 = not all(fails(lambda p=p: fs.login(p, "anything123"), V1_ERRORS) for p in payloads)
    with new() as (vt, _):
        r2 = not all(fails(lambda p=p: vt.login(p, "anything-at-all"), V2_ERRORS) for p in payloads)
    return r1, r2, "SQL in the username field"


def token_after_logout():
    with old() as (fs, smith):
        fs.logout(smith)
        r1 = not fails(lambda: fs.read_file(smith, "patient_101.txt"), V1_ERRORS)
    with new() as (vt, smith):
        vt.logout(smith)
        r2 = not fails(lambda: vt.read_file(smith, "patient_101.txt"), V2_ERRORS)
    return r1, r2, "reuse a session token after logout"


ATTACKS = [
    ("Join a privileged group", self_assigned_group),
    ("Case-variant file overwrite", case_variant_overwrite),
    ("List files without access", list_without_login),
    ("Edit a record on disk", edit_on_disk),
    ("Swap two records", swap_records),
    ("Roll back a record", rollback),
    ("Read a stolen disk", stolen_disk),
    ("Rewrite the access log", cover_tracks),
    ("Online password guessing", password_guessing),
    ("Path traversal", path_traversal),
    ("SQL injection", sql_injection),
    ("Token reuse after logout", token_after_logout),
]


def label(succeeded) -> str:
    if succeeded is None:
        return "n/a*"
    return "WORKS" if succeeded else "blocked"


def run() -> int:
    w = max(len(n) for n, _ in ATTACKS)
    print(f"{'attack':{w}}  {'v1':8} {'v2':8} what the attacker does")
    print("-" * (w + 70))
    v2_failures = 0
    footnote = False
    for name, fn in ATTACKS:
        r1, r2, desc = fn()
        footnote |= r1 is None
        v2_failures += bool(r2)
        print(f"{name:{w}}  {label(r1):8} {label(r2):8} {desc}")
    if footnote:
        print("\n* needs a case-insensitive filesystem (Windows, macOS). CI runs it on both.")
    print(f"\nv2: {len(ATTACKS) - v2_failures}/{len(ATTACKS)} attacks blocked")
    return 1 if v2_failures else 0


if __name__ == "__main__":
    sys.exit(run())
