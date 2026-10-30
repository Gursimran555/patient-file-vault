import shutil
import sqlite3

import pytest

from vault import IntegrityError

from .conftest import RECORD


def blob_of(vault, name):
    return vault._blob(vault._meta(name)["id"])


def test_plaintext_never_on_disk(vault, users):
    for p in vault.base.rglob("*"):
        if p.is_file():
            assert b"hypertension" not in p.read_bytes()


def test_tampered_blob_detected(vault, users):
    blob = blob_of(vault, "patient_101.txt")
    data = bytearray(blob.read_bytes())
    data[20] ^= 0xFF
    blob.write_bytes(bytes(data))
    with pytest.raises(IntegrityError):
        vault.read_file(users["dr_smith"], "patient_101.txt")


def test_swapped_blob_detected(vault, users):
    vault.create_file(users["dr_smith"], "patient_102.txt", "Patient 102", 0o640)
    shutil.copy(blob_of(vault, "patient_102.txt"), blob_of(vault, "patient_101.txt"))
    with pytest.raises(IntegrityError):
        vault.read_file(users["dr_smith"], "patient_101.txt")


def test_rollback_detected(vault, users):
    blob = blob_of(vault, "patient_101.txt")
    old = blob.read_bytes()
    vault.write_file(users["dr_smith"], "patient_101.txt", RECORD + "; allergy - penicillin")
    blob.write_bytes(old)
    with pytest.raises(IntegrityError):
        vault.read_file(users["dr_smith"], "patient_101.txt")


def test_deleted_blob_detected(vault, users):
    blob_of(vault, "patient_101.txt").unlink()
    with pytest.raises(IntegrityError):
        vault.read_file(users["dr_smith"], "patient_101.txt")


def test_integrity_failure_is_audited(vault, users):
    blob_of(vault, "patient_101.txt").write_bytes(b"\x00" * 40)
    with pytest.raises(IntegrityError):
        vault.read_file(users["dr_smith"], "patient_101.txt")
    assert vault.audit.entries("patient_101.txt")[-1]["outcome"] == "integrity_failure"


def test_write_then_read(vault, users):
    vault.write_file(users["dr_smith"], "patient_101.txt", "updated")
    vault.write_file(users["dr_smith"], "patient_101.txt", "updated again")
    assert vault.read_file(users["dr_jones"], "patient_101.txt") == "updated again"


def test_different_master_key_cannot_read(tmp_path, vault, users):
    from vault import Vault, new_master_key
    vault.close()
    other = Vault(vault.base, new_master_key(), pbkdf2_iterations=1_000)
    tok = other.login("dr_smith", "stethoscope-blue-41")
    with pytest.raises(IntegrityError):
        other.read_file(tok, "patient_101.txt")
    other.close()

# --- audit log -------------------------------------------------------------------

def test_every_decision_is_logged(vault, users):
    with pytest.raises(Exception):
        vault.read_file(users["nurse_amy"], "patient_101.txt")
    vault.read_file(users["dr_jones"], "patient_101.txt")
    outcomes = [(e["actor"], e["action"], e["outcome"])
                for e in vault.audit.entries("patient_101.txt")]
    assert ("nurse_amy", "read", "denied") in outcomes
    assert ("dr_jones", "read", "ok") in outcomes


def test_chain_verifies(vault, users):
    assert vault.audit.verify() == (True, None)


@pytest.mark.parametrize("sql", [
    "UPDATE audit SET outcome = 'ok' WHERE outcome = 'denied'",
    "UPDATE audit SET actor = 'someone_else' WHERE seq = 3",
    "DELETE FROM audit WHERE seq = 4",
    "UPDATE audit SET ts = ts + 3600 WHERE seq = 2",
])
def test_chain_detects_edits(vault, users, sql):
    with pytest.raises(Exception):
        vault.read_file(users["nurse_amy"], "patient_101.txt")
    db = sqlite3.connect(str(vault.base / "vault.db"))
    db.execute(sql)
    db.commit()
    db.close()
    ok, bad = vault.audit.verify()
    assert not ok and bad is not None


def test_only_admin_reads_history(vault, admin, users):
    from vault import AccessDeniedError
    with pytest.raises(AccessDeniedError):
        vault.access_history(users["dr_smith"], "patient_101.txt")
    assert vault.access_history(admin, "patient_101.txt")
