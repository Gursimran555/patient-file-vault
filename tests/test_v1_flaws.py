"""Reproduce version 1's flaws, so the README's claims are checked by CI.

The case-variant test only runs on case-insensitive filesystems. CI runs this
suite on Windows and macOS as well as Linux for exactly that reason.
"""

import pytest

from legacy import v1

RECORD = "Patient 101: diagnosis - hypertension"


@pytest.fixture
def fs(tmp_path, monkeypatch):
    monkeypatch.setattr(v1, "PBKDF2_ITERATIONS", 1_000)
    s = v1.SecureFileSystem(tmp_path)
    s.register("dr_smith", "Doctor2026", "doctors")
    s.register("nurse_amy", "Nurse2026", "nurses")
    tok = s.login("dr_smith", "Doctor2026")
    s.create_file(tok, "patient_101.txt", RECORD, 0o640)
    yield s, tok
    s.close()


def case_insensitive(path):
    (path / "Probe.tmp").write_text("x")
    try:
        return (path / "probe.tmp").exists()
    finally:
        (path / "Probe.tmp").unlink()


def test_v1_anyone_can_join_doctors(fs):
    s, _ = fs
    s.register("mallory", "Mallory2026", "doctors")
    assert s.read_file(s.login("mallory", "Mallory2026"), "patient_101.txt") == RECORD


def test_v1_lists_files_without_a_session(fs):
    s, _ = fs
    assert s.list_files()[0]["filename"] == "patient_101.txt"


def test_v1_serves_tampered_files(fs):
    s, tok = fs
    (s.storage_dir / "patient_101.txt").write_text("Patient 101: no known conditions")
    assert s.read_file(tok, "patient_101.txt") == "Patient 101: no known conditions"


def test_v1_case_variant_overwrite(fs):
    s, smith = fs
    if not case_insensitive(s.storage_dir):
        pytest.skip("filesystem is case-sensitive")
    amy = s.login("nurse_amy", "Nurse2026")
    with pytest.raises(v1.AccessDeniedError):
        s.write_file(amy, "patient_101.txt", "edited by nurse_amy")      # correctly refused...
    s.create_file(amy, "PATIENT_101.TXT", "edited by nurse_amy", 0o666)  # ...but this isn't
    assert s.read_file(smith, "patient_101.txt") == "edited by nurse_amy"
