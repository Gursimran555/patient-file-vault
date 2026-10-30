import pytest

from vault import AccessDeniedError, AuthenticationError, NotFound, ValidationError

from .conftest import RECORD


@pytest.mark.parametrize("who,can_read,can_write", [
    ("dr_smith", True, True),      # owner: rw-
    ("dr_jones", True, False),     # group: r--
    ("nurse_amy", False, False),   # other: ---
    ("visitor", False, False),     # no group at all: other
])
def test_640_permissions(vault, users, who, can_read, can_write):
    tok = users[who]
    if can_read:
        assert vault.read_file(tok, "patient_101.txt") == RECORD
    else:
        with pytest.raises(AccessDeniedError):
            vault.read_file(tok, "patient_101.txt")
    if can_write:
        vault.write_file(tok, "patient_101.txt", RECORD + "; BP 130/85")
    else:
        with pytest.raises(AccessDeniedError):
            vault.write_file(tok, "patient_101.txt", "edited")


def test_self_registration_gets_no_group(vault, users):
    row = vault.db.execute("SELECT user_group FROM users WHERE username='visitor'").fetchone()
    assert row[0] is None


def test_register_has_no_group_parameter(vault):
    with pytest.raises(TypeError):
        vault.register("mallory", "nightshade-orchard-9", "doctors")


def test_only_admin_assigns_groups(vault, users):
    with pytest.raises(AccessDeniedError):
        vault.assign_group(users["dr_smith"], "visitor", "doctors")
    with pytest.raises(AccessDeniedError):
        vault.read_file(users["visitor"], "patient_101.txt")


def test_admin_assignment_takes_effect(vault, admin, users):
    vault.assign_group(admin, "visitor", "doctors")
    assert vault.read_file(users["visitor"], "patient_101.txt") == RECORD


def test_second_admin_cannot_be_bootstrapped(vault):
    with pytest.raises(AccessDeniedError):
        vault.bootstrap_admin("mallory", "nightshade-orchard-9")


def test_only_owner_chmods_and_deletes(vault, users):
    with pytest.raises(AccessDeniedError):
        vault.chmod(users["dr_jones"], "patient_101.txt", 0o666)
    with pytest.raises(AccessDeniedError):
        vault.delete_file(users["dr_jones"], "patient_101.txt")
    vault.chmod(users["dr_smith"], "patient_101.txt", 0o600)
    with pytest.raises(AccessDeniedError):
        vault.read_file(users["dr_jones"], "patient_101.txt")
    vault.delete_file(users["dr_smith"], "patient_101.txt")
    with pytest.raises(NotFound):
        vault.read_file(users["dr_smith"], "patient_101.txt")


def test_names_are_case_insensitive_and_unique(vault, users):
    for variant in ("PATIENT_101.TXT", "Patient_101.txt", "patient_101.TXT"):
        with pytest.raises(ValidationError):
            vault.create_file(users["nurse_amy"], variant, "edited", 0o666)
    assert vault.read_file(users["dr_smith"], "patient_101.txt") == RECORD
    assert vault.read_file(users["dr_smith"], "PATIENT_101.TXT") == RECORD


def test_files_on_disk_are_not_named_by_users(vault, users):
    names = [p.name for p in vault.blobs.iterdir()]
    assert names and all(len(n) == 36 and n.endswith(".bin") for n in names)


def test_list_requires_session_and_filters(vault, users):
    with pytest.raises(AuthenticationError):
        vault.list_files("")
    assert vault.list_files(users["nurse_amy"]) == []
    listed = vault.list_files(users["dr_jones"])
    assert [f["name"] for f in listed] == ["patient_101.txt"]
    assert listed[0]["perms"] == "rw-r-----"


@pytest.mark.parametrize("name", ["../escape.txt", "..\\..\\win.ini", "/etc/passwd",
                                  "a/b.txt", "", "x" * 100, "file.", "a..b"])
def test_bad_file_names(vault, users, name):
    with pytest.raises(ValidationError):
        vault.create_file(users["dr_smith"], name, "x")


@pytest.mark.parametrize("mode", [-1, 0o1000, "640", 6.4, True])
def test_bad_modes(vault, users, mode):
    with pytest.raises(ValidationError):
        vault.create_file(users["dr_smith"], "new.txt", "x", mode)


def test_file_size_limit(vault, users):
    with pytest.raises(ValidationError):
        vault.create_file(users["dr_smith"], "big.txt", "x" * 1_000_001)
