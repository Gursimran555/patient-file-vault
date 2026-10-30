import pytest

from vault import Vault, new_master_key

RECORD = "Patient 101: diagnosis - hypertension"


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def vault(tmp_path, clock):
    vt = Vault(tmp_path, new_master_key(), pbkdf2_iterations=1_000, clock=clock)
    vt.bootstrap_admin("it_admin", "admin-passphrase-2026")
    yield vt
    vt.close()


@pytest.fixture
def admin(vault):
    return vault.login("it_admin", "admin-passphrase-2026")


@pytest.fixture
def users(vault, admin):
    """dr_smith + dr_jones (doctors), nurse_amy (nurses), visitor (no group)."""
    accounts = {"dr_smith": ("stethoscope-blue-41", "doctors"),
                "dr_jones": ("cardiac-rhythm-77", "doctors"),
                "nurse_amy": ("lantern-quiet-river-7", "nurses"),
                "visitor": ("paper-kite-harbor-3", None)}
    tokens = {}
    for name, (pw, group) in accounts.items():
        vault.register(name, pw)
        if group:
            vault.assign_group(admin, name, group)
        tokens[name] = vault.login(name, pw)
    vault.create_file(tokens["dr_smith"], "patient_101.txt", RECORD, 0o640)
    return tokens
