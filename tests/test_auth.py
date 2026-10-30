import base64

import pytest

from vault import AuthenticationError, ConfigError, ValidationError, load_master_key


def test_passwords_not_stored(vault, users):
    for (h,) in vault.db.execute("SELECT password_hash FROM users"):
        assert "stethoscope" not in h and len(h) == 64


def test_same_error_for_every_failure(vault, users):
    msgs = set()
    for u, p in [("dr_smith", "wrong-password-1"), ("ghost_user", "wrong-password-1"),
                 ("' OR '1'='1", "x"), ("dr_smith", None)]:
        with pytest.raises(AuthenticationError) as e:
            vault.login(u, p)
        msgs.add(str(e.value))
    assert len(msgs) == 1


def test_lockout(vault, users, clock):
    for i in range(5):
        with pytest.raises(AuthenticationError):
            vault.login("dr_smith", f"wrong-password-{i}")
    with pytest.raises(AuthenticationError):
        vault.login("dr_smith", "stethoscope-blue-41")
    clock.advance(301)
    assert vault.login("dr_smith", "stethoscope-blue-41")


def test_token_expiry(vault, users, clock):
    clock.advance(30 * 60)
    with pytest.raises(AuthenticationError):
        vault.list_files(users["dr_smith"])


def test_logout(vault, users):
    vault.logout(users["dr_smith"])
    with pytest.raises(AuthenticationError):
        vault.read_file(users["dr_smith"], "patient_101.txt")


def test_tokens_stored_hashed(vault, users):
    stored = [r[0] for r in vault.db.execute("SELECT token_hash FROM sessions")]
    assert users["dr_smith"] not in stored


@pytest.mark.parametrize("name,pw", [
    ("ab", "long-enough-pass-1"),
    ("bad user!", "long-enough-pass-1"),
    ("<script>", "long-enough-pass-1"),
    ("bob", "short"),
    ("bobby", "my-name-is-bobby-1"),
])
def test_registration_validation(vault, name, pw):
    with pytest.raises(ValidationError):
        vault.register(name, pw)


def test_master_key_from_env(monkeypatch):
    monkeypatch.delenv("VAULT_MASTER_KEY", raising=False)
    with pytest.raises(ConfigError):
        load_master_key()
    monkeypatch.setenv("VAULT_MASTER_KEY", base64.b64encode(b"x" * 16).decode())
    with pytest.raises(ConfigError, match="32 bytes"):
        load_master_key()
    monkeypatch.setenv("VAULT_MASTER_KEY", "not base64!!")
    with pytest.raises(ConfigError):
        load_master_key()
    monkeypatch.setenv("VAULT_MASTER_KEY", base64.b64encode(b"k" * 32).decode())
    assert load_master_key() == b"k" * 32
