# patient-file-vault

A file store for hospital records with Unix-style permissions (owner / group / other, `rw-r-----`), encryption at rest and a tamper-evident access log.

There are two versions here. `legacy/v1.py` is the first one I wrote, and `vault/` is the rewrite. The attack script runs the same attacks against both:

```
python -m vault.attacks
```

```
attack                       v1       v2       what the attacker does
-------------------------------------------------------------------------------------------------
Join a privileged group      WORKS    blocked  sign up as a 'doctor', then read a patient file
Case-variant file overwrite  WORKS*   blocked  user with no write access creates PATIENT_101.TXT
List files without access    WORKS    blocked  list patient file names without a session / without access
Edit a record on disk        WORKS    blocked  change a record's bytes directly on disk
Swap two records             WORKS    blocked  copy one patient's file over another's
Roll back a record           WORKS    blocked  restore an older copy to hide a newly added allergy
Read a stolen disk           WORKS    blocked  read records from a copied disk or backup
Rewrite the access log       WORKS    blocked  rewrite the access log after a denied read
Online password guessing     WORKS    blocked  20 wrong passwords, then the right one
Path traversal               blocked  blocked  ../ and absolute paths in the file name
SQL injection                blocked  blocked  SQL in the username field
Token reuse after logout     blocked  blocked  reuse a session token after logout

* Windows and macOS (case-insensitive filesystems). Shows as n/a on Linux.

v2: 12/12 attacks blocked
```

## What was wrong with v1

v1 did the things these projects usually get marked on, and did them properly: salted PBKDF2, constant-time comparison, a dummy hash so unknown usernames take as long as real ones, parameterized SQL everywhere, whitelist validation, and a path check that refuses anything that resolves outside the storage folder. Path traversal, SQL injection and token reuse were all blocked from the start.

The permission model was what broke.

**Anyone could make themselves a doctor.** `register(username, password, group)` let the new user pick their own group. A file with mode `640` is readable by its group, so signing up as `doctors` gave read access to every doctor's patient files. The permission check was correct. The input it trusted wasn't. In v2, self-registration creates an account with no group, and only an admin can assign one.

**`PATIENT_101.TXT` overwrote `patient_101.txt`.** The database treated file names as case-sensitive, but Windows and macOS filesystems don't. A nurse with no write access to `patient_101.txt` could "create" `PATIENT_101.TXT`. The database saw a new name, while the disk wrote over the existing file. The write check was never reached, because as far as the code knew, this was a new file. `tests/test_v1_flaws.py` reproduces it, and CI runs that test on Windows and macOS. v2 stores files on disk under random IDs that users never choose, and makes names unique ignoring case.

**File names leaked without logging in.** `list_files()` didn't take a token and returned every file with its owner. `patient_101.txt` is already sensitive information. In v2 it needs a session and only shows files the caller can read.

**The disk was trusted completely.** Records sat on disk as plain text, and whatever was there got served. Someone with access to the server or a backup could read them, edit them, swap two patients' files, or put back an older version, and the system would never notice.

**There was no record of who read what.** For health records, that's usually a legal requirement on its own.

## What v2 adds

- **AES-256-GCM at rest.** The associated data is `file_id:version`, so editing, swapping or rolling back a file makes decryption fail with an `IntegrityError` instead of returning the wrong data.
- **Disk names are never user input.** Files are stored as `blobs/<uuid4>.bin`. The name a user picks is just a database column with a case-insensitive unique index. That removes path traversal and case tricks at the design level, not by filtering.
- **Groups are assigned by an admin.** The first admin is created with `bootstrap_admin()` on the server, and it refuses to run a second time.
- **A tamper-evident audit log.** Every read, write, chmod, delete and login, allowed or denied, is logged. Each row includes an HMAC of the previous row, so `audit.verify()` finds edited, deleted or reordered rows.
- **Separate keys per purpose.** One 32-byte master key from `VAULT_MASTER_KEY`, with HKDF deriving separate keys for files and for the audit log.
- **Account lockout** after 5 failed logins, and PBKDF2 raised from 200,000 to 600,000 iterations (the OWASP 2023 figure).
- **`list_files` only returns what you can read**, and owner-only `chmod` and `delete`.
- **A 1 MB file size cap**, and writes go to a temporary file and are then renamed into place.

## Run it

```bash
pip install -e ".[dev]"
python -m vault demo          # walkthrough: permissions, a tampered file, the access history
python -m vault.attacks       # the table above
pytest                        # 58 tests (57 + 1 that only runs on Windows/macOS)
```

```python
import base64, os
from vault import Vault, load_master_key

# export VAULT_MASTER_KEY="$(python -c 'import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())')"
vt = Vault("data", load_master_key())
vt.bootstrap_admin("it_admin", "...")
```

## Layout

```
vault/
  core.py        users, sessions, permissions, file operations
  crypto.py      AES-GCM, HKDF, master key loading
  audit.py       HMAC-chained access log
  validation.py  whitelist validation
  attacks.py     v1 vs v2 attack runner
legacy/v1.py     the original version, kept for comparison
tests/           58 tests, including ones that reproduce v1's flaws
docs/threat-model.md
```

## Known limits

- **Truncating the end of the audit log isn't detected on its own.** A shorter chain is still a valid chain. The fix is to ship the latest `(seq, mac)` to somewhere the database admin can't write, like a SIEM, and compare.
- **The master key is an environment variable.** In production it would live in a KMS or HSM, with envelope encryption so rotating it doesn't mean re-encrypting every file.
- **Lockout is per account,** so it can be used to lock someone out on purpose. Per-IP rate limiting would fix that.
- **Groups are one per user.** Real hospitals need several groups per user and, ideally, per-patient access lists (care team only), which is closer to ABAC than to Unix permissions.

## License

MIT
