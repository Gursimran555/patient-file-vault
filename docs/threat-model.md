# Threat model

**Assets:** patient records (confidentiality and integrity), the record of who accessed them, and staff accounts.

**Attackers:**
- **Insider with an account** (any staff member), trying to read or change records outside their role.
- **Outsider** who can reach the login and file API.
- **Someone with the disk or a backup**: an admin, a stolen laptop, a leaked backup. They have the files and the database, but not `VAULT_MASTER_KEY`.

| Threat | v1 | v2 control | Test |
|---|---|---|---|
| Self-assigned privileged group | Vulnerable | Register creates no group; only admin assigns | `test_self_registration_gets_no_group`, `test_only_admin_assigns_groups` |
| Case-variant name overwrites another user's file | Vulnerable on Windows/macOS | Random on-disk IDs; `name_key` unique on `casefold()` | `test_names_are_case_insensitive_and_unique`, `test_v1_case_variant_overwrite` |
| File name enumeration | Vulnerable (`list_files()` needs no token) | Session required, results filtered by read permission | `test_list_requires_session_and_filters` |
| Reading records from disk/backup | Vulnerable (plaintext) | AES-256-GCM | `test_plaintext_never_on_disk` |
| Editing a record on disk | Undetected | GCM tag | `test_tampered_blob_detected` |
| Swapping two records | Undetected | File id in AAD | `test_swapped_blob_detected` |
| Restoring an old version | Undetected | Version in AAD | `test_rollback_detected` |
| Hiding access after the fact | No log | HMAC-chained audit log | `test_chain_detects_edits` |
| Online password guessing | No limit | Lockout after 5 failures | `test_lockout` |
| Offline cracking of password hashes | PBKDF2 200k | PBKDF2 600k, per-user salt | `test_passwords_not_stored` |
| Username enumeration | Blocked (generic error + dummy hash) | Same | `test_same_error_for_every_failure` |
| SQL injection | Blocked (parameterized) | Same | attack script |
| Path traversal | Blocked (regex + resolved-path check) | Not possible: disk names are never user input | `test_bad_file_names` |
| Stolen session token from the DB | Blocked (only SHA-256 stored) | Same | `test_tokens_stored_hashed` |
| Owner-only operations bypassed | Blocked for chmod | chmod and delete owner-only | `test_only_owner_chmods_and_deletes` |
| Oversized uploads filling the disk | No limit | 1 MB cap | `test_file_size_limit` |

## Out of scope / known gaps

- Audit log tail truncation (see README).
- Key management beyond an environment variable.
- Transport security: this is a library, so TLS is the job of whatever serves it.
- Per-IP rate limiting.
- Multi-group users and per-patient care-team access.
