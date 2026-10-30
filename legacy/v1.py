"""Version 1 of the file system, kept as it was apart from this docstring and
a few comment edits.

The attack script (python -m vault.attacks) runs every attack against this
version and against the current one in vault/, so the difference is visible.
Do not use this version for anything real: see the README for its flaws.
"""

import hashlib          # hashlib: cryptographic hash functions (PBKDF2 for passwords, SHA-256 for tokens)
import hmac             # hmac: provides compare_digest(), a constant-time string comparison
import random           # random: NON-secure random numbers - used ONLY to demonstrate a weak token
import re               # re: regular expressions, used for whitelist input validation
import secrets          # secrets: cryptographically secure random numbers (salts and session tokens)
import sqlite3          # sqlite3: built-in SQL database engine that stores users, sessions and files
import time             # time: current time, used for token expiry
from pathlib import Path  # "from X import Y" imports only Y; Path is an object-oriented file path

# ==========================================================================
# CONFIGURATION CONSTANTS
# By convention, names written in UPPER_CASE are constants (values that never change).
# ==========================================================================
PBKDF2_ITERATIONS = 200_000          # number of hashing rounds; the "_" is only a digit separator (= 200000).
                                     # More rounds make each password guess slower for an attacker.
SALT_BYTES = 16                      # length of the random salt in bytes (16 bytes = 128 bits)
TOKEN_BYTES = 32                     # length of a session token in bytes (32 bytes = 256 bits)
TOKEN_TTL_SECONDS = 30 * 60          # "time to live" of a token: 30 minutes x 60 seconds = 1800 seconds

# Unix-style permission bits. In Unix, r = 4, w = 2, x = 1, and they are added together
# (for example rw- = 4 + 2 = 6). This system only uses read and write.
READ = 4                             # the "r" bit
WRITE = 2                            # the "w" bit

# --------------------------------------------------------------------------
# Whitelist validation rules (regular expressions)
# A whitelist describes what IS allowed; everything else is rejected.
# This is safer than a blacklist, which tries to list every bad input.
# --------------------------------------------------------------------------
# r"..." is a "raw string": backslashes are kept as-is, which is what regex needs.
# ^ = start of text, $ = end of text, [A-Za-z0-9_] = one letter, digit or underscore,
# {3,32} = repeated between 3 and 32 times.
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
# Filename = 1-64 letters/digits/underscore/hyphen, then OPTIONALLY ( ... )? one dot and
# a 1-10 character extension. "\." means a literal dot. No "/", "\", ".." or ":" can match,
# so a filename can never contain a directory path.
FILENAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}(\.[A-Za-z0-9]{1,10})?$")
ALLOWED_GROUPS = {"doctors", "nurses", "admin", "reception"}  # {...} creates a set (fast membership test)
PASSWORD_MIN, PASSWORD_MAX = 8, 128  # tuple unpacking: assigns 8 to PASSWORD_MIN and 128 to PASSWORD_MAX


# ==========================================================================
# CUSTOM EXCEPTIONS
# "class Name(Parent):" creates a new class that inherits from Parent.
# Raising different exception types lets the caller tell WHY something failed.
# ==========================================================================
class ValidationError(ValueError):   # inherits from Python's built-in ValueError
    """Input failed whitelist validation (possible malicious input)."""


class AuthenticationError(Exception):  # inherits from the base Exception class
    """Login failed or the session token is invalid/expired."""


class AccessDeniedError(PermissionError):  # inherits from Python's built-in PermissionError
    """User is authenticated but lacks permission for the operation."""


# ==========================================================================
# INPUT VALIDATION FUNCTIONS
# "def name(parameters):" defines a function. Each function below either returns
# the value unchanged (valid) or raises ValidationError (invalid).
# ==========================================================================
def validate_username(username):
    """Allow only 3-32 letters, digits or underscores (blocks SQL and script characters)."""
    # isinstance(x, str) checks that x is a string; fullmatch() checks the WHOLE string matches the regex.
    # "not A or not B" -> reject if it is not a string OR it does not match the whitelist.
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        # "raise" stops the function and sends the error back to the caller.
        raise ValidationError("Invalid username: use 3-32 letters, digits or underscore")
    return username  # "return" sends the (valid) value back to the caller


def validate_filename(filename):
    """Allow only simple file names such as 'patient_101.txt' (blocks path traversal)."""
    if not isinstance(filename, str) or not FILENAME_RE.fullmatch(filename):  # same pattern as above
        raise ValidationError("Invalid filename: only letters, digits, '_', '-' and one extension allowed")
    return filename


def validate_password(password):
    """Password policy: 8-128 characters and must contain at least one letter and one digit."""
    # "A <= x <= B" is Python's chained comparison: true only when x is between A and B.
    # len() returns the number of characters in the string.
    if not isinstance(password, str) or not (PASSWORD_MIN <= len(password) <= PASSWORD_MAX):
        # f"..." is an f-string: values inside {} are inserted into the text.
        raise ValidationError(f"Password must be {PASSWORD_MIN}-{PASSWORD_MAX} characters")
    # re.search() looks for the pattern ANYWHERE in the text; \d means any digit 0-9.
    if not (re.search(r"[A-Za-z]", password) and re.search(r"\d", password)):
        raise ValidationError("Password must contain letters and digits")
    return password


def validate_group(group):
    """The group must be one of the known hospital roles."""
    if group not in ALLOWED_GROUPS:  # "not in" checks that the value is missing from the set
        # sorted() turns the set into an alphabetically sorted list for a readable message.
        raise ValidationError(f"Invalid group: must be one of {sorted(ALLOWED_GROUPS)}")
    return group


def validate_mode(mode):
    """A permission mode must be an integer between 0o000 and 0o777 (octal, like Unix chmod)."""
    # 0o777 is an octal (base-8) number literal, the same notation Unix uses for permissions.
    if not isinstance(mode, int) or not (0 <= mode <= 0o777):
        raise ValidationError("Invalid mode: must be an octal value between 000 and 777")
    return mode


# ==========================================================================
# PASSWORD HASHING
# Passwords are never stored. We store a random salt and a slow, salted hash.
# ==========================================================================
def hash_password(password, salt=None):
    """Return (salt_hex, hash_hex) using PBKDF2-HMAC-SHA256 with a random salt."""
    # "salt=None" is a default parameter value: if the caller does not pass a salt, it is None.
    if salt is None:                                  # "is None" is the correct way to test for None
        salt = secrets.token_bytes(SALT_BYTES)        # new random salt from the OS secure random generator
    # pbkdf2_hmac(algorithm, password_bytes, salt, iterations) runs SHA-256 200,000 times.
    # .encode("utf-8") converts the text password into bytes, which hashing functions require.
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    # .hex() turns bytes into readable hexadecimal text so it can be stored in the database.
    # "return a, b" returns a tuple of two values.
    return salt.hex(), digest.hex()


def verify_password(password, salt_hex, hash_hex):
    """Re-hash the given password with the stored salt and compare it to the stored hash."""
    # bytes.fromhex() converts the stored hex text back into bytes.
    # "_" is a throw-away variable name: we do not need the returned salt, only the hash.
    _, candidate = hash_password(password, bytes.fromhex(salt_hex))
    # compare_digest() takes the same time whether the first or the last character differs,
    # so an attacker cannot learn the hash by measuring response time (timing attack).
    return hmac.compare_digest(candidate, hash_hex)   # constant-time comparison


# ==========================================================================
# TOKENS: WEAK vs STRONG
# ==========================================================================
def generate_weak_token(seed=None):
    """INSECURE - for demonstration only.
    Uses the `random` module (Mersenne Twister) seeded with the current time.
    Anyone who knows roughly when the token was created can reproduce it."""
    # Conditional expression "A if condition else B":
    # use the current time (in whole seconds) as the seed unless a seed was given.
    # random.Random(seed) creates a generator whose output is fully decided by the seed.
    rng = random.Random(int(time.time()) if seed is None else seed)
    # randint(0, 999_999) picks a number from 0 to 999999 (only one million possibilities).
    # "%06d" % number formats it as a 6-digit string with leading zeros, e.g. 42 -> "000042".
    return "%06d" % rng.randint(0, 999_999)


def generate_strong_token():
    """SECURE - 256 bits from the operating system CSPRNG (`secrets`)."""
    # token_urlsafe(32) takes 32 random bytes from the OS and encodes them as URL-safe text
    # (about 43 characters). 2^256 possible values: impossible to guess or brute force.
    return secrets.token_urlsafe(TOKEN_BYTES)


def token_digest(token):
    """Only the SHA-256 digest of a token is stored, never the token itself."""
    # If the database is stolen, the attacker sees only hashes and cannot use them as tokens.
    # .hexdigest() returns the hash as a 64-character hexadecimal string.
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def permission_string(mode):
    """0o640 -> 'rw-r-----' (execute bit shown for completeness)."""
    out = ""                          # start with an empty string and build it up
    for shift in (6, 3, 0):           # "for x in (...)" loops over owner (6), group (3), other (0)
        # ">>" shifts the bits right; "& 0o7" keeps only the last 3 bits.
        # Example: 0o640 >> 6 = 0o6 (owner = rw-), (0o640 >> 3) & 0o7 = 0o4 (group = r--).
        bits = (mode >> shift) & 0o7
        # "bits & 4" is non-zero when the read bit is set; "+=" appends to the string.
        out += ("r" if bits & 4 else "-") + ("w" if bits & 2 else "-") + ("x" if bits & 1 else "-")
    return out


# ==========================================================================
# THE SECURE FILE SYSTEM CLASS
# A class groups data (attributes, e.g. self.db) and behaviour (methods, e.g. login).
# "self" refers to the current object and is the first parameter of every method.
# ==========================================================================
class SecureFileSystem:
    def __init__(self, base_dir, token_ttl=TOKEN_TTL_SECONDS):
        """__init__ is the constructor: it runs automatically when SecureFileSystem(...) is created."""
        # Path(...).resolve() turns the folder into a full absolute path with ".." removed.
        self.base_dir = Path(base_dir).resolve()
        # The "/" operator on Path objects joins path parts: base_dir / "storage".
        # All patient files live ONLY inside this storage folder.
        self.storage_dir = (self.base_dir / "storage").resolve()
        # mkdir creates the folder; parents=True also creates missing parent folders,
        # exist_ok=True means "no error if it already exists".
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.token_ttl = token_ttl                       # how long new tokens stay valid (seconds)
        # Open (or create) the SQLite database file. str() converts the Path to text.
        self.db = sqlite3.connect(str(self.base_dir / "hospital.db"))
        # SQLite does not enforce REFERENCES (foreign keys) unless this setting is turned on.
        self.db.execute("PRAGMA foreign_keys = ON")
        self._create_tables()                            # a leading "_" marks an internal helper method
        # Dummy hash so failed logins for unknown users take the same time
        # (otherwise an attacker could tell which usernames exist by timing the response).
        self._dummy_salt, self._dummy_hash = hash_password("dummy-password-1")

    def _create_tables(self):
        """Create the three database tables if they do not exist yet."""
        # executescript() runs several SQL statements at once. The SQL is a fixed string
        # written by the developer; it contains NO user input, so it is safe.
        # users:    one row per staff member (password stored only as salt + hash)
        # sessions: one row per logged-in token (token stored only as a SHA-256 hash)
        # files:    owner, group and permission mode of every file
        # PRIMARY KEY = unique value per row; NOT NULL = value is required;
        # REFERENCES users(username) = must match an existing user (foreign key).
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                username      TEXT PRIMARY KEY,
                salt          TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                user_group    TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                username   TEXT NOT NULL REFERENCES users(username),
                expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS files (
                filename   TEXT PRIMARY KEY,
                owner      TEXT NOT NULL REFERENCES users(username),
                file_group TEXT NOT NULL,
                mode       INTEGER NOT NULL
            );
            """
        )
        self.db.commit()                                 # commit() saves the changes to disk

    def close(self):
        """Close the database connection when we are finished."""
        self.db.close()

    # ======================================================================
    # 1. AUTHENTICATION
    # ======================================================================
    def register(self, username, password, group):
        """Create a new user account after validating every input."""
        validate_username(username)                      # raises ValidationError if the name is unsafe
        validate_password(password)                      # enforces the password policy
        validate_group(group)                            # group must be a known hospital role
        salt, pw_hash = hash_password(password)          # tuple unpacking of the (salt, hash) result
        try:                                             # "try" runs code that might raise an error
            # Parameterized query: user input is never concatenated into SQL.
            # Each "?" is a placeholder; the values in the tuple are sent separately, so the
            # database always treats them as DATA, never as SQL code (prevents SQL injection).
            self.db.execute(
                "INSERT INTO users (username, salt, password_hash, user_group) VALUES (?, ?, ?, ?)",
                (username, salt, pw_hash, group),        # the tuple of values for the 4 placeholders
            )
            self.db.commit()                             # save the new user
        except sqlite3.IntegrityError:                   # "except" catches the error raised in "try"
            # IntegrityError happens when the PRIMARY KEY (username) already exists.
            raise ValidationError("Username already exists")
        return True                                      # registration succeeded

    def login(self, username, password):
        """Returns a strong session token. Error message is identical for every failure."""
        try:
            validate_username(username)                  # reject malformed / malicious usernames early
        except ValidationError:
            # Convert to the SAME generic message used for every login failure,
            # so the attacker learns nothing about why the login failed.
            raise AuthenticationError("Invalid username or password")

        # Look up the user's salt and hash with a parameterized query.
        # (username,) - the trailing comma makes a one-item tuple, which execute() requires.
        # fetchone() returns the first matching row as a tuple, or None if there is no match.
        row = self.db.execute(
            "SELECT salt, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()

        if row is None:                                  # no such user
            # Still do a full (slow) hash so the response time is the same as for a real user.
            verify_password(str(password), self._dummy_salt, self._dummy_hash)
            raise AuthenticationError("Invalid username or password")
        # row[0] is the salt column and row[1] the password_hash column (tuples are indexed from 0).
        if not isinstance(password, str) or not verify_password(password, row[0], row[1]):
            raise AuthenticationError("Invalid username or password")   # wrong password

        token = generate_strong_token()                  # 256-bit random session token
        # Store only the token's SHA-256 hash and its expiry time (now + TTL seconds).
        self.db.execute(
            "INSERT INTO sessions (token_hash, username, expires_at) VALUES (?, ?, ?)",
            (token_digest(token), username, time.time() + self.token_ttl),
        )
        self.db.commit()
        return token                                     # the plain token is given ONLY to the user

    def authenticate(self, token):
        """Map a token to (username, group) or raise AuthenticationError."""
        # Reject anything that is not a non-empty string ("not token" is True for "").
        if not isinstance(token, str) or not token:
            raise AuthenticationError("Invalid or expired token")
        # JOIN combines rows of two tables: the session row (alias s) with its user row (alias u),
        # so one query returns the username, the user's group and the token's expiry time.
        # Two string literals placed next to each other are joined automatically by Python.
        row = self.db.execute(
            "SELECT s.username, u.user_group, s.expires_at FROM sessions s "
            "JOIN users u ON u.username = s.username WHERE s.token_hash = ?",
            (token_digest(token),),                      # look up by HASH of the presented token
        ).fetchone()
        if row is None:                                  # unknown, fake or tampered token
            raise AuthenticationError("Invalid or expired token")
        if row[2] < time.time():                         # row[2] = expires_at; expired if in the past
            # Remove the expired session so it can never be used again.
            self.db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_digest(token),))
            self.db.commit()
            raise AuthenticationError("Invalid or expired token")
        return row[0], row[1]                            # (username, group) of the logged-in user

    def logout(self, token):
        """Delete the session so the token stops working immediately."""
        # str(token) makes sure the value is text before hashing it.
        self.db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_digest(str(token)),))
        self.db.commit()

    # ======================================================================
    # 3. ACCESS CONTROL - Unix-style owner / group / other
    # ======================================================================
    def _get_file_meta(self, filename):
        """Return the owner, group and mode of a file, or raise FileNotFoundError."""
        row = self.db.execute(
            "SELECT owner, file_group, mode FROM files WHERE filename = ?", (filename,)
        ).fetchone()
        if row is None:                                  # file is not registered in the database
            raise FileNotFoundError(f"File '{filename}' does not exist")
        # {"key": value, ...} creates a dictionary (a set of named values).
        return {"owner": row[0], "group": row[1], "mode": row[2]}

    @staticmethod   # a decorator: this method does not use "self", so it can be called without an object
    def check_permission(username, user_group, meta, needed):
        """Unix rule: owner bits if owner, else group bits if same group, else other bits."""
        mode = meta["mode"]                              # dictionary lookup by key
        if username == meta["owner"]:                    # 1st class: the user owns the file
            bits = (mode >> 6) & 0o7                     #   -> use the owner digit (e.g. 6 in 640)
        elif user_group == meta["group"]:                # "elif" = else if. 2nd class: same group
            bits = (mode >> 3) & 0o7                     #   -> use the group digit (e.g. 4 in 640)
        else:                                            # 3rd class: everybody else
            bits = mode & 0o7                            #   -> use the other digit (e.g. 0 in 640)
        # "bits & needed" keeps only the requested bit (READ=4 or WRITE=2);
        # bool() turns the result into True (allowed) or False (denied).
        return bool(bits & needed)

    # ======================================================================
    # 4. SECURE FILE OPERATIONS
    # Every operation follows the same order:
    #   authenticate token -> validate & confine path -> check permission -> act
    # ======================================================================
    def _safe_path(self, filename):
        """Layer 1: whitelist regex. Layer 2: resolved path must stay inside storage."""
        validate_filename(filename)                      # Layer 1: reject "../", "\", "/", ":" etc.
        # resolve() produces the real absolute path, collapsing any ".." parts and symlinks.
        path = (self.storage_dir / filename).resolve()
        # Layer 2 (defence in depth): the file's parent folder must be EXACTLY the storage folder.
        # Even if Layer 1 had a bug, a path that escapes storage is refused here.
        if path.parent != self.storage_dir:
            raise ValidationError("Path traversal attempt blocked")
        return path

    def create_file(self, token, filename, content, mode=0o640):
        """Create a new file owned by the logged-in user. Default mode 640 = rw-r-----."""
        username, group = self.authenticate(token)       # who is making the request?
        path = self._safe_path(filename)                 # safe location inside storage
        validate_mode(mode)                              # mode must be between 000 and 777
        # "SELECT 1" just checks whether a row exists; a found row is "truthy" in Python.
        if self.db.execute("SELECT 1 FROM files WHERE filename = ?", (filename,)).fetchone():
            raise ValidationError("File already exists")  # do not let a user overwrite someone else's file
        path.write_text(content, encoding="utf-8")       # write the text content to disk
        # Record the owner, the owner's group and the permission mode in the database.
        self.db.execute(
            "INSERT INTO files (filename, owner, file_group, mode) VALUES (?, ?, ?, ?)",
            (filename, username, group, mode),
        )
        self.db.commit()
        return True

    def read_file(self, token, filename):
        """Return the file's content if the user holds the READ permission."""
        username, group = self.authenticate(token)       # 1. valid, unexpired token required
        path = self._safe_path(filename)                 # 2. path traversal prevention
        meta = self._get_file_meta(filename)             # 3. owner / group / mode of the file
        if not self.check_permission(username, group, meta, READ):   # 4. authorization check
            raise AccessDeniedError(f"{username} has no READ permission on {filename}")
        return path.read_text(encoding="utf-8")          # 5. only now is the file actually read

    def write_file(self, token, filename, content):
        """Replace the file's content if the user holds the WRITE permission."""
        username, group = self.authenticate(token)       # same 5 steps as read_file,
        path = self._safe_path(filename)                 # but checking the WRITE bit
        meta = self._get_file_meta(filename)
        if not self.check_permission(username, group, meta, WRITE):
            raise AccessDeniedError(f"{username} has no WRITE permission on {filename}")
        path.write_text(content, encoding="utf-8")
        return True

    def chmod(self, token, filename, mode):
        """Only the owner may change a file's permissions (as in Unix)."""
        username, _ = self.authenticate(token)           # "_" ignores the group; it is not needed here
        self._safe_path(filename)                        # validate the filename (result not needed)
        validate_mode(mode)
        meta = self._get_file_meta(filename)
        if username != meta["owner"]:                    # "!=" means "not equal"
            raise AccessDeniedError("Only the file owner can change permissions")
        self.db.execute("UPDATE files SET mode = ? WHERE filename = ?", (mode, filename))
        self.db.commit()
        return True

    def list_files(self):
        """Return every file with its owner, group, mode and permission string (e.g. rw-r-----)."""
        rows = self.db.execute("SELECT filename, owner, file_group, mode FROM files ORDER BY filename")
        # List comprehension: [expression for item in iterable] builds a list in one line.
        # Here it builds one dictionary per database row.
        return [
            {"filename": r[0], "owner": r[1], "group": r[2], "mode": r[3], "perms": permission_string(r[3])}
            for r in rows
        ]
