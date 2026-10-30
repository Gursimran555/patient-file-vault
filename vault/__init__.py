"""Patient file vault: Unix-style permissions, encryption at rest, tamper-evident audit log."""

from .core import (READ, WRITE, AccessDeniedError, AuthenticationError, NotFound, Vault,
                   permission_string)
from .crypto import ConfigError, IntegrityError, load_master_key, new_master_key
from .validation import ValidationError

__all__ = ["Vault", "AccessDeniedError", "AuthenticationError", "ConfigError", "IntegrityError",
           "NotFound", "ValidationError", "READ", "WRITE", "load_master_key", "new_master_key",
           "permission_string"]
__version__ = "2.0.0"
