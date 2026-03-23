"""Custom exception hierarchy for opvault."""


class OpvaultError(Exception):
    """Base exception for all opvault errors."""


class VaultNotFoundError(OpvaultError):
    """Raised when no vault exists at the expected path."""


class VaultExistsError(OpvaultError):
    """Raised when attempting to init a vault that already exists."""


class InvalidPasswordError(OpvaultError):
    """Raised when the master password is incorrect."""


class CredentialNotFoundError(OpvaultError):
    """Raised when a credential lookup finds no match."""


class CredentialExistsError(OpvaultError):
    """Raised when adding a credential with a duplicate name."""


class StorageError(OpvaultError):
    """Raised on file I/O failures."""


class CryptoError(OpvaultError):
    """Raised on encryption/decryption failures unrelated to password."""
