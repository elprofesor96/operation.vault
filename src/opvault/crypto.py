"""AES-256-GCM encryption and key derivation for opvault."""

from __future__ import annotations

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256

from opvault.constants import (
    KDF_ARGON2ID,
    KDF_PBKDF2,
    KEY_LENGTH,
    NONCE_LENGTH,
    PBKDF2_ITERATIONS,
    SALT_LENGTH,
    VERIFICATION_TOKEN_LENGTH,
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
)
from opvault.exceptions import CryptoError, InvalidPasswordError


def is_argon2_available() -> bool:
    """Check if argon2-cffi is installed."""
    try:
        import argon2  # noqa: F401

        return True
    except ImportError:
        return False


def get_preferred_kdf() -> str:
    """Return the best available KDF identifier."""
    return KDF_ARGON2ID if is_argon2_available() else KDF_PBKDF2


def generate_salt() -> bytes:
    """Generate a cryptographically random salt."""
    return os.urandom(SALT_LENGTH)


def derive_key(
    password: str,
    salt: bytes,
    kdf: str = KDF_PBKDF2,
    kdf_params: dict | None = None,
) -> bytes:
    """Derive a 256-bit key from a password and salt.

    Args:
        password: Master password.
        salt: Random salt bytes.
        kdf: KDF identifier (pbkdf2-sha256 or argon2id).
        kdf_params: Optional override for KDF parameters.

    Returns:
        32-byte derived key.
    """
    params = kdf_params or {}

    if kdf == KDF_PBKDF2:
        iterations = params.get("iterations", PBKDF2_ITERATIONS)
        kdf_instance = PBKDF2HMAC(
            algorithm=SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=iterations,
        )
        return kdf_instance.derive(password.encode("utf-8"))

    if kdf == KDF_ARGON2ID:
        if not is_argon2_available():
            raise CryptoError("argon2-cffi is not installed but argon2id KDF was requested")

        from argon2.low_level import Type, hash_secret_raw

        time_cost = params.get("time_cost", ARGON2_TIME_COST)
        memory_cost = params.get("memory_cost", ARGON2_MEMORY_COST)
        parallelism = params.get("parallelism", ARGON2_PARALLELISM)

        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=KEY_LENGTH,
            type=Type.ID,
        )

    raise CryptoError(f"Unknown KDF: {kdf!r}")


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt plaintext with AES-256-GCM.

    Returns:
        nonce (12 bytes) || ciphertext || GCM tag (16 bytes).
    """
    nonce = os.urandom(NONCE_LENGTH)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM data.

    Args:
        data: nonce || ciphertext || tag.
        key: 32-byte derived key.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        InvalidPasswordError: On authentication failure (wrong key or tampered data).
    """
    if len(data) < NONCE_LENGTH + 16:
        raise CryptoError("Ciphertext too short")

    nonce = data[:NONCE_LENGTH]
    ciphertext = data[NONCE_LENGTH:]
    aesgcm = AESGCM(key)

    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise InvalidPasswordError("Decryption failed: wrong password or tampered data")


def create_verification_blob(key: bytes) -> str:
    """Create a verification blob by encrypting random bytes.

    Returns:
        Base64-encoded encrypted token.
    """
    token = os.urandom(VERIFICATION_TOKEN_LENGTH)
    encrypted = encrypt(token, key)
    return base64.b64encode(encrypted).decode("ascii")


def verify_password(key: bytes, blob: str) -> bool:
    """Verify a derived key against the stored verification blob.

    Returns:
        True if decryption succeeds.

    Raises:
        InvalidPasswordError: If the key cannot decrypt the blob.
    """
    raw = base64.b64decode(blob)
    decrypt(raw, key)
    return True
