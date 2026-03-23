"""Vault class — core orchestrator for opvault."""

from __future__ import annotations

import base64
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opvault.constants import (
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    EXPORT_FORMAT_VERSION,
    KDF_ARGON2ID,
    KDF_PBKDF2,
    PBKDF2_ITERATIONS,
)
from opvault.crypto import (
    create_verification_blob,
    decrypt,
    derive_key,
    encrypt,
    generate_salt,
    get_preferred_kdf,
    verify_password,
)
from opvault.exceptions import ExportError
from opvault.models import Credential, VaultConfig, VaultData
from opvault.storage import (
    delete_vault_dir,
    init_vault_dir,
    read_vault_conf,
    read_vault_enc,
    vault_exists,
    write_vault_conf,
    write_vault_enc,
)


class Vault:
    """High-level vault operations: init, unlock, CRUD, status."""

    def __init__(self, base_path: Path | None = None) -> None:
        self.base_path = base_path or Path.cwd()

    @classmethod
    def init(cls, password: str, base_path: Path | None = None) -> Vault:
        """Create a new vault with the given master password.

        Returns:
            A Vault instance pointing to the new vault.
        """
        base = base_path or Path.cwd()
        init_vault_dir(base)

        kdf = get_preferred_kdf()
        salt = generate_salt()

        kdf_params = _build_kdf_params(kdf)
        key = derive_key(password, salt, kdf, kdf_params)
        verification_blob = create_verification_blob(key)

        config = VaultConfig(
            kdf=kdf,
            kdf_params=kdf_params,
            salt=base64.b64encode(salt).decode("ascii"),
            verification_blob=verification_blob,
        )
        write_vault_conf(config, base)

        # Write empty vault data
        empty = VaultData()
        _save_vault_data(empty, key, base)

        return cls(base)

    def _unlock(self, password: str) -> bytes:
        """Derive key and verify against the stored verification blob.

        Returns:
            The derived 32-byte key.
        """
        config = read_vault_conf(self.base_path)
        salt = base64.b64decode(config.salt)
        key = derive_key(password, salt, config.kdf, config.kdf_params)
        verify_password(key, config.verification_blob)
        return key

    def add(self, password: str, credential: Credential) -> None:
        """Add a credential to the vault."""
        key = self._unlock(password)
        data = _load_vault_data(key, self.base_path)
        data.add_credential(credential)
        _save_vault_data(data, key, self.base_path)

    def get(self, password: str, name: str) -> Credential:
        """Retrieve a credential by name."""
        key = self._unlock(password)
        data = _load_vault_data(key, self.base_path)
        return data.get_credential(name)

    def list_(
        self,
        password: str,
        type_filter: str | None = None,
        scope_filter: str | None = None,
    ) -> list[Credential]:
        """List credentials with optional filters."""
        key = self._unlock(password)
        data = _load_vault_data(key, self.base_path)
        return data.list_credentials(type_filter=type_filter, scope_filter=scope_filter)

    def remove(self, password: str, name: str) -> Credential:
        """Remove a credential by name."""
        key = self._unlock(password)
        data = _load_vault_data(key, self.base_path)
        removed = data.remove_credential(name)
        _save_vault_data(data, key, self.base_path)
        return removed

    def purge(self, password: str, type_filter: str | None = None) -> int:
        """Remove all credentials, optionally filtered by type.

        Returns:
            Number of credentials removed.
        """
        key = self._unlock(password)
        data = _load_vault_data(key, self.base_path)
        count = data.purge(type_filter=type_filter)
        _save_vault_data(data, key, self.base_path)
        return count

    def status(self, password: str) -> dict[str, Any]:
        """Return vault status information."""
        config = read_vault_conf(self.base_path)
        key = self._unlock(password)
        data = _load_vault_data(key, self.base_path)

        type_counts: dict[str, int] = {}
        for cred in data.credentials:
            type_counts[cred.type] = type_counts.get(cred.type, 0) + 1

        return {
            "vault_path": str(self.base_path / ".opvault"),
            "version": config.version,
            "created": config.created,
            "kdf": config.kdf,
            "total_credentials": len(data.credentials),
            "by_type": type_counts,
        }

    def export_vault(self, password: str) -> tuple[dict[str, Any], int, str]:
        """Export the vault re-encrypted under a fresh export password.

        Returns:
            (export_dict, credential_count, export_password)
        """
        key = self._unlock(password)
        data = _load_vault_data(key, self.base_path)
        config = read_vault_conf(self.base_path)

        export_password = secrets.token_urlsafe(18)
        export_salt = generate_salt()
        export_kdf_params = {KDF_PBKDF2: {"iterations": PBKDF2_ITERATIONS}}[KDF_PBKDF2]
        export_key = derive_key(export_password, export_salt, KDF_PBKDF2, export_kdf_params)
        export_verification = create_verification_blob(export_key)

        plaintext = json.dumps(data.to_dict(), indent=2).encode("utf-8")
        vault_data_enc = encrypt(plaintext, export_key)

        export_dict: dict[str, Any] = {
            "opvault_export": EXPORT_FORMAT_VERSION,
            "kdf": KDF_PBKDF2,
            "kdf_params": export_kdf_params,
            "salt": base64.b64encode(export_salt).decode("ascii"),
            "verification_blob": export_verification,
            "vault_data": base64.b64encode(vault_data_enc).decode("ascii"),
            "created": datetime.now(UTC).isoformat(),
            "source_version": config.version,
        }
        return export_dict, len(data.credentials), export_password

    @classmethod
    def import_vault(
        cls,
        export_data: dict[str, Any],
        export_password: str,
        master_password: str,
        base_path: Path | None = None,
        force: bool = False,
    ) -> tuple[Vault, int]:
        """Import a vault from an export dict, re-encrypting under a new master password.

        Returns:
            (Vault, credential_count)
        """
        base = base_path or Path.cwd()

        fmt_version = export_data.get("opvault_export")
        if fmt_version != EXPORT_FORMAT_VERSION:
            raise ExportError(
                f"Unsupported export format version: {fmt_version} "
                f"(expected {EXPORT_FORMAT_VERSION})"
            )

        # Decrypt export data
        export_salt = base64.b64decode(export_data["salt"])
        export_kdf = export_data["kdf"]
        export_kdf_params = export_data.get("kdf_params", {})
        export_key = derive_key(export_password, export_salt, export_kdf, export_kdf_params)
        verify_password(export_key, export_data["verification_blob"])

        vault_data_enc = base64.b64decode(export_data["vault_data"])
        plaintext = decrypt(vault_data_enc, export_key)
        vault_data = VaultData.from_dict(json.loads(plaintext.decode("utf-8")))
        credential_count = len(vault_data.credentials)

        # Handle existing vault
        if vault_exists(base):
            if not force:
                raise ExportError("Vault already exists. Use --force to overwrite.")
            delete_vault_dir(base)

        # Re-key under master password
        kdf = get_preferred_kdf()
        salt = generate_salt()
        kdf_params = _build_kdf_params(kdf)
        key = derive_key(master_password, salt, kdf, kdf_params)
        verification_blob = create_verification_blob(key)

        init_vault_dir(base)
        config = VaultConfig(
            kdf=kdf,
            kdf_params=kdf_params,
            salt=base64.b64encode(salt).decode("ascii"),
            verification_blob=verification_blob,
        )
        write_vault_conf(config, base)
        _save_vault_data(vault_data, key, base)

        return cls(base), credential_count

    def exists(self) -> bool:
        """Check if a vault exists at the base path."""
        return vault_exists(self.base_path)


def _build_kdf_params(kdf: str) -> dict[str, Any]:
    """Build default KDF parameters for the given KDF."""
    if kdf == KDF_ARGON2ID:
        return {
            "time_cost": ARGON2_TIME_COST,
            "memory_cost": ARGON2_MEMORY_COST,
            "parallelism": ARGON2_PARALLELISM,
        }
    return {"iterations": PBKDF2_ITERATIONS}


def _load_vault_data(key: bytes, base_path: Path | None = None) -> VaultData:
    """Decrypt and deserialize vault data."""
    raw = read_vault_enc(base_path)
    plaintext = decrypt(raw, key)
    data = json.loads(plaintext.decode("utf-8"))
    return VaultData.from_dict(data)


def _save_vault_data(data: VaultData, key: bytes, base_path: Path | None = None) -> None:
    """Serialize and encrypt vault data."""
    plaintext = json.dumps(data.to_dict(), indent=2).encode("utf-8")
    ciphertext = encrypt(plaintext, key)
    write_vault_enc(ciphertext, base_path)
