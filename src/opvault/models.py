"""Dataclass models for opvault."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from opvault.constants import (
    CREDENTIAL_TYPES,
    DEFAULT_CREDENTIAL_TYPE,
    KDF_PBKDF2,
    VAULT_VERSION,
)
from opvault.exceptions import CredentialExistsError, CredentialNotFoundError

# Credential names: alphanumeric, hyphens, underscores, dots, slashes, max 128 chars
_CREDENTIAL_NAME_RE = re.compile(r"^[a-zA-Z0-9._/][a-zA-Z0-9._/ -]{0,127}$")


def validate_credential_name(name: str) -> str:
    """Validate and return a stripped credential name."""
    name = name.strip()
    if not _CREDENTIAL_NAME_RE.match(name):
        msg = (
            f"Invalid credential name: {name!r}. "
            "Use alphanumeric, hyphens, underscores, dots, slashes (1-128 chars)."
        )
        raise ValueError(msg)
    return name


@dataclass
class Credential:
    """A single stored credential."""

    name: str
    secret: str
    type: str = DEFAULT_CREDENTIAL_TYPE
    username: str = ""
    url: str = ""
    scope: str = ""
    note: str = ""
    added: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        self.name = validate_credential_name(self.name)
        if self.type not in CREDENTIAL_TYPES:
            msg = f"Invalid credential type: {self.type!r}. Must be one of {sorted(CREDENTIAL_TYPES)}"
            raise ValueError(msg)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "secret": self.secret,
            "type": self.type,
            "username": self.username,
            "url": self.url,
            "scope": self.scope,
            "note": self.note,
            "added": self.added,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Credential:
        return cls(
            name=data["name"],
            secret=data["secret"],
            type=data.get("type", DEFAULT_CREDENTIAL_TYPE),
            username=data.get("username", ""),
            url=data.get("url", ""),
            scope=data.get("scope", ""),
            note=data.get("note", ""),
            added=data.get("added", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class VaultConfig:
    """Vault configuration stored in vault.conf."""

    version: int = VAULT_VERSION
    created: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    kdf: str = KDF_PBKDF2
    kdf_params: dict[str, Any] = field(default_factory=dict)
    salt: str = ""  # base64-encoded
    verification_blob: str = ""  # base64-encoded

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "created": self.created,
            "kdf": self.kdf,
            "kdf_params": self.kdf_params,
            "salt": self.salt,
            "verification_blob": self.verification_blob,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VaultConfig:
        return cls(
            version=data["version"],
            created=data["created"],
            kdf=data["kdf"],
            kdf_params=data.get("kdf_params", {}),
            salt=data["salt"],
            verification_blob=data["verification_blob"],
        )


@dataclass
class VaultData:
    """Decrypted vault contents."""

    credentials: list[Credential] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_credential(self, credential: Credential) -> None:
        if any(c.name == credential.name for c in self.credentials):
            raise CredentialExistsError(f"Credential already exists: {credential.name!r}")
        self.credentials.append(credential)

    def get_credential(self, name: str) -> Credential:
        for c in self.credentials:
            if c.name == name:
                return c
        raise CredentialNotFoundError(f"Credential not found: {name!r}")

    def remove_credential(self, name: str) -> Credential:
        for i, c in enumerate(self.credentials):
            if c.name == name:
                return self.credentials.pop(i)
        raise CredentialNotFoundError(f"Credential not found: {name!r}")

    def list_credentials(
        self,
        type_filter: str | None = None,
        scope_filter: str | None = None,
    ) -> list[Credential]:
        results = self.credentials
        if type_filter:
            results = [c for c in results if c.type == type_filter]
        if scope_filter:
            results = [c for c in results if c.scope == scope_filter]
        return results

    def purge(self, type_filter: str | None = None) -> int:
        if type_filter:
            before = len(self.credentials)
            self.credentials = [c for c in self.credentials if c.type != type_filter]
            return before - len(self.credentials)
        count = len(self.credentials)
        self.credentials.clear()
        return count

    def to_dict(self) -> dict[str, Any]:
        return {
            "credentials": [c.to_dict() for c in self.credentials],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VaultData:
        credentials = [Credential.from_dict(c) for c in data.get("credentials", [])]
        return cls(
            credentials=credentials,
            metadata=data.get("metadata", {}),
        )
