"""File I/O for the .vault/ directory."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from opvault.constants import VAULT_CONF, VAULT_DIR, VAULT_ENC, VAULT_GITIGNORE
from opvault.exceptions import StorageError, VaultExistsError, VaultNotFoundError
from opvault.models import VaultConfig


def get_vault_path(base_path: Path | None = None) -> Path:
    """Resolve the .vault/ directory path."""
    base = base_path or Path.cwd()
    return base / VAULT_DIR


def vault_exists(base_path: Path | None = None) -> bool:
    """Check if a vault exists at the given base path."""
    vault_path = get_vault_path(base_path)
    return (vault_path / VAULT_CONF).is_file()


def init_vault_dir(base_path: Path | None = None) -> Path:
    """Create the .vault/ directory structure.

    Returns:
        Path to the created .vault/ directory.

    Raises:
        VaultExistsError: If a vault already exists.
        StorageError: On I/O failure.
    """
    vault_path = get_vault_path(base_path)

    if vault_exists(base_path):
        raise VaultExistsError(f"Vault already exists at {vault_path}")

    try:
        vault_path.mkdir(parents=True, exist_ok=True)
        # .gitignore inside .vault/ to exclude all vault data from git
        gitignore = vault_path / VAULT_GITIGNORE
        gitignore.write_text("*\n", encoding="utf-8")
    except OSError as e:
        raise StorageError(f"Failed to create vault directory: {e}") from e

    return vault_path


def read_vault_conf(base_path: Path | None = None) -> VaultConfig:
    """Read and parse vault.conf.

    Raises:
        VaultNotFoundError: If vault.conf does not exist.
        StorageError: On parse/read failure.
    """
    conf_path = get_vault_path(base_path) / VAULT_CONF

    if not conf_path.is_file():
        raise VaultNotFoundError(f"No vault found at {conf_path.parent}")

    try:
        data = json.loads(conf_path.read_text(encoding="utf-8"))
        return VaultConfig.from_dict(data)
    except (json.JSONDecodeError, KeyError) as e:
        raise StorageError(f"Corrupt vault.conf: {e}") from e
    except OSError as e:
        raise StorageError(f"Failed to read vault.conf: {e}") from e


def write_vault_conf(config: VaultConfig, base_path: Path | None = None) -> None:
    """Atomically write vault.conf.

    Raises:
        StorageError: On I/O failure.
    """
    vault_path = get_vault_path(base_path)
    conf_path = vault_path / VAULT_CONF
    tmp_path = vault_path / f"{VAULT_CONF}.tmp"

    try:
        payload = json.dumps(config.to_dict(), indent=2) + "\n"
        tmp_path.write_text(payload, encoding="utf-8")
        tmp_path.replace(conf_path)
    except OSError as e:
        raise StorageError(f"Failed to write vault.conf: {e}") from e


def read_vault_enc(base_path: Path | None = None) -> bytes:
    """Read vault.enc and decode from base64.

    Returns:
        Raw encrypted bytes.

    Raises:
        VaultNotFoundError: If vault.enc does not exist.
        StorageError: On read/decode failure.
    """
    enc_path = get_vault_path(base_path) / VAULT_ENC

    if not enc_path.is_file():
        raise VaultNotFoundError(f"No encrypted vault data at {enc_path}")

    try:
        encoded = enc_path.read_text(encoding="utf-8").strip()
        return base64.b64decode(encoded)
    except Exception as e:
        raise StorageError(f"Failed to read vault.enc: {e}") from e


def write_vault_enc(data: bytes, base_path: Path | None = None) -> None:
    """Base64-encode and atomically write vault.enc.

    Raises:
        StorageError: On I/O failure.
    """
    vault_path = get_vault_path(base_path)
    enc_path = vault_path / VAULT_ENC
    tmp_path = vault_path / f"{VAULT_ENC}.tmp"

    try:
        encoded = base64.b64encode(data).decode("ascii") + "\n"
        tmp_path.write_text(encoded, encoding="utf-8")
        tmp_path.replace(enc_path)
    except OSError as e:
        raise StorageError(f"Failed to write vault.enc: {e}") from e


def delete_vault_dir(base_path: Path | None = None) -> None:
    """Delete the entire .vault/ directory. For testing/reset.

    Raises:
        StorageError: On I/O failure.
    """
    import shutil

    vault_path = get_vault_path(base_path)

    if not vault_path.exists():
        return

    try:
        shutil.rmtree(vault_path)
    except OSError as e:
        raise StorageError(f"Failed to delete vault: {e}") from e
