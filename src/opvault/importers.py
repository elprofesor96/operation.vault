"""Import credentials from JSON and text files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opvault.exceptions import StorageError
from opvault.models import Credential


def from_json(source: str | Path) -> list[Credential]:
    """Import credentials from a JSON file or string.

    Accepts either:
        - A list of credential dicts: [{...}, ...]
        - A dict with a "credentials" key: {"credentials": [{...}, ...]}
    """
    text = _read_source(source)

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise StorageError(f"Invalid JSON: {e}") from e

    items: list[dict[str, Any]]
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict) and "credentials" in data:
        items = data["credentials"]
    else:
        raise StorageError("JSON must be a list or an object with a 'credentials' key")

    return [Credential.from_dict(item) for item in items]


def from_text(source: str | Path, cred_type: str = "password") -> list[Credential]:
    """Import credentials from a text file (one per line).

    Supported formats:
        - user:password
        - name:user:password
    """
    text = _read_source(source)
    credentials: list[Credential] = []

    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(":", maxsplit=2)

        if len(parts) == 2:
            username, secret = parts
            name = f"import-{lineno}"
        elif len(parts) == 3:
            name, username, secret = parts
        else:
            raise StorageError(f"Line {lineno}: expected 'user:pass' or 'name:user:pass'")

        credentials.append(
            Credential(
                name=name.strip(),
                secret=secret.strip(),
                username=username.strip(),
                type=cred_type,
            )
        )

    return credentials


def _read_source(source: str | Path) -> str:
    """Read from a file path or return the string directly."""
    if isinstance(source, Path):
        try:
            return source.read_text(encoding="utf-8")
        except OSError as e:
            raise StorageError(f"Failed to read file: {e}") from e
    return source
