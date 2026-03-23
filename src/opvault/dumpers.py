"""Dump credentials to JSON, CSV, and Markdown formats."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from opvault.models import Credential

_REDACT_FIELDS = frozenset({"secret"})
_REDACT_PLACEHOLDER = "********"


def _redact(data: dict[str, Any]) -> dict[str, Any]:
    """Replace sensitive fields with placeholder."""
    return {k: (_REDACT_PLACEHOLDER if k in _REDACT_FIELDS else v) for k, v in data.items()}


def to_json(credentials: list[Credential], redact: bool = False) -> str:
    """Dump credentials as pretty-printed JSON."""
    items = [c.to_dict() for c in credentials]
    if redact:
        items = [_redact(item) for item in items]
    return json.dumps(items, indent=2) + "\n"


def to_csv(credentials: list[Credential], redact: bool = False) -> str:
    """Dump credentials as CSV."""
    if not credentials:
        return ""

    fieldnames = list(credentials[0].to_dict().keys())
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()

    for cred in credentials:
        row = cred.to_dict()
        if redact:
            row = _redact(row)
        writer.writerow(row)

    return buf.getvalue()


def to_markdown(credentials: list[Credential], redact: bool = False) -> str:
    """Dump credentials as a Markdown table."""
    if not credentials:
        return ""

    headers = ["Name", "Type", "Username", "Secret", "URL", "Scope", "Note", "Added"]
    keys = ["name", "type", "username", "secret", "url", "scope", "note", "added"]

    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join("---" for _ in headers) + " |")

    for cred in credentials:
        data = cred.to_dict()
        if redact:
            data = _redact(data)
        values = [str(data.get(k, "")) for k in keys]
        lines.append("| " + " | ".join(values) + " |")

    return "\n".join(lines) + "\n"
