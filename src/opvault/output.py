"""Rich-based output helpers for opvault CLI."""

from __future__ import annotations

import sys
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from opvault.models import Credential


def _console() -> Console:
    """Create a stdout console (factory for CliRunner compatibility)."""
    return Console(highlight=False)


def _err_console() -> Console:
    """Create a stderr console (factory for CliRunner compatibility)."""
    return Console(stderr=True, highlight=False)


def print_error(msg: str) -> None:
    """Print a red error message to stderr and exit."""
    _err_console().print(f"[bold red]error:[/bold red] {escape(msg)}")
    sys.exit(1)


def print_success(msg: str) -> None:
    """Print a green success message."""
    _console().print(f"[green]{escape(msg)}[/green]")


def print_warning(msg: str) -> None:
    """Print a yellow warning message."""
    _console().print(f"[yellow]{escape(msg)}[/yellow]")


def print_credential(cred: Credential) -> None:
    """Display a single credential as a key-value table."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold")
    table.add_column("Value")

    table.add_row("Name:", cred.name)
    table.add_row("Type:", cred.type)
    table.add_row("Secret:", cred.secret)
    if cred.username:
        table.add_row("Username:", cred.username)
    if cred.url:
        table.add_row("URL:", cred.url)
    if cred.scope:
        table.add_row("Scope:", cred.scope)
    if cred.note:
        table.add_row("Note:", cred.note)
    table.add_row("Added:", cred.added)

    _console().print(table)


def print_credential_table(creds: list[Credential]) -> None:
    """Display credentials as a table."""
    table = Table(box=None, padding=(0, 2))
    table.add_column("NAME", style="bold")
    table.add_column("TYPE")
    table.add_column("USERNAME")
    table.add_column("SCOPE")
    table.add_column("ADDED")

    for c in creds:
        table.add_row(
            c.name,
            c.type,
            c.username or "-",
            c.scope or "-",
            c.added[:10],
        )

    _console().print(table)


def print_status(info: dict[str, Any]) -> None:
    """Display vault status as a panel with key-value table."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold")
    table.add_column("Value")

    table.add_row("Vault:", str(info["vault_path"]))
    table.add_row("Version:", str(info["version"]))
    table.add_row("Created:", str(info["created"]))
    table.add_row("KDF:", str(info["kdf"]))
    table.add_row("Credentials:", str(info["total_credentials"]))

    by_type: dict[str, int] = info.get("by_type", {})
    if by_type:
        for t, count in sorted(by_type.items()):
            table.add_row(f"  {t}:", str(count))

    _console().print(Panel(table, title="Vault Status", expand=False))
