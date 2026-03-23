"""Click CLI for opvault."""

from __future__ import annotations

import stat
from pathlib import Path

import rich_click as click

from opvault.constants import CREDENTIAL_TYPES, DEFAULT_CREDENTIAL_TYPE
from opvault.exceptions import OpvaultError
from opvault.exporters import to_csv, to_json, to_markdown
from opvault.importers import from_json, from_text
from opvault.models import Credential
from opvault.output import (
    print_credential,
    print_credential_table,
    print_error,
    print_status,
    print_success,
    print_warning,
)
from opvault.vault import Vault

SESSION_DIR = Path.home() / ".opvault"
SESSION_FILE = SESSION_DIR / "session"


def _get_password(confirm: bool = False) -> str:
    """Prompt for the master password, checking session cache first."""
    cached = _read_session()
    if cached and not confirm:
        return cached
    password = click.prompt("Master password", hide_input=True, confirmation_prompt=confirm)
    return password


def _read_session() -> str | None:
    """Read cached password from session file if it exists."""
    if not SESSION_FILE.is_file():
        return None
    try:
        return SESSION_FILE.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def _write_session(password: str) -> None:
    """Write password to session file with restrictive permissions."""
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    SESSION_FILE.write_text(password + "\n", encoding="utf-8")
    SESSION_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600


def _clear_session() -> None:
    """Remove the session file."""
    try:
        SESSION_FILE.unlink(missing_ok=True)
    except OSError:
        pass


@click.group()
@click.version_option(package_name="opvault")
@click.option(
    "--vault-path",
    type=click.Path(path_type=Path),
    default=None,
    envvar="OPVAULT_PATH",
    help="Base path for the vault (default: current directory).",
)
@click.pass_context
def cli(ctx: click.Context, vault_path: Path | None) -> None:
    """opvault — secure credential storage for security engagements."""
    ctx.ensure_object(dict)
    ctx.obj["base_path"] = vault_path


@cli.command()
@click.pass_context
def init(ctx: click.Context) -> None:
    """Initialize a new vault in the current directory."""
    base_path = ctx.obj["base_path"]
    try:
        password = _get_password(confirm=True)
        Vault.init(password, base_path)
        print_success("Vault initialized.")
    except OpvaultError as e:
        print_error(str(e))


@cli.command()
@click.argument("name")
@click.option("--secret", prompt=True, hide_input=True, help="The secret value.")
@click.option(
    "--type",
    "cred_type",
    type=click.Choice(sorted(CREDENTIAL_TYPES), case_sensitive=False),
    default=DEFAULT_CREDENTIAL_TYPE,
    help="Credential type.",
)
@click.option("--username", default="", help="Associated username.")
@click.option("--url", default="", help="Associated URL.")
@click.option("--scope", default="", help="Engagement scope tag.")
@click.option("--note", default="", help="Free-form note.")
@click.pass_context
def add(
    ctx: click.Context,
    name: str,
    secret: str,
    cred_type: str,
    username: str,
    url: str,
    scope: str,
    note: str,
) -> None:
    """Add a credential to the vault."""
    base_path = ctx.obj["base_path"]
    try:
        password = _get_password()
        credential = Credential(
            name=name,
            secret=secret,
            type=cred_type,
            username=username,
            url=url,
            scope=scope,
            note=note,
        )
        vault = Vault(base_path)
        vault.add(password, credential)
        print_success(f"Added: {name}")
    except (OpvaultError, ValueError) as e:
        print_error(str(e))


@cli.command()
@click.argument("name")
@click.option("--plain", is_flag=True, help="Print only the secret (for piping).")
@click.option("--field", type=str, default=None, help="Print a specific field value.")
@click.pass_context
def get(ctx: click.Context, name: str, plain: bool, field: str | None) -> None:
    """Retrieve a credential by name."""
    base_path = ctx.obj["base_path"]
    try:
        password = _get_password()
        vault = Vault(base_path)
        cred = vault.get(password, name)

        if plain:
            click.echo(cred.secret)
            return

        if field:
            value = cred.to_dict().get(field)
            if value is None:
                print_error(f"Unknown field: {field!r}")
            click.echo(value)
            return

        print_credential(cred)
    except OpvaultError as e:
        print_error(str(e))


@cli.command("list")
@click.option("--type", "type_filter", default=None, help="Filter by credential type.")
@click.option("--scope", "scope_filter", default=None, help="Filter by scope.")
@click.pass_context
def list_cmd(ctx: click.Context, type_filter: str | None, scope_filter: str | None) -> None:
    """List all credentials in the vault."""
    base_path = ctx.obj["base_path"]
    try:
        password = _get_password()
        vault = Vault(base_path)
        creds = vault.list_(password, type_filter=type_filter, scope_filter=scope_filter)

        if not creds:
            print_warning("No credentials found.")
            return

        print_credential_table(creds)
    except OpvaultError as e:
        print_error(str(e))


@cli.command()
@click.argument("name")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation.")
@click.pass_context
def remove(ctx: click.Context, name: str, yes: bool) -> None:
    """Remove a credential by name."""
    base_path = ctx.obj["base_path"]
    try:
        if not yes:
            click.confirm(f"Remove credential {name!r}?", abort=True)
        password = _get_password()
        vault = Vault(base_path)
        vault.remove(password, name)
        print_success(f"Removed: {name}")
    except OpvaultError as e:
        print_error(str(e))


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show vault status and statistics."""
    base_path = ctx.obj["base_path"]
    try:
        password = _get_password()
        vault = Vault(base_path)
        info = vault.status(password)
        print_status(info)
    except OpvaultError as e:
        print_error(str(e))


@cli.command()
@click.option("--type", "type_filter", default=None, help="Only purge this credential type.")
@click.option("--force", "-f", is_flag=True, help="Skip confirmation.")
@click.pass_context
def purge(ctx: click.Context, type_filter: str | None, force: bool) -> None:
    """Remove all credentials (or all of a given type)."""
    base_path = ctx.obj["base_path"]
    try:
        target = f"all {type_filter} credentials" if type_filter else "ALL credentials"
        if not force:
            click.confirm(f"Purge {target}?", abort=True)
        password = _get_password()
        vault = Vault(base_path)
        count = vault.purge(password, type_filter=type_filter)
        print_warning(f"Purged {count} credential(s).")
    except OpvaultError as e:
        print_error(str(e))


@cli.command("export")
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "csv", "markdown"], case_sensitive=False),
    default="json",
    help="Export format.",
)
@click.option("--redact", is_flag=True, help="Mask secrets in output.")
@click.option("--output", "-o", type=click.Path(path_type=Path), default=None, help="Output file.")
@click.pass_context
def export_cmd(ctx: click.Context, fmt: str, redact: bool, output: Path | None) -> None:
    """Export credentials to JSON, CSV, or Markdown."""
    base_path = ctx.obj["base_path"]
    try:
        password = _get_password()
        vault = Vault(base_path)
        creds = vault.list_(password)

        exporters = {"json": to_json, "csv": to_csv, "markdown": to_markdown}
        result = exporters[fmt](creds, redact=redact)

        if output:
            output.write_text(result, encoding="utf-8")
            print_success(f"Exported {len(creds)} credential(s) to {output}")
        else:
            click.echo(result, nl=False)
    except OpvaultError as e:
        print_error(str(e))


@cli.command("import")
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "text"], case_sensitive=False),
    default=None,
    help="Import format (auto-detected from extension if omitted).",
)
@click.option("--type", "cred_type", default="password", help="Type for text imports.")
@click.pass_context
def import_cmd(ctx: click.Context, file: Path, fmt: str | None, cred_type: str) -> None:
    """Import credentials from a JSON or text file."""
    base_path = ctx.obj["base_path"]
    try:
        # Auto-detect format from extension
        if fmt is None:
            fmt = "json" if file.suffix.lower() == ".json" else "text"

        if fmt == "json":
            creds = from_json(file)
        else:
            creds = from_text(file, cred_type=cred_type)

        password = _get_password()
        vault = Vault(base_path)
        added = 0
        for cred in creds:
            vault.add(password, cred)
            added += 1

        print_success(f"Imported {added} credential(s).")
    except (OpvaultError, ValueError) as e:
        print_error(str(e))


@cli.command()
@click.pass_context
def unlock(ctx: click.Context) -> None:
    """Unlock the vault and cache the session (avoids repeated password prompts)."""
    base_path = ctx.obj["base_path"]
    try:
        password = click.prompt("Master password", hide_input=True)
        vault = Vault(base_path)
        vault._unlock(password)  # verify password is correct
        _write_session(password)
        print_success("Vault unlocked. Session cached.")
    except OpvaultError as e:
        print_error(str(e))


@cli.command()
def lock() -> None:
    """Lock the vault by clearing the cached session."""
    _clear_session()
    print_success("Session cleared. Vault locked.")


@cli.command()
def push() -> None:
    """Push vault to remote (enterprise feature)."""
    print_warning("Push is not available in the open source version.")
