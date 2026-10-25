"""sAScan command-line interface."""

from __future__ import annotations

import asyncio
import json
import platform
import re
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Callable

import click

from sascan import __version__
from sascan.banner import print_banner
from sascan.config import (
    DEFAULT_CONCURRENCY,
    DEFAULT_REGION,
    DEFAULT_TIMEOUT,
    ENGINE_CHOICES,
    LEGAL_NOTICE,
)
from sascan.core.engine import EngineError, ScanEngine, ScanOptions
from sascan.core.progress import ScanProgress
from sascan.core.sites import SiteRegistry, SitesConfigError
from sascan.models import SeedKind
from sascan.modules.external import tool_status
from sascan.reports.console import render_console_report
from sascan.reports.html import ReportError, open_report, write_html_report
from sascan.ui import (
    console,
    error_console,
    error_panel,
    scan_header,
)
from sascan.utils.validators import InvalidSeed, detect_seed

CONTEXT_SETTINGS = {
    "help_option_names": ["-h", "--help"],
    "max_content_width": 110,
}

GLOBAL_FLAGS = frozenset({"--no-banner", "--quiet", "--no-color"})


class ReorderingGroup(click.Group):
    """Accept global flags before or after the subcommand.

    Click normally requires group options to precede the subcommand. Moving the
    known boolean global flags to the front keeps both styles working:
    ``sascan --no-banner version`` and ``sascan version --no-banner``.
    """

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        flags = [arg for arg in args if arg in GLOBAL_FLAGS]
        if flags:
            args = flags + [arg for arg in args if arg not in GLOBAL_FLAGS]
        return super().parse_args(ctx, args)


def _start(ctx: click.Context, *, json_mode: bool = False) -> None:
    flags = ctx.obj or {}
    if not flags.get("quiet") and not flags.get("no_banner") and not json_mode:
        print_banner(console)


def _fail(message: str, *, code: int = 2) -> None:
    error_console.print(error_panel(message))
    raise click.exceptions.Exit(code)


def _split_only(values: tuple[str, ...]) -> tuple[str, ...]:
    items: list[str] = []
    for raw in values:
        for part in re.split(r"[,;]", raw):
            value = part.strip()
            if value and value.casefold() not in {item.casefold() for item in items}:
                items.append(value)
    return tuple(items)


def _region_callback(
    ctx: click.Context, param: click.Parameter, value: str
) -> str:
    value = (value or "").strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", value):
        raise click.BadParameter(
            "Use a two-letter ISO region code such as SA, US, GB or EG."
        )
    return value


def scan_options(func: Callable[..., Any]) -> Callable[..., Any]:
    """Options shared by scan, user, email and phone."""
    options = [
        click.option(
            "--deep",
            is_flag=True,
            help="Follow derived username candidates (email seeds, bounded).",
        ),
        click.option(
            "--engine",
            "engine_name",
            type=click.Choice(ENGINE_CHOICES, case_sensitive=False),
            default="auto",
            show_default=True,
            help="native = built-in, auto = native + installed tools, both = require both.",
        ),
        click.option(
            "--region",
            default=DEFAULT_REGION,
            show_default=True,
            callback=_region_callback,
            help="ISO country code used to parse phone numbers.",
        ),
        click.option(
            "--timeout",
            type=click.FloatRange(2.0, 120.0),
            default=DEFAULT_TIMEOUT,
            show_default=True,
            help="Per-request timeout in seconds.",
        ),
        click.option(
            "--concurrency",
            type=click.IntRange(1, 100),
            default=DEFAULT_CONCURRENCY,
            show_default=True,
            help="Maximum concurrent HTTP requests.",
        ),
        click.option(
            "--only",
            multiple=True,
            metavar="FILTER",
            help="Limit native sites (comma separated or repeatable).",
        ),
        click.option(
            "--output",
            type=click.Path(dir_okay=True, file_okay=True, writable=True),
            default=None,
            help="HTML file path, or a directory for the generated report.",
        ),
        click.option("--no-open", is_flag=True, help="Do not open the HTML report."),
        click.option("--no-report", is_flag=True, help="Skip HTML report generation."),
        click.option(
            "--json",
            "as_json",
            is_flag=True,
            help="Print machine-readable JSON only (implies --no-report --no-open).",
        ),
        click.option(
            "--verbose",
            is_flag=True,
            help="Show every inconclusive finding and debug errors.",
        ),
    ]
    for option in reversed(options):
        func = option(func)
    return func


@click.group(
    invoke_without_command=True,
    context_settings=CONTEXT_SETTINGS,
    no_args_is_help=False,
    cls=ReorderingGroup,
)
@click.option(
    "--no-banner",
    is_flag=True,
    help="Hide the ASCII banner.",
)
@click.option(
    "--quiet",
    is_flag=True,
    help="Hide banner and progress animation; results are still printed.",
)
@click.option(
    "--no-color",
    is_flag=True,
    help="Disable ANSI colors.",
)
@click.version_option(__version__, "-V", "--version", prog_name="sAScan")
@click.pass_context
def cli(
    ctx: click.Context,
    no_banner: bool,
    quiet: bool,
    no_color: bool,
) -> None:
    """sAScan 🐉 — dragon-grade digital footprint intelligence.

    Stateless username, email and phone reconnaissance with a native engine,
    optional Sherlock / Holehe / PhoneInfoga adapters, correlation analysis and
    an interactive HTML report.

    \b
    Examples:
      sascan user alice
      sascan scan alice@example.com --deep
      sascan phone +966501234567 --region SA
      sascan sites --search github

    Only scan your own footprint or data you have explicit permission to examine.
    """
    if no_color:
        console.no_color = True
        error_console.no_color = True
    ctx.ensure_object(dict)
    ctx.obj.update(
        {
            "no_banner": no_banner,
            "quiet": quiet,
            "no_color": no_color,
        }
    )
    if ctx.invoked_subcommand is None:
        if not quiet and not no_banner:
            print_banner(console)
        click.echo(ctx.get_help())


def _run(
    ctx: click.Context,
    *,
    target: str,
    forced_kind: SeedKind | None,
    deep: bool,
    engine_name: str,
    region: str,
    timeout: float,
    concurrency: int,
    only: tuple[str, ...],
    output: str | None,
    no_open: bool,
    no_report: bool,
    as_json: bool,
    verbose: bool,
) -> None:
    _start(ctx, json_mode=as_json)
    try:
        seed = detect_seed(target, forced_kind=forced_kind, region=region)
    except InvalidSeed as exc:
        _fail(str(exc))

    options = ScanOptions(
        engine=engine_name.lower(),
        deep=deep,
        region=region,
        timeout=timeout,
        concurrency=concurrency,
        only=_split_only(only),
    )
    try:
        engine = ScanEngine(options)
    except EngineError as exc:
        _fail(str(exc), code=1)

    if options.only and seed.kind is not SeedKind.USERNAME:
        console.print(
            "[dim]Note: --only applies to native username site checks and was ignored.[/dim]"
        )

    if not (ctx.obj or {}).get("quiet") and not as_json:
        console.print(
            scan_header(
                seed,
                engine=options.engine,
                region=options.region,
                deep=options.deep,
                site_count=(
                    engine.site_count
                    if seed.kind is SeedKind.USERNAME
                    and options.engine in {"native", "auto", "both"}
                    else None
                ),
            )
        )

    progress = ScanProgress(
        total=1,
        console=console,
        enabled=not (ctx.obj or {}).get("quiet")
        and not as_json
        and console.is_terminal,
        description="Starting scan",
    )
    try:
        with progress as tracker:
            result = asyncio.run(engine.scan(seed, progress=tracker))
    except EngineError as exc:
        _fail(str(exc), code=1)
    except KeyboardInterrupt:
        error_console.print(error_panel("Scan interrupted by the user.", title="Interrupted"))
        raise click.exceptions.Exit(130) from None
    except Exception as exc:
        if verbose:
            raise
        _fail(
            f"Unexpected engine failure: {type(exc).__name__}: {exc}\n"
            "Re-run with --verbose for a traceback.",
            code=1,
        )
        return

    if as_json:
        click.echo(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        return

    render_console_report(result, console=console, verbose=verbose)

    if no_report:
        return

    status = (
        nullcontext()
        if (ctx.obj or {}).get("quiet") or not console.is_terminal
        else console.status("[cyan]Rendering interactive HTML report…[/cyan]", spinner="dots")
    )
    try:
        with status:
            report_path = write_html_report(result, output)
    except ReportError as exc:
        error_console.print(error_panel(str(exc), title="Report error"))
        return

    link = f"[bold cyan link={report_path.as_uri()}]{report_path}[/bold cyan link]"
    console.print(f"[green3]✓[/green3] HTML report saved to {link}")
    if no_open:
        console.print("[dim]Auto-open disabled (--no-open).[/dim]")
        return
    if open_report(report_path):
        console.print("[dim]Opened in your default browser.[/dim]")
    else:
        console.print(
            "[yellow3]Could not launch a browser automatically. "
            "Open the report path manually.[/yellow3]"
        )
    console.print()


@cli.command()
@click.argument("target")
@scan_options
@click.pass_context
def scan(ctx: click.Context, target: str, **kwargs: Any) -> None:
    """Auto-detect the target kind, then scan it.

    TARGET may be a username, email address or phone number.
    """
    _run(ctx, target=target, forced_kind=None, **kwargs)


@cli.command()
@click.argument("username")
@scan_options
@click.pass_context
def user(ctx: click.Context, username: str, **kwargs: Any) -> None:
    """Scan a USERNAME across native sites (and Sherlock if available)."""
    _run(ctx, target=username, forced_kind=SeedKind.USERNAME, **kwargs)


@cli.command()
@click.argument("email")
@scan_options
@click.pass_context
def email(ctx: click.Context, email: str, **kwargs: Any) -> None:
    """Scan an EMAIL: DNS, Gravatar, GitHub commit evidence and optional Holehe."""
    _run(ctx, target=email, forced_kind=SeedKind.EMAIL, **kwargs)


@cli.command()
@click.argument("phone")
@scan_options
@click.pass_context
def phone(ctx: click.Context, phone: str, **kwargs: Any) -> None:
    """Scan a PHONE number: metadata plus optional PhoneInfoga."""
    _run(ctx, target=phone, forced_kind=SeedKind.PHONE, **kwargs)


@cli.command("sites")
@click.option("--search", "query", default="", help="Filter by name, category or kind.")
@click.option("--json", "as_json", is_flag=True, help="Print the site registry as JSON.")
@click.pass_context
def sites_command(ctx: click.Context, query: str, as_json: bool) -> None:
    """List the built-in platform rules (no network calls)."""
    _start(ctx, json_mode=as_json)
    registry = SiteRegistry()
    try:
        registry.load()
    except SitesConfigError as exc:
        _fail(str(exc), code=1)
        return
    rules = list(registry.rules)
    if query:
        needle = query.casefold()
        rules = [
            rule
            for rule in rules
            if needle
            in f"{rule.name} {rule.category} {rule.kind} {rule.url_template}".casefold()
        ]

    if as_json:
        payload = [
            {
                "name": rule.name,
                "category": rule.category,
                "kind": rule.kind,
                "url": rule.url_template,
                "link": rule.link_template,
                "has_markers": rule.needs_body,
                "enabled": rule.enabled,
            }
            for rule in rules
        ]
        click.echo(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    from rich import box
    from rich.table import Table
    from rich.text import Text

    table = Table(
        title=f"[bold]Native site registry · {len(rules)} site(s)[/bold]",
        box=box.SIMPLE_HEAD,
        header_style="bold bright_white",
        border_style="grey30",
        expand=True,
    )
    table.add_column("#", justify="right", style="bright_black", width=3)
    table.add_column("Platform", style="bold white", no_wrap=True)
    table.add_column("Category", style="bright_black", no_wrap=True)
    table.add_column("Kind", style="cyan", no_wrap=True)
    table.add_column("URL template", style="bright_black", overflow="fold")

    for index, rule in enumerate(rules, 1):
        table.add_row(
            str(index),
            Text(rule.name),
            Text(rule.category),
            Text(rule.kind),
            Text(rule.url_template),
        )
    console.print(table)
    console.print(
        "[dim]Use --only with a scan to limit native checks. "
        "Site rules live in sascan/data/sites.json.[/dim]"
    )
    console.print()


@cli.command("version")
@click.pass_context
def version_command(ctx: click.Context) -> None:
    """Show version, runtime and optional engine availability."""
    _start(ctx)
    from rich import box
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    info = Table.grid(padding=(0, 2))
    info.add_column(style="dim", no_wrap=True)
    info.add_column(style="bold white")
    info.add_row("sAScan", f"v{__version__}")
    info.add_row("Python", platform.python_version())
    info.add_row("Platform", f"{platform.system()} {platform.release()}")
    info.add_row("Storage", "stateless (no database)")
    try:
        count = SiteRegistry().load()
        info.add_row("Native sites", str(count))
    except SitesConfigError as exc:
        info.add_row("Native sites", Text(str(exc), style="red3"))
    info.add_row("License", "MIT")
    console.print(
        Panel(
            info,
            title="[bold gold1]Runtime[/bold gold1]",
            border_style="gold1",
            box=box.ROUNDED,
            padding=(0, 1),
        )
    )

    tools = Table(
        box=box.SIMPLE_HEAD,
        header_style="bold bright_white",
        expand=True,
    )
    tools.add_column("Optional engine", style="bold white")
    tools.add_column("Executable", style="cyan")
    tools.add_column("Status", no_wrap=True)
    tools.add_column("Install", style="bright_black", overflow="fold")
    for label, command, found, install in tool_status():
        status = Text("available", style="bold green3") if found else Text("not installed", style="dim red")
        tools.add_row(label, command, status, install)
    console.print(
        Panel(
            tools,
            title="[bold cyan]External engines[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 1),
        )
    )
    console.print(f"[dim]{LEGAL_NOTICE}[/dim]")
    console.print()


def main() -> None:
    cli(prog_name="sascan")


if __name__ == "__main__":  # pragma: no cover
    main()
