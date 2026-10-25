"""Shared Rich console and small presentation helpers."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from sascan.models import Seed, SeedKind, Verdict

console = Console(highlight=False)
error_console = Console(stderr=True, highlight=False)

VERDICT_STYLES = {
    Verdict.FOUND: "bold green3",
    Verdict.ABSENT: "dim red",
    Verdict.UNKNOWN: "bold yellow3",
}


def confidence_bar(value: int, width: int = 18) -> Text:
    value = max(0, min(100, int(value)))
    filled = round(value / 100 * width)
    if value >= 70:
        style = "green3"
    elif value >= 45:
        style = "yellow3"
    else:
        style = "red3"
    text = Text()
    text.append("█" * filled, style=style)
    text.append("░" * (width - filled), style="grey30")
    text.append(f"  {value}%", style=f"bold {style}")
    return text


def verdict_text(verdict: Verdict) -> Text:
    return Text(verdict.label, style=VERDICT_STYLES[verdict])


def detected_phone_region(value: str, fallback: str) -> str:
    """Return the number's own region instead of the parsing hint."""
    if value.startswith("+"):
        try:
            import phonenumbers

            parsed = phonenumbers.parse(value, None)
            code = phonenumbers.region_code_for_number(parsed)
            if code:
                return code.upper()
        except Exception:
            pass
    return fallback.upper()


def scan_header(
    seed: Seed,
    *,
    engine: str,
    region: str,
    deep: bool,
    site_count: int | None = None,
) -> Panel:
    body = Text()
    body.append("Target   ", style="dim")
    body.append(seed.value, style="bold bright_white")
    body.append("\nKind     ", style="dim")
    body.append(seed.kind.label, style="bold cyan")
    body.append("\nEngine   ", style="dim")
    body.append(engine, style="bold gold1")
    if site_count is not None:
        body.append("\nNative   ", style="dim")
        body.append(f"{site_count} site rule(s)", style="bold white")
    if seed.kind is SeedKind.PHONE:
        body.append("\nRegion   ", style="dim")
        body.append(detected_phone_region(seed.value, region), style="white")
    body.append("\nDeep     ", style="dim")
    body.append("on" if deep else "off", style="green3" if deep else "bright_black")
    return Panel(
        body,
        title="[bold]Scan brief[/bold]",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(0, 2),
    )


def error_panel(message: str, title: str = "Error") -> Panel:
    return Panel(
        Text(str(message), style="white"),
        title=f"[bold red]{title}[/bold red]",
        border_style="red3",
        box=box.ROUNDED,
        padding=(0, 2),
    )


def warning_panel(message: str, title: str = "Notice") -> Panel:
    return Panel(
        Text(str(message), style="white"),
        title=f"[bold yellow3]{title}[/bold yellow3]",
        border_style="yellow3",
        box=box.ROUNDED,
        padding=(0, 2),
    )
