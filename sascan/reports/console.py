"""Formatted Rich console report."""

from __future__ import annotations

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from sascan import __version__
from sascan.config import LEGAL_NOTICE
from sascan.models import Correlation, Finding, ScanResult, Verdict
from sascan.ui import VERDICT_STYLES, confidence_bar
from sascan.utils.text import human_duration, truncate

PALETTE = {
    "found": "green3",
    "unknown": "yellow3",
    "absent": "red3",
    "muted": "bright_black",
    "accent": "cyan",
    "gold": "gold1",
}


def _link(url: str, label: str | None = None) -> Text:
    text = Text()
    if url.startswith(("http://", "https://")):
        text.append(label or truncate(url, 58), style=f"underline {PALETTE['accent']} link {url}")
    else:
        text.append(label or url, style=PALETTE["muted"])
    return text


def _findings_table(findings: list[Finding], *, unknown: bool = False) -> Table:
    table = Table(
        box=box.SIMPLE_HEAD,
        header_style="bold bright_white",
        border_style="grey30",
        pad_edge=False,
        expand=True,
    )
    table.add_column("Platform", style="bold white", no_wrap=True, max_width=22)
    table.add_column("Category", style="bright_black", no_wrap=True, max_width=16)
    table.add_column("Source", style="cyan", no_wrap=True, max_width=10)
    table.add_column("Conf.", justify="right", no_wrap=True, width=6)
    table.add_column("Evidence", overflow="fold")

    for finding in findings:
        evidence = Text()
        if finding.detail:
            evidence.append(truncate(finding.detail, 96), style="white")
        if finding.url:
            if evidence:
                evidence.append("\n")
            evidence.append_text(_link(finding.url))
        if not finding.detail and not finding.url:
            evidence.append("—", style="dim")
        conf_style = (
            PALETTE["found"]
            if finding.confidence >= 70
            else PALETTE["unknown"]
            if finding.confidence >= 40
            else PALETTE["muted"]
        )
        table.add_row(
            Text(finding.platform, style="bold white"),
            Text(finding.category, style="bright_black"),
            Text(finding.source, style="cyan"),
            Text(f"{finding.confidence}%", style=conf_style),
            evidence,
        )
    return table


def _stats_bar(result: ScanResult) -> Table:
    stats = result.stats
    grid = Table.grid(expand=True)
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    entries = [
        ("FOUND", stats.found, PALETTE["found"]),
        ("UNKNOWN", stats.unknown, PALETTE["unknown"]),
        ("ABSENT", stats.absent, PALETTE["absent"]),
        ("DURATION", human_duration(stats.duration_ms), PALETTE["accent"]),
    ]
    cells = []
    for label, value, style in entries:
        cell = Text(justify="center")
        cell.append(f"{value}\n", style=f"bold {style}")
        cell.append(label, style="bright_black")
        cells.append(cell)
    grid.add_row(*cells)
    return grid


def _identifiers_tree(correlation: Correlation) -> Tree:
    tree = Tree(
        Text("Unified digital footprint", style="bold gold1"),
        guide_style="grey37",
    )
    roots = [
        ("Usernames", correlation.usernames, "cyan"),
        ("Emails", correlation.emails, "green3"),
        ("Phones", correlation.phones, "magenta"),
    ]
    for title, values, style in roots:
        if not values:
            continue
        branch = tree.add(Text(f"{title} ({len(values)})", style=f"bold {style}"))
        for value in values[:12]:
            branch.add(Text(value, style=style))
    if correlation.candidates:
        branch = tree.add(
            Text(f"Derived candidates ({len(correlation.candidates)})", style="bold yellow3")
        )
        for candidate in correlation.candidates[:12]:
            label = Text(candidate.value, style="yellow3")
            label.append(
                f"  {'scanned' if candidate.scanned else 'not scanned'} · "
                f"{candidate.confidence}% · {candidate.source}",
                style="bright_black",
            )
            branch.add(label)
    return tree


def _profile_panel(correlation: Correlation) -> Panel | None:
    profile = correlation.profile
    if not profile:
        return None
    body = Text()
    name = profile.get("display_name") or "Public profile"
    body.append(name, style="bold bright_white")
    fields = [
        ("Bio", profile.get("about_me")),
        ("Location", profile.get("location")),
        ("Job", profile.get("job_title")),
        ("Company", profile.get("company")),
    ]
    for label, value in fields:
        if value:
            body.append(f"\n{label}  ", style="dim")
            body.append(truncate(str(value), 180), style="white")
    links = profile.get("links") or []
    if links:
        body.append("\nLinks  ", style="dim")
        for index, link in enumerate(links[:3]):
            if index:
                body.append(" · ", style="dim")
            body.append_text(_link(link))
    accounts = profile.get("accounts") or []
    if accounts:
        body.append(f"\nLinked accounts  ", style="dim")
        body.append(str(len(accounts)), style="bold green3")
    return Panel(
        body,
        title="[bold green3]Public profile signal[/bold green3]",
        border_style="green3",
        box=box.ROUNDED,
        padding=(0, 1),
    )


def render_console_report(
    result: ScanResult,
    *,
    console: Console,
    verbose: bool = False,
) -> None:
    """Print the human-readable report for one completed scan."""
    stats = result.stats
    header = Text()
    header.append("Target  ", style="dim")
    header.append(result.seed.value, style="bold bright_white")
    header.append("\nKind  ", style="dim")
    header.append(result.seed.kind.label, style="cyan")
    header.append("\nConfidence  ", style="dim")
    header.append_text(confidence_bar(result.correlation.confidence))
    header.append("\nEngines  ", style="dim")
    header.append(", ".join(result.engines), style="gold1")

    console.print()
    console.rule("[bold gold1]SCAN RESULT[/bold gold1]", style="grey37")
    console.print(
        Panel(
            header,
            title=f"[bold green3]🐉 sAScan · {result.seed.kind.label}[/bold green3]",
            border_style="green3",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )
    console.print(_stats_bar(result))
    console.print()
    console.print(
        Panel(
            _identifiers_tree(result.correlation),
            title="[bold]Correlation engine[/bold]",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 1),
        )
    )

    profile_panel = _profile_panel(result.correlation)
    if profile_panel:
        console.print(profile_panel)

    found = result.found
    if found:
        console.print(
            Panel(
                _findings_table(found),
                title=f"[bold green3]Confirmed signals · {len(found)}[/bold green3]",
                border_style="green3",
                box=box.ROUNDED,
                padding=(0, 1),
            )
        )
    else:
        console.print(
            Panel(
                Text(
                    "No verified public account was confirmed in this pass.\n"
                    "This is not proof that the identity does not exist.",
                    style="yellow3",
                ),
                title="[bold yellow3]No confirmed profiles[/bold yellow3]",
                border_style="yellow3",
                box=box.ROUNDED,
                padding=(0, 1),
            )
        )

    unknown = result.unknown
    if unknown:
        shown = unknown if verbose else unknown[:10]
        table = _findings_table(shown, unknown=True)
        suffix = "" if len(shown) == len(unknown) else f" (showing {len(shown)} of {len(unknown)})"
        console.print(
            Panel(
                table,
                title=f"[bold yellow3]Inconclusive · {len(unknown)}{suffix}[/bold yellow3]",
                border_style="yellow3",
                box=box.ROUNDED,
                padding=(0, 1),
            )
        )

    if result.absent:
        absent = Text()
        absent.append(
            f"{len(result.absent)} check(s) returned a definitive absence signal.\n",
            style="dim",
        )
        absent.append(
            ", ".join(f.platform for f in result.absent[:40])
            + (" …" if len(result.absent) > 40 else ""),
            style="red3",
        )
        console.print(
            Panel(
                absent,
                title="[bold red3]Absent[/bold red3]",
                border_style="grey30",
                box=box.ROUNDED,
                padding=(0, 1),
            )
        )

    if result.errors:
        errors = Text()
        for error in result.errors[-6:]:
            errors.append(f"• {error}\n", style="red3")
        console.print(
            Panel(
                errors,
                title="[bold red3]Engine errors[/bold red3]",
                border_style="red3",
                box=box.ROUNDED,
                padding=(0, 1),
            )
        )

    if result.notes:
        notes = Text()
        for note in result.notes[:8]:
            notes.append(f"• {note}\n", style="bright_black")
        console.print(
            Panel(
                notes,
                title="[bold]Notes[/bold]",
                border_style="grey30",
                box=box.ROUNDED,
                padding=(0, 1),
            )
        )

    footer = Text()
    footer.append(f"Confidence {result.correlation.confidence}%", style="bold gold1")
    footer.append("  ·  ", style="bright_black")
    footer.append(f"{stats.platforms_found} platform(s)", style="cyan")
    footer.append("  ·  ", style="bright_black")
    footer.append(result.correlation.summary, style="white")
    console.print(Panel(footer, border_style="gold1", box=box.ROUNDED, padding=(0, 1)))
    console.print(f"[dim]{LEGAL_NOTICE}[/dim]")
    console.print(f"[bright_black]sAScan {__version__} · stateless · no database[/bright_black]")
    console.print()
