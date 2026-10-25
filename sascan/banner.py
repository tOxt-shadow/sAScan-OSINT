"""sAScan's dragon banner, rendered with Rich."""

from __future__ import annotations

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sascan import __version__
from sascan.config import LEGAL_NOTICE

DRAGON = r"""
        ,     \    /      ,
       / \    )\__/(     / \
      /   \  (_\  /_)   /   \
 ____/_____\__\@  @/___/_____\____
|             |\../|              |
|              \VV/               |
|        ----------------         |
|_________________________________|
 |    /\ /      \\       \ /\    |
 |  /   V        ))       V   \  |
 |/     `       //        '     \|
 `              V                '
"""

LOGO_LINES = [
    r"███████╗  █████╗  ███████╗  ██████╗  █████╗  ███╗   ██╗",
    r"██╔════╝ ██╔══██╗ ██╔════╝ ██╔════╝ ██╔══██╗ ████╗  ██║",
    r"███████╗ ███████║ ███████╗ ██║      ███████║ ██╔██╗ ██║",
    r"╚════██║ ██╔══██║ ╚════██║ ██║      ██╔══██║ ██║╚██╗██║",
    r"███████║ ██║  ██║ ███████║ ╚██████╗ ██║  ██║ ██║ ╚████║",
    r"╚══════╝ ╚═╝  ╚═╝ ╚══════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═╝  ╚═══╝",
]

LOGO_COLORS = ["bright_cyan", "cyan", "bright_cyan", "deep_sky_blue1", "cyan", "bright_cyan"]
DRAGON_COLORS = [
    "spring_green3",
    "green3",
    "spring_green2",
    "green3",
    "spring_green3",
    "green3",
    "spring_green2",
    "green3",
    "spring_green3",
    "green3",
    "spring_green2",
    "green3",
]


def _colored_block(lines: list[str], colors: list[str]) -> Text:
    text = Text()
    for index, line in enumerate(lines):
        if index:
            text.append("\n")
        text.append(line, style=colors[index % len(colors)])
    return text


LOGO_WIDTH = max(len(line) for line in LOGO_LINES)
DRAGON_WIDTH = max(len(line) for line in DRAGON.strip("\n").splitlines())
SIDE_BY_SIDE_MIN_WIDTH = DRAGON_WIDTH + LOGO_WIDTH + 3 + 4 + 2


def _dragon_text() -> Text:
    dragon = Text()
    for index, line in enumerate(DRAGON.strip("\n").splitlines()):
        if index:
            dragon.append("\n")
        dragon.append(line, style=DRAGON_COLORS[index % len(DRAGON_COLORS)])
    return dragon


def _logo_text(compact: bool = False) -> Text:
    if compact:
        logo = Text("sAScan", style="bold bright_cyan")
        logo.append("\n\nDigital Footprint Intelligence", style="bold white")
        logo.append("\nUsername · Email · Phone", style="bright_black")
        logo.justify = "center"
        return logo
    logo = _colored_block(LOGO_LINES, LOGO_COLORS)
    logo.append("\n")
    logo.append("\n  Digital Footprint Intelligence", style="bold white")
    logo.append("\n  Username · Email · Phone", style="bright_black")
    return logo


def _subtitle_text() -> Text:
    subtitle = Text()
    subtitle.append(f"v{__version__}", style="bold gold1")
    subtitle.append("   ·   stateless", style="dim")
    subtitle.append("   ·   native + optional engines", style="dim")
    subtitle.append("   ·   🐉", style="bold green")
    return subtitle


def banner_renderable(width: int = 100) -> Panel:
    dragon = _dragon_text()
    compact_logo = width < LOGO_WIDTH + 6
    logo = _logo_text(compact=compact_logo)
    subtitle = _subtitle_text()

    if width >= SIDE_BY_SIDE_MIN_WIDTH:
        grid = Table.grid(padding=(0, 3), expand=False)
        grid.add_column(justify="left", vertical="middle", no_wrap=True)
        grid.add_column(justify="left", vertical="middle", no_wrap=True)
        grid.add_row(dragon, logo)
        body = Group(Align.center(grid), Text(""), Align.center(subtitle))
    else:
        blocks = [Align.center(logo), Text(""), Align.center(subtitle)]
        if width >= DRAGON_WIDTH + 6:
            blocks = [Align.center(dragon), Text("")] + blocks
        body = Group(*blocks)

    return Panel(
        body,
        title="[bold gold1]sAScan[/bold gold1] [green3]🐉[/green3]",
        subtitle="[dim]dragon-grade OSINT CLI[/dim]",
        border_style="gold1",
        box=box.ROUNDED,
        padding=(0, 2),
    )


def print_banner(console: Console, *, show_legal: bool = True) -> None:
    console.print()
    console.print(banner_renderable(console.width))
    if show_legal:
        console.print(
            f"[dim yellow]⚠  {LEGAL_NOTICE}[/dim yellow]",
            justify="center",
        )
    console.print()
