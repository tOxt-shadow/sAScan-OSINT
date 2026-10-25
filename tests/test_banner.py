"""The banner must stay aligned on wide and narrow terminals."""

from __future__ import annotations

from rich.console import Console

from sascan.banner import LOGO_WIDTH, banner_renderable


def _render(width: int) -> str:
    console = Console(
        width=width,
        color_system=None,
        force_terminal=False,
        record=True,
    )
    console.print(banner_renderable(width))
    return console.export_text()


def test_wide_banner_contains_dragon_and_logo() -> None:
    output = _render(120)

    assert "…" not in output
    assert "@  @" in output
    assert "███████" in output
    assert "dragon-grade OSINT CLI" in output


def test_narrow_banner_stacks_without_truncation() -> None:
    output = _render(80)

    assert "…" not in output
    assert "@  @" in output
    assert "███████" in output
    assert "Digital Footprint Intelligence" in output


def test_very_narrow_banner_uses_compact_logo() -> None:
    output = _render(60)

    assert "…" not in output
    assert "███████" not in output
    assert "sAScan" in output
    assert "Digital Footprint Intelligence" in output


def test_banner_lines_fit_the_requested_width() -> None:
    for width in (40, 60, 80, 99, 100, 120):
        output = _render(width)
        assert max(len(line) for line in output.splitlines()) <= width, width


def test_compact_logo_threshold_is_consistent() -> None:
    assert LOGO_WIDTH > 0
    wide = _render(LOGO_WIDTH + 6)
    narrow = _render(LOGO_WIDTH + 5)
    assert "███████" in wide
    assert "███████" not in narrow
