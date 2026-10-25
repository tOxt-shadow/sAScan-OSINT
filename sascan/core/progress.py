"""Rich-powered progress reporting used by the scan engine."""

from __future__ import annotations

from contextlib import AbstractContextManager

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from sascan.utils.text import truncate


class ScanProgress(AbstractContextManager["ScanProgress"]):
    """A compact progress bar that degrades cleanly in quiet/non-TTY mode."""

    def __init__(
        self,
        total: int,
        *,
        console: Console | None = None,
        enabled: bool = True,
        description: str = "Scanning platforms",
    ) -> None:
        self.enabled = enabled and total > 0
        self.total = max(0, int(total))
        self.description = description
        self.console = console or Console()
        self._progress: Progress | None = None
        self._task_id: int | None = None

    def __enter__(self) -> "ScanProgress":
        if not self.enabled:
            return self
        self._progress = Progress(
            SpinnerColumn(style="bold cyan"),
            TextColumn("[bold white]{task.description}", justify="left"),
            BarColumn(
                bar_width=30,
                style="grey27",
                complete_style="cyan",
                finished_style="green",
            ),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        )
        self._progress.start()
        self._task_id = self._progress.add_task(self.description, total=self.total)
        return self

    def set_total(self, total: int) -> None:
        self.total = max(0, int(total))
        if self._progress and self._task_id is not None:
            self._progress.update(self._task_id, total=self.total)

    def advance(self, label: str = "") -> None:
        if self._progress and self._task_id is not None:
            description = self.description
            if label:
                description = f"{self.description} · {truncate(label, 28)}"
            self._progress.update(
                self._task_id,
                advance=1,
                description=description,
            )

    def finish(self) -> None:
        if self._progress:
            self._progress.stop()
            self._progress = None
            self._task_id = None

    def __exit__(self, *exc_info: object) -> None:
        self.finish()
