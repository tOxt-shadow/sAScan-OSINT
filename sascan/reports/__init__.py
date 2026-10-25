"""Report generators."""

from sascan.reports.console import render_console_report
from sascan.reports.html import (
    ReportError,
    default_report_path,
    open_report,
    render_html_report,
    write_html_report,
)

__all__ = [
    "ReportError",
    "default_report_path",
    "open_report",
    "render_console_report",
    "render_html_report",
    "write_html_report",
]
