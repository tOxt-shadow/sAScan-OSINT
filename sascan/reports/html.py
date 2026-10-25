"""Interactive HTML report generation."""

from __future__ import annotations

import json
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from sascan import __version__
from sascan.config import TEMPLATE_DIR
from sascan.models import ScanResult
from sascan.utils.text import slugify


class ReportError(RuntimeError):
    """Could not write or render the report."""


def default_report_path(seed_value: str, kind: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"sascan_{slugify(kind, 'scan')}_{slugify(seed_value)}_{stamp}.html"
    return Path.cwd() / "reports" / filename


def _safe_json(payload: object) -> str:
    raw = json.dumps(payload, ensure_ascii=False, indent=2)
    return (
        raw.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def render_html_report(result: ScanResult) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("report.html.j2")
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return template.render(
        result=result,
        version=__version__,
        generated_at=generated_at,
        sascan_json=_safe_json(result.to_dict()),
    )


def write_html_report(result: ScanResult, output: str | Path | None = None) -> Path:
    """Write the report and return its resolved path."""
    if output is None:
        path = default_report_path(result.seed.value, result.seed.kind.value)
    else:
        path = Path(output).expanduser()
        if path.suffix.lower() not in {".html", ".htm"}:
            path = path / default_report_path(
                result.seed.value, result.seed.kind.value
            ).name
    path = path.resolve()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_html_report(result), encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"Could not write the HTML report to {path}: {exc}") from exc
    except Exception as exc:
        raise ReportError(f"Could not render the HTML report: {exc}") from exc
    return path


def open_report(path: Path) -> bool:
    """Open the report in the default browser. Returns False when unavailable."""
    try:
        return bool(webbrowser.open(path.resolve().as_uri(), new=2))
    except Exception:
        return False
