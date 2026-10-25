"""Optional adapters for Sherlock, Holehe and PhoneInfoga.

They are used only when the executables exist in PATH. sAScan never vendors or
auto-installs third-party tools, and every external claim is labelled by source.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
from dataclasses import dataclass
from urllib.parse import urlparse

from sascan.models import Finding, Verdict
from sascan.modules.base import ModuleResult

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
URL_RE = re.compile(r"https?://[^\s)\]\"'<>]+")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

DOMAIN_NAMES = {
    "github.com": "GitHub",
    "gitlab.com": "GitLab",
    "codeberg.org": "Codeberg",
    "instagram.com": "Instagram",
    "tiktok.com": "TikTok",
    "twitter.com": "X (Twitter)",
    "x.com": "X (Twitter)",
    "reddit.com": "Reddit",
    "youtube.com": "YouTube",
    "twitch.tv": "Twitch",
    "soundcloud.com": "SoundCloud",
    "behance.net": "Behance",
    "dribbble.com": "Dribbble",
    "medium.com": "Medium",
    "steamcommunity.com": "Steam",
    "pinterest.com": "Pinterest",
    "telegram.org": "Telegram",
    "t.me": "Telegram",
    "dev.to": "Dev.to",
    "pypi.org": "PyPI",
    "news.ycombinator.com": "Hacker News",
    "facebook.com": "Facebook",
    "snapchat.com": "Snapchat",
    "spotify.com": "Spotify",
    "discord.com": "Discord",
    "patreon.com": "Patreon",
    "keybase.io": "Keybase",
    "about.me": "About.me",
    "linktr.ee": "Linktree",
    "mastodon.social": "Mastodon",
    "threads.net": "Threads",
}

IGNORED_HOSTS = {
    "sherlock-project.github.io",
    "github.com/sherlock-project",
    "phoneinfoga.io",
    "docs.phoneinfoga.io",
    "github.com/sundowndev",
    "github.com/megadose",
    "github.com/holehe",
}


@dataclass(frozen=True, slots=True)
class ExternalTool:
    key: str
    label: str
    command: str
    install: str

    @property
    def path(self) -> str | None:
        return shutil.which(self.command)


@dataclass(slots=True)
class ToolRun:
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    timed_out: bool = False
    error: str = ""

    @property
    def output(self) -> str:
        return "\n".join(part for part in (self.stdout, self.stderr) if part)


TOOLS: dict[str, ExternalTool] = {
    "sherlock": ExternalTool(
        key="sherlock",
        label="Sherlock",
        command="sherlock",
        install="pipx install sherlock-project",
    ),
    "holehe": ExternalTool(
        key="holehe",
        label="Holehe",
        command="holehe",
        install="pipx install holehe",
    ),
    "phoneinfoga": ExternalTool(
        key="phoneinfoga",
        label="PhoneInfoga",
        command="phoneinfoga",
        install=(
            "Install PhoneInfoga from "
            "https://github.com/sundowndev/phoneinfoga/releases"
        ),
    ),
}


def available_tools() -> dict[str, str | None]:
    return {key: tool.path for key, tool in TOOLS.items()}


def tool_status() -> list[tuple[str, str, bool, str]]:
    return [
        (tool.label, tool.command, bool(tool.path), tool.install)
        for tool in TOOLS.values()
    ]


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def _clean_line(line: str) -> str:
    return strip_ansi(line).replace("\r", "").strip()


def _platform_from_url(url: str, fallback: str = "") -> str:
    host = urlparse(url).netloc.lower().removeprefix("www.")
    for domain, name in DOMAIN_NAMES.items():
        if host == domain or host.endswith("." + domain):
            return name
    if fallback and not fallback.startswith("http"):
        return fallback.strip(" :-")[:48]
    return host or "External source"


def _ignored_url(url: str) -> bool:
    lowered = url.lower().rstrip(".,;")
    return any(host in lowered for host in IGNORED_HOSTS)


async def run_tool(tool: ExternalTool, args: list[str], timeout: float = 90.0) -> ToolRun:
    """Execute an external tool safely with a hard timeout and dumb terminal."""
    path = tool.path
    if not path:
        return ToolRun(error=f"{tool.label} is not installed.")
    env = os.environ.copy()
    env.update({"NO_COLOR": "1", "TERM": "dumb", "PYTHONIOENCODING": "utf-8"})
    try:
        process = await asyncio.create_subprocess_exec(
            path,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
    except (OSError, ValueError) as exc:
        return ToolRun(error=f"Could not start {tool.label}: {exc}")

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return ToolRun(timed_out=True, error=f"{tool.label} timed out ({timeout:.0f}s).")
    except asyncio.CancelledError:
        process.kill()
        await process.wait()
        raise

    return ToolRun(
        stdout=stdout.decode("utf-8", errors="ignore")[-500_000:],
        stderr=stderr.decode("utf-8", errors="ignore")[-100_000:],
        returncode=process.returncode,
    )


def _parse_sherlock(username: str, output: str) -> ModuleResult:
    result = ModuleResult()
    seen: set[str] = set()
    for raw_line in output.splitlines():
        line = _clean_line(raw_line)
        if not line.startswith("[+]") or "checking" in line.casefold():
            continue
        urls = URL_RE.findall(line)
        if not urls:
            continue
        url = urls[0].rstrip(".,;")
        if _ignored_url(url) or url in seen:
            continue
        seen.add(url)
        prefix = line[3:].split("http", 1)[0].strip(" :|-")
        result.findings.append(
            Finding(
                target=username,
                platform=_platform_from_url(url, prefix),
                kind="account",
                verdict=Verdict.FOUND,
                url=url,
                source="sherlock",
                category="Sherlock",
                detail="Found by Sherlock",
                confidence=82,
            )
        )
    if not result.findings:
        result.notes.append("Sherlock returned no profiles.")
    return result


async def run_sherlock(username: str, timeout: float = 120.0) -> ModuleResult:
    tool = TOOLS["sherlock"]
    run = await run_tool(
        tool,
        [username, "--timeout", "10", "--print-found", "--no-color"],
        timeout=timeout,
    )
    if run.error:
        return ModuleResult(errors=[run.error])
    result = _parse_sherlock(username, run.output)
    if run.returncode not in (0, None) and not result.findings:
        result.errors.append(f"Sherlock exited with code {run.returncode} and no results.")
    return result


def _parse_holehe(email: str, output: str) -> ModuleResult:
    result = ModuleResult()
    seen: set[str] = set()
    for raw_line in output.splitlines():
        line = _clean_line(raw_line)
        if not line.startswith("[+]"):
            continue
        urls = URL_RE.findall(line)
        text = line[3:].strip(" :-")
        if urls:
            url = urls[0].rstrip(".,;")
            if _ignored_url(url) or url in seen:
                continue
            seen.add(url)
            result.findings.append(
                Finding(
                    target=email,
                    platform=_platform_from_url(url),
                    kind="account",
                    verdict=Verdict.FOUND,
                    url=url,
                    source="holehe",
                    category="Holehe",
                    detail="Email is used for sign-in according to Holehe",
                    confidence=80,
                )
            )
            continue
        domain_match = re.search(r"([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)", text)
        if not domain_match:
            continue
        domain = domain_match.group(1).lower()
        if domain in seen:
            continue
        seen.add(domain)
        result.findings.append(
            Finding(
                target=email,
                platform=_platform_from_url(f"https://{domain}"),
                kind="account",
                verdict=Verdict.FOUND,
                url=f"https://{domain}",
                source="holehe",
                category="Holehe",
                detail="Email is used for sign-in according to Holehe",
                confidence=80,
            )
        )
    if not result.findings:
        result.notes.append("Holehe returned no used accounts.")
    return result


async def run_holehe(email: str, timeout: float = 120.0) -> ModuleResult:
    tool = TOOLS["holehe"]
    run = await run_tool(tool, [email, "--only-used", "--no-color"], timeout=timeout)
    if run.error:
        return ModuleResult(errors=[run.error])
    result = _parse_holehe(email, run.output)
    if run.returncode not in (0, None) and not result.findings:
        result.errors.append(f"Holehe exited with code {run.returncode} and no results.")
    return result


def _parse_phoneinfoga(phone: str, output: str) -> ModuleResult:
    result = ModuleResult()
    seen: set[str] = set()
    metadata_lines: list[str] = []
    for raw_line in output.splitlines():
        line = _clean_line(raw_line)
        if not line or line.startswith(("Running", "Scanning", "[*]")):
            continue
        emails = EMAIL_RE.findall(line)
        for email in emails:
            result.metadata.setdefault("emails", [])
            if email.lower() not in result.metadata["emails"]:
                result.metadata["emails"].append(email.lower())

        urls = URL_RE.findall(line)
        if not urls:
            if any(
                key in line.casefold()
                for key in ("country", "carrier", "line type", "location", "valid")
            ):
                metadata_lines.append(line)
            continue
        for url in urls:
            url = url.rstrip(".,;")
            if _ignored_url(url) or url in seen:
                continue
            seen.add(url)
            result.findings.append(
                Finding(
                    target=phone,
                    platform=_platform_from_url(url),
                    kind="lead",
                    verdict=Verdict.UNKNOWN,
                    url=url,
                    source="phoneinfoga",
                    category="PhoneInfoga",
                    detail="Possible lead from PhoneInfoga; verify manually",
                    confidence=40,
                )
            )
    if metadata_lines:
        result.notes.extend(metadata_lines[:8])
    if not result.findings:
        result.notes.append("PhoneInfoga returned no verifiable links.")
    return result


async def run_phoneinfoga(
    phone: str,
    timeout: float = 120.0,
    *,
    region: str = "SA",
) -> ModuleResult:
    tool = TOOLS["phoneinfoga"]
    run = await run_tool(tool, ["scan", "-n", phone], timeout=timeout)
    if run.error:
        return ModuleResult(errors=[run.error])
    result = _parse_phoneinfoga(phone, run.output)
    if run.returncode not in (0, None) and not result.findings:
        result.errors.append(f"PhoneInfoga exited with code {run.returncode} and no results.")
    if result.findings:
        result.notes.append("PhoneInfoga results are unverified leads, not proof.")
    return result
