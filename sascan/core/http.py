"""Shared async HTTP client with bounded concurrency and safe error handling."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from sascan.config import BASE_HEADERS, DEFAULT_BODY_LIMIT, DEFAULT_CONCURRENCY, DEFAULT_TIMEOUT

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class HttpResponse:
    url: str
    status: int | None = None
    body: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    error: str = ""
    elapsed_ms: int = 0

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 400

    @property
    def network_failed(self) -> bool:
        return self.status is None


class AsyncHttpClient:
    """One aiohttp session per scan, with a semaphore and one retry on network errors."""

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        concurrency: int = DEFAULT_CONCURRENCY,
        body_limit: int = DEFAULT_BODY_LIMIT,
        headers: dict[str, str] | None = None,
        retries: int = 1,
    ) -> None:
        self.timeout = max(1.0, float(timeout))
        self.concurrency = max(1, int(concurrency))
        self.body_limit = max(1_000, int(body_limit))
        self.headers = {**BASE_HEADERS, **(headers or {})}
        self.retries = max(0, int(retries))
        self._session: aiohttp.ClientSession | None = None
        self._semaphore = asyncio.Semaphore(self.concurrency)

    async def __aenter__(self) -> "AsyncHttpClient":
        await self.open()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    async def open(self) -> None:
        if self._session and not self._session.closed:
            return
        connector = aiohttp.TCPConnector(
            limit=self.concurrency,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers=self.headers,
        )

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()
        self._session = None

    async def get(
        self,
        url: str,
        *,
        read_body: bool = True,
        allow_redirects: bool = True,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        return await self.request(
            "GET",
            url,
            read_body=read_body,
            allow_redirects=allow_redirects,
            headers=headers,
        )

    async def request(
        self,
        method: str,
        url: str,
        *,
        read_body: bool = True,
        allow_redirects: bool = True,
        headers: dict[str, str] | None = None,
        json_body: Any | None = None,
    ) -> HttpResponse:
        if self._session is None or self._session.closed:
            await self.open()

        attempts = self.retries + 1
        last: HttpResponse | None = None
        for attempt in range(attempts):
            started = time.perf_counter()
            async with self._semaphore:
                try:
                    assert self._session is not None
                    async with self._session.request(
                        method,
                        url,
                        allow_redirects=allow_redirects,
                        headers=headers,
                        json=json_body,
                    ) as response:
                        body = ""
                        if read_body:
                            raw = await response.content.read(self.body_limit)
                            body = raw.decode(response.charset or "utf-8", errors="ignore")
                        return HttpResponse(
                            url=str(response.url),
                            status=response.status,
                            body=body,
                            headers={k.lower(): v for k, v in response.headers.items()},
                            elapsed_ms=int((time.perf_counter() - started) * 1000),
                        )
                except asyncio.TimeoutError:
                    last = HttpResponse(
                        url=url,
                        error="Request timed out",
                        elapsed_ms=int((time.perf_counter() - started) * 1000),
                    )
                except aiohttp.ClientError as exc:
                    last = HttpResponse(
                        url=url,
                        error=f"Connection failed ({type(exc).__name__})",
                        elapsed_ms=int((time.perf_counter() - started) * 1000),
                    )
                except Exception as exc:  # pragma: no cover - defensive
                    logger.debug("Unexpected HTTP error for %s", url, exc_info=True)
                    last = HttpResponse(
                        url=url,
                        error=f"Unexpected error ({type(exc).__name__})",
                        elapsed_ms=int((time.perf_counter() - started) * 1000),
                    )
            if attempt + 1 < attempts:
                await asyncio.sleep(0.25 * (attempt + 1))
        return last or HttpResponse(url=url, error="Unknown request failure")

    async def get_json(self, url: str, **kwargs: Any) -> tuple[Any | None, HttpResponse]:
        response = await self.get(url, **kwargs)
        if response.status is None or not response.body:
            return None, response
        try:
            import json

            return json.loads(response.body), response
        except (ValueError, TypeError):
            return None, response
