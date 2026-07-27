"""Optional robots.txt enforcement (opt-in via --respect-robots)."""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser


class RobotsCache:
    """Fetches and caches robots.txt per origin.

    Fail-open: an origin whose robots.txt cannot be fetched is treated as
    allowing everything, matching how crawlers conventionally behave.
    """

    def __init__(self, user_agent: str = "*", timeout_s: float = 10.0) -> None:
        self.user_agent = user_agent
        self.timeout_s = timeout_s
        self._parsers: dict[str, RobotFileParser | None] = {}
        self._lock = asyncio.Lock()

    async def allowed(self, url: str) -> bool:
        parser = await self._parser_for(url)
        if parser is None:
            return True
        return parser.can_fetch(self.user_agent, url)

    async def _parser_for(self, url: str) -> RobotFileParser | None:
        parts = urlsplit(url)
        origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        async with self._lock:
            if origin in self._parsers:
                return self._parsers[origin]

        parser = await self._fetch(f"{origin}/robots.txt")
        async with self._lock:
            self._parsers[origin] = parser
        return parser

    async def _fetch(self, robots_url: str) -> RobotFileParser | None:
        import httpx

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_s, follow_redirects=True
            ) as client:
                response = await client.get(robots_url)
        except Exception:
            return None

        if response.status_code >= 400:
            return None

        parser = RobotFileParser()
        parser.parse(response.text.splitlines())
        return parser
