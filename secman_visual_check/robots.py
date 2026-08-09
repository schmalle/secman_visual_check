"""Optional robots.txt enforcement (opt-in via --respect-robots)."""

from __future__ import annotations

import asyncio
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

from .ssrf_guard import is_unsafe_redirect

#: Every other outbound fetch in this tool (status.py, capture.py) validates
#: redirects against ssrf_guard before following them - a target's robots.txt
#: response is just as attacker-controlled as its page content, so a 3xx here
#: gets the same treatment instead of httpx's unrestricted follow_redirects.
_MAX_REDIRECTS = 5
_ALLOWED_SCHEMES = {"http", "https"}


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

        current = robots_url
        seen = {current}
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout_s, follow_redirects=False
            ) as client:
                for _ in range(_MAX_REDIRECTS + 1):
                    response = await client.get(current)
                    if not response.is_redirect:
                        break
                    location = response.headers.get("location")
                    if not location:
                        return None
                    nxt = urljoin(current, location)
                    if urlsplit(nxt).scheme not in _ALLOWED_SCHEMES:
                        return None
                    if nxt in seen:
                        return None  # redirect loop
                    if await is_unsafe_redirect(robots_url, nxt):
                        return None  # fail open: treat as unfetchable, same as any other error
                    seen.add(nxt)
                    current = nxt
                else:
                    return None  # too many redirects
        except Exception:
            return None

        if response.status_code >= 400:
            return None

        parser = RobotFileParser()
        parser.parse(response.text.splitlines())
        return parser
